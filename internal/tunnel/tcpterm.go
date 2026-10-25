package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Terminator is the §3.3 wave-5c TCP data path: a userspace TCP endpoint
// that SPOOFS the server side of tunnel-verdict flows.
//
// Why: live matrix 2026-10-25 (zz_gensyn/zz_tcprealip/zz_inbest tests)
// proved that on stock WinDivert 2.2 a NETWORK-layer injected TCP packet
// is delivered by the Windows stack ONLY for flows the stack authorized on
// the outbound leg (an outbound SYN ALE-authorizes the 5-tuple). Inbound
// SYNs toward a local listener — the NAT→tproxy forward leg of §3.3 — are
// silently dropped in every (IfIdx, Loopback, dst) combination, including
// byte-identical replays of genuine SYNs. The REDIRECT layer that would
// natively solve this exists only in the winws fork driver.
//
// So instead of moving the CLIENT's packets to a local listener, the
// terminator answers the client itself:
//
//	client SYN  (captured outbound, consumed)     ← engine Feed
//	forged SYN-ACK (src = original dst) injected INBOUND → delivers
//	                                       (the client's own SYN authorized it)
//	client ACK/data (captured outbound, consumed) ← engine Feed
//	stream relayed through the carrier chain (vless_tcp / fallback)
//	forged data/FIN/RST injected inbound          → delivers
//
// The client stack believes it talks to the original destination; the
// relay is a plain net.Conn pair. No loopback, no NAT map, no tproxy on
// the TCP path (UDP keeps the §3.3 NAT relay, whose inbound leg does
// deliver).
type Terminator struct {
	send PacketSender
	dial func(ctx context.Context, dst string) (net.Conn, error)
	log  *slog.Logger

	mu    sync.Mutex
	conns map[termKey]*termConn
	closed bool

	stopSweep chan struct{}

	// dialGate is storm control (live finding 2026-10-25: answering a
	// client's whole retransmit backlog at once — dozens of CONNECTs
	// through the carrier in milliseconds — takes the whole VLESS path
	// down, marker included).
	gate *dialGate

	// admission is the health gate: nil = always admit; otherwise SYNs
	// are dropped while it reports false (cold start backlog + HOLD).
	admission func() bool

	// stormDrops counts SYNs dropped by the gate.
	stormDrops atomic.Uint64

	wg sync.WaitGroup
}

// dialGate bounds dial concurrency (sem), rate (token bucket) and adds
// failure backoff: after a refused carrier dial the whole gate cools down
// (1s doubling to 30s; one success resets it). Live finding 2026-10-25:
// the user VPS's CONNECT refuses come in waves — hammering it makes the
// refusal state last minutes.
type dialGate struct {
	mu           sync.Mutex
	tokens       float64
	last         time.Time
	sem          chan struct{}
	interval     time.Duration
	cooldownEnds time.Time
}

func newDialGate() *dialGate {
	return &dialGate{tokens: dialBurst, last: time.Now(), sem: make(chan struct{}, dialConc), interval: time.Second}
}

func (g *dialGate) allow() bool {
	g.mu.Lock()
	now := time.Now()
	if now.Before(g.cooldownEnds) {
		g.mu.Unlock()
		return false
	}
	g.tokens += now.Sub(g.last).Seconds() * dialRate
	if g.tokens > dialBurst {
		g.tokens = dialBurst
	}
	g.last = now
	if g.tokens < 1 {
		g.mu.Unlock()
		return false
	}
	g.tokens--
	g.mu.Unlock()
	select {
	case g.sem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (g *dialGate) done() { <-g.sem }

// success resets the backoff after a good carrier dial.
func (g *dialGate) success() {
	g.mu.Lock()
	g.interval = time.Second
	g.cooldownEnds = time.Time{}
	g.mu.Unlock()
}

// failure doubles the cooldown after a refused carrier dial.
func (g *dialGate) failure() {
	g.mu.Lock()
	g.interval *= 2
	if g.interval > 30*time.Second {
		g.interval = 30 * time.Second
	}
	g.cooldownEnds = time.Now().Add(g.interval)
	g.mu.Unlock()
}

const (
	dialConc  = 2   // concurrent carrier dials
	dialRate  = 1.0 // sustained dials/second
	dialBurst = 2   // burst size
)

// PacketSender injects one forged inbound IPv4/TCP packet. ifIdx/subIfIdx
// come from the captured outbound packet (the live matrix delivery combo:
// inbound, not-loopback, client-NIC IfIdx).
type PacketSender interface {
	SendInboundTCP(pkt []byte, ifIdx, subIfIdx uint32) error
}

// TermPkt is one consumed client packet (parsed by the capture layer).
type TermPkt struct {
	SrcIP, DstIP             [4]byte // client, original destination
	SrcPort, DstPort         uint16
	Seq, Ack                 uint32
	Flags                    byte // tcpFlagSYN/ACK/PSH/FIN/RST
	Window                   uint16
	Payload                  []byte
	IfIdx, SubIfIdx          uint32
}

// TCP flags (mirror of the capture layer's tcpFlag*).
const (
	termSYN byte = 0x02
	termACK byte = 0x10
	termPSH byte = 0x08
	termFIN byte = 0x01
	termRST byte = 0x04
)

type termKey struct {
	srcIP   [4]byte
	srcPort uint16
	dstIP   [4]byte
	dstPort uint16
}

// NewTerminator builds a terminator over the carrier dialer (see
// tunnel.TCPDialer: HOLD gate + fallback chain).
func NewTerminator(send PacketSender, dial func(ctx context.Context, dst string) (net.Conn, error), logger *slog.Logger) *Terminator {
	if logger == nil {
		logger = slog.Default()
	}
	tm := &Terminator{
		send:      send,
		dial:      dial,
		log:       logger,
		conns:     make(map[termKey]*termConn),
		stopSweep: make(chan struct{}),
		gate:      newDialGate(),
	}
	tm.wg.Add(1)
	go tm.sweepLoop()
	return tm
}

// TermStats is the terminator's diagnostic snapshot.
type TermStats struct {
	Conns       int
	StormDrops  uint64
}

// Stats returns a point-in-time snapshot (diagnostics/logging).
func (tm *Terminator) Stats() TermStats {
	tm.mu.Lock()
	n := 0
	if tm.conns != nil {
		n = len(tm.conns)
	}
	tm.mu.Unlock()
	return TermStats{Conns: n, StormDrops: tm.stormDrops.Load()}
}

// SetAdmission installs the health gate (nil disables it). Call before
// Run. While it reports false every new SYN is dropped (the client's own
// retransmit backoff paces the backlog).
func (tm *Terminator) SetAdmission(f func() bool) {
	tm.mu.Lock()
	tm.admission = f
	tm.mu.Unlock()
}

// Feed consumes one outbound client packet of a tunnel-verdict TCP flow.
// Called from the capture hot path; must not block on network I/O.
func (tm *Terminator) Feed(p TermPkt) {
	k := termKey{srcIP: p.SrcIP, srcPort: p.SrcPort, dstIP: p.DstIP, dstPort: p.DstPort}

	tm.mu.Lock()
	if tm.closed {
		tm.mu.Unlock()
		return
	}
	c := tm.conns[k]
	if c == nil {
		if p.Flags&termSYN == 0 || p.Flags&termACK != 0 {
			// Data without a SYN we answered (late retransmit after
			// teardown, or a race): reset the stray.
			tm.mu.Unlock()
			return
		}
		// Admission (health) gate first, storm gate second: the day-long
		// retransmit backlog of a blocked client is hundreds of flows —
		// admitting any of them before the marker passes takes the
		// carrier down (live finding 2026-10-25).
		if tm.admission != nil && !tm.admission() {
			tm.mu.Unlock()
			tm.stormDrops.Add(1)
			return
		}
		if !tm.gate.allow() {
			tm.mu.Unlock()
			tm.stormDrops.Add(1)
			return
		}
		c = newTermConn(tm, k, p)
		tm.conns[k] = c
		tm.mu.Unlock()
		c.start() // SYN-ACK + async carrier dial
		return
	}
	tm.mu.Unlock()
	c.feed(p)
}

// Close tears down every connection and stops the sweeper.
func (tm *Terminator) Close() {
	tm.mu.Lock()
	if tm.closed {
		tm.mu.Unlock()
		return
	}
	tm.closed = true
	conns := tm.conns
	tm.conns = nil
	tm.mu.Unlock()
	close(tm.stopSweep)
	for _, c := range conns {
		c.kill(false)
	}
	tm.wg.Wait()
}

// sweepLoop retires idle connections (both stuck half-closes and leaks).
func (tm *Terminator) sweepLoop() {
	defer tm.wg.Done()
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-tm.stopSweep:
			return
		case <-t.C:
		}
		tm.mu.Lock()
		if tm.closed || tm.conns == nil {
			tm.mu.Unlock()
			return
		}
		var idle []*termConn
		for k, c := range tm.conns {
			if time.Since(c.lastSeen.Load()) > 3*time.Minute {
				idle = append(idle, c)
				delete(tm.conns, k)
			}
		}
		tm.mu.Unlock()
		for _, c := range idle {
			c.kill(true)
		}
	}
}

// ---------------------------------------------------------------------------
// per-connection state machine
// ---------------------------------------------------------------------------

const (
	// termMSS is the MSS we advertise (and obey for our own segments): the
	// forged packets ride the inbound NIC path; keep them comfortably
	// under a 1500-byte MTU.
	termMSS = 1240
	// termWindow is the receive window we advertise to the client.
	termWindow = 0xFFFF
	// dialWait bounds the carrier dial before the client SYN-ACK retransmit
	// path gives up naturally (~3 client SYN retransmits).
	dialWait = 12 * time.Second
)

type termConn struct {
	tm *Terminator
	k  termKey

	// re-injection interface (from the captured SYN's address; immutable).
	ifidx, subifidx uint32

	lastSeen atomicTime

	mu         sync.Mutex // guards the fields below
	clientNext uint32     // next expected client byte
	clientWin  uint16     // client's advertised window
	serverISN  uint32
	serverNext uint32 // next seq WE send
	serverUna  uint32 // oldest unacked byte we sent (from client ACKs)
	clientFIN  bool   // client half-closed
	finSent    bool
	dead       bool

	// upstream relay
	upstream net.Conn
	dialErr  error
	dialDone chan struct{}
	writeCh  chan []byte
	ackSignal chan struct{} // wakes the pump when serverUna advances
	closed   chan struct{}
	closeOne sync.Once
}

type atomicTime struct{ mu sync.Mutex; t time.Time }

func (a *atomicTime) Store(t time.Time) { a.mu.Lock(); a.t = t; a.mu.Unlock() }
func (a *atomicTime) Load() time.Time   { a.mu.Lock(); defer a.mu.Unlock(); return a.t }

func newTermConn(tm *Terminator, k termKey, syn TermPkt) *termConn {
	isn := rand.Uint32()
	c := &termConn{
		tm:         tm,
		k:          k,
		ifidx:      syn.IfIdx,
		subifidx:   syn.SubIfIdx,
		clientNext: syn.Seq + 1,
		clientWin:  syn.Window,
		serverISN:  isn,
		serverNext: isn + 1,
		serverUna:  isn + 1,
		dialDone:   make(chan struct{}),
		writeCh:    make(chan []byte, 128),
		ackSignal:  make(chan struct{}, 1),
		closed:     make(chan struct{}),
	}
	if c.clientWin == 0 {
		c.clientWin = termWindow // defensive: zero-window SYN
	}
	c.lastSeen.Store(time.Now())
	return c
}

// start answers the SYN and kicks the async carrier dial.
func (c *termConn) start() {
	c.sendSYNACK()
	dst := net.JoinHostPort(net.IP(c.k.dstIP[:]).String(), fmt.Sprint(c.k.dstPort))
	c.tm.wg.Add(1)
	go func() {
		defer c.tm.wg.Done()
		defer c.tm.gate.done() // dial slot released once the dial resolves
		ctx, cancel := context.WithTimeout(context.Background(), dialWait)
		defer cancel()
		up, err := c.tm.dial(ctx, dst)
		c.mu.Lock()
		c.upstream, c.dialErr = up, err
		close(c.dialDone)
		c.mu.Unlock()
		if err != nil {
			c.tm.log.Info("term: carrier dial failed",
				slog.String("flow", c.flowDesc()), slog.Any("err", err))
			c.tm.gate.failure()
			c.reset(err) // dial failed (incl. HOLD): reset the client
			return
		}
		c.tm.gate.success()
		c.tm.log.Info("term: carrier dial ok", slog.String("flow", c.flowDesc()))
		c.tm.wg.Add(2)
		go c.pumpWrites()
		go c.pumpReads()
	}()
}

// feed processes one client packet (engine thread).
func (c *termConn) feed(p TermPkt) {
	c.lastSeen.Store(time.Now())

	// RST from the client: tear everything down.
	if p.Flags&termRST != 0 {
		c.kill(false)
		return
	}

	c.mu.Lock()
	if c.dead {
		c.mu.Unlock()
		return
	}

	// SYN retransmit: our SYN-ACK (or the dial) is late; re-answer.
	if p.Flags&termSYN != 0 && p.Flags&termACK == 0 {
		c.mu.Unlock()
		c.sendSYNACK()
		return
	}

	if p.Flags&termACK != 0 {
		// Advance our unacked point (client ACKs our forged segments);
		// window updates (pure window probes) must wake a window-blocked
		// pump too.
		if int32(p.Ack-c.serverUna) > 0 {
			c.serverUna = p.Ack
			c.tm.log.Debug("term: client acked our data",
				slog.String("flow", c.flowDesc()),
				slog.Uint64("ack", uint64(p.Ack)), slog.Uint64("serverNext", uint64(c.serverNext)))
		}
		if c.clientWin != p.Window {
			c.clientWin = p.Window
		}
		select {
		case c.ackSignal <- struct{}{}:
		default:
		}
		if c.finSent && p.Ack == c.serverNext+1 {
			// Client ACKed our FIN: done.
			c.mu.Unlock()
			c.kill(false)
			return
		}
	}

	// Data (in-order; duplicates dropped by the seq check).
	if n := len(p.Payload); n > 0 && p.Seq == c.clientNext {
		c.clientNext += uint32(n)
		c.clientWin = p.Window
		payload := make([]byte, n)
		copy(payload, p.Payload)
		c.mu.Unlock()
		c.deliver(payload)
		c.sendACK()
		return
	}

	// Retransmitted in-flight data: the payload is already delivered —
	// re-ACK so the client stops retransmitting.
	if n := len(p.Payload); n > 0 && int32(c.clientNext-(p.Seq+uint32(n))) >= 0 {
		c.clientWin = p.Window
		c.mu.Unlock()
		c.sendACK()
		return
	}

	// Zero-window / keep-alive / pure ACK updates.
	c.clientWin = p.Window

	// FIN (possibly with the final payload handled above via p.Seq match).
	if p.Flags&termFIN != 0 && !c.clientFIN {
		c.clientFIN = true
		c.clientNext = p.Seq + uint32(len(p.Payload)) + 1
		c.mu.Unlock()
		c.sendACK() // ACK the FIN
		<-c.dialDone
		c.mu.Lock()
		up := c.upstream
		c.mu.Unlock()
		if up != nil {
			_ = up.Close() // client is done sending: half-close is not
			// expressible on net.Conn; closing ends the relay, pumpReads
			// drains what the carrier already delivered and FINs us.
		}
		return
	}
	c.mu.Unlock()
}

// deliver queues client payload for the carrier (drops on overflow: the
// client would retransmit into a reset — see sendACK ordering).
func (c *termConn) deliver(payload []byte) {
	select {
	case c.writeCh <- payload:
	case <-c.closed:
	default:
		// Channel full: the carrier is wedged; fail the connection.
		c.tm.log.Warn("term: write queue overflow",
			slog.String("flow", c.flowDesc()))
		c.kill(false)
	}
}

// pumpWrites forwards client payload into the carrier.
func (c *termConn) pumpWrites() {
	defer c.tm.wg.Done()
	for {
		select {
		case p := <-c.writeCh:
			if _, err := c.upstream.Write(p); err != nil {
				c.reset(err)
				return
			}
		case <-c.closed:
			return
		}
	}
}

// pumpReads turns carrier replies into forged data segments, respecting the
// client's advertised window, and FINs the client at EOF.
func (c *termConn) pumpReads() {
	defer c.tm.wg.Done()
	buf := make([]byte, termMSS)
	for {
		n, err := c.upstream.Read(buf)
		if n > 0 {
			if !c.sendData(buf[:n]) {
				return
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				c.sendFIN()
			} else {
				c.reset(err)
			}
			return
		}
	}
}

// sendData segments and injects one carrier chunk, blocking while the
// client's window is full (woken by ACK feeds).
func (c *termConn) sendData(b []byte) bool {
	for len(b) > 0 {
		n := len(b)
		if n > termMSS {
			n = termMSS
		}
		if !c.waitWindow(n) {
			return false
		}
		c.mu.Lock()
		if c.dead {
			c.mu.Unlock()
			return false
		}
		seq := c.serverNext
		c.serverNext += uint32(n)
		ack := c.clientNext
		pkt := c.craft(seq, ack, termACK|termPSH, b[:n])
		una := c.serverUna
		c.mu.Unlock()
		if err := c.tm.send.SendInboundTCP(pkt, c.ifIdx(), c.subIfIdx()); err != nil {
			c.tm.log.Warn("term: data inject failed", slog.String("err", err.Error()))
			c.kill(false)
			return false
		}
		c.tm.log.Debug("term: data injected",
			slog.String("flow", c.flowDesc()), slog.Int("len", n),
			slog.Uint64("seq", uint64(seq)), slog.Uint64("una", uint64(una)))
		b = b[n:]
	}
	return true
}

// waitWindow blocks until the client window fits n more bytes of our data.
func (c *termConn) waitWindow(n int) bool {
	for {
		c.mu.Lock()
		if c.dead {
			c.mu.Unlock()
			return false
		}
		usable := int32(uint32(c.clientWin) - (c.serverNext - c.serverUna))
		c.mu.Unlock()
		if usable >= int32(n) {
			return true
		}
		select {
		case <-c.ackSignal:
		case <-c.closed:
			return false
		case <-time.After(10 * time.Second):
			// Window never opened: peer wedged.
			c.reset(errors.New("client window stalled"))
			return false
		}
	}
}

func (c *termConn) sendSYNACK() {
	c.mu.Lock()
	if c.dead {
		c.mu.Unlock()
		return
	}
	pkt := c.craft(c.serverISN, c.clientNext, termSYN|termACK, nil)
	c.mu.Unlock()
	if err := c.tm.send.SendInboundTCP(pkt, c.ifIdx(), c.subIfIdx()); err != nil {
		c.tm.log.Warn("term: syn-ack inject failed", slog.String("err", err.Error()))
	}
}

func (c *termConn) sendACK() {
	c.mu.Lock()
	if c.dead {
		c.mu.Unlock()
		return
	}
	pkt := c.craft(c.serverNext, c.clientNext, termACK, nil)
	c.mu.Unlock()
	_ = c.tm.send.SendInboundTCP(pkt, c.ifIdx(), c.subIfIdx())
}

func (c *termConn) sendFIN() {
	c.mu.Lock()
	if c.dead || c.finSent {
		c.mu.Unlock()
		return
	}
	c.finSent = true
	pkt := c.craft(c.serverNext, c.clientNext, termFIN|termACK, nil)
	c.mu.Unlock()
	if err := c.tm.send.SendInboundTCP(pkt, c.ifIdx(), c.subIfIdx()); err != nil {
		c.tm.log.Warn("term: fin inject failed", slog.String("err", err.Error()))
		c.kill(false)
	}
}

func (c *termConn) reset(reason error) {
	c.tm.log.Debug("term: reset", slog.String("flow", c.flowDesc()), slog.String("err", reason.Error()))
	c.mu.Lock()
	clientFIN := c.clientFIN
	if !c.dead && !c.finSent {
		if clientFIN {
			// The client already half-closed: end cleanly with a FIN, not
			// an abort (net.Pipe surfaces the upstream close as
			// ErrClosedPipe, not EOF).
			c.mu.Unlock()
			c.sendFIN()
			return
		}
		pkt := c.craft(c.serverNext, c.clientNext, termRST|termACK, nil)
		c.mu.Unlock()
		_ = c.tm.send.SendInboundTCP(pkt, c.ifIdx(), c.subIfIdx())
	} else {
		c.mu.Unlock()
	}
	c.kill(false)
}

// kill closes the upstream relay and marks the conn dead; remove=true also
// drops it from the table (sweeper path).
func (c *termConn) kill(remove bool) {
	c.closeOne.Do(func() {
		close(c.closed)
		c.mu.Lock()
		c.dead = true
		up := c.upstream
		c.mu.Unlock()
		if up != nil {
			_ = up.Close()
		}
	})
	if remove {
		c.tm.mu.Lock()
		if c.tm.conns != nil {
			delete(c.tm.conns, c.k)
		}
		c.tm.mu.Unlock()
	}
}

// ---------------------------------------------------------------------------
// packet crafting (pure IPv4/TCP with checksums; no driver dependency)
// ---------------------------------------------------------------------------

// ifIdx/subIfIdx ride the packet's captured address; stored immutable at
// SYN time (first feed).
func (c *termConn) ifIdx() uint32    { return c.ifidx }
func (c *termConn) subIfIdx() uint32 { return c.subifidx }

// craft builds one forged packet: src = original destination (the server
// the client thinks it talks to), dst = client.
//
// Payload must be ≤ termMSS. Options: MSS on SYN-ACK only.
func (c *termConn) craft(seq, ack uint32, flags byte, payload []byte) []byte {
	optLen := 0
	if flags&termSYN != 0 {
		optLen = 4
	}
	ipLen, tcpLen := 20, 20+optLen+len(payload)
	pkt := make([]byte, ipLen+tcpLen)

	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(ipLen+tcpLen))
	pkt[4], pkt[5] = 0x12, 0x34
	pkt[6], pkt[7] = 0x40, 0x00 // DF
	pkt[8] = 64                 // TTL
	pkt[9] = 6                  // TCP
	copy(pkt[12:16], c.k.dstIP[:]) // src = the "server"
	copy(pkt[16:20], c.k.srcIP[:]) // dst = the client
	sum := ipChecksum(pkt[:20])
	pkt[10], pkt[11] = byte(sum>>8), byte(sum)

	tcp := pkt[ipLen:]
	binary.BigEndian.PutUint16(tcp[0:], c.k.dstPort) // server port
	binary.BigEndian.PutUint16(tcp[2:], c.k.srcPort) // client port
	binary.BigEndian.PutUint32(tcp[4:], seq)
	binary.BigEndian.PutUint32(tcp[8:], ack)
	tcp[12] = byte((20+optLen)/4) << 4 // data offset in 32-bit words
	binary.BigEndian.PutUint16(tcp[14:], termWindow)
	tcp[13] = flags
	if optLen == 4 {
		tcp[20], tcp[21] = 2, 4 // MSS kind, len
		binary.BigEndian.PutUint16(tcp[22:], termMSS)
	}
	copy(tcp[20+optLen:], payload)

	// TCP checksum over the pseudo-header + segment.
	var pseudo [12]byte
	copy(pseudo[0:4], c.k.dstIP[:])
	copy(pseudo[4:8], c.k.srcIP[:])
	pseudo[8] = 6
	binary.BigEndian.PutUint16(pseudo[10:], uint16(tcpLen))
	sums := make([]byte, 0, 12+tcpLen)
	sums = append(sums, pseudo[:]...)
	sums = append(sums, tcp...)
	tcpSum := ipChecksum(sums)
	tcp[16], tcp[17] = byte(tcpSum>>8), byte(tcpSum&0xff)
	return pkt
}

func (c *termConn) flowDesc() string {
	return net.IP(c.k.srcIP[:]).String() + ":" + fmt.Sprint(c.k.srcPort) +
		" -> " + net.IP(c.k.dstIP[:]).String() + ":" + fmt.Sprint(c.k.dstPort)
}

// ipChecksum computes the 16-bit one's-complement sum (RFC 1071), pre-zeroed
// checksum fields.
func ipChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
