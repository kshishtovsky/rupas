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
		c.kill(false, "shutdown")
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
			c.kill(true, "idle sweep")
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
	// termWindow is the INITIAL window advertised in the SYN-ACK; every
	// later segment advertises the real free space (recvWindowLocked).
	termWindow = 0xFFFF
	// recvBufCap is the upload receive buffer in bytes: each ACK
	// advertises its free part (relay-queue bytes + reorder-buffer
	// bytes). Live upload finding 2026-10-25: the old code advertised a
	// CONSTANT 0xFFFF window, so the client kept a full 64KB in flight
	// regardless of the carrier drain rate; the relay queue hit its slot
	// cap, the deferred head turned every already-in-flight successor
	// into an out-of-order segment, and the reorder buffer overflowed
	// (575+ evictions per flow — self-inflicted loss, recovered only by
	// retransmits). With the real window the client throttles itself
	// (win=0 → its persist timer; our window-update ACK on drain) and
	// the queue never overfills: zero evictions, zero deferrals.
	recvBufCap = 0xFFFF
	// oooBatchReserve: the in-order path enqueues the current segment
	// plus up to this many reorder-buffer segments in one batch; the
	// slot part of the advertised window keeps at least that many
	// queue slots free (see recvWindowLocked).
	oooBatchReserve = 8
	// dialWait bounds the carrier dial (the client's own SYN retransmit
	// backoff paces the wait). It must COVER the carrier's own
	// DefaultDialTimeout (tunnel.go): a shorter deadline here reset the
	// client while the carrier dial was still legitimately in flight,
	// so slow VLESS connects never came up at all.
	dialWait = DefaultDialTimeout + 2*time.Second
)

type termConn struct {
	tm *Terminator
	k  termKey

	// re-injection interface (from the captured SYN's address; immutable).
	ifidx, subifidx uint32

	lastSeen atomicTime

	// flowDesc cache (immutable 4-tuple; see flowDesc).
	fdOnce sync.Once
	fdStr  string

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
	// queuedBytes tracks the payload bytes sitting in writeCh (hot path:
	// atomic add at enqueue/consume; recvWindowLocked reads it without
	// extra sync). Together with oooBytes it forms the outstanding
	// receive-buffer occupancy the advertised window is derived from.
	queuedBytes atomic.Int64
	// finSignal wakes an idle pumpWrites for a half-close accepted with
	// an already-empty queue (see feed's FIN acceptance).
	finSignal chan struct{}
	ackSignal chan struct{} // wakes the pump when serverUna advances
	closed    chan struct{}
	closeOne  sync.Once

	// reorder buffer for out-of-order client segments. The old code
	// silently DROPPED any segment ahead of a sequence hole, truncating
	// upload streams at the first retransmit.
	ooo      map[uint32][]byte // seq → buffered payload (lazy)
	oooFIFO  []uint32          // insertion order (oldest evicted first)
	oooBytes int
	// finPend: client half-closed; pumpWrites ends the upstream relay
	// once the queue drains. Closing upstream immediately at FIN time
	// dropped the already-ACKed upload tail still sitting in the queue.
	finPend bool

	// advWin is the window value carried by the most recent injected
	// ACK (mu-guarded): pumpWrites compares against it to decide when a
	// window-update ACK is due (zero-crossing or a full step regrown).
	advWin uint16

	// diagnostics (hot path: incremented without extra locking)
	qFullN   atomic.Uint64 // segments deferred by relay-queue backpressure
	oooBufN  atomic.Uint64 // segments buffered out-of-order
	oooDropN atomic.Uint64 // segments evicted from the reorder buffer
	dupAckN  atomic.Uint64 // dup-ACKs sent to prompt a client fast retransmit
	// qFullWarnAt rate-limits the queue-full WARN: that path runs on the
	// capture receive goroutine, and an unbounded upload burst defers
	// thousands of segments — one synchronous log write per segment would
	// itself stall every other flow (unix-nano; 0 = never logged).
	qFullWarnAt atomic.Int64
	// oooWarnAt rate-limits the reorder-buffer-overflow WARN for the same
	// reason: evictions fire per NEW out-of-order segment, which under a
	// pathological burst is every packet.
	oooWarnAt atomic.Int64
}

// atomicTime is a lock-free timestamp: feed stores it on EVERY packet of a
// tunnel flow (i.e. on the capture receive goroutine), so a mutex here is
// pure per-packet contention for a value only the 30 s sweeper reads.
type atomicTime struct{ ns atomic.Int64 }

func (a *atomicTime) Store(t time.Time) { a.ns.Store(t.UnixNano()) }
func (a *atomicTime) Load() time.Time   { return time.Unix(0, a.ns.Load()) }

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
		advWin:     termWindow,
		dialDone:   make(chan struct{}),
		writeCh:    make(chan []byte, 128),
		finSignal:  make(chan struct{}, 1),
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
		c.kill(false, "client rst")
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
			// Guarded: this runs on the capture receive goroutine for
			// every ACK, and flowDesc() builds two strings. A disabled
			// level must cost one bool check, not an allocation.
			if c.tm.log.Enabled(context.Background(), slog.LevelDebug) {
				c.tm.log.Debug("term: client acked our data",
					slog.String("flow", c.flowDesc()),
					slog.Uint64("ack", uint64(p.Ack)), slog.Uint64("serverNext", uint64(c.serverNext)))
			}
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
			c.kill(false, "client fin acked")
			return
		}
	}

	n := len(p.Payload)
	hasFIN := p.Flags&termFIN != 0
	seqEnd := p.Seq + uint32(n)

	// Accept the FIN only once every byte before it was consumed: either
	// a pure in-order FIN, or a retransmitted FIN whose payload has since
	// been delivered. Never accept a FIN past a sequence hole — the old
	// code did and silently skipped the missing bytes.
	if hasFIN && !c.clientFIN && seqEnd == c.clientNext {
		empty := c.acceptFINLocked()
		c.mu.Unlock()
		c.sendACK() // ACK the FIN
		if empty {
			c.wakeHalfClose()
		}
		return
	}

	// Data path: in-order → relay (plus any reorder-buffer backlog the
	// segment completes); fully-old → re-ACK; future → buffer bounded.
	if n > 0 {
		switch {
		case p.Seq == c.clientNext:
			// In-order segment. If the relay queue is full, do NOT
			// consume and do not ACK: the client retransmits. The old
			// code killed the connection here, so any upload burst
			// deeper than the queue tore the flow down.
			if len(c.writeCh) >= cap(c.writeCh) {
				total := c.qFullN.Add(1)
				c.dupAckN.Add(1)
				c.mu.Unlock()
				c.warnQueueFull(total)
				c.sendACK() // dup-ack: prompts the client's fast retransmit
				return
			}
			c.clientWin = p.Window
			// Build the batch within the room reserved under this same
			// lock (only feed enqueues; pumpWrites only drains), so
			// enqueueLocked cannot hit its full-queue arm here.
			var batch [oooBatchReserve + 1][]byte
			var seqs [oooBatchReserve + 1]uint32
			out, outSeq := batch[:0], seqs[:0]
			out = append(out, copyPayload(p.Payload))
			outSeq = append(outSeq, p.Seq)
			next := seqEnd
			// Close the reorder-buffer gap behind this segment while
			// the relay queue has room (bounded per feed; the next
			// ack/segment drains the rest).
			for len(out) < cap(batch) && len(c.writeCh)+len(out) < cap(c.writeCh) {
				b, ok := c.oooPop(next)
				if !ok {
					break
				}
				outSeq = append(outSeq, next)
				next += uint32(len(b))
				out = append(out, b)
			}
			c.clientNext = next
			if left := c.enqueueLocked(out); left > 0 {
				// Unreachable by construction (room was reserved above),
				// but never lose data silently: release the tail that did
				// not fit and rewind clientNext to the first unconsumed
				// segment. The client's retransmit — prompted by the
				// dup-ACK below — refills that hole; a silent gap would
				// have stalled the upload on an RTO.
				first := len(out) - left
				for i := first; i < len(out); i++ {
					putPayload(out[i])
				}
				c.clientNext = outSeq[first]
				c.dupAckN.Add(1)
				total := c.qFullN.Add(1)
				c.mu.Unlock()
				c.warnQueueFull(total)
				c.sendACK() // dup-ack: prompts the client's fast retransmit
				return
			}
			finNow := hasFIN && c.clientNext == seqEnd
			empty := false
			if finNow {
				empty = c.acceptFINLocked()
			}
			c.mu.Unlock()
			c.sendACK()
			if finNow {
				c.sendACK() // ACK the FIN as well
				if empty {
					c.wakeHalfClose()
				}
			}
			return

		case int32(c.clientNext-seqEnd) >= 0:
			// Fully-old retransmit: the payload is already queued —
			// re-ACK so the client stops retransmitting.
			c.mu.Unlock()
			c.sendACK()
			return

		default:
			// Future segment (a hole precedes it): buffer it bounded;
			// every newly buffered (or evicting) segment fires ONE
			// dup-ACK — three in a row make the client fast-retransmit
			// the hole within an RTT instead of waiting out its RTO
			// (the old silent-drop / RTO-only recovery stalled uploads
			// for minutes). Retransmits of already-buffered segments
			// are deduplicated: at most one dup-ACK per NEW
			// out-of-order segment.
			payload := copyPayload(p.Payload)
			buffered, evicted := c.oooPush(p.Seq, payload)
			bufferedTotal := c.oooBufN.Load()
			if !buffered {
				c.mu.Unlock()
				return // dedup: no extra dup-ACK for a buffered retransmit
			}
			c.dupAckN.Add(1)
			c.mu.Unlock()
			if evicted {
				c.warnOOOOverflow()
			} else if c.tm.log.Enabled(context.Background(), slog.LevelDebug) {
				c.tm.log.Debug("term: out-of-order segment buffered",
					slog.String("flow", c.flowDesc()),
					slog.Uint64("seq", uint64(p.Seq)), slog.Int("len", n),
					slog.Uint64("buffered_total", bufferedTotal))
			}
			c.sendACK() // dup-ack (ack = clientNext): fast-retransmit prompt
			return
		}
	}

	if hasFIN && !c.clientFIN && int32(seqEnd-c.clientNext) > 0 {
		// FIN ahead of a hole: not acceptable yet; dup-ack so the
		// client retransmits the missing data first.
		c.dupAckN.Add(1)
		c.mu.Unlock()
		c.sendACK()
		return
	}
	if hasFIN {
		// Retransmit of an already-accepted FIN: our ACK may have been
		// lost — re-ACK so the client stops.
		c.mu.Unlock()
		c.sendACK()
		return
	}

	// Zero-window / keep-alive / pure ACK updates.
	c.clientWin = p.Window
	c.mu.Unlock()
}

// acceptFINLocked records the client half-close (caller holds mu; at both
// call sites c.clientNext == the FIN's seqEnd). Reports whether the relay
// queue is already empty (no queued upload tail to drain).
func (c *termConn) acceptFINLocked() bool {
	c.clientFIN = true
	c.finPend = true
	c.clientNext++
	return len(c.writeCh) == 0
}

// wakeHalfClose tells an idle pumpWrites to end the upstream relay
// (net.Conn cannot half-close; pumpReads drains the carrier and FINs).
func (c *termConn) wakeHalfClose() {
	select {
	case c.finSignal <- struct{}{}:
	default:
	}
}

// payloadBufSize covers compliant client segments (we advertise MSS 1240,
// real stacks use ≤ 1460); larger outliers allocate once and are not pooled.
const payloadBufSize = 2048

// payloadPool recycles payload buffers on the data hot path: steady-state
// relay runs with zero per-segment allocations.
var payloadPool = sync.Pool{New: func() any { b := make([]byte, payloadBufSize); return &b }}

// craftPool recycles forged-packet buffers (ACK / window-update / FIN / RST
// injections run at per-segment frequency on bulk flows). craft rents from
// it; the caller MUST return the buffer with putCraftBuf right after the
// synchronous SendInboundTCP call — neither sender retains the slice.
// Fixed-size arrays: boxing a *[N]byte in sync.Pool is allocation-free.
var craftPool = sync.Pool{New: func() any { return new([payloadBufSize]byte) }}

// craftBuf rents a buffer with at least n bytes (len == n). Outliers above
// the pooled size get a plain allocation (documented, not pooled).
func craftBuf(n int) []byte {
	if n > payloadBufSize {
		return make([]byte, n)
	}
	return craftPool.Get().(*[payloadBufSize]byte)[:n]
}

// putCraftBuf returns a rented buffer to craftPool. Oversized (non-pooled)
// outliers are dropped for GC.
func putCraftBuf(pkt []byte) {
	if cap(pkt) != payloadBufSize {
		return
	}
	craftPool.Put((*[payloadBufSize]byte)(pkt[:cap(pkt)]))
}

// copyPayload copies a client payload into a pooled buffer.
func copyPayload(p []byte) []byte {
	if len(p) > payloadBufSize {
		out := make([]byte, len(p))
		copy(out, p)
		return out
	}
	bp := payloadPool.Get().(*[]byte)
	out := (*bp)[:len(p)]
	copy(out, p)
	return out
}

// putPayload returns a payload buffer to the pool after the carrier write.
// Unreturned buffers (killed conn, oversized) are simply collected by the GC.
func putPayload(b []byte) {
	if cap(b) == payloadBufSize {
		full := b[:cap(b)]
		payloadPool.Put(&full)
	}
}

const (
	// oooSegLimit / oooByteLimit bound the client-side reorder buffer.
	// Live upload finding 2026-10-25: with the old 64-segment / 256KB
	// cap a long upload (sender window growing to ~1-2MB through the
	// forged-path ACK cadence) blew the buffer on every burst, and each
	// evicted segment was NOT yet ACKed — the client recovered it only
	// on its RTO (seconds), so uploads stalled for minutes at a time.
	// 512 segments (~630KB at MSS 1240) / 2MB cover the observed window
	// range with headroom; eviction now also fires an immediate dup-ACK
	// so even a real overflow recovers within one RTT, not one RTO.
	oooSegLimit  = 512
	oooByteLimit = 2 << 20 // 2MB
)

// oooPush buffers a future segment (caller holds mu). Bounded: on reaching
// the segment/byte limit the OLDEST buffered segment is evicted — it was
// never ACKed, so the dup-ACK fast-retransmit prompt (feed) recovers it.
// Reports whether the segment was newly buffered (false = retransmit of an
// already-buffered seq, payload released) and whether an eviction happened.
func (c *termConn) oooPush(seq uint32, payload []byte) (buffered, evicted bool) {
	if c.ooo == nil {
		c.ooo = make(map[uint32][]byte)
	}
	if _, dup := c.ooo[seq]; dup {
		putPayload(payload) // retransmit of an already-buffered segment
		return false, false
	}
	for len(c.ooo) >= oooSegLimit || c.oooBytes+len(payload) > oooByteLimit {
		if len(c.ooo) == 0 {
			break
		}
		old := c.oooFIFO[0]
		c.oooFIFO = c.oooFIFO[1:]
		c.oooBytes -= len(c.ooo[old])
		putPayload(c.ooo[old])
		delete(c.ooo, old)
		c.oooDropN.Add(1)
		evicted = true
	}
	c.ooo[seq] = payload
	c.oooFIFO = append(c.oooFIFO, seq)
	c.oooBytes += len(payload)
	c.oooBufN.Add(1)
	return true, evicted
}

// oooPop removes the buffered segment at seq (caller holds mu), if any.
func (c *termConn) oooPop(seq uint32) ([]byte, bool) {
	b, ok := c.ooo[seq]
	if !ok {
		return nil, false
	}
	delete(c.ooo, seq)
	c.oooBytes -= len(b)
	for i, s := range c.oooFIFO {
		if s == seq {
			c.oooFIFO = append(c.oooFIFO[:i], c.oooFIFO[i+1:]...)
			break
		}
	}
	return b, true
}

// qFullWarnEvery rate-limits the relay-queue-full WARN. The warning is
// emitted from feed, i.e. on the capture receive goroutine; an upload burst
// defers a segment per retransmit, so an unthrottled WARN would put a
// synchronous log write in front of EVERY packet of EVERY flow.
const qFullWarnEvery = 2 * time.Second

// warnQueueFull emits the queue-full WARN at most once per qFullWarnEvery
// (the first one immediately) — atomics only, no allocation when silent.
func (c *termConn) warnQueueFull(total uint64) {
	if !rateLimit(&c.qFullWarnAt, qFullWarnEvery) {
		return
	}
	c.tm.log.Warn("term: relay queue full, deferring segment for retransmit",
		slog.String("flow", c.flowDesc()), slog.Uint64("total", total))
}

// warnOOOOverflow emits the reorder-buffer-overflow WARN, rate-limited like
// warnQueueFull (evictions can fire on every packet of a bad burst).
func (c *termConn) warnOOOOverflow() {
	if !rateLimit(&c.oooWarnAt, qFullWarnEvery) {
		return
	}
	c.tm.log.Warn("term: reorder buffer overflow, evicted oldest segment",
		slog.String("flow", c.flowDesc()),
		slog.Uint64("total_drops", c.oooDropN.Load()))
}

// rateLimit reports whether a log at this site may be emitted now, and marks
// it emitted. One atomic load when silent — no time.Now on the fast path
// until the window has plausibly elapsed.
func rateLimit(last *atomic.Int64, every time.Duration) bool {
	now := time.Now().UnixNano()
	prev := last.Load()
	if prev != 0 && now-prev < int64(every) {
		return false
	}
	return last.CompareAndSwap(prev, now)
}

// enqueueLocked queues payloads for the carrier in order (caller holds mu).
//
// TRULY non-blocking: the send has a default arm, so a full queue reports
// the leftover count instead of parking the caller. The old select had no
// default and no send-side alternative — with a full queue and a live
// connection it blocked the SINGLE capture receive goroutine (feed ← Feed
// ← relayTunnelTCP ← processPacket ← recvLoop), which froze the whole
// machine's networking, DIRECT flows included, until the carrier drained.
//
// Returns the number of payloads that did not fit. Every queued byte is
// counted and stays charged against the advertised window until the
// carrier write completes. A non-zero return is backpressure: feed reserves
// room under this same lock before consuming, so on a live flow it cannot
// happen (see feed's in-order branch); it can only be observed after kill,
// when the queue is abandoned and its buffers are reclaimed by the GC.
func (c *termConn) enqueueLocked(out [][]byte) int {
	for i, b := range out {
		select {
		case c.writeCh <- b:
			c.queuedBytes.Add(int64(len(b)))
		default:
			return len(out) - i
		}
	}
	return 0
}

// recvWindowLocked computes the window to advertise to the client
// (caller holds mu): the free part of the receive buffer — recvBufCap
// minus the bytes still unconsumed by the carrier (relay queue) or held
// out-of-order — clamped to [0, 0xFFFF]. The queue's slot capacity joins
// the byte cap (minus the reorder-flush reserve): tiny client segments
// would otherwise exhaust slots long before the byte budget.
func (c *termConn) recvWindowLocked() uint16 {
	free := int64(recvBufCap) - c.queuedBytes.Load() - int64(c.oooBytes)
	if slotFree := int64(cap(c.writeCh)-len(c.writeCh)-oooBatchReserve) * termMSS; slotFree < free {
		free = slotFree
	}
	if free < 0 {
		free = 0
	}
	if free > 0xFFFF {
		free = 0xFFFF
	}
	return uint16(free)
}

// windowUpdateStep: re-advertise the window proactively once the free
// part of the receive buffer has regrown by this much (or crosses zero)
// — bounds the extra injected ACKs to ~4 per window while keeping the
// client from stalling on its persist timer.
const windowUpdateStep = recvBufCap / 4

// maybeWindowUpdate sends a window-update ACK after the relay queue
// drained (called from pumpWrites). The client may be blocked waiting
// for its persist timer after a win=0 advertisement; the standard
// window-update mechanic answers as soon as real space has opened.
func (c *termConn) maybeWindowUpdate() {
	c.mu.Lock()
	if c.dead {
		c.mu.Unlock()
		return
	}
	prev := c.advWin
	w := c.recvWindowLocked()
	if w == prev || (prev != 0 && w-prev < windowUpdateStep) {
		c.mu.Unlock()
		return
	}
	c.advWin = w
	pkt := c.craft(c.serverNext, c.clientNext, termACK, nil, w)
	c.mu.Unlock()
	_ = c.tm.send.SendInboundTCP(pkt, c.ifIdx(), c.subIfIdx())
	putCraftBuf(pkt)
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
			putPayload(p)
			// The byte left the receive buffer: uncharge it and let the
			// client know the window opened (window-update ACK).
			c.queuedBytes.Add(-int64(len(p)))
			c.maybeWindowUpdate()
			// Client half-closed and this was the last queued byte:
			// end the relay. The queue must drain FIRST — the old code
			// closed upstream at FIN time and dropped the already-ACKed
			// upload tail still sitting in it.
			c.mu.Lock()
			pend := c.finPend && len(c.writeCh) == 0
			c.mu.Unlock()
			if pend {
				c.mu.Lock()
				up := c.upstream
				c.mu.Unlock()
				if up != nil {
					_ = up.Close()
				}
				return
			}
		case <-c.finSignal:
			// Half-close accepted with an empty queue. No enqueue can
			// follow: after clientFIN only dups arrive, and they are
			// never queued.
			c.mu.Lock()
			up := c.upstream
			c.mu.Unlock()
			if up != nil {
				_ = up.Close()
			}
			return
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
		pkt := c.craft(seq, ack, termACK|termPSH, b[:n], c.recvWindowLocked())
		una := c.serverUna
		c.mu.Unlock()
		if err := c.tm.send.SendInboundTCP(pkt, c.ifIdx(), c.subIfIdx()); err != nil {
			c.tm.log.Warn("term: data inject failed", slog.String("err", err.Error()))
			c.kill(false, "data inject failed: "+err.Error())
			putCraftBuf(pkt)
			return false
		}
		putCraftBuf(pkt)
		c.tm.log.Debug("term: data injected",
			slog.String("flow", c.flowDesc()), slog.Int("len", n),
			slog.Uint64("seq", uint64(seq)), slog.Uint64("una", uint64(una)))
		b = b[n:]
	}
	return true
}

// windowStallTimeout bounds how long a carrier reply waits WITHOUT PROGRESS
// for the client's window to open before the flow is reset as wedged.
const windowStallTimeout = 10 * time.Second

// waitWindow blocks until the client window fits n more bytes of our data.
func (c *termConn) waitWindow(n int) bool { return c.waitWindowFor(n, windowStallTimeout) }

// waitWindowFor is waitWindow with an explicit stall budget (tests).
//
// ONE timer for the whole call: the old code created a fresh time.After on
// every loop iteration — a timer plus garbage per iteration on a hot path —
// and, because each iteration re-armed it, a client that kept sending
// zero-window probes held the pump forever. Here the timer is Reset ONLY on
// real progress (an ACK advanced our unacked point or changed the advertised
// window), so:
//   - a slow but progressing peer is never reset (no data loss),
//   - a wedged peer is bounded by windowStallTimeout of NO progress,
//   - the steady path pays one timer per call and no per-iteration alloc.
func (c *termConn) waitWindowFor(n int, stall time.Duration) bool {
	t := time.NewTimer(stall)
	defer t.Stop()
	for {
		c.mu.Lock()
		if c.dead {
			c.mu.Unlock()
			return false
		}
		usable := int32(uint32(c.clientWin) - (c.serverNext - c.serverUna))
		una, win := c.serverUna, c.clientWin
		c.mu.Unlock()
		if usable >= int32(n) {
			return true
		}
		select {
		case <-c.ackSignal:
			c.mu.Lock()
			moved := c.serverUna != una || c.clientWin != win
			c.mu.Unlock()
			if moved {
				// Real progress: give the peer a fresh stall budget.
				if !t.Stop() {
					select {
					case <-t.C:
					default:
					}
				}
				t.Reset(stall)
			}
		case <-c.closed:
			return false
		case <-t.C:
			// No progress for a full stall budget: peer wedged.
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
	pkt := c.craft(c.serverISN, c.clientNext, termSYN|termACK, nil, termWindow)
	c.mu.Unlock()
	if err := c.tm.send.SendInboundTCP(pkt, c.ifIdx(), c.subIfIdx()); err != nil {
		c.tm.log.Warn("term: syn-ack inject failed", slog.String("err", err.Error()))
	}
	putCraftBuf(pkt)
}

func (c *termConn) sendACK() {
	c.mu.Lock()
	if c.dead {
		c.mu.Unlock()
		return
	}
	// Every ACK advertises the REAL free receive-buffer space: a full
	// buffer → win=0 (the client throttles itself via its persist
	// timer), space regrown → the client resumes. This is what keeps
	// the reorder buffer empty and evictions at zero.
	c.advWin = c.recvWindowLocked()
	pkt := c.craft(c.serverNext, c.clientNext, termACK, nil, c.advWin)
	c.mu.Unlock()
	_ = c.tm.send.SendInboundTCP(pkt, c.ifIdx(), c.subIfIdx())
	putCraftBuf(pkt)
}

func (c *termConn) sendFIN() {
	c.mu.Lock()
	if c.dead || c.finSent {
		c.mu.Unlock()
		return
	}
	c.finSent = true
	pkt := c.craft(c.serverNext, c.clientNext, termFIN|termACK, nil, c.recvWindowLocked())
	c.mu.Unlock()
	if err := c.tm.send.SendInboundTCP(pkt, c.ifIdx(), c.subIfIdx()); err != nil {
		c.tm.log.Warn("term: fin inject failed", slog.String("err", err.Error()))
		c.kill(false, "fin inject failed: "+err.Error())
	}
	putCraftBuf(pkt)
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
		pkt := c.craft(c.serverNext, c.clientNext, termRST|termACK, nil, c.recvWindowLocked())
		c.mu.Unlock()
		_ = c.tm.send.SendInboundTCP(pkt, c.ifIdx(), c.subIfIdx())
		putCraftBuf(pkt)
	} else {
		c.mu.Unlock()
	}
	c.kill(false, "reset: "+reason.Error())
}

// kill closes the upstream relay and marks the conn dead; remove=true also
// drops it from the table (sweeper path). reason is logged once — WARN for
// relay failures, DEBUG for the orderly teardowns (shutdown/idle/RST/FIN).
//
// The upstream Close runs on a DETACHED goroutine: kill is reached from feed
// on the capture receive goroutine (a client RST, a dial failure, a reset),
// and net.Conn.Close on a carrier socket can block on a TLS close_notify
// write. The conn is already marked dead before the close starts, so no
// reader can observe a half-closed relay.
func (c *termConn) kill(remove bool, reason string) {
	c.closeOne.Do(func() {
		lvl := slog.LevelWarn
		switch reason {
		case "shutdown", "idle sweep", "client rst", "client fin acked":
			lvl = slog.LevelDebug
		}
		c.tm.log.Log(context.Background(), lvl, "term: connection killed",
			slog.String("flow", c.flowDesc()), slog.String("reason", reason))
		close(c.closed)
		c.mu.Lock()
		c.dead = true
		up := c.upstream
		c.mu.Unlock()
		if up != nil {
			go func() { _ = up.Close() }()
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
// Payload must be ≤ termMSS. Options: MSS on SYN-ACK only. win is the
// receive window advertised (real free receive-buffer space; see
// recvWindowLocked — the SYN-ACK uses termWindow).
func (c *termConn) craft(seq, ack uint32, flags byte, payload []byte, win uint16) []byte {
	optLen := 0
	if flags&termSYN != 0 {
		optLen = 4
	}
	ipLen, tcpLen := 20, 20+optLen+len(payload)
	pkt := craftBuf(ipLen + tcpLen)

	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(ipLen+tcpLen))
	pkt[4], pkt[5] = 0x12, 0x34
	pkt[6], pkt[7] = 0x40, 0x00 // DF
	pkt[8] = 64                 // TTL
	pkt[9] = 6                  // TCP
	copy(pkt[12:16], c.k.dstIP[:]) // src = the "server"
	copy(pkt[16:20], c.k.srcIP[:]) // dst = the client
	pkt[10], pkt[11] = 0, 0        // pooled buffer: stale checksum must not leak into the sum
	sum := ipChecksum(pkt[:20])
	pkt[10], pkt[11] = byte(sum>>8), byte(sum)

	tcp := pkt[ipLen:]
	binary.BigEndian.PutUint16(tcp[0:], c.k.dstPort) // server port
	binary.BigEndian.PutUint16(tcp[2:], c.k.srcPort) // client port
	binary.BigEndian.PutUint32(tcp[4:], seq)
	binary.BigEndian.PutUint32(tcp[8:], ack)
	tcp[12] = byte((20+optLen)/4) << 4 // data offset in 32-bit words
	binary.BigEndian.PutUint16(tcp[14:], win)
	tcp[13] = flags
	if optLen == 4 {
		tcp[20], tcp[21] = 2, 4 // MSS kind, len
		binary.BigEndian.PutUint16(tcp[22:], termMSS)
	}
	copy(tcp[20+optLen:], payload)

	// TCP checksum over the pseudo-header + segment (no concat buffer).
	// Pooled buffer: stale bytes 16-17 must be zeroed or they poison the sum.
	tcp[16], tcp[17] = 0, 0
	var pseudo [12]byte
	copy(pseudo[0:4], c.k.dstIP[:])
	copy(pseudo[4:8], c.k.srcIP[:])
	pseudo[8] = 6
	binary.BigEndian.PutUint16(pseudo[10:], uint16(tcpLen))
	tcpSum := ipChecksum2(pseudo[:], tcp)
	tcp[16], tcp[17] = byte(tcpSum>>8), byte(tcpSum&0xff)
	return pkt
}

func (c *termConn) flowDesc() string {
	// Cached: the 4-tuple is immutable, and flowDesc sits in per-segment
	// log calls (data injected / reorder warnings) — building the string
	// on every call allocated per segment.
	c.fdOnce.Do(func() {
		c.fdStr = net.IP(c.k.srcIP[:]).String() + ":" + fmt.Sprint(c.k.srcPort) +
			" -> " + net.IP(c.k.dstIP[:]).String() + ":" + fmt.Sprint(c.k.dstPort)
	})
	return c.fdStr
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

// ipChecksum2 is ipChecksum over the concatenation of a and b, without
// allocating the concatenated buffer (hot path: per-forged-packet).
// Requires len(a) to be even (true for the 12-byte TCP pseudo-header),
// otherwise word alignment would differ from a true concat.
func ipChecksum2(a, b []byte) uint16 {
	var sum uint32
	for _, s := range [2][]byte{a, b} {
		for i := 0; i+1 < len(s); i += 2 {
			sum += uint32(s[i])<<8 | uint32(s[i+1])
		}
		if len(s)%2 == 1 {
			sum += uint32(s[len(s)-1]) << 8
		}
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
