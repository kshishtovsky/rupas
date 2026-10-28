//go:build windows

package capture

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/kshishtovsky/rupas/internal/config"
	"github.com/kshishtovsky/rupas/internal/core"
	"github.com/kshishtovsky/rupas/internal/desync"
	"github.com/kshishtovsky/rupas/internal/flowtable"
	"github.com/kshishtovsky/rupas/internal/inspector"
	"github.com/kshishtovsky/rupas/internal/rules"
	"github.com/kshishtovsky/rupas/pkg/windivert"
)

// UDP relay port range captured for the tunnel branch (Discord voice et al.,
// SYSTEM_DESIGN §3.3 / ADR-5). FilterBuilder has no range primitive and
// enumerating 15 536 ports exceeds the 8 KB filter limit, so the clause is
// rendered as explicit >=/<= comparisons.
const (
	udpRangeLo uint16 = 50000
	udpRangeHi uint16 = 65535
)

// Defaults for the engine's resource pools.
const (
	defaultBatchSize  = 64 // §3.2: batch ≤ 64 packets
	defaultPacketSize = 65575
	defaultIdleTTL    = 5 * time.Minute
	// gcTick is coarse on purpose: TTLs are tens of seconds, and a 1 s tick
	// was 86400 scheduler wakeups/day on the phone for an empty table.
	gcTick = 5 * time.Second

	// ipTTLDefault is the TTL of crafted packets sent verbatim to the
	// client (resetClientFlow's forged RST); fakes lower their own TTL.
	ipTTLDefault = 64
)

// Options configures an Engine. Rules and the desync profile come from the
// compiled config; TProxyPort is the local loopback listener the NAT branch
// redirects to (0 disables the tunnel branch and the second handle).
type Options struct {
	Rules        *rules.Table        // compiled decision table (required)
	Desync       config.DesyncParams // desync profile for Engine.Actions
	FakeTemplate []byte              // fake ClientHello template bytes
	TProxyPort   uint16              // local tproxy port; must not be 443 or in [50000,65535]
	TGCIDRs      []string            // Telegram CIDRs, widen the capture filter
	// TermFilter443 declares that SNI-rule TUNNEL flows to :443 (YouTube/
	// Discord, wave 7) will be served by the terminator: the factory relay
	// (Options.TunnelTCP) is then installed even without TG CIDRs and
	// BuildTermFilter gains the tcp.SrcPort == 443 clause (the forged
	// packets use the ORIGINAL destination as their source — src port 443).
	TermFilter443 bool
	BatchSize     int           // recv batch slots; 0 = 64
	PacketSize    int           // per-slot buffer; 0 = 65575
	FlowIdleTTL   time.Duration // flow GC idle timeout; 0 = 5 min
	SniffMode     bool          // open real handles with FlagSniff (diagnostics only)

	// CHLog, when set, receives ONE line per ClientHello routing decision
	// ("CH sni=%q ech=%v dst=%s:%d verdict=%s") — TSPU-shape diagnostics.
	// NIL = silent: the hot path pays nothing for diagnostics (per-flow
	// cold call, never per steady-state segment).
	CHLog func(format string, args ...any)

	// TunnelTCP, when set, replaces the NAT→tproxy forward leg for TCP with
	// the userspace terminator (wave 5c): the engine opens a third handle
	// (inbound, TG CIDRs — see BuildTermFilter), hands it to the factory
	// and feeds every tunnel-verdict TCP packet to the returned hook
	// instead of NAT-rewriting it. Live finding 2026-10-25: the stack
	// drops NETWORK-layer injected inbound SYNs toward a local listener in
	// every address shape, so the NAT forward leg cannot deliver TCP.
	TunnelTCP TunnelTCPFactory
}

// TunnelTCPFactory builds the TCP terminator over the dedicated inbound
// send handle. Invoked once, in Run/openTransports, before any FeedTCP.
type TunnelTCPFactory func(send Transport) TunnelTCP

// TunnelTCP consumes tunnel-verdict TCP packets (the userspace terminator).
// FeedTCP is called on the capture hot path; it must not block on network
// I/O and must COPY anything it retains from pkt (the receive buffer is
// recycled on return). Close is called once from Stop.
type TunnelTCP interface {
	FeedTCP(pkt TCPPkt)
	Close()
}

// TCPPkt is one parsed outbound client packet handed to the terminator.
type TCPPkt struct {
	SrcIP, DstIP     [4]byte // client, original destination
	SrcPort, DstPort uint16
	Seq, Ack         uint32
	Flags            byte // SYN/ACK/PSH/FIN/RST
	Window           uint16
	Payload          []byte
	IfIdx, SubIfIdx  uint32 // re-injection interface (captured address)
}

// Engine is the capture hot path: one WinDivert NETWORK-layer receive loop
// plus (when the tunnel branch is enabled) a second loopback handle for the
// reverse NAT direction. Create with New, run with Run, stop with Stop.
type Engine struct {
	opts     Options
	desync   *desync.Engine
	fakeTpl  []byte
	flows    *flowtable.FlowTable
	rules    *rules.Table
	tproxyOn bool

	// Transport is set either by the test harness (fake) or by
	// openTransports (real driver). Once Run has started it is immutable.
	transport     Transport
	loopTransport Transport
	// termTransport is the terminator's dedicated inbound send handle;
	// tunnelTCP (from Options.TunnelTCP) consumes TCP flows when non-nil.
	termTransport Transport
	tunnelTCP     TunnelTCP

	// tgPrefixes mirrors opts.TGCIDRs for the §4.2 TCP fast path.
	tgPrefixes    []netip.Prefix
	ownsTransport bool

	streams    map[flowtable.FlowKey]*inspector.Stream
	streamMu   sync.Mutex // guards streams (main loop writes; cleanup from both loops)
	streamPool sync.Pool
	nat        map[natKey]natVal
	natMu      sync.RWMutex // guards nat (main inserts; loopback lookups/deletes)

	// ClientHello hold buffers (winws parity, wave 4A): partial CH
	// segments are held until the inspector reaches a verdict so the
	// fakes can precede the FIRST real segment on the wire.
	holds    map[flowtable.FlowKey]*chHold
	holdPool sync.Pool

	batches sync.Pool // *batchBuf
	scratch sync.Pool // *[]byte

	// Tunnel-redial cache (§3.2 "TUNNEL → следующий SYN пересоздаём"):
	// destinations whose CH-verdict flowed to TUNNEL (live: real ECH that
	// TSPU drops) — the client's next SYN (browser re-dial after the RST)
	// then takes the fast path straight into the tunnel. Zero value ready.
	tcache tunnelCache

	cnt counters

	stop     chan struct{}
	runDone  chan struct{}
	loopDone chan struct{}

	mu         sync.Mutex // guards the transport fields below (cold paths)
	runStarted atomic.Bool
	stopping   atomic.Bool
	stopOnce   sync.Once
}

// batchBuf is one pooled receive batch: a contiguous buffer (RecvBatch
// contract: ordered, non-overlapping slot views of one allocation) plus the
// slot views and address array. reset() restores full slot capacity, which
// RecvBatch clobbers by re-slicing slots to actual packet lengths.
type batchBuf struct {
	buf     []byte
	packets [][]byte
	addrs   []windivert.Address
	each    int
}

func (b *batchBuf) reset() {
	for i := range b.packets {
		b.packets[i] = b.buf[i*b.each : (i+1)*b.each]
	}
}

// New validates the options and assembles the engine (flow table, desync
// engine, pools). It does not touch the driver; Run opens the handles unless
// a transport was injected (tests).
func New(opts Options) (*Engine, error) {
	if opts.Rules == nil {
		return nil, errors.New("capture: Options.Rules is required")
	}
	if opts.TProxyPort == 443 {
		return nil, errors.New("capture: TProxyPort must not be 443 (filter self-match loop)")
	}
	if opts.TProxyPort >= udpRangeLo && opts.TProxyPort <= udpRangeHi {
		return nil, fmt.Errorf("capture: TProxyPort %d is inside the UDP relay range [%d,%d] (filter self-match loop)",
			opts.TProxyPort, udpRangeLo, udpRangeHi)
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = defaultBatchSize
	}
	if opts.PacketSize <= 0 {
		opts.PacketSize = defaultPacketSize
	}
	if opts.FlowIdleTTL <= 0 {
		opts.FlowIdleTTL = defaultIdleTTL
	}
	de, err := desync.New(opts.Desync, opts.FakeTemplate)
	if err != nil {
		return nil, fmt.Errorf("capture: desync engine: %w", err)
	}
	e := &Engine{
		opts:     opts,
		desync:   de,
		fakeTpl:  de.Template(),
		flows:    flowtable.New(),
		rules:    opts.Rules,
		tproxyOn: opts.TProxyPort != 0,
		streams:  make(map[flowtable.FlowKey]*inspector.Stream),
		holds:    make(map[flowtable.FlowKey]*chHold),
		nat:      make(map[natKey]natVal),
		stop:     make(chan struct{}),
		runDone:  make(chan struct{}),
		loopDone: make(chan struct{}),
	}
	for _, c := range opts.TGCIDRs {
		if p, err := netip.ParsePrefix(c); err == nil {
			e.tgPrefixes = append(e.tgPrefixes, p)
		}
	}
	e.streamPool.New = func() any { return inspector.NewStream() }
	e.holdPool.New = func() any { return &chHold{buf: make([]byte, 0, 2048)} }
	e.batches.New = func() any {
		buf, packets, addrs := windivert.NewBatch(opts.BatchSize, opts.PacketSize)
		return &batchBuf{buf: buf, packets: packets, addrs: addrs, each: opts.PacketSize}
	}
	e.scratch.New = func() any {
		b := make([]byte, 0, defaultPacketSize)
		return &b
	}
	return e, nil
}

// InjectTransport replaces the driver transports (main and, optionally,
// loopback) — the test seam. Must be called before Run.
func (e *Engine) InjectTransport(main, loop Transport) {
	e.mu.Lock()
	e.transport, e.loopTransport = main, loop
	e.mu.Unlock()
}

// SetTunnelTCP installs the TCP terminator hook directly — the test seam
// for Options.TunnelTCP (production runs the factory in openTransports).
// Must be called before Run.
func (e *Engine) SetTunnelTCP(hook TunnelTCP) {
	e.mu.Lock()
	e.tunnelTCP = hook
	e.mu.Unlock()
}

// TermFilter443Enabled reports whether the engine was configured for the
// terminator filter's tcp.SrcPort == 443 clause (wave 7 SNI-rule TUNNEL
// flows). The options are not otherwise observable after New — the app
// wiring tests assert the tunnel-live gate through this accessor.
func (e *Engine) TermFilter443Enabled() bool { return e.opts.TermFilter443 }

// Counters returns a point-in-time snapshot of the engine counters.
func (e *Engine) Counters() core.Counters { return e.cnt.snapshot() }

// TunnelRedirects counts §3.2 reset-and-redial verdicts: CH-decided TUNNEL
// flows that got the forged RST and whose dst joined the redial cache.
func (e *Engine) TunnelRedirects() uint64 { return e.cnt.tunnelRedirect.Load() }

// Flows exposes the flow table for diagnostics.
func (e *Engine) Flows() *flowtable.FlowTable { return e.flows }

// Run opens the WinDivert handles (unless a transport was injected), starts
// the flow-table GC, the loopback receive goroutine and then blocks in the
// main receive loop until ctx is canceled, Stop is called or the transport
// fails. It returns nil on a graceful stop.
func (e *Engine) Run(ctx context.Context) error {
	if !e.runStarted.CompareAndSwap(false, true) {
		return errors.New("capture: Run called twice")
	}
	defer close(e.runDone)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// Stop bridge: whichever fires first — parent ctx, e.stop — cancels the
	// loop context AND shuts the transports down (cancellation must precede
	// Shutdown, so a Recv unblocked by Shutdown always observes ctx.Done).
	go func() {
		select {
		case <-ctx.Done():
		case <-e.stop:
		}
		e.stopping.Store(true)
		cancel()
		e.shutdownTransports()
	}()

	e.mu.Lock()
	opened := false
	if e.transport == nil {
		if err := e.openTransports(); err != nil {
			e.mu.Unlock()
			return err
		}
		opened = true
	}
	main := e.transport
	loop := e.loopTransport
	term := e.termTransport
	e.mu.Unlock()
	if opened {
		defer e.closeTransports()
	}

	stopGC := e.flows.GC(e.opts.FlowIdleTTL, gcTick)
	defer stopGC()

	// Cold maintenance: release inspector streams orphaned by the flow GC.
	sweepDone := make(chan struct{})
	go func() {
		defer close(sweepDone)
		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				e.sweepStreams()
			}
		}
	}()

	loopRunning := false
	if loop != nil {
		loopRunning = true
		go func() {
			defer close(e.loopDone)
			e.loopRecv(ctx, loop)
		}()
	}
	if !loopRunning {
		close(e.loopDone)
	}

	// Terminator handle drain: everything it captures that is NOT one of
	// its own injections (same-handle Send is never re-captured) is foreign
	// inbound TG traffic (leftover pre-start connections) — relay untouched.
	if term != nil {
		go e.termRecv(ctx, term)
	}

	err := e.recvLoop(ctx, main)
	cancel() // unblocks the loopback goroutine and the sweeper
	<-e.loopDone
	<-sweepDone
	return err
}

// termRecv drains the terminator's dedicated handle: relay everything
// captured untouched through the same handle (same-handle Send is never
// re-captured, so this cannot loop).
func (e *Engine) termRecv(ctx context.Context, t Transport) {
	for {
		bb := e.getBatch()
		n, err := t.RecvBatch(bb.packets, bb.addrs)
		if err != nil {
			e.putBatch(bb)
			return
		}
		for i := 0; i < n; i++ {
			if err := t.Send(bb.packets[i], &bb.addrs[i]); err != nil {
				e.sendFailed(err) // loss is loss, even on the drain handle
			} else {
				e.sendOK()
			}
		}
		e.putBatch(bb)
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

// recvLoop is the hot loop: batch receive → per-packet verdict → recycle.
func (e *Engine) recvLoop(ctx context.Context, t Transport) error {
	for {
		bb := e.getBatch()
		n, err := t.RecvBatch(bb.packets, bb.addrs)
		if err != nil {
			e.putBatch(bb)
			// A Recv unblocked by Stop's Shutdown may land before the
			// context cancellation is observed; the stopping flag is set
			// BEFORE Shutdown, so it classifies those as graceful.
			if e.stopping.Load() {
				return nil
			}
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("capture: recv: %w", err)
			}
		}
		for i := 0; i < n; i++ {
			e.processPacket(bb.packets[i], &bb.addrs[i])
		}
		e.putBatch(bb)
		select {
		case <-ctx.Done():
			return nil
		default:
		}
	}
}

// loopRecv drains the second handle (loopback replies of the tproxy).
func (e *Engine) loopRecv(ctx context.Context, t Transport) {
	for {
		bb := e.getBatch()
		n, err := t.RecvBatch(bb.packets, bb.addrs)
		if err != nil {
			e.putBatch(bb)
			return
		}
		for i := 0; i < n; i++ {
			e.processLoopback(t, bb.packets[i], &bb.addrs[i])
		}
		e.putBatch(bb)
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

// Stop shuts the engine down gracefully: it unblocks pending receives
// (WinDivert SHUTDOWN_RECV — packets still queued in the driver are
// re-injected by the driver itself when the handle closes), waits for both
// loops to drain and closes the handles this engine opened. Stop is
// idempotent and safe to call before or while Run executes.
func (e *Engine) Stop() {
	e.stopOnce.Do(func() {
		e.stopping.Store(true)
		close(e.stop)
		e.shutdownTransports()
		if e.runStarted.Load() {
			select {
			case <-e.runDone:
			case <-time.After(5 * time.Second):
			}
		}
		e.mu.Lock()
		hook := e.tunnelTCP
		e.mu.Unlock()
		if hook != nil {
			hook.Close() // closes the terminator's upstream relays
		}
		if e.ownsTransport {
			e.closeTransports()
		}
	})
}

// shutdownTransports unblocks pending RecvBatch calls on both handles.
// Idempotent; also invoked by Run's stop bridge on parent-context cancel.
func (e *Engine) shutdownTransports() {
	e.mu.Lock()
	ts := []Transport{}
	if e.transport != nil {
		ts = append(ts, e.transport)
	}
	if e.loopTransport != nil {
		ts = append(ts, e.loopTransport)
	}
	if e.termTransport != nil {
		ts = append(ts, e.termTransport)
	}
	e.mu.Unlock()
	for _, t := range ts {
		_ = t.Shutdown()
	}
}

// openTransports opens the main NETWORK-layer handle and, when the tunnel
// branch is enabled, the loopback handle for the reverse NAT direction.
// Called with e.mu held.
func (e *Engine) openTransports() error {
	filter, err := BuildMainFilter(e.opts.TGCIDRs)
	if err != nil {
		return err
	}
	flags := uint64(0)
	if e.opts.SniffMode {
		flags |= windivert.FlagSniff
	}
	h, err := windivert.OpenWithFlags(filter, windivert.LayerNetwork, 0, flags)
	if err != nil {
		return fmt.Errorf("capture: open main handle: %w", err)
	}
	raiseQueueParams(h)
	e.transport = NewWinTransport(h)
	e.ownsTransport = true
	if e.tproxyOn {
		loFilter, err := BuildLoopbackFilter(e.opts.TProxyPort)
		if err != nil {
			e.closeTransports()
			return err
		}
		// READ_ONLY would forbid Send; the reverse-NAT rewrite must inject.
		lh, err := windivert.OpenWithFlags(loFilter, windivert.LayerNetwork, 0, flags)
		if err != nil {
			e.closeTransports()
			return fmt.Errorf("capture: open loopback handle: %w", err)
		}
		raiseQueueParams(lh)
		e.loopTransport = NewWinTransport(lh)
	}
	// Wave 5c: the terminator's dedicated inbound send handle. Its filter
	// matches the forged packets (inbound, TG CIDR / src-port-443 sources)
	// — the live matrix only proved delivery through content-matching
	// handles. Wave 7: SNI-rule TUNNEL flows (YouTube/Discord on :443) also
	// ride it, so TermFilter443 installs the handle without any TG CIDRs.
	if e.opts.TunnelTCP != nil && (len(e.opts.TGCIDRs) > 0 || e.opts.TermFilter443) {
		tf, err := BuildTermFilter(e.opts.TGCIDRs)
		if err != nil {
			e.closeTransports()
			return err
		}
		th, err := windivert.OpenWithFlags(tf, windivert.LayerNetwork, 0, flags)
		if err != nil {
			e.closeTransports()
			return fmt.Errorf("capture: open terminator handle: %w", err)
		}
		raiseQueueParams(th)
		e.termTransport = NewWinTransport(th)
		e.tunnelTCP = e.opts.TunnelTCP(e.termTransport)
	}
	return nil
}

func (e *Engine) closeTransports() {
	e.mu.Lock()
	t, l, tm := e.transport, e.loopTransport, e.termTransport
	e.transport, e.loopTransport, e.termTransport = nil, nil, nil
	e.mu.Unlock()
	if t != nil {
		_ = t.Close()
	}
	if l != nil {
		_ = l.Close()
	}
	if tm != nil {
		_ = tm.Close()
	}
}

// raiseQueueParams lifts the driver's internal capture-queue bounds to
// the WinDivert 2.2 maximums (stock defaults: 4096 packets / 4 MB /
// 2000 ms). Live upload finding 2026-10-25: the drain loop is a single
// goroutine whose per-packet work includes a synchronous injected-ACK
// send (Terminator.FeedTCP → termConn.feed → SendInboundTCP), so on a
// busy uplink the default queue overflows — and the driver's overflow
// drop is SILENT (no error ever reaches Recv): the segment simply never
// arrives and the terminator sees a sequence hole. SetParam failures
// are non-fatal: the defaults still work, just with less headroom.
func raiseQueueParams(h *windivert.Handle) {
	_ = h.SetParam(windivert.ParamQueueLength, 16384)
	_ = h.SetParam(windivert.ParamQueueSize, 33554432) // 32 MB (driver max)
	_ = h.SetParam(windivert.ParamQueueTime, 16000)    // ms (driver max)
}

// getBatch / putBatch recycle receive batches through the pool.
func (e *Engine) getBatch() *batchBuf {
	bb := e.batches.Get().(*batchBuf)
	bb.reset()
	return bb
}

func (e *Engine) putBatch(bb *batchBuf) { e.batches.Put(bb) }

// getScratch / putScratch recycle the scratch buffers used to craft fake and
// split packets. The pool stores *[]byte so the slice header (grown by the
// rare oversize path) round-trips correctly.
func (e *Engine) getScratch(need int) []byte {
	pb := e.scratch.Get().(*[]byte)
	if cap(*pb) < need { // oversized template: cold, at most once
		b := make([]byte, need)
		*pb = b
	}
	return (*pb)[:need]
}

func (e *Engine) putScratch(b []byte) {
	// Keep the pool's default capacity even if this view is shorter.
	pb := &b
	if cap(b) >= defaultPacketSize {
		*pb = b[:0]
	}
	e.scratch.Put(pb)
}

// ---------------------------------------------------------------------------
// Packet classification (SYSTEM_DESIGN §3.2)
// ---------------------------------------------------------------------------

// processPacket classifies one captured packet and applies the verdict.
// Warm-path budget: zero heap allocations.
func (e *Engine) processPacket(pkt []byte, addr *windivert.Address) {
	p, ok := parsePkt(pkt)
	if !ok || (p.proto != protoTCP && p.proto != protoUDP) {
		e.cnt.parseErrors.Add(1)
		e.passVerdict(pkt, addr, core.VerdictPass)
		return
	}
	if addr.Outbound() {
		e.processOutbound(pkt, addr, &p)
	} else {
		e.processInbound(pkt, addr, &p)
	}
}

func (e *Engine) processOutbound(pkt []byte, addr *windivert.Address, p *pktInfo) {
	// Never touch traffic already addressed to the loopback tproxy: those
	// are our own re-injections (or unrelated local traffic).
	if isLoopback(p.dst4) {
		e.passVerdict(pkt, addr, core.VerdictPass)
		return
	}

	if p.isUDP() {
		e.processUDP(pkt, addr, p)
		return
	}

	key := flowKeyOut(p)

	// §4.2 TCP fast path: a CIDR rule already decides TUNNEL without any
	// ClientHello — MTProto and other non-TLS Telegram traffic never
	// produces one (live finding: such dials leaked DIRECT into the TSPU
	// blackhole). SNI/port rules still run the CH pipeline below.
	// §3.2 redial: a dst cached by a CH-verdict TUNNEL (resetTunnelRedial)
	// rides the same fast path from its FIRST SYN — the browser's re-dial
	// after the forged RST enters the tunnel without touching the real
	// (ECH-blackholed) server again.
	if e.tgFastTunnel(p) || e.tcache.get(p.dst4, p.dstPort) {
		f := e.flows.GetOrCreate(key)
		if f.State.Load() != flowtable.FlowTunnel {
			f.State.Store(flowtable.FlowTunnel)
		}
		e.relayTunnelTCP(pkt, addr, p, key, f)
		return
	}

	// Hard connection teardown: the tunnel-verdict flow must close on the
	// SAME leg it rode (wave 7: the userspace terminator forges the FIN/RST
	// relay; the NAT fallback only when no terminator is installed).
	if p.rst() || p.fin() {
		if f, ok := e.flows.Get(key); ok {
			if f.State.Load() == flowtable.FlowTunnel {
				e.relayTunnelTCP(pkt, addr, p, key, f)
			} else {
				e.passVerdict(pkt, addr, core.VerdictPass)
			}
			e.cleanupFlow(natKey{ip: v4mapped(fakeIP4()), port: p.srcPort, proto: p.proto}, key)
			return
		}
		e.passVerdict(pkt, addr, core.VerdictPass)
		return
	}

	// SYN (no ACK): create the flow. A SYN retransmission of a flow that
	// already went TUNNEL is re-relayed (§3.2: "next SYN via redirect").
	if p.syn() && !p.ack() {
		f := e.flows.GetOrCreate(key)
		f.TouchSyn()
		f.ClientISN = p.seq // wave 4A: fake CH builds on ISN+1 (winws parity)
		if f.State.Load() == flowtable.FlowTunnel {
			e.relayTunnelTCP(pkt, addr, p, key, f)
		} else {
			e.passVerdict(pkt, addr, core.VerdictPass)
		}
		return
	}

	if len(p.payload) > 0 {
		f := e.flows.GetOrCreate(key)
		f.TouchData()
		switch f.State.Load() {
		case flowtable.FlowTunnel:
			e.relayTunnelTCP(pkt, addr, p, key, f)
		case flowtable.FlowDirect, flowtable.FlowDesynced, flowtable.FlowEstablished:
			e.passVerdict(pkt, addr, core.VerdictPass)
		default: // FlowNew: first(ish) data segment → ClientHello pipeline
			e.inspectClientHello(pkt, addr, p, key, f)
		}
		return
	}

	// Pure ACK / window probe: relayed on the same leg as the flow's data.
	if f, ok := e.flows.Get(key); ok && f.State.Load() == flowtable.FlowTunnel {
		e.relayTunnelTCP(pkt, addr, p, key, f)
		return
	}
	e.passVerdict(pkt, addr, core.VerdictPass)
}

// inspectClientHello runs the §3.2 pipeline on a data segment of a NEW flow:
// feed the inspector, then DIRECT / DESYNC / TUNNEL by rules.Match, with ECH
// forcing TUNNEL.
//
// Wave 4A (winws parity): while the inspector reassembles a multi-segment
// ClientHello, the earlier segments are HELD (not forwarded) — otherwise the
// first real CH bytes egress before any fake and the DPI simply parses the
// real ClientHello (live finding 2026-10-25: engine blocked where winws
// punched through; winws holds the CH, sends N fakes, then releases the
// real segments). On the completing segment the verdict fires and every
// held segment is released in order AFTER the InjectFake ops
// (see applyDesync).
func (e *Engine) inspectClientHello(pkt []byte, addr *windivert.Address, p *pktInfo, key flowtable.FlowKey, f *flowtable.Flow) {
	e.streamMu.Lock()
	st, ok := e.streams[key]
	if !ok { // cold: one insert per inspected flow
		st = e.streamPool.Get().(*inspector.Stream)
		e.streams[key] = st
	}
	e.streamMu.Unlock()
	res, err := st.Feed(p.payload)
	if err == inspector.ErrNeedMore {
		if e.holdSegment(key, pkt, addr) {
			return // segment held until the CH completes
		}
		// Hold overflow (pathological segmentation): degrade to the old
		// immediate pass-through; this CH is simply not protected.
		e.passVerdict(pkt, addr, core.VerdictPass)
		return
	}
	// Terminal for the inspector either way: recycle the stream.
	f.CHSeen = true
	e.streamMu.Lock()
	delete(e.streams, key)
	e.streamMu.Unlock()
	st.Reset()
	e.streamPool.Put(st)
	held := e.takeHold(key)

	if err != nil || !res.IsTLS {
		// Not a TLS ClientHello (or malformed): nothing to decide on.
		f.State.Store(flowtable.FlowDirect)
		e.chLog(p, res.SNI, res.ECH, "DIRECT")
		e.releaseHeld(held)
		e.passVerdict(pkt, addr, core.VerdictPass)
		return
	}
	f.ECH = res.ECH

	action := e.rules.MatchProto(v4mapped(p.dst4), unsafeString(res.SNI), p.dstPort, config.ProtoTCP)
	if res.ECH && action != config.ActionDirect {
		// Encrypted Client Hello: desync is pointless (lab: Schannel-ECH
		// не пробивается) — route to the tunnel instead.
		//
		// But an explicit DIRECT rule wins: TSPU only drops ECH CHs for
		// blocked resources. RU hosts (yandex.net CDN, strm speedtest)
		// send real ECH from DNS HTTPS records and pass it through fine —
		// forcing them into the tunnel moves the exit region and caps
		// throughput (live finding 2026-10-26, internetometer). A browser
		// retries without ECH if a direct ECH CH ever gets dropped, so the
		// fallback cost is one RTT, not a hang.
		action = config.ActionTunnel
	}

	switch action {
	case config.ActionDirect:
		e.chLog(p, res.SNI, res.ECH, action.String())
		f.State.Store(flowtable.FlowDirect)
		e.releaseHeld(held)
		e.passVerdict(pkt, addr, core.VerdictPass)
	case config.ActionDesync:
		e.chLog(p, res.SNI, res.ECH, action.String())
		e.applyDesync(pkt, p, addr, res.SNI, held)
		f.State.Store(flowtable.FlowDesynced)
	case config.ActionBlock:
		// PRD §5: administratively dropped (e.g. proto-scoped QUIC
		// block). The packet AND any held CH segments die here — never
		// re-injected, so a TCP block cannot leak through the hold path.
		e.chLog(p, res.SNI, res.ECH, action.String())
		if held != nil {
			e.putHold(held) // recycle; nil when the CH completed in-segment
		}
		e.cnt.countVerdict(core.VerdictDrop)
	default: // ActionTunnel (and any invalid value): §3.2 reset-and-redial.
		// Live finding 2026-10-25: relaying the CH into the tunnel branch
		// here (termHeld+relayTunnelTCP) hangs the browser forever — the
		// terminator only terminates from the SYN state, and THIS flow
		// already completed its handshake with the REAL server (the SYN
		// egressed before any verdict existed), so no carrier dial ever
		// happens. Instead: cache the dst, recycle the held segments
		// (never egress — the TSPU drops ECH), forge an RST from the real
		// destination so the client re-dials at once, and let the fresh
		// SYN take the cached fast path into the tunnel (processOutbound).
		e.chLog(p, res.SNI, res.ECH, action.String())
		f.State.Store(flowtable.FlowTunnel)
		e.resetTunnelRedial(p, addr, key, held)
	}
}

// resetTunnelRedial executes the §3.2 "TUNNEL → следующий SYN пересоздаём"
// verdict for one CH-decided flow: (a) the destination joins the redial
// cache, (b) the held CH segments (and the completing one) are recycled —
// no byte of this ECH ClientHello ever reaches the TSPU, (c) the client is
// reset with a forged RST|ACK from the real destination, (d) the dead
// flow's state (stream/hold/flow-table entries) is freed. One INFO line.
func (e *Engine) resetTunnelRedial(p *pktInfo, addr *windivert.Address, key flowtable.FlowKey, held *chHold) {
	e.tcache.add(p.dst4, p.dstPort)
	if held != nil {
		e.putHold(held) // recycle, never relay
	}
	e.resetClientFlow(p, addr)
	e.cnt.tunnelRedirect.Add(1)
	// The CH segment itself never egresses (that is the point — the TSPU
	// drops ECH): accounted as a drop, like the BLOCK branch.
	e.cnt.countVerdict(core.VerdictDrop)
	if e.opts.CHLog != nil {
		e.opts.CHLog("term: ech/tunnel reset, dst cached for redial dst=%d.%d.%d.%d:%d",
			p.dst4[0], p.dst4[1], p.dst4[2], p.dst4[3], p.dstPort)
	}
	// The RST kills the flow on the client side too: free every table
	// entry (mirrors the FIN/RST teardown in processOutbound).
	e.cleanupFlow(natKey{ip: v4mapped(fakeIP4()), port: p.srcPort, proto: p.proto}, key)
}

// resetClientFlow forges and injects one inbound RST|ACK that appears to
// come from the flow's real destination: the client socket dies at once and
// the application re-dials (§3.2 reset-and-redial) instead of hanging until
// its own timeout.
//
// Header values (server-side view): src = the flow's ORIGINAL destination
// (the server the client thinks it talks to), seq = the client's current
// ack (the server's send-next as far as the client knows), ack = the
// client's next byte (its seq + this segment's payload), flags RST|ACK,
// window 0 — the same shape the terminator's reset uses (tcpterm.craft:
// termRST|termACK, seq = serverNext, ack = clientNext).
//
// Injection follows the crafted-send doctrine (ops.go #4/#5): checksums
// precomputed into the bytes through FixChecksums, a synthetic address with
// every checksum-valid flag SET and NO impostor flag, direction INBOUND on
// the client's captured interface — the only shape the live matrix proved
// delivers to a client socket. Sent through the terminator's dedicated
// handle when installed (its filter matches inbound src-port-443 / TG-src
// traffic), else through the main handle.
func (e *Engine) resetClientFlow(p *pktInfo, addr *windivert.Address) {
	buf := e.getScratch(40)
	b := buf[:40]
	for i := range b {
		b[i] = 0
	}
	// IPv4 header.
	b[0] = 0x45 // v4, IHL 5
	binary.BigEndian.PutUint16(b[2:4], 40)
	b[8] = ipTTLDefault
	b[9] = protoTCP
	copy(b[12:16], p.dst4[:]) // src = real destination
	copy(b[16:20], p.src4[:]) // dst = client
	// TCP header.
	binary.BigEndian.PutUint16(b[20:22], p.dstPort)
	binary.BigEndian.PutUint16(b[22:24], p.srcPort)
	binary.BigEndian.PutUint32(b[24:28], p.ackNum) // server seq = client's ack
	binary.BigEndian.PutUint32(b[28:32], p.seq+uint32(len(p.payload)))
	b[32] = 0x50 // data offset 5 words
	b[33] = tcpFlagRST | tcpFlagACK
	// window 0, checksum/urgent zeroed above.
	rstAddr := inboundSendAddr(addr)
	t := e.termTransport
	if t == nil {
		t = e.transport
	}
	if err := t.FixChecksums(b, &rstAddr); err != nil {
		e.sendErr()
		e.putScratch(buf)
		return
	}
	if err := t.Send(b, &rstAddr); err != nil {
		e.sendFailed(err)
	} else {
		e.sendOK()
	}
	e.putScratch(buf)
}

// inboundSendAddr is fakeSendAddr's inbound twin (crafted-send doctrine
// #5): zeroed address, checksum-valid flags SET, the captured packet's
// interface — but direction INBOUND, not loopback, which is the shape the
// client stack accepts from a foreign "server" (live matrix: self-sourced
// or outbound-flagged re-injections never deliver).
func inboundSendAddr(captured *windivert.Address) windivert.Address {
	a := windivert.Address{}
	a.Layer = captured.Layer
	a.SetOutbound(false)
	a.SetLoopback(false)
	a.SetIPChecksum(true)
	a.SetTCPChecksum(true)
	a.SetUDPChecksum(true)
	na, ca := a.Network(), captured.Network()
	na.IfIdx, na.SubIfIdx = ca.IfIdx, ca.SubIfIdx
	return a
}

// ---------------------------------------------------------------------------
// ClientHello segment hold (winws parity)
// ---------------------------------------------------------------------------

// maxCHHoldSegs bounds how many segments of one ClientHello the engine will
// hold. §3.2 reassembles up to 4 segments / 64 KB; the slack absorbs
// pathological-but-legal segmentations before the overflow fallback.
const maxCHHoldSegs = 8

// chHold buffers the raw bytes (and WinDivert addresses) of a flow's
// partial ClientHello segments in arrival order inside one pooled backing
// buffer. Zero heap allocations after pool warm-up: add() copies into the
// pooled buffer and only grows it on the cold first oversize.
type chHold struct {
	buf  []byte // pooled backing; segments appended contiguously
	end  [maxCHHoldSegs]uint32
	addr [maxCHHoldSegs]windivert.Address
	n    int
}

func (h *chHold) add(pkt []byte, addr *windivert.Address) bool {
	if h.n >= maxCHHoldSegs {
		return false
	}
	if cap(h.buf)-len(h.buf) < len(pkt) { // cold growth, at most a few times
		nb := make([]byte, len(h.buf), max(2*cap(h.buf), len(h.buf)+len(pkt)))
		copy(nb, h.buf)
		h.buf = nb
	}
	h.buf = append(h.buf, pkt...)
	h.end[h.n] = uint32(len(h.buf))
	h.addr[h.n] = *addr
	h.n++
	return true
}

// seg returns the raw bytes of held segment i.
func (h *chHold) seg(i int) []byte {
	lo := uint32(0)
	if i > 0 {
		lo = h.end[i-1]
	}
	return h.buf[lo:h.end[i]]
}

func (h *chHold) reset() {
	h.buf = h.buf[:0]
	h.n = 0
}

// holdSegment buffers one partial ClientHello segment until the CH
// completes. Cold except for the copy itself: one map insert per inspected
// flow, buffers pooled.
func (e *Engine) holdSegment(key flowtable.FlowKey, pkt []byte, addr *windivert.Address) bool {
	e.streamMu.Lock()
	h, ok := e.holds[key]
	if !ok {
		h = e.holdPool.Get().(*chHold)
		e.holds[key] = h
	}
	e.streamMu.Unlock()
	return h.add(pkt, addr)
}

// takeHold removes and returns the flow's hold (nil when the ClientHello
// fit in a single segment). The caller releases or recycles it.
func (e *Engine) takeHold(key flowtable.FlowKey) *chHold {
	e.streamMu.Lock()
	h := e.holds[key]
	delete(e.holds, key)
	e.streamMu.Unlock()
	return h
}

// releaseHeld re-injects held segments in their original order (pass
// verdicts) and recycles the hold.
func (e *Engine) releaseHeld(h *chHold) {
	if h == nil {
		return
	}
	for i := 0; i < h.n; i++ {
		e.passVerdict(h.seg(i), &h.addr[i], core.VerdictPass)
	}
	e.putHold(h)
}

// chLog emits the one-line ClientHello routing record (wave 7: TSPU-shape
// diagnostics) — at most once per flow, never on the steady-state segment
// path. Nil formatter = silent, so the hot path pays a single nil check.
func (e *Engine) chLog(p *pktInfo, sni []byte, ech bool, verdict string) {
	if e.opts.CHLog == nil {
		return
	}
	e.opts.CHLog("CH sni=%q ech=%v dst=%d.%d.%d.%d:%d verdict=%s",
		sni, ech, p.dst4[0], p.dst4[1], p.dst4[2], p.dst4[3], p.dstPort, verdict)
}

func (e *Engine) putHold(h *chHold) {
	h.reset()
	e.holdPool.Put(h)
}

// processUDP applies the tunnel branch to UDP relay traffic (ADR-5): no
// inspector, rules decide by CIDR/port. A proto-scoped udp rule (e.g. the
// PRD §5 QUIC block) resolves only here; TUNNEL → NAT, BLOCK → drop (the
// datagram is counted and silently discarded — the browser falls back to
// TCP), everything else passes.
func (e *Engine) processUDP(pkt []byte, addr *windivert.Address, p *pktInfo) {
	key := flowKeyOut(p)
	action := e.rules.MatchProto(v4mapped(p.dst4), "", p.dstPort, config.ProtoUDP)
	switch action {
	case config.ActionTunnel:
		f := e.flows.GetOrCreate(key)
		f.State.Store(flowtable.FlowTunnel)
		e.natOutbound(pkt, p, key, f, addr)
	case config.ActionBlock:
		e.cnt.countVerdict(core.VerdictDrop)
	default:
		e.passVerdict(pkt, addr, core.VerdictPass)
	}
}

// tgFastTunnel reports the §4.2 fast-path verdict: the destination is in a
// TG CIDR AND the rules table resolves TUNNEL for (dst, port) with no SNI.
func (e *Engine) tgFastTunnel(p *pktInfo) bool {
	if len(e.tgPrefixes) == 0 {
		return false
	}
	dst := netip.AddrFrom4(p.dst4)
	for _, px := range e.tgPrefixes {
		if px.Contains(dst) && e.rules.MatchProto(v4mapped(p.dst4), "", p.dstPort, config.ProtoTCP) == config.ActionTunnel {
			return true
		}
	}
	return false
}

// relayTunnelTCP carries one tunnel-verdict TCP packet (wave 7): to the
// userspace terminator when installed, else to the legacy NAT→tproxy leg —
// but ONLY with a configured tproxy port (live finding: that forward leg
// cannot deliver TCP, so without both we pass honestly; a DstPort=0
// rewrite in port-0 mode would silently blackhole the flow).
func (e *Engine) relayTunnelTCP(pkt []byte, addr *windivert.Address, p *pktInfo, key flowtable.FlowKey, f *flowtable.Flow) {
	if e.tunnelTCP != nil {
		win := uint16(0)
		if p.ipLen+16 <= len(pkt) {
			win = binary.BigEndian.Uint16(pkt[p.ipLen+14 : p.ipLen+16])
		}
		tp := TCPPkt{
			SrcIP: p.src4, DstIP: p.dst4,
			SrcPort: p.srcPort, DstPort: p.dstPort,
			Seq: p.seq, Ack: p.ackNum, Flags: p.flags, Window: win,
			Payload: p.payload,
		}
		if na := addr.Network(); na != nil {
			tp.IfIdx, tp.SubIfIdx = na.IfIdx, na.SubIfIdx
		}
		e.tunnelTCP.FeedTCP(tp)
		e.cnt.tunnelTx.Add(1)
		if p.fin() || p.rst() {
			e.cleanupFlow(natKey{ip: v4mapped(fakeIP4()), port: p.srcPort, proto: p.proto}, key)
		}
		return
	}
	if e.tproxyOn {
		e.natOutbound(pkt, p, key, f, addr)
		// §3.2 teardown parity with the terminator branch: a FIN/RST that
		// rode the fast path (TG CIDR or cached tunnel dst) must free the
		// flow even when no terminator is installed (NAT→tproxy leg).
		if p.fin() || p.rst() {
			e.cleanupFlow(natKey{ip: v4mapped(fakeIP4()), port: p.srcPort, proto: p.proto}, key)
		}
		return
	}
	e.passVerdict(pkt, addr, core.VerdictPass)
}

// processInbound handles packets captured in the server→client direction
// (with the production outbound-only filter these occur on the loopback
// handle and in tests). Any data segment from the server completes the
// handshake for a DESYNCED flow (§3.2, simplified detector: ACK after
// ServerHello ≈ any server data segment).
func (e *Engine) processInbound(pkt []byte, addr *windivert.Address, p *pktInfo) {
	// Best-effort ServerISN capture (wave 4A): the production main filter
	// is outbound-only, so this only fires where inbound is visible (tests,
	// loopback handle). The fake's ack is otherwise cloned from the first
	// data segment (= ServerISN+1), so this is diagnostics/fallback.
	if p.isTCP() && p.syn() && p.ack() {
		if f, ok := e.flows.Get(flowKeyIn(p)); ok && f.State.Load() == flowtable.FlowNew {
			f.ServerISN = p.seq
		}
	}
	if p.isTCP() && len(p.payload) > 0 {
		if f, ok := e.flows.Get(flowKeyIn(p)); ok && f.State.Load() == flowtable.FlowDesynced {
			f.State.Store(flowtable.FlowEstablished)
			f.TouchEst()
			e.cnt.handshakeOK.Add(1)
		}
	}
	if p.isTCP() && (p.fin() || p.rst()) {
		key := flowKeyIn(p)
		if _, ok := e.flows.Get(key); ok {
			// NAT entries are keyed by the FAKE source IP; key.SrcPort is
			// the client's ephemeral port (client lands in the src fields).
			e.cleanupFlow(natKey{ip: v4mapped(fakeIP4()), port: key.SrcPort, proto: p.proto}, key)
		}
	}
	e.passVerdict(pkt, addr, core.VerdictPass)
}

// ---------------------------------------------------------------------------
// Send-failure backpressure (wave 9)
// ---------------------------------------------------------------------------

// A WinDivert send failure (its send queue overflowing, or a driver error)
// means the packet we just decided to re-inject is GONE. For DIRECT traffic
// that is silent packet loss: the peer retransmits, its congestion window
// collapses, and the whole machine stalls for seconds — the owner's
// "network freezes, then recovers on its own". The old code incremented a
// counter nobody read and ploughed on.
//
// Policy: count every failure, and once a BURST of consecutive failures
// shows the driver cannot keep up, (a) WARN with a rate limit so the log is
// not flooded, (b) pause the receive loop briefly — a 2 ms pause costs
// nothing and lets the driver drain, while a dropped packet costs a TCP
// retransmit (RTO ≥ 200 ms). The pause NEVER happens in the normal path:
// it is gated behind the burst threshold, so steady-state latency is
// untouched.
const (
	// sendErrBurst is how many consecutive failures trip the throttle.
	sendErrBurst = 64
	// sendErrWarnEvery rate-limits the WARN (first burst logs immediately).
	sendErrWarnEvery = 2 * time.Second
	// sendErrPause is the receive pause after a failed burst.
	sendErrPause = 2 * time.Millisecond
)

// sendOK clears the consecutive-failure burst. One atomic load in the
// success path (a store only after a failure), so the hot path pays nothing
// in steady state.
func (e *Engine) sendOK() {
	if e.cnt.sendErrBurst.Load() != 0 {
		e.cnt.sendErrBurst.Store(0)
	}
}

// sendFailed records one failed re-injection and, on each burst of
// consecutive failures, throttles the receive loop. Never returns an error:
// the caller has nothing better to do with the packet (it is already lost)
// than to slow the source down.
func (e *Engine) sendFailed(err error) {
	total := e.cnt.sendErrors.Add(1)
	burst := e.cnt.sendErrBurst.Add(1)
	// One pause per burst (not per packet): a permanently failing driver
	// must not turn every packet into a 2 ms stall.
	if burst < sendErrBurst || burst%sendErrBurst != 0 {
		return
	}
	now := time.Now().UnixNano()
	last := e.cnt.sendWarnAt.Load()
	if last == 0 || now-last >= int64(sendErrWarnEvery) {
		if e.cnt.sendWarnAt.CompareAndSwap(last, now) {
			msg := "send failed"
			if err != nil {
				msg = err.Error()
			}
			slog.Warn("capture: WARN send failures — throttling receive to drain the driver",
				slog.Uint64("send_errors_total", total),
				slog.Uint64("consecutive", uint64(burst)),
				slog.String("err", msg))
		}
	}
	e.cnt.sendPauses.Add(1)
	time.Sleep(sendErrPause)
}

// sendErr counts a failed injection without the burst throttle — for
// failures a pause cannot help (checksum preparation), which still must be
// visible in the counters.
func (e *Engine) sendErr() { e.cnt.sendErrors.Add(1) }

// passVerdict counts and re-injects a packet untouched.
func (e *Engine) passVerdict(pkt []byte, addr *windivert.Address, v core.Verdict) {
	e.cnt.countVerdict(v)
	if err := e.transport.Send(pkt, addr); err != nil {
		e.sendFailed(err)
		return
	}
	e.sendOK()
}

// unsafeString reinterprets b as a string without copying — the standard
// zero-allocation bridge for byte-slice keys. Safe here because
// rules.Table.Match only reads the string (map lookups over its own keys)
// and never retains it, and b outlives the call.
func unsafeString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return *(*string)(unsafe.Pointer(&b))
}

// ---------------------------------------------------------------------------
// Capture filters
// ---------------------------------------------------------------------------

// BuildMainFilter renders the outbound NETWORK-layer filter
// (SYSTEM_DESIGN §3.1):
//
//	(outbound and tcp and tcp.DstPort == 443)          — desync branch
//	 or (outbound and <TG CIDR ranges>)                — tunnel branch, any proto/port
//	 or (outbound and udp and udp.DstPort >= 50000 …)  — UDP relay (Discord)
//
// Each clause is assembled by windivert.FilterBuilder (which emits the
// DLL-accepted >=/<= CIDR range syntax); the UDP port range is rendered
// explicitly because FilterBuilder has no range primitive and enumerating
// 15 536 ports would exceed the 8 KB filter limit.
func BuildMainFilter(tgCIDRs []string) (string, error) {
	type clause struct {
		build func() (string, error)
	}
	clauses := []clause{
		{func() (string, error) { return windivert.NewFilter().Outbound().TCP().DstPorts(443).Build() }},
	}
	if len(tgCIDRs) > 0 {
		clauses = append(clauses, clause{func() (string, error) {
			return windivert.NewFilter().Outbound().DstCIDRs(tgCIDRs...).Build()
		}})
	}
	clauses = append(clauses, clause{func() (string, error) {
		return fmt.Sprintf("outbound and udp and udp.DstPort >= %d and udp.DstPort <= %d", udpRangeLo, udpRangeHi), nil
	}})
	parts := make([]string, 0, len(clauses))
	for _, c := range clauses {
		s, err := c.build()
		if err != nil {
			return "", fmt.Errorf("capture: main filter clause: %w", err)
		}
		parts = append(parts, "("+s+")")
	}
	return strings.Join(parts, " or "), nil
}

// BuildLoopbackFilter renders the second handle's filter. Live matrix
// findings (2026-10-25): genuine loopback traffic surfaces at the NETWORK
// layer ONLY as its outbound leg, so the reverse NAT captures the tproxy
// replies' OUTBOUND legs (source port == tproxyPort). The inbound clauses
// cover the forward NAT re-injections (destination port == tproxyPort),
// which natOutbound releases through this handle.
func BuildLoopbackFilter(tproxyPort uint16) (string, error) {
	tcpFwd, err := windivert.NewFilter().Inbound().TCP().DstPorts(tproxyPort).Build()
	if err != nil {
		return "", err
	}
	tcpRev, err := windivert.NewFilter().Outbound().TCP().SrcPorts(tproxyPort).Build()
	if err != nil {
		return "", err
	}
	udpFwd, err := windivert.NewFilter().Inbound().UDP().DstPorts(tproxyPort).Build()
	if err != nil {
		return "", err
	}
	udpRev, err := windivert.NewFilter().Outbound().UDP().SrcPorts(tproxyPort).Build()
	if err != nil {
		return "", err
	}
	return "(((" + tcpFwd + ") or (" + tcpRev + ")) or ((" + udpFwd + ") or (" + udpRev + ")))", nil
}

// BuildTermFilter renders the terminator handle's filter: the INBOUND legs
// its own injections occupy — TG-CIDR TCP (src = original TG destination)
// and, wave 7, tcp.SrcPort == 443 (src = ORIGINAL :443 destination of the
// SNI-rule TUNNEL flows: YouTube/Discord). The 443 clause is unconditional:
// TermFilter443 opts in without TG CIDRs. The live matrix only proved
// delivery through handles whose filter MATCHES the injected content, so
// the filter doubles as the send-path contract. Everything else it can
// capture is foreign inbound traffic, relayed untouched by termRecv
// (same-handle Send is never re-captured — no loop).
func BuildTermFilter(tgCIDRs []string) (string, error) {
	f443, err := windivert.NewFilter().Inbound().TCP().SrcPorts(443).Build()
	if err != nil {
		return "", fmt.Errorf("capture: terminator filter: %w", err)
	}
	parts := []string{"(" + f443 + ")"}
	if len(tgCIDRs) > 0 {
		cidr, err := windivert.NewFilter().Inbound().TCP().SrcCIDRs(tgCIDRs...).Build()
		if err != nil {
			return "", fmt.Errorf("capture: terminator filter: %w", err)
		}
		parts = append(parts, "("+cidr+")")
	}
	return strings.Join(parts, " or "), nil
}

// ---------------------------------------------------------------------------
// Tunnel-redial cache (§3.2 "TUNNEL → следующий SYN пересоздаём")
// ---------------------------------------------------------------------------

// The redial cache turns a CH-verdict TUNNEL into a first-SYN tunnel entry:
// after resetTunnelRedial RSTs the client, the browser's re-dial SYN hits
// the fast path (processOutbound) and enters the userspace terminator —
// which only terminates from the SYN state, so the fresh connection is the
// one that gets served. Entries live tunnelCacheTTL (long enough for the
// browser's instant re-dial, short enough not to pin a dst whose rules
// changed).
//
// Shape: a 4-way set-associative array of atomic entries (128 entries).
// The SYN fast-path lookup is a handful of loads — no locks, no allocations
// (§3.2 hot-path budget; pinned by TestAllocsPerRunZero). Writers are the
// capture hot-loop goroutine; entries are atomics so stray concurrent
// readers (diagnostics, tests) stay race-free. On a full bucket the OLDEST
// entry (lowest insertion tick) is evicted.
const (
	tunnelCacheWays    = 4
	tunnelCacheBuckets = 32 // 4-way → 128 entries
	tunnelCacheTTL     = 60 * time.Second
)

type tunnelEntry struct {
	ip   [4]byte
	port uint16
	exp  atomic.Int64  // unixNano deadline; 0 = free slot
	tick atomic.Uint64 // insertion order (eviction victim choice)
}

type tunnelCache struct {
	ins     atomic.Uint64
	buckets [tunnelCacheBuckets][tunnelCacheWays]tunnelEntry
}

// tunnelCacheHash spreads (ip, port) over the buckets. Pure arithmetic on
// the caller's values — zero allocations.
func tunnelCacheHash(ip [4]byte, port uint16) int {
	h := uint32(ip[0]) | uint32(ip[1])<<8 | uint32(ip[2])<<16 | uint32(ip[3])<<24
	h = (h ^ uint32(port)) * 16777619
	h ^= h >> 16
	return int(h & (tunnelCacheBuckets - 1))
}

// add records dst as tunnel-redial until now+tunnelCacheTTL.
func (c *tunnelCache) add(ip [4]byte, port uint16) {
	b := &c.buckets[tunnelCacheHash(ip, port)]
	now := time.Now().UnixNano()
	tick := c.ins.Add(1)
	var victim *tunnelEntry
	oldest := ^uint64(0)
	for i := range b {
		e := &b[i]
		if e.port == port && e.ip == ip {
			victim = e // refresh in place
			break
		}
		if d := e.exp.Load(); d == 0 || d <= now {
			victim = e // free/expired slot beats eviction
			break
		}
		if t := e.tick.Load(); t < oldest {
			oldest, victim = t, e
		}
	}
	// Key first, deadline last: a torn write can only ever delay a hit,
	// never fake one against a different dst.
	victim.ip = ip
	victim.port = port
	victim.exp.Store(now + int64(tunnelCacheTTL))
	victim.tick.Store(tick)
}

// get reports whether (ip, port) is a cached tunnel-redial destination and
// its deadline has not passed.
func (c *tunnelCache) get(ip [4]byte, port uint16) bool {
	b := &c.buckets[tunnelCacheHash(ip, port)]
	now := time.Now().UnixNano()
	for i := range b {
		if e := &b[i]; e.port == port && e.ip == ip {
			return e.exp.Load() > now
		}
	}
	return false
}
