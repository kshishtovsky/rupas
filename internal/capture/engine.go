//go:build windows

package capture

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/rupas/rupas/internal/config"
	"github.com/rupas/rupas/internal/core"
	"github.com/rupas/rupas/internal/desync"
	"github.com/rupas/rupas/internal/flowtable"
	"github.com/rupas/rupas/internal/inspector"
	"github.com/rupas/rupas/internal/rules"
	"github.com/rupas/rupas/pkg/windivert"
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
	gcTick            = time.Second
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
	BatchSize    int                 // recv batch slots; 0 = 64
	PacketSize   int                 // per-slot buffer; 0 = 65575
	FlowIdleTTL  time.Duration       // flow GC idle timeout; 0 = 5 min
	SniffMode    bool                // open real handles with FlagSniff (diagnostics only)
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
	ownsTransport bool

	streams    map[flowtable.FlowKey]*inspector.Stream
	streamMu   sync.Mutex // guards streams (main loop writes; cleanup from both loops)
	streamPool sync.Pool
	nat        map[natKey]*flowtable.Flow
	natMu      sync.RWMutex // guards nat (main inserts; loopback lookups/deletes)

	// ClientHello hold buffers (winws parity, wave 4A): partial CH
	// segments are held until the inspector reaches a verdict so the
	// fakes can precede the FIRST real segment on the wire.
	holds    map[flowtable.FlowKey]*chHold
	holdPool sync.Pool

	batches sync.Pool // *batchBuf
	scratch sync.Pool // *[]byte

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
		nat:      make(map[natKey]*flowtable.Flow),
		stop:     make(chan struct{}),
		runDone:  make(chan struct{}),
		loopDone: make(chan struct{}),
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

// Counters returns a point-in-time snapshot of the engine counters.
func (e *Engine) Counters() core.Counters { return e.cnt.snapshot() }

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

	err := e.recvLoop(ctx, main)
	cancel() // unblocks the loopback goroutine and the sweeper
	<-e.loopDone
	<-sweepDone
	return err
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
		e.loopTransport = NewWinTransport(lh)
	}
	return nil
}

func (e *Engine) closeTransports() {
	e.mu.Lock()
	t, l := e.transport, e.loopTransport
	e.transport, e.loopTransport = nil, nil
	e.mu.Unlock()
	if t != nil {
		_ = t.Close()
	}
	if l != nil {
		_ = l.Close()
	}
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

	// Hard connection teardown: clean up and forward (tunnel flows still
	// need the NAT rewrite so the tproxy sees the close).
	if p.rst() || p.fin() {
		if f, ok := e.flows.Get(key); ok {
			if f.State.Load() == flowtable.FlowTunnel {
				e.natOutbound(pkt, p, key, f, addr)
			} else {
				e.passVerdict(pkt, addr, core.VerdictPass)
			}
			e.cleanupFlow(natKey{ip: v4mapped(p.src4), port: p.srcPort, proto: p.proto}, key)
			return
		}
		e.passVerdict(pkt, addr, core.VerdictPass)
		return
	}

	// SYN (no ACK): create the flow. A SYN retransmission of a flow that
	// already went TUNNEL is re-redirected (§3.2: "next SYN via redirect").
	if p.syn() && !p.ack() {
		f := e.flows.GetOrCreate(key)
		f.TouchSyn()
		f.ClientISN = p.seq // wave 4A: fake CH builds on ISN+1 (winws parity)
		if f.State.Load() == flowtable.FlowTunnel {
			e.natOutbound(pkt, p, key, f, addr)
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
			e.natOutbound(pkt, p, key, f, addr)
		case flowtable.FlowDirect, flowtable.FlowDesynced, flowtable.FlowEstablished:
			e.passVerdict(pkt, addr, core.VerdictPass)
		default: // FlowNew: first(ish) data segment → ClientHello pipeline
			e.inspectClientHello(pkt, addr, p, key, f)
		}
		return
	}

	// Pure ACK / window probe.
	if f, ok := e.flows.Get(key); ok && f.State.Load() == flowtable.FlowTunnel {
		e.natOutbound(pkt, p, key, f, addr)
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
		e.releaseHeld(held)
		e.passVerdict(pkt, addr, core.VerdictPass)
		return
	}
	f.ECH = res.ECH

	action := e.rules.Match(v4mapped(p.dst4), unsafeString(res.SNI), p.dstPort)
	if res.ECH {
		// Encrypted Client Hello: desync is pointless (lab: Schannel-ECH
		// не пробивается) — route to the tunnel instead.
		action = config.ActionTunnel
	}

	switch action {
	case config.ActionDirect:
		f.State.Store(flowtable.FlowDirect)
		e.releaseHeld(held)
		e.passVerdict(pkt, addr, core.VerdictPass)
	case config.ActionDesync:
		e.applyDesync(pkt, p, addr, res.SNI, held)
		f.State.Store(flowtable.FlowDesynced)
	default: // ActionTunnel (and any invalid value): NAT-redirect
		f.State.Store(flowtable.FlowTunnel)
		e.natHeld(held, key, f)
		e.natOutbound(pkt, p, key, f, addr)
	}
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

// natHeld applies the tunnel NAT-redirect to held segments (cold path,
// re-parses each segment).
func (e *Engine) natHeld(h *chHold, key flowtable.FlowKey, f *flowtable.Flow) {
	if h == nil {
		return
	}
	for i := 0; i < h.n; i++ {
		if p, ok := parsePkt(h.seg(i)); ok {
			e.natOutbound(h.seg(i), &p, key, f, &h.addr[i])
		} else {
			e.passVerdict(h.seg(i), &h.addr[i], core.VerdictPass)
		}
	}
	e.putHold(h)
}

func (e *Engine) putHold(h *chHold) {
	h.reset()
	e.holdPool.Put(h)
}

// processUDP applies the tunnel branch to UDP relay traffic (ADR-5): no
// inspector, rules decide by CIDR/port; TUNNEL → NAT, everything else passes.
func (e *Engine) processUDP(pkt []byte, addr *windivert.Address, p *pktInfo) {
	key := flowKeyOut(p)
	action := e.rules.Match(v4mapped(p.dst4), "", p.dstPort)
	if action != config.ActionTunnel {
		e.passVerdict(pkt, addr, core.VerdictPass)
		return
	}
	f := e.flows.GetOrCreate(key)
	f.State.Store(flowtable.FlowTunnel)
	e.natOutbound(pkt, p, key, f, addr)
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
			e.cleanupFlow(natKey{ip: key.SrcIP, port: key.SrcPort, proto: p.proto}, key)
		}
	}
	e.passVerdict(pkt, addr, core.VerdictPass)
}

// passVerdict counts and re-injects a packet untouched.
func (e *Engine) passVerdict(pkt []byte, addr *windivert.Address, v core.Verdict) {
	e.cnt.countVerdict(v)
	if err := e.transport.Send(pkt, addr); err != nil {
		e.cnt.sendErrors.Add(1)
	}
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

// BuildLoopbackFilter renders the second handle's filter: inbound replies of
// the tproxy listener (SYSTEM_DESIGN §3.3). Both TCP and UDP responses carry
// source 127.0.0.1:tproxyPort.
func BuildLoopbackFilter(tproxyPort uint16) (string, error) {
	tcpF, err := windivert.NewFilter().Inbound().TCP().SrcCIDRs("127.0.0.1/32").SrcPorts(tproxyPort).Build()
	if err != nil {
		return "", err
	}
	udpF, err := windivert.NewFilter().Inbound().UDP().SrcCIDRs("127.0.0.1/32").SrcPorts(tproxyPort).Build()
	if err != nil {
		return "", err
	}
	return "(" + tcpF + ") or (" + udpF + ")", nil
}
