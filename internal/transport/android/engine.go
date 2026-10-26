package android

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Engine owns one TUN-backed transport session. It is created per Start and
// parked under the mobile/ package's lifecycle guard. Start is non-blocking:
// run (platform-specific) executes in a goroutine and shuts down on
// Stop/context cancel.
type Engine struct {
	verdict  Verdict
	protect  ProtectFunc
	logFn    func(string)
	dialer   *net.Dialer
	counters Counters

	// W3: compiled rule tables and the sing-box tunnel relay. rules win
	// over verdict; a nil relay (or an unavailable one) escalates TUNNEL
	// flows per the settings' fallback flag.
	settings *Settings
	rules    *Rules
	relay    *Relay
	// preferIPv4: PreferIPv4 mode (default ON) — v6 flows fast-dropped,
	// DNS AAAA answered empty (dns4.go). Disabled by settings prefer_ipv4=false.
	preferIPv4 bool
	// carriers: the TUNNEL dial chain (relay inbounds + own xhttp client),
	// built after the relay starts (buildCarriers from engine_chain.go).
	carriers []tcpCarrier
	// health: per-carrier failure cooldowns, same length/order as carriers
	// (engine_chain.go carrierHealth).
	health []carrierHealth
	// activeIdx: dial-chain index of the carrier that delivered the last
	// payload (markCarrierSuccess); surfaced to the UI via CarrierStates.
	activeIdx atomic.Int64
	// filesDir: app-private dir (from Platform.FilesDir) where the relay
	// creates its protect unix-socket file. Empty on the dev host.
	filesDir string

	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc
	done    chan struct{}
}

// NewEngine assembles an engine. verdict is the wave-2 seam (pass
// DirectVerdict for the current all-direct behaviour); protect is called
// inside dialer Control hooks with the raw socket fd; logFn receives
// transport log lines (nil-safe: drops them).
func NewEngine(verdict Verdict, protect ProtectFunc, logFn func(string)) *Engine {
	if verdict == nil {
		verdict = DirectVerdict
	}
	if logFn == nil {
		logFn = func(string) {}
	}
	return &Engine{
		verdict:    verdict,
		protect:    protect,
		logFn:      logFn,
		dialer:     ProtectedDialer(protect),
		preferIPv4: true, // default ON; settings may disable explicitly
	}
}

// NewW3Engine assembles a W3 engine: the PRD §5 rule tables are compiled
// immediately (immutable), and settings drive the sing-box tunnel relay.
// nil settings mean "tunnel unavailable": every TUNNEL-rule flow escalates
// to DIRECT (counted + logged) instead of failing.
func NewW3Engine(settings *Settings, protect ProtectFunc, logFn func(string), filesDir string) *Engine {
	e := NewEngine(nil, protect, logFn)
	e.settings = settings
	e.rules = CompileRulesEx(filesDir, func(line string) { e.logf("%s", line) })
	e.filesDir = filesDir
	if settings != nil {
		e.relay = NewRelay(settings, func(line string) { e.logf("%s", line) })
		e.preferIPv4 = settings.PreferIPv4Enabled()
	}
	return e
}

// Settings returns the tunnel settings the engine was built with.
func (e *Engine) Settings() *Settings { return e.settings }

// Rules returns the compiled rule table (immutable).
func (e *Engine) Rules() *Rules { return e.rules }

// isEndpoint reports whether a flow is destined to one of the tunnel
// endpoints themselves (IP:port or camouflage SNI). Endpoint traffic must
// NEVER be looped into the tunnel relay.
func (e *Engine) isEndpoint(m FlowMeta) bool {
	if e.settings == nil {
		return false
	}
	eps, err := e.settings.Endpoints()
	if err != nil || len(eps) == 0 {
		return false
	}
	addrStr := m.Destination.Addr().String()
	for n, ep := range eps {
		if ep.Port > 0 && m.Destination.Port() == ep.Port && addrStr == ep.Host {
			return true
		}
		if e.relay != nil && e.relay.resolvedServer != "" &&
			n < len(e.relay.endpoints) && ep.Host == e.relay.endpoints[0].Host &&
			m.Destination.Port() == ep.Port && addrStr == e.relay.resolvedServer {
			return true
		}
		if m.SNI != "" {
			if ep.SNI != "" && strings.EqualFold(m.SNI, ep.SNI) {
				return true
			}
			if strings.EqualFold(m.SNI, ep.Host) {
				return true
			}
		}
	}
	return false
}

// decide maps a flow onto an action: W3 rules when compiled (they take
// SNI/ECH from FlowMeta), otherwise the wave-2 verdict seam.
func (e *Engine) decide(m FlowMeta) Action {
	if e.isEndpoint(m) {
		return ActionDirect
	}
	if e.rules != nil {
		return e.rules.Decide(m)
	}
	return e.verdict(m)
}

// decidePre is DecidePre for engines without compiled rules (wave-2): the
// verdict is always final and never needs the ClientHello.
func (e *Engine) decidePre(m FlowMeta) (Action, bool) {
	if e.isEndpoint(m) {
		return ActionDirect, true
	}
	if e.rules != nil {
		return e.rules.DecidePre(m)
	}
	return e.verdict(m), true
}

// fallbackAllowed reports whether TUNNEL flows may escalate to DIRECT.
// No settings (tunnel unconfigured) → yes, per the W3 contract; explicit
// settings honour the fallback flag.
func (e *Engine) fallbackAllowed() bool {
	return e.settings == nil || e.settings.Fallback
}

// dialEgress opens the egress connection for one flow according to its
// action: DIRECT via the protected dialer, TUNNEL through the relay with
// honest escalation, BLOCK refused. escalated reports that the flow was
// originally TUNNEL but fell back to direct/drop.
func (e *Engine) dialEgress(ctx context.Context, m FlowMeta) (conn net.Conn, escalated bool, err error) {
	switch e.decide(m) {
	case ActionBlock:
		return nil, false, errFlowBlocked
	case ActionTunnel:
		e.counters.TunnelDial()
		if len(e.carriers) > 0 {
			c, dErr := e.dialChain(m.Destination)
			if dErr == nil {
				return c, false, nil
			}
			e.logf("tcp %s: tunnel dial failed: %v", m.Destination, dErr)
		} else {
			e.logf("tcp %s: tunnel unavailable (no endpoint settings)", m.Destination)
		}
		e.counters.TunnelEscalate()
		if !e.fallbackAllowed() {
			return nil, true, fmt.Errorf("android: tunnel dial failed and fallback is disabled")
		}
		e.logf("tcp %s: ESCALATED tunnel->direct (counter honest)", m.Destination)
		c, dErr := e.dialer.DialContext(ctx, "tcp", m.Destination.String())
		return c, true, dErr
	default: // ActionDirect
		c, dErr := e.dialer.DialContext(ctx, "tcp", m.Destination.String())
		return c, false, dErr
	}
}

// Start launches the transport on a Java-owned TUN fd. Non-blocking; a
// second Start without Stop returns an error.
func (e *Engine) Start(fd int) error {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return errors.New("android: engine already running (call Stop first)")
	}
	if fd <= 0 {
		e.mu.Unlock()
		return errors.New("android: invalid tun fd")
	}
	e.running = true
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.done = make(chan struct{})
	done := e.done
	// Unlock BEFORE returning: e.mu guards lifecycle fields only. Holding it
	// across the return deadlocks Status()/Stop() (sync.Mutex не реентерабелен —
	// тот же поток повиснет на повторном захвате; главный поток Java = ANR).
	e.mu.Unlock()

	go func() {
		defer close(done)
		// A Go panic in the transport goroutine aborts the whole app
		// (gomobile has no recover seam). Dump the stack through the log
		// seam so the failure is diagnosable on-device, then re-panic.
		defer func() {
			if r := recover(); r != nil {
				e.logf("PANIC in transport: %v\n%s", r, debug.Stack())
				panic(r)
			}
		}()
		if err := e.run(ctx, fd); err != nil && ctx.Err() == nil {
			e.logf("transport exited: %v", err)
		}
	}()
	return nil
}

// Stop shuts the transport down. Without a prior Start it is a no-op
// returning nil (matches the mobile contract). The wait for the transport
// goroutine is bounded: this may be called from the Java main thread, and an
// unbounded join there is an ANR.
func (e *Engine) Stop() error {
	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return nil
	}
	cancel := e.cancel
	done := e.done
	e.running = false
	e.cancel = nil
	e.done = nil
	e.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		// Transport is still draining; it will exit on its own (ctx is
		// cancelled). Do not block the caller any longer.
		return fmt.Errorf("android: transport stop timed out after 3s (exiting in background)")
	}
	return nil
}

// Running reports whether the engine was started and not yet stopped.
func (e *Engine) Running() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running
}

// Snapshot returns the transport counters.
func (e *Engine) Snapshot() StatusSnapshot { return e.counters.Snapshot() }

func (e *Engine) logf(format string, args ...any) {
	e.logFn("android: " + fmt.Sprintf(format, args...))
}

func (e *Engine) logln(args ...any) {
	e.logFn("android: " + strings.TrimSuffix(fmt.Sprintln(args...), "\n"))
}

// pump copies one direction of a TCP relay and adds the payload bytes to
// the matching counter (rx: app→internet, tx: internet→app).
func (e *Engine) pump(dst, src net.Conn, add func(int64)) {
	n, _ := copyConn(dst, src)
	add(n)
}

// relayBufPool recycles the 16 KiB relay buffers. On Android every TCP flow
// allocates two of them (one per direction); browsers open hundreds of flows,
// so pooling removes megabytes of steady-state garbage per session.
var relayBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 16*1024)
		return &b
	},
}

// copyConn copies src→dst with a 16 KiB buffer (comfortably above the TUN
// MTU, so MTU-sized netstack reads complete in one write).
func copyConn(dst, src net.Conn) (int64, error) {
	bufp := relayBufPool.Get().(*[]byte)
	defer relayBufPool.Put(bufp)
	buf := *bufp
	var total int64
	for {
		n, rErr := src.Read(buf)
		if n > 0 {
			written, wErr := dst.Write(buf[:n])
			total += int64(written)
			if wErr != nil {
				return total, wErr
			}
		}
		if rErr != nil {
			return total, rErr
		}
	}
}
