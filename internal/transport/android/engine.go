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

	"github.com/rupas/rupas/internal/config"
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
	// endpoints: settings.Endpoints() parsed once at construction — the
	// flow-entry path (isEndpoint) must not re-parse every share link.
	endpoints []Endpoint
	// preferIPv4: PreferIPv4 mode (default ON) — v6 flows fast-dropped,
	// DNS AAAA answered empty (dns4.go). Disabled by settings prefer_ipv4=false.
	preferIPv4 bool
	// adblock: the compiled ads/trackers matcher (adblock.go), nil when the
	// filter is off. adblockDetail carries the compile failure for Status().
	adblock       *Adblock
	adblockDetail string
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
	// uidResolve is the platform UID resolver (Platform.ResolveUID), nil on
	// the dev host and in tests. Consulted once per new flow, and only when
	// per-app rules are compiled (docs/PERAPP_ROUTING.md §2).
	uidResolve UIDResolver
	// tunnel is the honest tunnel state set once per transport run in tun.go
	// (read from the UI thread, written from the transport goroutine).
	tunnel atomic.Pointer[tunnelInfo]

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
// to DIRECT (counted + logged) instead of failing. Routing rules come from
// settings.Rules when present, else from the W3 preset (DefaultRules).
func NewW3Engine(settings *Settings, protect ProtectFunc, logFn func(string), filesDir string) *Engine {
	return NewW3EngineWithRules(settings, protect, logFn, filesDir, nil)
}

// NewW3EngineWithRules is NewW3Engine with an explicit rule set: ruleSet (the
// app's Routing screen) wins over settings.Rules, and both being empty falls
// back to DefaultRules. Rules and tunnel settings stay independent inputs, so
// a core can run user rules with no endpoint configured.
//
// Per-app rules (settings.AppRules) compile into their own UID table and
// outrank every rule stage (docs/PERAPP_ROUTING.md §3).
func NewW3EngineWithRules(settings *Settings, protect ProtectFunc, logFn func(string), filesDir string, ruleSet []config.Rule) *Engine {
	e := NewEngine(nil, protect, logFn)
	e.settings = settings
	if len(ruleSet) == 0 && settings != nil {
		ruleSet = settings.Rules
	}
	var appRules []AppRule
	if settings != nil {
		appRules = settings.AppRules
	}
	e.rules = CompileRulesWithApps(ruleSet, appRules, filesDir, func(line string) { e.logf("%s", line) })
	e.filesDir = filesDir
	if settings != nil {
		e.relay = NewRelay(settings, func(line string) { e.logf("%s", line) })
		e.preferIPv4 = settings.PreferIPv4Enabled()
		// Parsed here, once: isEndpoint runs 2-3× per flow. A parse error
		// leaves the slice empty (isEndpoint false) — ParseSettings has
		// already validated the links, so this is belt-and-braces.
		if eps, err := settings.Endpoints(); err == nil {
			e.endpoints = eps
		}
		e.initAdblock(settings.Adblock)
	}
	return e
}

// initAdblock compiles the filter once per engine and logs the single start
// line: a silent "on" over a broken list is the failure this guards against.
func (e *Engine) initAdblock(cfg *AdblockSettings) {
	if cfg == nil {
		return
	}
	a, err := compileAdblock(cfg)
	switch {
	case err != nil:
		e.adblockDetail = err.Error()
		e.logf("adblock failed: %v", err)
	case a == nil:
		e.logf("adblock off: ads=false trackers=false")
	default:
		e.adblock = a
		e.logf("adblock on: ads=%d trackers=%d enabled=%s whitelist=%d",
			a.AdsCount(), a.TrackersCount(), a.EnabledNames(), a.WhitelistCount())
	}
}

// AdblockState reports the filter for Status(): "on" | "off" | "failed" plus
// the failure reason and the compiled list sizes. "on" means at least one
// list compiled — never a claim the core cannot back.
func (e *Engine) AdblockState() (state, detail string, ads, trackers int) {
	switch {
	case e.adblockDetail != "":
		return "failed", e.adblockDetail, 0, 0
	case e.adblock == nil:
		return "off", "", 0, 0
	default:
		return "on", "", e.adblock.AdsCount(), e.adblock.TrackersCount()
	}
}

// UIDResolver resolves the owning app UID of a new flow; it is the Go face of
// Platform.ResolveUID (Java's ConnectivityManager.getConnectionOwnerUid). A
// non-positive return means "unknown".
type UIDResolver func(network string, srcIP string, srcPort int, dstIP string, dstPort int) int

// SetUIDResolver installs the platform UID resolver. Call it before Start:
// per-app rules without a resolver degrade honestly — flows carry UID 0 and
// follow the shared policy (the UI shows the warning).
func (e *Engine) SetUIDResolver(r UIDResolver) { e.uidResolve = r }

// resolveUID returns the app UID of a new flow, or 0 when it is unknown.
//
// It is deliberately free unless the feature is in use: with no per-app rules
// compiled — or no resolver installed — it returns 0 without touching the
// platform, so an unconfigured core pays one nil/bool compare per flow and
// zero JNI calls. Called once per flow (JudgeFlow for UDP, the head of
// relayTCP for TCP), never per packet.
func (e *Engine) resolveUID(m FlowMeta) int {
	if e.uidResolve == nil || e.rules == nil || !e.rules.hasAppRules() {
		return 0
	}
	src, dst := m.Source, m.Destination
	uid := e.uidResolve(m.Network, src.Addr().Unmap().String(), int(src.Port()),
		dst.Addr().Unmap().String(), int(dst.Port()))
	if uid <= 0 {
		// Platform -1/0: the socket is not owned yet (netd race) or the
		// caller is invisible. Honest degradation, no retry (§7.4).
		return 0
	}
	return uid
}

// Settings returns the tunnel settings the engine was built with.
func (e *Engine) Settings() *Settings { return e.settings }

// Rules returns the compiled rule table (immutable).
func (e *Engine) Rules() *Rules { return e.rules }

// isEndpoint reports whether a flow is destined to one of the tunnel
// endpoints themselves (IP:port or camouflage SNI). Endpoint traffic must
// NEVER be looped into the tunnel relay.
func (e *Engine) isEndpoint(m FlowMeta) bool {
	if len(e.endpoints) == 0 {
		return false
	}
	addrStr := m.Destination.Addr().String()
	for n, ep := range e.endpoints {
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

// decide maps a flow onto an action: a per-app UID rule first (the most
// specific stage, docs/PERAPP_ROUTING.md §3), then W3 rules when compiled
// (they take SNI/ECH from FlowMeta), otherwise the wave-2 verdict seam.
func (e *Engine) decide(m FlowMeta) Action {
	if e.isEndpoint(m) {
		return ActionDirect
	}
	if a, ok := e.appAction(m); ok {
		return a
	}
	// Adblock outranks the routing table: a blocked name never gets an
	// egress socket, whatever the rules would say about its address.
	if a := e.adblock; a != nil && m.SNI != "" {
		if list, blocked := a.Match(m.SNI); blocked {
			e.counters.AdblockSNI()
			e.logf("adblock: %s (sni, %s)", m.SNI, list)
			return ActionBlock
		}
	}
	if e.rules != nil {
		return e.rules.Decide(m)
	}
	return e.verdict(m)
}

// decidePre is DecidePre for engines without compiled rules (wave-2): the
// verdict is always final and never needs the ClientHello. Like decide it
// applies the per-app rule first, and such a decision is always final: an app
// rule outranks SNI, so no ClientHello is needed.
func (e *Engine) decidePre(m FlowMeta) (Action, bool) {
	if e.isEndpoint(m) {
		return ActionDirect, true
	}
	if a, ok := e.appAction(m); ok {
		return a, true
	}
	if e.rules != nil {
		return e.rules.DecidePre(m)
	}
	return e.verdict(m), true
}

// appAction resolves the per-app rule for a flow. The cost when the feature is
// unused is one UID compare plus one nil-map branch; when used it is a single
// int-keyed map lookup — zero allocation either way. The check lives here
// rather than in Rules.Decide, so the hot MatchProto path is untouched.
func (e *Engine) appAction(m FlowMeta) (Action, bool) {
	if e.rules == nil || m.UID <= 0 {
		return ActionDirect, false
	}
	return e.rules.appAction(m.UID)
}

// logAppRule writes the one log line for a flow decided by a per-app rule
// (docs/PERAPP_ROUTING.md §8.5): "app uid=10086 → TUNNEL". The flow entry
// points call it once, so a flow logs once and packets never log at all.
func (e *Engine) logAppRule(m FlowMeta) {
	if a, ok := e.appAction(m); ok {
		e.logf("app uid=%d → %s", m.UID, a)
	}
}

// fallbackAllowed reports whether TUNNEL flows may escalate to DIRECT.
// No settings (tunnel unconfigured) → yes, per the W3 contract; explicit
// settings honour the fallback flag.
func (e *Engine) fallbackAllowed() bool {
	return e.settings == nil || e.settings.Fallback
}

// tunnelInfo is the tunnel state the transport run ended up in. The app shows
// it as-is: a core whose TUNNEL rules all escalate to direct must never be
// presented as "protected" (that is how a misconfigured device silently
// blackholes Telegram while YouTube keeps working).
type tunnelInfo struct {
	state  string // "off" | "on" | "failed"
	detail string // human-readable reason; never carries uuid/keys
}

// setTunnel records the state and logs it once per run.
func (e *Engine) setTunnel(state, detail string) {
	e.tunnel.Store(&tunnelInfo{state: state, detail: detail})
	e.logf("tunnel %s: %s", state, detail)
}

// TunnelInfo reports the run's tunnel state and its reason. Before Start (or
// on an engine built without settings) it is "off".
func (e *Engine) TunnelInfo() (string, string) {
	if t := e.tunnel.Load(); t != nil {
		return t.state, t.detail
	}
	if e.settings == nil {
		return "off", "no endpoint settings"
	}
	return "off", "engine not started"
}

// tunnelCarrierCount counts the real tunnel carriers — "direct" is the
// escalation tail, not a carrier.
func (e *Engine) tunnelCarrierCount() int {
	n := 0
	for _, c := range e.carriers {
		if c.name != "direct" {
			n++
		}
	}
	return n
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
			st, detail := e.TunnelInfo()
			e.logf("tcp %s: tunnel unavailable (%s: %s)", m.Destination, st, detail)
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
