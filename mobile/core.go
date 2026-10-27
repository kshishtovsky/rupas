// Package core is the gobind API surface of the rupas Android core (the
// directory is mobile/, the package name is deliberately `core` so gomobile
// generates the Java class core.Core).
//
// W3 scope: rules (CIDR/SNI/ports/default) + the sing-box tunnel on the
// wave-2 Verdict seam, IPv6 TUN, and the SetSettings(json) call feeding
// the tunnel endpoint. The Start(tunFd, Platform) signature is unchanged —
// the Java side is coded against it (SYSTEM_DESIGN §3).
//
// Routing screen bridge (docs/ROUTING_UI.md §10): RulesJSON / SetRulesJSON
// carry the app's rule list (rules are read at the next Start, the core's
// existing semantics), and TestRoute traces a probe against them.
package core

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"

	"github.com/rupas/rupas/internal/config"
	"github.com/rupas/rupas/internal/geoip"
	"github.com/rupas/rupas/internal/rules"
	"github.com/rupas/rupas/internal/transport/android"
)

// Platform is the reverse-bound interface implemented on the Java side
// (VpnService host). gobind turns it into callbacks into the app.
type Platform interface {
	// Protect removes a socket fd from the VPN (VpnService.protect).
	// The Go dialer calls it for every egress socket it creates; a
	// false return means the socket would loop back into the TUN and
	// the dial is refused.
	Protect(fd int) bool
	// Log receives core log lines for the on-screen log.
	Log(line string)
	// FilesDir is the app-private directory (Context.getFilesDir()) for
	// artifacts that must live on the filesystem (unix sockets). W3.1.
	FilesDir() string
	// ResolveUID returns the UID of the app that owns a flow, or -1 when
	// unknown (API < 29, netd race, SecurityException) — the core then
	// falls back to the shared policy. network is "tcp"/"udp"; the
	// addresses are the packet's source/destination. Called only when
	// per-app rules are configured and only once per new flow
	// (docs/PERAPP_ROUTING.md §2), so it can afford a platform round trip.
	ResolveUID(network string, srcIP string, srcPort int, dstIP string, dstPort int) int
}

// coreVersion is the fixed stamp surfaced by Version().
const coreVersion = "0.1.0-w3"

var (
	mu       sync.Mutex
	engine   *android.Engine
	settings *android.Settings
	// ruleSet is the Routing screen's policy; nil/empty means "compile the
	// built-in W3 preset" (android.DefaultRules).
	ruleSet []config.Rule
	// filesDir is the app-private dir handed over by Start; the geoip cache
	// for TestRoute lives there.
	filesDir string
)

// SetSettings installs the tunnel endpoint description BEFORE Start as
// JSON of the exact shape:
//
//	{"uuid":"…","server":"host","port":443,"sni":"…",
//	 "public_key":"…","short_id":"…","fallback":true}
//
// public_key/short_id switch the endpoint to VLESS+Reality; fallback=true
// allows honest escalation of TUNNEL flows to DIRECT when the tunnel dial
// fails. An empty string clears the settings: the core starts with the
// tunnel unavailable — every TUNNEL-rule flow escalates to direct + log.
//
// Changing settings while the engine is running is refused.
func SetSettings(jsonStr string) error {
	mu.Lock()
	defer mu.Unlock()
	if engine != nil {
		return errors.New("core: cannot change settings while the engine is running (call Stop first)")
	}
	if strings.TrimSpace(jsonStr) == "" {
		settings = nil
		return nil
	}
	s, err := android.ParseSettings(jsonStr)
	if err != nil {
		return err
	}
	settings = s
	// A settings document that carries rules is authoritative for them; an
	// absent/empty `rules` field leaves the policy set through SetRulesJSON
	// untouched (the two channels do not clobber each other).
	if len(s.Rules) > 0 {
		ruleSet = s.Rules
	}
	return nil
}

// Start brings the core up on the TUN fd handed over from VpnService.
// Non-blocking: the transport lives in Go goroutines. A second Start
// without Stop returns an error. The rule set (PRD ru §5) is compiled at
// Start and stays immutable while the engine runs.
func Start(tunFd int, plat Platform) error {
	mu.Lock()
	defer mu.Unlock()
	if engine != nil {
		return errors.New("core: already started (call Stop first)")
	}
	if plat == nil {
		return errors.New("core: nil Platform")
	}
	filesDir = plat.FilesDir()
	eng := android.NewW3EngineWithRules(settings, plat.Protect, plat.Log, filesDir, ruleSet)
	// Per-app routing (docs/PERAPP_ROUTING.md §2): the UID resolver is
	// bound next to Protect/FilesDir. The engine calls it only when the
	// settings carry per-app rules, so a core without them never reaches
	// the platform.
	eng.SetUIDResolver(func(network, srcIP string, srcPort int, dstIP string, dstPort int) int {
		return plat.ResolveUID(network, srcIP, srcPort, dstIP, dstPort)
	})
	if err := eng.Start(tunFd); err != nil {
		return err
	}
	engine = eng
	return nil
}

// Stop shuts the core down. Without a prior Start it returns nil.
func Stop() error {
	mu.Lock()
	eng := engine
	engine = nil
	mu.Unlock()
	if eng == nil {
		return nil
	}
	return eng.Stop()
}

// statusJSON is the exact shape surfaced by Status().
type statusJSON struct {
	Running     bool   `json:"running"`
	TCPFlows    int64  `json:"tcp_flows"`
	UDPSessions int64  `json:"udp_sessions"`
	RxBytes     uint64 `json:"rx_bytes"`
	TxBytes     uint64 `json:"tx_bytes"`
	TCPTotal    uint64 `json:"tcp_total"`
	UDPTotal    uint64 `json:"udp_total"`
	Dropped     uint64 `json:"dropped"`
	// TunnelDials/TunnelEscalated: W3 tunnel accounting; TunnelEscalated
	// counts honestly-marked tunnel→direct degradations.
	TunnelDials     uint64 `json:"tunnel_dials"`
	TunnelEscalated uint64 `json:"tunnel_escalated"`
	// Carriers: the live dial chain (name + active/cooldown/ready per
	// carrier) so the app can show which config is actually in use.
	Carriers []android.CarrierState `json:"carriers,omitempty"`
	// Tunnel: honest tunnel state of the running transport ("off" | "on" |
	// "failed") + reason. The app must not claim protection while every
	// TUNNEL flow escalates to direct.
	Tunnel       string `json:"tunnel"`
	TunnelDetail string `json:"tunnel_detail,omitempty"`
}

// Status returns a JSON status string (running, tcp_flows, udp_sessions,
// rx_bytes, tx_bytes, tcp_total, udp_total, dropped, tunnel_dials,
// tunnel_escalated, carriers — the live dial chain with per-carrier
// active/cooldown/ready state).
func Status() string {
	mu.Lock()
	eng := engine
	mu.Unlock()

	st := statusJSON{}
	st.Tunnel = "off"
	if eng != nil {
		snap := eng.Snapshot()
		st.Running = eng.Running()
		st.TCPFlows = snap.TCPFlows
		st.UDPSessions = snap.UDPSessions
		st.RxBytes = snap.RxBytes
		st.TxBytes = snap.TxBytes
		st.TCPTotal = snap.TCPTotal
		st.UDPTotal = snap.UDPTotal
		st.Dropped = snap.Dropped
		st.TunnelDials = snap.TunnelDials
		st.TunnelEscalated = snap.TunnelEscalated
		st.Carriers = eng.CarrierStates()
		st.Tunnel, st.TunnelDetail = eng.TunnelInfo()
	}
	b, err := json.Marshal(st)
	if err != nil {
		return `{"running":false}`
	}
	return string(b)
}

// Version returns the core version string.
func Version() string { return coreVersion }

// ---------- Routing screen bridge (docs/ROUTING_UI.md §10) ----------

// RulesJSON returns the routing rules the core would compile at the next
// Start, as a JSON array of {cidr,sni,ports,geoip,proto,action}. When no
// rules were installed it returns the built-in W3 preset, so the screen always
// shows the policy that is actually in effect.
func RulesJSON() string {
	mu.Lock()
	rs := ruleSet
	if len(rs) == 0 && settings != nil {
		rs = settings.Rules
	}
	mu.Unlock()
	if len(rs) == 0 {
		rs = android.DefaultRules()
	}
	b, err := json.Marshal(rs)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// SetRulesJSON replaces the routing rules with a JSON array of
// {cidr,sni,ports,geoip,proto,action} objects. The array is validated with the
// engine's own validators (an invalid set is refused with the rule index in
// the message). Rules are compiled at Start, so — like SetSettings — a change
// requires a restart: while the engine runs this returns an error. An empty
// string clears the policy back to the built-in preset.
func SetRulesJSON(jsonRules string) error {
	mu.Lock()
	defer mu.Unlock()
	if engine != nil {
		return errors.New("core: cannot change rules while the engine is running (call Stop first)")
	}
	if strings.TrimSpace(jsonRules) == "" {
		ruleSet = nil
		if settings != nil {
			settings.Rules = nil
		}
		return nil
	}
	rs, err := config.ParseRulesJSON([]byte(jsonRules))
	if err != nil {
		return err
	}
	ruleSet = rs
	if settings != nil {
		settings.Rules = rs
	}
	return nil
}

// traceError is the shape returned by TestRoute when the probe cannot be
// resolved (bad rules, empty query). The Java side checks for "error".
type traceError struct {
	Error string `json:"error"`
}

// TestRoute resolves a probe ("youtube.com", "8.8.8.8", "1.2.3.4:443") against
// the rules the core would compile and returns the Trace as JSON
// ({stage,stageName,matcher,action,note}). Geoip rules are expanded from the
// cached country table in the app's files dir; a missing table is reported in
// the note, never downloaded.
func TestRoute(query string) string {
	mu.Lock()
	rs := ruleSet
	if len(rs) == 0 && settings != nil {
		rs = settings.Rules
	}
	dir := filesDir
	mu.Unlock()
	if len(rs) == 0 {
		rs = android.DefaultRules()
	}
	tr, err := rules.TestRouteWithGeo(rs, query, geoipParams(dir))
	if err != nil {
		b, _ := json.Marshal(traceError{Error: err.Error()})
		return string(b)
	}
	b, err := json.Marshal(tr)
	if err != nil {
		b, _ = json.Marshal(traceError{Error: err.Error()})
	}
	return string(b)
}

// geoipParams points the tracer at the app-private geoip cache.
func geoipParams(dir string) geoip.Params {
	if dir == "" {
		return geoip.Params{} // no cache dir: geoip rules stay a note
	}
	return geoip.Params{Dir: dir}
}
