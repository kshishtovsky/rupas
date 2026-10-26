// Package core is the gobind API surface of the rupas Android core (the
// directory is mobile/, the package name is deliberately `core` so gomobile
// generates the Java class core.Core).
//
// W3 scope: rules (CIDR/SNI/ports/default) + the sing-box tunnel on the
// wave-2 Verdict seam, IPv6 TUN, and the SetSettings(json) call feeding
// the tunnel endpoint. The Start(tunFd, Platform) signature is unchanged —
// the Java side is coded against it (SYSTEM_DESIGN §3).
package core

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"

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
}

// coreVersion is the fixed stamp surfaced by Version().
const coreVersion = "0.1.0-w3"

var (
	mu       sync.Mutex
	engine   *android.Engine
	settings *android.Settings
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
	eng := android.NewW3Engine(settings, plat.Protect, plat.Log, plat.FilesDir())
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
	TunnelDials     uint64                `json:"tunnel_dials"`
	TunnelEscalated uint64                `json:"tunnel_escalated"`
	// Carriers: the live dial chain (name + active/cooldown/ready per
	// carrier) so the app can show which config is actually in use.
	Carriers []android.CarrierState `json:"carriers,omitempty"`
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
	}
	b, err := json.Marshal(st)
	if err != nil {
		return `{"running":false}`
	}
	return string(b)
}

// Version returns the core version string.
func Version() string { return coreVersion }
