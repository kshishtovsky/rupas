// Package core is the gobind API surface of the rupas Android core (the
// directory is mobile/, the package name is deliberately `core` so gomobile
// generates the Java class core.Core). This contract is FIXED — the Java
// side is already being coded against it (SYSTEM_DESIGN §3).
//
// W2 scope: TUN transport with all-direct relaying. No rules, desync or
// tunnel yet; the Verdict seam inside internal/transport/android is where
// later waves plug in.
package core

import (
	"encoding/json"
	"errors"
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
}

// coreVersion is the fixed stamp surfaced by Version().
const coreVersion = "0.1.0-w2"

var (
	mu     sync.Mutex
	engine *android.Engine
)

// Start brings the core up on the TUN fd handed over from VpnService.
// Non-blocking: the transport lives in Go goroutines. A second Start
// without Stop returns an error.
func Start(tunFd int, plat Platform) error {
	mu.Lock()
	defer mu.Unlock()
	if engine != nil {
		return errors.New("core: already started (call Stop first)")
	}
	if plat == nil {
		return errors.New("core: nil Platform")
	}
	eng := android.NewEngine(android.W2PolicyVerdict, plat.Protect, plat.Log)
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
}

// Status returns a JSON status string (running, tcp_flows, udp_sessions,
// rx_bytes, tx_bytes).
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
	}
	b, err := json.Marshal(st)
	if err != nil {
		return `{"running":false}`
	}
	return string(b)
}

// Version returns the core version string.
func Version() string { return coreVersion }
