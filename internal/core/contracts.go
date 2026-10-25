// Package core defines cross-module contracts shared by capture, desync,
// supervisor and rpc. Keep it tiny and dependency-free: types and interfaces
// only, no logic.
package core

import "time"

// Verdict is what the hot path decided for a flow.
type Verdict uint8

const (
	VerdictPass     Verdict = iota // re-inject untouched
	VerdictDesync                  // DPI desync applied (fake/split/...)
	VerdictRedirect                // NAT-redirected to local tproxy
	VerdictDrop                    // administratively dropped
)

// Snapshot is the point-in-time status exposed to rpc/CLI/GUI.
// Supervisor owns the authoritative copy behind an atomic pointer.
type Snapshot struct {
	State         string // OFF|PROBING|ACTIVE|ACTIVE_TUNNEL_ONLY|DEGRADED
	Since         time.Time
	ProfileID     string
	TunnelHealthy bool
	// Tunnel is the live tunnel-branch status rendered by `rupasctl
	// status` (nil when the tunnel branch is not assembled).
	Tunnel   *TunnelStatus
	Flows    map[string]int64 // state -> count
	Counters Counters
}

// TunnelStatus is the tunnel-branch section of the status (§3.3/§6):
// health, mode, relayed bytes, flows and honest drop counters.
type TunnelStatus struct {
	// Mode is how TUNNEL-rule flows are currently served:
	//   "tunnel"     — NAT → tproxy → VLESS+Reality relay
	//   "escalated"  — no usable endpoint: SNI rules → DESYNC fallback,
	//                  CIDR/port rules → DIRECT (logged + counted)
	//   "off"        — tunnel branch disabled (-tunnel=off)
	Mode    string `json:"mode"`
	Healthy bool   `json:"healthy"`
	// Held: marker failed 3× — new flows dropped (not escalated to direct).
	Held bool `json:"held"`
	// RxBytes/TxBytes: payload bytes relayed through the tunnel.
	RxBytes uint64 `json:"rx_bytes"`
	TxBytes uint64 `json:"tx_bytes"`
	// TCPFlows: active TCP relays; TCPConns: total redirected flows.
	TCPFlows int64 `json:"tcp_flows"`
	TCPConns int64 `json:"tcp_conns"`
	// UDPSessions: live UDP pseudo-sessions; UDPDgrams: total datagrams.
	UDPSessions int64  `json:"udp_sessions"`
	UDPDgrams   uint64 `json:"udp_dgrams"`
	// UDPHealthy/UDPFallback (wave 7): voice-relay observability.
	// UDPHealthy mirrors the periodic UDP endpoint probe (false = probe
	// failed — voice likely down); UDPFallback reports whether datagrams
	// are currently escaping via the DESYNC fallback path.
	UDPHealthy  bool `json:"udp_healthy"`
	UDPFallback bool `json:"udp_fallback"`
	// Dropped: flows/datagrams refused (no orig-dst, dial failure, HOLD).
	Dropped uint64 `json:"dropped"`
	// EscalatedRules: TUNNEL rules rewritten by the escalation fallback.
	EscalatedRules int `json:"escalated_rules"`
}

type Counters struct {
	PacketsTotal  uint64
	PacketsPass   uint64
	PacketsDesync uint64
	PacketsRedir  uint64
	PacketsDrop   uint64
	HandshakeOK   uint64
	HandshakeFail uint64
	TunnelRx      uint64
	TunnelTx      uint64
	LastProbeAt   time.Time
	LastProbeNote string
}

// StatusSource is implemented by supervisor and consumed by rpc.
type StatusSource interface {
	Snapshot() Snapshot
}

// Lifecycle events supervisor subscribes to.
type Event uint8

const (
	EventNetChange   Event = iota // default route / NIC set changed
	EventResume                   // power resume
	EventDegradation              // passive detector threshold tripped
	EventProbeDone                // prober finished a cycle
)

// EventSink is implemented by supervisor; capture/prober push events.
type EventSink interface {
	Notify(ev Event, note string)
}
