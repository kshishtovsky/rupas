package android

import (
	"sync/atomic"
)

// Counters is the Android transport's own accounting (decoupled from
// core.Counters on purpose: this layer runs inside the AAR without the
// Windows supervisor). All fields are atomic — the hot path is concurrent.
//
// Rx counts payload bytes app→internet (read from the netstack, written to
// the egress socket); Tx counts internet→app. Active gauges are negative-
// safe; drops are non-blocking refusals (dial failure / protect failure).
type Counters struct {
	rxBytes           atomic.Uint64
	txBytes           atomic.Uint64
	tcpFlowsActive    atomic.Int64
	tcpFlowsTotal     atomic.Uint64
	udpSessionsActive atomic.Int64
	udpSessionsTotal  atomic.Uint64
	drops             atomic.Uint64
	tunnelDials       atomic.Uint64
	tunnelEscalations atomic.Uint64
}

// StatusSnapshot is a point-in-time copy for Status()/gobind.
type StatusSnapshot struct {
	TCPFlows    int64  `json:"tcp_flows"`
	UDPSessions int64  `json:"udp_sessions"`
	RxBytes     uint64 `json:"rx_bytes"`
	TxBytes     uint64 `json:"tx_bytes"`
	// TCPTotal/UDPTotal: cumulative flows/sessions since Start.
	TCPTotal uint64 `json:"tcp_total"`
	UDPTotal uint64 `json:"udp_total"`
	// Dropped: flows refused before any byte was relayed.
	Dropped uint64 `json:"dropped"`
	// TunnelDials: flows handed to the tunnel relay. TunnelEscalated:
	// flows whose tunnel dial failed and were honestly escalated to
	// DIRECT (or dropped when fallback is disabled).
	TunnelDials     uint64 `json:"tunnel_dials"`
	TunnelEscalated uint64 `json:"tunnel_escalated"`
}

// AddRx/AddTx record relayed payload bytes.
func (c *Counters) AddRx(n int64) {
	if n > 0 {
		c.rxBytes.Add(uint64(n))
	}
}

// AddTx is the reverse direction of AddRx.
func (c *Counters) AddTx(n int64) {
	if n > 0 {
		c.txBytes.Add(uint64(n))
	}
}

// TCPFlowOpen registers a new TCP relay.
func (c *Counters) TCPFlowOpen() {
	c.tcpFlowsActive.Add(1)
	c.tcpFlowsTotal.Add(1)
}

// TCPFlowClose unregisters a finished TCP relay.
func (c *Counters) TCPFlowClose() { c.tcpFlowsActive.Add(-1) }

// UDPSessionOpen registers a new UDP pseudo-session.
func (c *Counters) UDPSessionOpen() {
	c.udpSessionsActive.Add(1)
	c.udpSessionsTotal.Add(1)
}

// UDPSessionClose unregisters a finished UDP pseudo-session.
func (c *Counters) UDPSessionClose() { c.udpSessionsActive.Add(-1) }

// Drop counts a flow refused before any byte was relayed (dial or protect
// failure). Non-blocking: the flow is closed, never queued.
func (c *Counters) Drop() { c.drops.Add(1) }

// TunnelDial counts a flow handed to the tunnel relay.
func (c *Counters) TunnelDial() { c.tunnelDials.Add(1) }

// TunnelEscalate counts a TUNNEL flow that failed to dial through the
// relay and was escalated (direct or drop).
func (c *Counters) TunnelEscalate() { c.tunnelEscalations.Add(1) }

// Snapshot returns a consistent-enough point-in-time copy (individual
// fields are atomic reads; cross-field skew is acceptable for status UI).
func (c *Counters) Snapshot() StatusSnapshot {
	return StatusSnapshot{
		TCPFlows:        c.tcpFlowsActive.Load(),
		UDPSessions:     c.udpSessionsActive.Load(),
		RxBytes:         c.rxBytes.Load(),
		TxBytes:         c.txBytes.Load(),
		TCPTotal:        c.tcpFlowsTotal.Load(),
		UDPTotal:        c.udpSessionsTotal.Load(),
		Dropped:         c.drops.Load(),
		TunnelDials:     c.tunnelDials.Load(),
		TunnelEscalated: c.tunnelEscalations.Load(),
	}
}
