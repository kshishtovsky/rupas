// Package android is the Android platform transport layer (SYSTEM_DESIGN
// §2/§4/§5): a TUN device taken over from Java VpnService via a raw file
// descriptor, a gVisor netstack turning packets back into flows, and a
// protected egress dialer whose sockets are unhooked from the VPN via the
// Java VpnService.protect callback.
//
// Wave 2 scope: every flow is served DIRECT through the protected dialer —
// including DNS:53. No rules, no desync, no tunnel yet. The Verdict seam
// (verdict.go) is the single point where later waves plug rule matching in.
package android

import "net/netip"

// Action is the decision for a flow. Wave 2 only produces ActionDirect;
// ActionBlock exists so the drop path is reachable through the same seam.
type Action uint8

const (
	// ActionDirect relays the flow through the protected dialer.
	ActionDirect Action = iota
	// ActionBlock drops the flow (netstack-side, no egress socket).
	ActionBlock
)

// String returns the canonical upper-case action name.
func (a Action) String() string {
	switch a {
	case ActionDirect:
		return "DIRECT"
	case ActionBlock:
		return "BLOCK"
	default:
		return "INVALID"
	}
}

// FlowMeta describes one flow at decision time. Deliberately tiny: later
// waves add inspected fields (SNI, host, geo) without changing the seam.
type FlowMeta struct {
	// Network is "tcp" or "udp".
	Network     string
	Source      netip.AddrPort
	Destination netip.AddrPort
}

// Verdict decides an action for a flow. It runs once per new TCP flow /
// UDP session on the netstack goroutine; keep it cheap — zero calls per
// packet (SYSTEM_DESIGN §2, option 3).
type Verdict func(FlowMeta) Action

// DirectVerdict is the wave-2 default verdict: everything — including
// DNS:53 — goes DIRECT.
func DirectVerdict(FlowMeta) Action { return ActionDirect }

// W2PolicyVerdict: parity with the desktop routing table (PRD ru §5) —
// everything DIRECT except QUIC (UDP:443) which is BLOCKed. The RU TSPU
// blackholes QUIC; relaying it makes apps (YouTube first of all) stall in
// multi-second QUIC handshakes instead of falling back to TCP fast, where
// later waves (desync/tunnel) can pick them up.
func W2PolicyVerdict(m FlowMeta) Action {
	if m.Network == "udp" && m.Destination.Port() == 443 {
		return ActionBlock
	}
	return ActionDirect
}
