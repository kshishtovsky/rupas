package android

import (
	"net"
	"time"
)

// Egress tuning constants (SYSTEM_DESIGN §5). TUN MTU must match the
// VpnService.Builder setMtu() value.
const (
	// DefaultMTU is the MTU the Android side configures on the TUN
	// (§3: Builder.setMtu(1500)).
	DefaultMTU = 1500
	// DialTimeout bounds TCP/UDP egress establishment.
	DialTimeout = 15 * time.Second
	// KeepAlive keeps relayed TCP flows alive through mobile NATs. 30 s is
	// the Go default but wakes the cellular radio far more often than the
	// OS keepalive (Linux default ~2 h idle / 75 s probes); 2 minutes still
	// survives carrier NAT and keeps idle pooled connections quiet.
	KeepAlive = 2 * time.Minute
	// UDPTimeout is the idle timeout for UDP pseudo-sessions (mirrors
	// sing-tun's default; explicit here so both sides agree).
	UDPTimeout = 5 * time.Minute
	// DefaultTUNAddress must match the VpnService.Builder address
	// (§3: 26.26.26.1/24).
	DefaultTUNAddress = "26.26.26.1/24"
	// DefaultTUNAddress6 is the IPv6 TUN address (W3). The Java side adds
	// the ::/0 route in parallel — the contract is exactly this prefix.
	DefaultTUNAddress6 = "fdfe:dcba:9876::1/126"
)

// ProtectedDialer returns a *net.Dialer whose sockets are protected via
// the given hook: TCP connects and UDP "connections" both pass through
// Control before any packet leaves, so they bypass the TUN route.
func ProtectedDialer(protect ProtectFunc) *net.Dialer {
	return &net.Dialer{
		Timeout:   DialTimeout,
		KeepAlive: KeepAlive,
		Control:   ProtectControl(protect),
	}
}

// ProtectedListenConfig is the listen-side counterpart of ProtectedDialer
// (UDP sockets created via ListenPacket carry the same Control hook).
func ProtectedListenConfig(protect ProtectFunc) *net.ListenConfig {
	return &net.ListenConfig{
		Control: ProtectControl(protect),
	}
}
