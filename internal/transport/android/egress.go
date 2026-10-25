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
	// KeepAlive keeps relayed TCP flows alive through mobile NATs.
	KeepAlive = 30 * time.Second
	// UDPTimeout is the idle timeout for UDP pseudo-sessions (mirrors
	// sing-tun's default; explicit here so both sides agree).
	UDPTimeout = 5 * time.Minute
	// DefaultTUNAddress must match the VpnService.Builder address
	// (§3: 26.26.26.1/24).
	DefaultTUNAddress = "26.26.26.1/24"
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
