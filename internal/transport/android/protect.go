package android

import (
	"strconv"
	"syscall"
)

// ProtectFunc reports whether an fd was successfully unhooked from the VPN
// (Java VpnService.protect on Android). Returning false means the socket
// would loop back into the TUN — the egress must refuse the dial.
type ProtectFunc func(fd int) bool

// ProtectControl turns a ProtectFunc into a net.Dialer/net.ListenConfig
// Control hook: it grabs the just-created socket's raw fd and hands it to
// protect before any connect/send traffic escapes (SYSTEM_DESIGN §3
// "protect"). Works for TCP and UDP sockets alike — the hook fires for
// every socket the dialer/listener creates.
func ProtectControl(protect ProtectFunc) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var protectErr error
		err := c.Control(func(fd uintptr) {
			if protect == nil {
				return
			}
			if !protect(int(fd)) {
				protectErr = &ProtectError{FD: int(fd), Network: network, Address: address}
			}
		})
		if err != nil {
			return err
		}
		return protectErr
	}
}

// ProtectError reports a failed protect(fd) for a would-be egress socket.
type ProtectError struct {
	FD      int
	Network string
	Address string
}

func (e *ProtectError) Error() string {
	return "android: protect(" + strconv.Itoa(e.FD) + ") failed for " + e.Network + " " + e.Address
}
