//go:build unix

package android

// Local fd-passing protect server for the embedded sing-box outbound
// (SYSTEM_DESIGN §3 "protect"). sing-box's dialer only speaks the
// protect_path protocol: it connects to a unix socket and sends one dummy
// byte plus the socket fd via SCM_RIGHTS, expecting a one-byte reply. This
// server receives the (duplicated) fd, unhooks it from the VPN through the
// Java VpnService.protect callback, and answers.
//
// An abstract-namespace socket is used (name starts with '@'): no
// filesystem location is needed, which sidesteps app-dir permission
// questions entirely.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"syscall"
)

const protectorSocketPrefix = "@rupas-protect-"

// startProtector serves the protect protocol until the returned stop is
// called. It never blocks the caller.
func startProtector(protect ProtectFunc) (path string, stop func(), err error) {
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		return "", nil, fmt.Errorf("android: protector: random name: %w", err)
	}
	path = protectorSocketPrefix + hex.EncodeToString(suffix)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return "", nil, fmt.Errorf("android: protector: listen %s: %w", path, err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, aErr := ln.Accept()
			if aErr != nil {
				return
			}
			go serveProtect(conn.(*net.UnixConn), protect)
		}
	}()
	return path, func() {
		ln.Close()
		<-done
	}, nil
}

// serveProtect handles one protector client: read the dummy byte with the
// SCM_RIGHTS ancillary data, protect every received fd, reply one byte
// (0x01 = protected, 0x00 = refused).
func serveProtect(c *net.UnixConn, protect ProtectFunc) {
	defer c.Close()
	buf := make([]byte, 16)
	oob := make([]byte, 64) // room for several fds
	n, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
	if err != nil || n == 0 {
		return
	}
	ok := true
	if oobn > 0 {
		msgs, pErr := syscall.ParseSocketControlMessage(oob[:oobn])
		if pErr != nil {
			ok = false
		}
		for _, msg := range msgs {
			fds, rErr := syscall.ParseUnixRights(&msg)
			if rErr != nil {
				ok = false
				continue
			}
			for _, fd := range fds {
				// The received fd is a dup inside our process; it
				// refers to the same open socket description, so
				// protecting the dup unhooks the peer's socket too.
				if !protect(fd) {
					ok = false
				}
				syscall.Close(fd) //nolint:errcheck // dup, not the peer's copy
			}
		}
	}
	if ok {
		c.Write([]byte{0x01}) //nolint:errcheck // client may be gone
	} else {
		c.Write([]byte{0x00}) //nolint:errcheck
	}
}
