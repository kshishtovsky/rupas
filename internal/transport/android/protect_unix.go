//go:build unix

package android

// Local fd-passing protect server for the embedded sing-box outbound
// (SYSTEM_DESIGN §3 "protect"). sing-box's dialer only speaks the
// protect_path protocol: it connects to a unix socket and sends one dummy
// byte plus the socket fd via SCM_RIGHTS, expecting a one-byte reply. This
// server receives the (duplicated) fd, unhooks it from the VPN through the
// Java VpnService.protect callback, and answers.
//
// The socket is a REAL file in the app-private cwd (filesDir): see the
// NOTE at protectorSocketPrefix below.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

// NOTE: NOT an abstract-namespace socket ("@name"): sing's ProtectPath
// client (common/control/protect_unix.go) passes the path literally to
// syscall.Connect(SockaddrUnix) — an "@name" string there resolves to a
// FILESYSTEM path "@name" (leading NUL only appears when the first byte is
// NUL), so the client would get ENOENT and every protected dial would die
// in the Control hook. A real file under the app's private dir is visible
// to both sides; it lives in filesDir (codir of the Go runtime) — no
// other app can touch it.
const protectorSocketPrefix = "rupas-protect-"

// startProtector serves the protect protocol until the returned stop is
// called. It never blocks the caller.
func startProtector(protect ProtectFunc, dir string, logFn func(string)) (path string, stop func(), err error) {
	if logFn == nil {
		logFn = func(string) {}
	}
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		return "", nil, fmt.Errorf("android: protector: random name: %w", err)
	}
	// Absolute path in the app-private dir (filesDir from Java): the
	// Android process cwd is "/", so a relative path would land there and
	// fail (EPERM/EACCES). Same absolute string works for both sides.
	path = filepath.Join(dir, protectorSocketPrefix+hex.EncodeToString(suffix))
	_ = os.Remove(path) // stale socket from a killed previous process
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
			go serveProtect(conn.(*net.UnixConn), protect, logFn)
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
func serveProtect(c *net.UnixConn, protect ProtectFunc, logFn func(string)) {
	defer c.Close()
	buf := make([]byte, 16)
	oob := make([]byte, 64) // room for several fds
	n, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
	if err != nil || n == 0 {
		logFn(fmt.Sprintf("android: protect: receive failed: n=%d oob=%d err=%v", n, oobn, err))
		return
	}
	logFn(fmt.Sprintf("android: protect: fd message n=%d oob=%d", n, oobn))
	ok := true
	if oobn <= 0 {
		ok = false
	} else {
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
				protected := protect(fd)
				logFn(fmt.Sprintf("android: protect: fd=%d result=%t", fd, protected))
				if !protected {
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
