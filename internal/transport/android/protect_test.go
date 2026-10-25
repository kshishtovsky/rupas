package android

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
)

// TestProtectControlAllowsDial verifies the Control hook hands the real
// socket fd to the protect callback before the dial proceeds (loopback TCP).
func TestProtectControlAllowsDial(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		io.Copy(c, c) //nolint:errcheck
		c.Close()
	}()

	var mu sync.Mutex
	var gotFDs []int
	hook := func(fd int) bool {
		mu.Lock()
		defer mu.Unlock()
		gotFDs = append(gotFDs, fd)
		return true
	}

	d := ProtectedDialer(hook)
	conn, err := d.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(gotFDs) != 1 {
		t.Fatalf("protect hook called %d times, want 1", len(gotFDs))
	}
	if gotFDs[0] <= 0 {
		t.Fatalf("protect hook got fd %d, want > 0", gotFDs[0])
	}

	// The connection must actually work end-to-end.
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q, want ping", buf)
	}
}

// TestProtectControlRefusesOnFailure verifies a failed protect(fd) aborts
// the dial instead of letting the socket loop back into the TUN.
func TestProtectControlRefusesOnFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	d := ProtectedDialer(func(fd int) bool { return false })
	_, err = d.Dial("tcp", ln.Addr().String())
	if err == nil {
		t.Fatal("dial succeeded despite protect failure, want error")
	}
	var pErr *ProtectError
	if !errors.As(err, &pErr) {
		t.Fatalf("err = %v, want *ProtectError", err)
	}
	if !strings.Contains(pErr.Error(), "protect(") {
		t.Fatalf("message %q missing protect detail", pErr.Error())
	}
}

// TestProtectedListenConfigUDP verifies UDP sockets get the same control
// hook (ТЗ W2: "UDP-сокеты тоже защищать").
func TestProtectedListenConfigUDP(t *testing.T) {
	var called bool
	lc := ProtectedListenConfig(func(fd int) bool {
		called = true
		return true
	})
	pc, err := lc.ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer pc.Close()
	if !called {
		t.Fatal("protect hook not invoked for UDP socket")
	}
}

// TestDialerControlAppliesToUDPDial verifies the dialer-based UDP path is
// protected too.
func TestDialerControlAppliesToUDPDial(t *testing.T) {
	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer ln.Close()

	var called bool
	d := ProtectedDialer(func(fd int) bool {
		called = true
		return true
	})
	conn, err := d.Dial("udp", ln.LocalAddr().String())
	if err != nil {
		t.Fatalf("dial udp: %v", err)
	}
	defer conn.Close()
	if !called {
		t.Fatal("protect hook not invoked for UDP dial")
	}
}
