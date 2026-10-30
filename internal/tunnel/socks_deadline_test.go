package tunnel

// The CONNECT reply only arrives after the exit reached the destination. The
// connection used to lose every deadline right after the greeting, so a silent
// exit was waited on forever: the caller's DialTimeout never reached the read
// (live log 2026-10-30: flows blocked ~15.7s and could not fail over).

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func stallSocks5(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var greet [3]byte
				if _, err := io.ReadFull(c, greet[:]); err != nil {
					return
				}
				if _, err := c.Write([]byte{socks5Version, socks5NoAuth}); err != nil {
					return
				}
				buf := make([]byte, 512)
				c.Read(buf)
				time.Sleep(3 * time.Second)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestSocks5ConnectHonorsCtxDeadline(t *testing.T) {
	proxy := stallSocks5(t)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		conn, err := socks5Connect(ctx, proxy, netip.MustParseAddrPort("149.154.167.50:443"))
		if conn != nil {
			conn.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("stalled CONNECT reply accepted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CONNECT reply wait ignored the caller deadline: still blocked after 2s")
	}
}
