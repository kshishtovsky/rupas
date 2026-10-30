package android

// SOCKS5 frame/reply tests: the ATYP=domain forms are legal per RFC 1928
// and used to abort a live UDP session (parseUDPFrame) or a CONNECT
// (socks5ReadReplyAddr) — the address is discarded, only offsets matter.

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

// buildUDPFrame hand-builds RSV FRAG ATYP=domain LEN NAME PORT PAYLOAD.
func buildUDPFrame(name, payload string, port uint16) []byte {
	b := []byte{0, 0, 0, atypName, byte(len(name))}
	b = append(b, name...)
	b = append(b, byte(port>>8), byte(port))
	return append(b, payload...)
}

func TestParseUDPFrameDomainAddr(t *testing.T) {
	name, payload := "bnd.example.net", "hi"
	b := buildUDPFrame(name, payload, 53552)
	_, off, err := parseUDPFrame(b)
	if err != nil {
		t.Fatalf("domain frame rejected: %v", err)
	}
	want := 5 + len(name) + 2
	if off != want {
		t.Fatalf("payload offset = %d, want %d", off, want)
	}
	if got := string(b[off:]); got != payload {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
	// Truncated name frame must still be refused.
	if _, _, err := parseUDPFrame(b[:5+len(name)+1]); err == nil {
		t.Fatal("short name frame accepted")
	}
}

func TestSocks5ReplyDomainBindAddr(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		name := "bnd.example.net"
		reply := []byte{socks5Version, 0x00, 0x00, atypName, byte(len(name))}
		reply = append(reply, name...)
		reply = append(reply, 0x1f, 0x90) // port 8080
		server.Write(reply)               //nolint:errcheck
		server.Close()
	}()
	client.SetReadDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
	if _, err := socks5ReadReplyAddr(client); err != nil {
		t.Fatalf("domain BND.ADDR reply rejected: %v", err)
	}
}

// stallSocks5 is a proxy that answers the no-auth greeting and then never
// replies to CONNECT — what the relay does while its exit cannot reach the
// destination (live log 2026-10-30: 38 flows sat ~15.7s).
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
				c.Read(buf) // swallow the request, never answer it
				time.Sleep(3 * time.Second)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// TestSocks5ConnectHonorsCtxDeadline: the wait for the CONNECT reply must be
// bounded by the caller's deadline. Without it the socket had no deadline at
// all after the greeting, so carrierDialTimeout (6s) bounded nothing and a
// flow hung for the relay's own ~15.7s before it could fail over.
func TestSocks5ConnectHonorsCtxDeadline(t *testing.T) {
	proxy := stallSocks5(t)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	type res struct{ err error }
	ch := make(chan res, 1)
	go func() {
		conn, err := socks5Connect(ctx, proxy, netip.MustParseAddrPort("149.154.167.50:443"))
		if conn != nil {
			conn.Close()
		}
		ch <- res{err}
	}()
	select {
	case r := <-ch:
		if r.err == nil {
			t.Fatal("stalled CONNECT reply accepted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CONNECT reply wait ignored the caller deadline: still blocked after 2s")
	}
}
