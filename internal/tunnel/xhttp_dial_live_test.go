//go:build live && with_utls

package tunnel

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/rupas/rupas/internal/config"
)

// TestLiveXHTTPDial dials a real destination through the exported XHTTP
// dialer (the mobile carrier path) and reads a 204 back.
// Run: go test -tags "live with_utls" -run TestLiveXHTTPDial -v ./internal/tunnel
func TestLiveXHTTPDial(t *testing.T) {
	ep := config.Endpoint{
		Kind:        config.KindVLESSXHTTP,
		Host:        "45.67.202.247",
		Port:        4443,
		UUID:        "d4550250-3222-431e-b8cc-eac9b45bcd7f",
		SNI:         "mylifemyrulesonline.ru",
		ALPN:        []string{"h2", "http/1.1"},
		Fingerprint: "chrome",
		Path:        "/steamVideo",
		Mode:        "packet-up",
		XPadding:    "100-1000",
	}
	// Probe destinations: :443 serves TLS only — a PLAINTEXT request there
	// is closed silently by Google with zero bytes (empty EOF) for ANY
	// client, always (char 2026-10-26 from server egress and desktop).
	// Probes must match real traffic: plaintext to :80, TLS to :443.
	dial, err := NewXHTTPDialer(ep, slog.Default())
	if err != nil {
		t.Fatalf("NewXHTTPDialer: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req := []byte("GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n")
	for i, useTLS := range []bool{false, true} {
		dst := netip.MustParseAddrPort("142.250.150.99:80")
		if useTLS {
			dst = netip.MustParseAddrPort("142.250.150.99:443")
		}
		conn, derr := dial(ctx, dst)
		if derr != nil {
			t.Fatalf("dial %d (tls=%v): %v", i, useTLS, derr)
		}
		var c net.Conn = conn
		if useTLS {
			c = tls.Client(conn, &tls.Config{ //nolint:gosec // probe through our own tunnel
				InsecureSkipVerify: true,
				ServerName:         "www.gstatic.com",
				NextProtos:         []string{"http/1.1"},
			})
		}
		if _, err := c.Write(req); err != nil {
			conn.Close()
			t.Fatalf("write %d (tls=%v): %v", i, useTLS, err)
		}
		conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		buf := make([]byte, 512)
		n, rerr := c.Read(buf)
		t.Logf("dial %d (tls=%v): read n=%d err=%v body=%q", i, useTLS, n, rerr, string(buf[:min(n, 40)]))
		if n == 0 {
			conn.Close()
			t.Fatalf("dial %d (tls=%v): no data: %v", i, useTLS, rerr)
		}
		conn.Close()
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
