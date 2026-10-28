//go:build live && with_utls

package tunnel

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/kshishtovsky/rupas/internal/config"
)

// TestLiveXHTTPDial dials a real destination through the exported XHTTP
// dialer (the mobile carrier path) and reads a 204 back.
// Run: RELAY_XHTTP_ENDPOINT='{"host":"…","port":443,"uuid":"…","sni":"…","path":"/…","mode":"packet-up"}' \
//
//	go test -tags "live with_utls" -run TestLiveXHTTPDial -v ./internal/tunnel
//
// The endpoint comes from the environment: hardcoding it here would commit a
// live credential (AGENTS.md invariant 6).
func TestLiveXHTTPDial(t *testing.T) {
	raw := os.Getenv("RELAY_XHTTP_ENDPOINT")
	if raw == "" {
		t.Skip("set RELAY_XHTTP_ENDPOINT to run against a real endpoint")
	}
	var ep config.Endpoint
	if err := json.Unmarshal([]byte(raw), &ep); err != nil {
		t.Fatalf("RELAY_XHTTP_ENDPOINT: %v", err)
	}
	ep.Kind = config.KindVLESSXHTTP
	if len(ep.ALPN) == 0 {
		ep.ALPN = []string{"h2", "http/1.1"}
	}
	if ep.Fingerprint == "" {
		ep.Fingerprint = "chrome"
	}
	if ep.XPadding == "" {
		ep.XPadding = "100-1000"
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
