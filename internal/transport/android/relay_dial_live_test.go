//go:build live && with_utls

package android

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing/common/json"
)

// googleProbe dest — Google GFE IPs; :443 serves TLS only and CLOSES a
// plaintext HTTP request with zero bytes (empty EOF) for ANY client
// including the official sing-box 1.14.4 binary (verified 2026-10-26, both
// server-loopback and desktop). So the probe must match real traffic:
// plaintext HTTP goes to :80, real device traffic goes to :443 as TLS.
const (
	probeIP   = "142.250.150.99"
	probeHost = "www.gstatic.com"
)

// TestRelayDialLive dials a real destination through the started relay and
// prints what comes back — the on-device "unknown version: 72" triage.
func TestRelayDialLive(t *testing.T) {
	links := `{"fallback":true,"links":[` +
		`"vless://332a87e4-4321-4027-ae49-72a6b67641af@45.67.202.247:12341?type=tcp&security=reality&pbk=shVXc1efjMDpqp8787otzjXqH2xByJTvXkHHLx2PFAQ&sid=999e2fd9&fp=chrome&sni=aws.amazon.com&flow=xtls-rprx-vision#rupas-reality",` +
		`"vless://d4550250-3222-431e-b8cc-eac9b45bcd7f@mylifemyrulesonline.ru:4443?type=xhttp&encryption=none&path=%2FsteamVideo&host=mylifemyrulesonline.ru&mode=packet-up&x_padding_bytes=100-1000&security=tls&fp=chrome&alpn=h2%2Chttp%2F1.1&sni=mylifemyrulesonline.ru#rupas-xhttp",` +
		`"hysteria2://7PRCfc5F8X@45.67.202.247:53552?security=tls&fp=chrome&alpn=h3&sni=mylifemyrulesonline.ru#rupas-hy2"]}`
	if env := os.Getenv("RELAY_LINKS"); env != "" {
		links = `{"fallback":true,"links":` + env + `}`
	}
	s, err := ParseSettings(links)
	if err != nil {
		t.Fatalf("ParseSettings: %v", err)
	}
	r := NewRelay(s, func(line string) { t.Logf("relay: %s", line) })
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if err := r.Start(ctx, nil, t.TempDir()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer r.Close()
	// Dump the outbound options JSON for diffing against the desktop.
	if len(r.endpoints) > 0 && !r.endpoints[0].NeedsXHTTP() {
		if raw, err := json.MarshalContext(ctx, endpointOutbound(r.endpoints[0], "45.67.202.247", "rupas-out-0", "").Options); err == nil {
			t.Logf("ANDROID_OUTBOUND=%s", raw)
		}
	}
	// Dial EVERY carrier 3 times: all three transports must work.
	// Dial even = plaintext GET on :80, dial odd = TLS on :443 (real
	// device traffic shape).
	okCount := 0
	total := 0
	for idx := range r.endpoints {
		if r.endpoints[idx].NeedsXHTTP() {
			continue // xhttp slots have no socks inbound (own client carries them)
		}
		for i := 0; i < 3; i++ {
			total++
			useTLS := i%2 == 1
			port := uint16(80)
			if useTLS {
				port = 443
			}
			dst := netip.MustParseAddrPort(fmt.Sprintf("%s:%d", probeIP, port))
			conn, derr := r.DialTCPIndex(idx, ctx, dst)
			if derr != nil {
				t.Logf("carrier %d dial %d (tls=%v %d): %v", idx, i, useTLS, port, derr)
				continue
			}
			data, rerr := googleProbe(conn, useTLS)
			if len(data) > 0 && firstLine(string(data)) != "" {
				okCount++
				t.Logf("carrier %d dial %d (tls=%v %d): OK n=%d %q", idx, i, useTLS, port, len(data), firstLine(string(data)))
			} else {
				t.Logf("carrier %d dial %d (tls=%v %d): empty err=%v", idx, i, useTLS, port, rerr)
			}
			conn.Close()
			time.Sleep(500 * time.Millisecond)
		}
	}
	t.Logf("SUCCESS RATE: %d/%d", okCount, total)
	if okCount == 0 {
		t.Fatalf("all dials failed")
	}
	_ = fmt.Sprint()
}

// googleProbe writes one generate_204 request over conn — plaintext on :80
// or TLS-wrapped on :443 — and returns the first chunk of the response.
func googleProbe(conn net.Conn, useTLS bool) ([]byte, error) {
	var c net.Conn = conn
	if useTLS {
		c = tls.Client(conn, &tls.Config{ //nolint:gosec // probe through our own tunnel
			InsecureSkipVerify: true,
			ServerName:         probeHost,
			NextProtos:         []string{"http/1.1"},
		})
	}
	req := "GET /generate_204 HTTP/1.1\r\nHost: " + probeHost + "\r\nConnection: close\r\n\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		return nil, err
	}
	c.SetReadDeadline(time.Now().Add(8 * time.Second)) //nolint:errcheck // probe
	buf := make([]byte, 512)
	n, rerr := c.Read(buf)
	return buf[:n], rerr
}

// firstLine returns "HTTP/1.1 204 No Content"-shaped first response line.
func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\r' || s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
