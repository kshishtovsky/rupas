//go:build live && with_utls

package tunnel

// WAVE-6 LIVE REPRO (throwaway diagnostics): surgical poison isolation for
// the TG path. Rounds (each self-contained, marker verdicts between):
//
//	R1  marker(vless) → 1× TG probe via vless → marker(vless)
//	R2  1× TG probe via hy2 → marker(hy2)
//	R3  5× rapid TG probes via vless → marker(vless)
//	R4  5× rapid TG probes via hy2 → marker(hy2)
//
// A "TG probe" = CONNECT 149.154.167.51:443 + TLS ClientHello + read
// (TG's fake-TLS answers any ClientHello — rx>0 proof).
//
//	go test ./internal/tunnel -tags "live with_utls" -run TestLiveReproPoison -v -timeout 600s

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kshishtovsky/rupas/internal/config"
)

func reproConfigPath(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for dir, up := wd, 0; up < 6; up++ {
		cand := filepath.Join(dir, "configs", "rupas.yaml")
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("configs/rupas.yaml not found")
	return ""
}

func poisonTunnel(t *testing.T) (*tunnel, func()) {
	t.Helper()
	cfg, err := config.Load(reproConfigPath(t))
	if err != nil {
		t.Fatalf("load configs/rupas.yaml: %v", err)
	}
	plan := cfg.TunnelPlan()
	os.Setenv("RUPAS_TUNNEL_SBLOG", "1")
	tport, err := freeTCPPort()
	if err != nil {
		t.Fatal(err)
	}
	tun := NewTunnel(plan, tport, Options{
		MarkerURL:      DefaultMarkerURL,
		HealthInterval: 8 * time.Second,
		NoHoldFlows:    true,
		DialTimeout:    15 * time.Second,
	}).(*tunnel)
	ctx, cancel := context.WithCancel(context.Background())
	if err := tun.Start(ctx); err != nil {
		cancel()
		t.Fatalf("tunnel start: %v", err)
	}
	return tun, func() { cancel(); _ = tun.Stop(); os.Unsetenv("RUPAS_TUNNEL_SBLOG") }
}

// tgProbe does one TG-IP CONNECT + TLS ClientHello and reports whether ANY
// response bytes came back. TG's :443 fake-TLS answers every ClientHello, so
// a completed handshake OR a RecordHeaderError ("first record does not look
// like a TLS handshake") both prove rx bytes flowed; timeout/EOF do not.
func tgProbe(t *testing.T, addr, label string) (rx bool, elapsed time.Duration) {
	t.Helper()
	t0 := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
	defer cancel()
	raw, err := socks5Connect(ctx, addr, netip.MustParseAddrPort("149.154.167.51:443"))
	if err != nil {
		t.Logf("[%s] TG CONNECT FAIL %v: %v", label, time.Since(t0).Round(time.Millisecond), err)
		return false, time.Since(t0)
	}
	defer raw.Close()
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: "149.154.167.51", MinVersion: tls.VersionTLS12})
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	herr := tc.Handshake()
	d := time.Since(t0).Round(time.Millisecond)
	if herr == nil {
		t.Logf("[%s] TG TLS HANDSHAKE COMPLETE %v (rx ok)", label, d)
		_ = tc.Close()
		return true, d
	}
	var rhe tls.RecordHeaderError
	if errors.As(herr, &rhe) {
		t.Logf("[%s] TG answered NON-TLS bytes in %v (rx ok, RecordHeaderError: %s)", label, d, rhe.Msg)
		return true, d
	}
	t.Logf("[%s] TG probe NO BYTES in %v: %v", label, d, herr)
	return false, d
}

// pathMarker probes the marker through ONE mixed inbound directly (bypasses
// the chain): verdict for a single carrier.
func pathMarker(t *testing.T, addr, label string) bool {
	t.Helper()
	t0 := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	c, err := socks5DialHost(ctx, addr, "www.gstatic.com", 443)
	if err != nil {
		t.Logf("[%s] marker connect FAIL %v: %v", label, time.Since(t0).Round(time.Millisecond), err)
		return false
	}
	defer c.Close()
	req := "GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nUser-Agent: curl/8.0\r\nConnection: close\r\n\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		t.Logf("[%s] marker write FAIL: %v", label, err)
		return false
	}
	buf := make([]byte, 512)
	_ = c.SetReadDeadline(time.Now().Add(8 * time.Second))
	n, err := c.Read(buf)
	if n > 0 {
		first := string(buf[:min(n, 12)])
		t.Logf("[%s] marker ANSWERED %v: %q", label, time.Since(t0).Round(time.Millisecond), first)
		return true
	}
	t.Logf("[%s] marker NO ANSWER %v: n=%d err=%v", label, time.Since(t0).Round(time.Millisecond), n, err)
	return false
}

func TestLiveReproPoison(t *testing.T) {
	tun, done := poisonTunnel(t)
	defer done()

	// Fresh engine: wait until at least one carrier answers the marker.
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if pathMarker(t, tun.sb.mainAddr(), "vless@start") || pathMarker(t, tun.sb.fbAddr(), "hy2@start") {
			break
		}
		time.Sleep(3 * time.Second)
	}
	mixed, hy2 := tun.sb.mainAddr(), tun.sb.fbAddr()
	t.Logf("mixed=%s hy2=%s", mixed, hy2)

	// R1: vless marker → 1 TG probe → vless marker.
	v1 := pathMarker(t, mixed, "R1.vless-before")
	rx1, d1 := tgProbe(t, mixed, "R1.vless-tg")
	v2 := pathMarker(t, mixed, "R1.vless-after")
	t.Logf("R1 RESULT: vless marker %v→%v, TG rx=%v (%v)", v1, v2, rx1, d1)

	// R2: hy2 marker → 1 TG probe → hy2 marker.
	h1 := pathMarker(t, hy2, "R2.hy2-before")
	rx2, d2 := tgProbe(t, hy2, "R2.hy2-tg")
	h2 := pathMarker(t, hy2, "R2.hy2-after")
	t.Logf("R2 RESULT: hy2 marker %v→%v, TG rx=%v (%v)", h1, h2, rx2, d2)

	// R3: 5 rapid TG probes via vless → vless marker.
	var r3 []bool
	for i := 0; i < 5; i++ {
		rx, _ := tgProbe(t, mixed, fmt.Sprintf("R3.vless-tg[%d]", i))
		r3 = append(r3, rx)
	}
	v3 := pathMarker(t, mixed, "R3.vless-after")
	t.Logf("R3 RESULT: 5× TG via vless rx=%v, vless marker after=%v", r3, v3)

	// R4: 5 rapid TG probes via hy2 → hy2 marker.
	var r4 []bool
	for i := 0; i < 5; i++ {
		rx, _ := tgProbe(t, hy2, fmt.Sprintf("R4.hy2-tg[%d]", i))
		r4 = append(r4, rx)
	}
	h4 := pathMarker(t, hy2, "R4.hy2-after")
	t.Logf("R4 RESULT: 5× TG via hy2 rx=%v, hy2 marker after=%v", r4, h4)

	// Cross check: is the OTHER carrier alive when one is poisoned?
	t.Logf("final: vless=%v hy2=%v", pathMarker(t, mixed, "final.vless"), pathMarker(t, hy2, "final.hy2"))
}
