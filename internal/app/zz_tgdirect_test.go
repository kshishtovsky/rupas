//go:build windows && live && with_utls

package app

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/kshishtovsky/rupas/internal/config"
	"github.com/kshishtovsky/rupas/internal/tunnel"
)

// TestLiveUserVPSTGDirect: does the user's VLESS chain reach Telegram DCs
// at all, with NO capture engine in the loop? Isolates VPS-side CONNECT
// failures ("socks5: reply code 1") from the terminator burst.
func TestLiveUserVPSTGDirect(t *testing.T) {
	if _, src, err := loadFakeTemplate("", config.Default()); err != nil {
		t.Skipf("fake template unavailable: %v", err)
	} else {
		t.Logf("template %s", src)
	}
	plan := loadUserPlan(t)
	if plan.TCP == nil {
		t.Fatal("configs/rupas.yaml has no tcp endpoint")
	}
	tproxy := freeTCPPort(t)
	tun := tunnel.NewTunnel(plan, tproxy, tunnel.Options{
		MarkerURL:       tunnel.DefaultMarkerURL,
		Logger:          liveTunnelLogger(),
		HealthInterval:  8 * time.Second,
		DialTimeout:     15 * time.Second,
		NoHoldFlows:     true,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tun.Start(ctx); err != nil {
		t.Fatalf("tunnel start: %v", err)
	}
	defer func() { _ = tun.Stop() }()

	waitFor(t, "tunnel healthy", 40*time.Second, func() bool { return tun.Healthy() })

	dialer := tun.(interface {
		TCPDialer() func(ctx context.Context, dst string) (net.Conn, error)
	}).TCPDialer()

	for _, tgt := range []string{
		"149.154.167.51:443",
		"149.154.175.100:80",
		"91.108.56.198:443",
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		conn, err := dialer(ctx, tgt)
		cancel()
		if err != nil {
			t.Errorf("dial %s via plan: %v", tgt, err)
			continue
		}
		// DATA observation: Telegram DCs do NOT answer synthetic frames
		// (invalid req_pq) — silence is expected; informational only.
		conn.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
		if _, err := conn.Write(tgProbeBytes(t)); err != nil {
			t.Errorf("write %s via plan: %v", tgt, err)
			conn.Close()
			continue
		}
		buf := make([]byte, 128)
		n, rerr := conn.Read(buf)
		if rerr != nil || n == 0 {
			t.Logf("DATA silent %s via plan (expected for a synthetic probe)", tgt)
		} else {
			t.Logf("DATA answered %s via plan: %d bytes", tgt, n)
		}
		conn.Close()
	}
}
