//go:build windows && live && with_utls

package app

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/rupas/rupas/internal/config"
	"github.com/rupas/rupas/internal/tunnel"
)

// TestLiveVLESSLifetime: fresh CONNECTs through the plan every 5s for ~70s
// — does the carrier die after N seconds (TSPU connection killing) and
// does it recover?
func TestLiveVLESSLifetime(t *testing.T) {
	if _, src, err := loadFakeTemplate("", config.Default()); err != nil {
		t.Skipf("fake template unavailable: %v", err)
	} else {
		t.Logf("template %s", src)
	}
	plan := loadUserPlan(t)
	tproxy := freeTCPPort(t)
	tun := tunnel.NewTunnel(plan, tproxy, tunnel.Options{
		MarkerURL:       tunnel.DefaultMarkerURL,
		Logger:          liveTunnelLogger(),
		HealthInterval:  8 * time.Second,
		DialTimeout:     10 * time.Second,
		NoHoldFlows:     true,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tun.Start(ctx); err != nil {
		t.Fatalf("tunnel start: %v", err)
	}
	defer func() { _ = tun.Stop() }()

	dialer := tun.(interface {
		TCPDialer() func(ctx context.Context, dst string) (net.Conn, error)
	}).TCPDialer()

	t0 := time.Now()
	for i := 0; i < 14; i++ {
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			c, err := dialer(ctx, "149.154.167.51:443")
			d := time.Since(t0).Round(time.Second)
			if err != nil {
				t.Logf("[%2d] t+%v CONNECT FAIL: %v", i, d, err)
				return
			}
			t.Logf("[%2d] t+%v CONNECT OK", i, d)
			c.Close()
		}()
		time.Sleep(5 * time.Second)
	}
}
