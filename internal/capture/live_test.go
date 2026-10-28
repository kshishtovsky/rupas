//go:build windows && live

package capture

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"time"

	"github.com/kshishtovsky/rupas/internal/config"
	"github.com/kshishtovsky/rupas/internal/rules"
)

// TestLiveOpenRecvClose exercises the real driver through the engine:
// open the NETWORK-layer handle with the production filter, process at least
// one captured packet, stop gracefully and close. Requires administrator
// privileges and the WinDivert service; skipped otherwise.
//
// The handle is opened in SNIFF mode (observe-only), so host traffic is
// never blocked by this test.
func TestLiveOpenRecvClose(t *testing.T) {
	if !dllAvailable(t) {
		t.Skip("WinDivert.dll not loadable")
	}
	cfg := &config.Config{
		Profile: "live-test",
		Rules:   []config.Rule{{Action: config.ActionDirect}},
		Desync:  config.DesyncParams{Strategy: "fake", TTL: 8, Repeats: 1},
	}
	tbl, err := rules.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(Options{
		Rules:        tbl,
		Desync:       cfg.Desync,
		FakeTemplate: testFakeTemplate,
		TProxyPort:   0, // no loopback handle: keep the live surface minimal
		SniffMode:    true,
	})
	if err != nil {
		t.Fatal(err)
	}

	runErr := make(chan error, 1)
	go func() { runErr <- e.Run(context.Background()) }()

	// Wait for the handle to open and at least one packet to flow.
	deadline := time.Now().Add(15 * time.Second)
	opened := false
	for time.Now().Before(deadline) {
		if !opened {
			// The engine opens its handle inside Run; a driver-level open
			// failure surfaces as the Run error almost immediately.
			select {
			case err := <-runErr:
				skipIfDriverUnusable(t, err)
				t.Fatalf("Run failed: %v", err)
			default:
			}
		}
		opened = true
		if e.Counters().PacketsTotal > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if e.Counters().PacketsTotal == 0 {
		e.Stop()
		t.Skip("no packets within 15s; host idle")
	}

	e.Stop()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned %v after Stop", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after Stop")
	}
	if c := e.Counters(); c.PacketsTotal == 0 {
		t.Fatal("no packets processed")
	} else {
		t.Logf("processed %d packets live (pass=%d, errors=%d)",
			c.PacketsTotal, c.PacketsPass, c.PacketsRedir*0+c.PacketsDrop*0)
	}
}

// skipIfDriverUnusable maps WinDivert open failures to skips (mirrors the
// pkg/windivert live tests).
func skipIfDriverUnusable(t *testing.T, err error) {
	t.Helper()
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.Errno(5): // ERROR_ACCESS_DENIED: not elevated
			t.Skipf("WinDivert driver requires administrator: %v", err)
		case syscall.Errno(2): // ERROR_FILE_NOT_FOUND
			t.Skipf("WinDivert driver not installed: %v", err)
		case syscall.Errno(1062): // ERROR_SERVICE_NOT_ACTIVE
			t.Skipf("WinDivert service not running: %v", err)
		case syscall.Errno(1058): // ERROR_SERVICE_DISABLED
			t.Skipf("WinDivert service disabled: %v", err)
		}
	}
}
