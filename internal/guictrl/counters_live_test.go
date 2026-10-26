//go:build live

// counters_live_test.go — verifies the traffic-counter data plane end to end
// (GUI_DESIGN §4a cards): capture → tunnel relay counters → RPC status →
// guictrl.Snapshot mapping (the exact function the GUI poller renders).
//
//	go test -tags live ./internal/guictrl/ -run TestLiveTrafficCounters -v -timeout 5m
//
// Requires: elevated shell (daemon already running or startable) and network.
// Traffic: HTTPS GETs to a tunnel-routed SNI (discord.com in the preset).
package guictrl

import (
	"fmt"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestLiveTrafficCounters(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(Options{
		DaemonPath: filepath.Join(root, "build", "rupasd.exe"),
		ConfigPath: filepath.Join(root, "configs", "rupas.yaml"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.EnsureDaemon(); err != nil {
		t.Fatalf("EnsureDaemon: %v", err)
	}

	// Bring interception up if needed (idempotent).
	before := c.poll()
	if !before.Online {
		t.Fatal("daemon down")
	}
	if before.State != "ACTIVE" && before.State != "ACTIVE_TUNNEL_ONLY" {
		if err := c.On(); err != nil {
			t.Fatalf("on: %v", err)
		}
		deadline := time.Now().Add(5 * time.Minute)
		for time.Now().Before(deadline) {
			before = c.poll()
			if before.Online && before.State != "PROBING" && before.State != "OFF" {
				break
			}
			time.Sleep(2 * time.Second)
		}
	}
	if before.State != "ACTIVE" && before.State != "ACTIVE_TUNNEL_ONLY" {
		t.Fatalf("not steady: %+v", before)
	}

	client := &http.Client{Timeout: 20 * time.Second}
	var fetch = func() error {
		var lastErr error
		for attempt := 0; attempt < 4; attempt++ {
			// First dial to a fresh dst is RST+redial by design (tunnel
			// verdict after SYN): one-shot clients must retry.
			resp, err := client.Get("https://discord.com/")
			if err == nil {
				defer resp.Body.Close()
				return nil
			}
			lastErr = err
			time.Sleep(time.Second)
		}
		return lastErr
	}
	if err := fetch(); err != nil {
		t.Fatalf("probe fetch: %v", err)
	}
	time.Sleep(1500 * time.Millisecond)

	after := c.poll()
	t.Logf("before: rx=%d tx=%d flows=%d tunnel=%q", before.RxBytes, before.TxBytes, before.TCPFlows, before.TunnelMode)
	t.Logf("after:  rx=%d tx=%d flows=%d", after.RxBytes, after.TxBytes, after.TCPFlows)

	if after.RxBytes < before.RxBytes {
		t.Fatalf("rx shrank: %d -> %d", before.RxBytes, after.RxBytes)
	}
	if after.TxBytes == before.TxBytes && after.RxBytes == before.RxBytes {
		// No growth at all: either the fetch did not ride the tunnel or the
		// counters are stuck — check mode first.
		if before.TunnelMode != "tunnel" {
			t.Fatalf("tunnel mode %q (not relaying — config/endpoint issue, not counters)", before.TunnelMode)
		}
		t.Fatal("counters did not move despite tunnel traffic")
	}
	if after.RxBytes == before.RxBytes {
		t.Fatal("rx did not move (response bytes should be relayed back)")
	}
	fmt.Printf("OK: rx +%d bytes, tx +%d bytes\n", after.RxBytes-before.RxBytes, after.TxBytes-before.TxBytes)
}
