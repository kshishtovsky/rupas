//go:build live

// live_test.go — end-to-end backend check of the GUI control plane against the
// real daemon (build/rupasd.exe + WinDivert + configs/rupas.yaml):
//
//	go test -tags live ./internal/guictrl/ -run TestLiveGUIPipeline -v -timeout 15m
//
// It spawns rupasd via EnsureDaemon (no UAC needed from an elevated shell),
// turns interception on, waits for a steady state and turns it off. The
// daemon is left running (by design `off` does not kill the process); the
// harness kills it afterwards to restore the pre-test state.
package guictrl

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLiveGUIPipeline(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	daemon := filepath.Join(root, "build", "rupasd.exe")
	cfg := filepath.Join(root, "configs", "rupas.yaml")
	for _, p := range []string{daemon, cfg, filepath.Join(root, "build", "WinDivert.dll")} {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("asset missing: %s (%v)", p, err)
		}
	}

	c, err := New(Options{
		DaemonPath: daemon,
		ConfigPath: cfg,
		LogPath:    filepath.Join(root, "build", "rupasd-gui.log"),
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := c.EnsureDaemon(); err != nil {
		t.Fatalf("EnsureDaemon: %v", err)
	}
	t.Log("daemon is up")

	if err := c.On(); err != nil {
		t.Fatalf("on: %v", err)
	}

	// Wait for a steady state: ACTIVE / ACTIVE_TUNNEL_ONLY (fast path via a
	// persisted profile) or DEGRADED (honest failure) — PROBING means the
	// full calibration ladder, up to ~150 s.
	deadline := time.Now().Add(5 * time.Minute)
	var last Snapshot
	for time.Now().Before(deadline) {
		last = c.poll()
		if last.Online && last.State != "PROBING" && last.State != "OFF" {
			break
		}
		time.Sleep(2 * time.Second)
	}
	t.Logf("state: online=%v state=%q tunnel=%q", last.Online, last.State, last.TunnelMode)
	if !last.Online {
		t.Fatal("daemon stopped answering")
	}
	switch last.State {
	case "ACTIVE", "ACTIVE_TUNNEL_ONLY":
		// success
	case "DEGRADED":
		t.Log("DEGRADED (honest state — ISP/deps issue, not the GUI plane)")
	default:
		t.Fatalf("stuck in %q", last.State)
	}

	logs, err := c.Logs()
	if err != nil || len(logs) == 0 {
		t.Logf("logs: err=%v n=%d (non-fatal)", err, len(logs))
	} else {
		t.Logf("last log: %s", logs[len(logs)-1])
	}

	if err := c.Off(); err != nil {
		t.Fatalf("off: %v", err)
	}
	time.Sleep(time.Second)
	final := c.poll()
	if !final.Online || final.State != "OFF" {
		t.Fatalf("after off: online=%v state=%q", final.Online, final.State)
	}
	t.Log("off OK")
}
