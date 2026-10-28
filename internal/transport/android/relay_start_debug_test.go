//go:build live && with_utls

package android

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestRelayStartLiveShape reproduces the on-device relay start with the
// legacy flat settings (vless tcp): Start must not panic and must report
// its failure reason clearly.
func TestRelayStartLiveShape(t *testing.T) {
	// Legacy flat settings from the environment: no credentials in git
	// (AGENTS.md invariant 6).
	raw := os.Getenv("RELAY_LEGACY_SETTINGS")
	if raw == "" {
		t.Skip("set RELAY_LEGACY_SETTINGS to run against a real endpoint")
	}
	s, err := ParseSettings(raw)
	if err != nil {
		t.Fatalf("ParseSettings: %v", err)
	}
	r := NewRelay(s, func(line string) { t.Logf("relay: %s", line) })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := r.Start(ctx, nil, t.TempDir()); err != nil {
		t.Fatalf("relay start: %v", err)
	}
	defer r.Close()
	if !r.Available() {
		t.Fatal("relay not available after successful start")
	}
	t.Logf("socks=%s", r.socksAddr)
}
