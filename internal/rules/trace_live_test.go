//go:build live

package rules

import (
	"os"
	"testing"

	"github.com/kshishtovsky/rupas/internal/config"
	"github.com/kshishtovsky/rupas/internal/geoip"
)

// TestLiveTraceProductionConfig traces real queries through the owner's real
// rule set (configs/rupas.yaml, gitignored) with the real geoip cache
// (build/geoip-ru.txt). Opt-in:
//
//	go test -tags live -run TestLiveTraceProductionConfig -v ./internal/rules/
//
// This is the check that catches a trace that lies: the stage tests use a
// synthetic 7-rule fixture, while a semantic bug — a bare IP walking the udp
// bucket and answering BLOCK, a missing geoip table decorating every note —
// only shows against the 51-rule production policy.
func TestLiveTraceProductionConfig(t *testing.T) {
	if _, err := os.Stat("../../configs/rupas.yaml"); err != nil {
		t.Skip("configs/rupas.yaml absent (gitignored): live trace needs the owner's rule set")
	}
	cfg, err := config.Load("../../configs/rupas.yaml")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	queries := []string{
		"youtube.com", "example.com", "discord.com", "vk.com", "www.googlevideo.com",
		"149.154.167.51", "91.105.192.5", "77.88.55.88", "1.1.1.1", "1.1.1.1:443/udp",
	}
	for _, q := range queries {
		tr, err := TestRouteWithGeo(cfg.Rules, q, geoip.Params{Dir: "../../build"})
		if err != nil {
			t.Logf("%-18s ERROR %v", q, err)
			continue
		}
		t.Logf("%-18s stage=%d %-12s matcher=%-22q action=%-7s note=%q warn=%q",
			q, tr.Stage, tr.StageName, tr.Matcher, tr.Action, tr.Note, tr.Warning)
	}
	t.Logf("rules in production config: %d", len(cfg.Rules))
}
