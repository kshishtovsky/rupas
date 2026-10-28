package tunnel

import (
	"context"
	"testing"

	"github.com/kshishtovsky/rupas/internal/config"
	"github.com/sagernet/sing/common/json"
)

// TestDumpVlessOutboundJSON prints the exact sing-box outbound options the
// DESKTOP builds for the production vless_tcp endpoint — the reference for
// diffing against the mobile relay's options (unknown-version triage).
func TestDumpVlessOutboundJSON(t *testing.T) {
	cfg, err := config.Load("../../configs/rupas.yaml")
	if err != nil {
		t.Skipf("config load: %v", err)
	}
	plan := cfg.TunnelPlan()
	if plan.TCP == nil {
		t.Skip("no tcp endpoint")
	}
	out := endpointOutbound(*plan.TCP, "rupas-out")
	raw, err := json.MarshalContext(context.Background(), out.Options)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	t.Logf("DESKTOP_OUTBOUND=%s", redact(string(raw), plan.TCP.UUID))
}

func redact(s, secret string) string {
	if secret == "" {
		return s
	}
	out := []byte(s)
	sec := []byte(secret)
	for i := 0; i+len(sec) <= len(out); i++ {
		match := true
		for j := range sec {
			if out[i+j] != sec[j] {
				match = false
				break
			}
		}
		if match {
			for j := 0; j < len(sec); j++ {
				out[i+j] = '*'
			}
		}
	}
	return string(out)
}
