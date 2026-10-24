package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/rupas/rupas/internal/core"
)

func TestRenderSnapshot(t *testing.T) {
	s := core.Snapshot{
		State:         "ACTIVE_TUNNEL_ONLY",
		Since:         time.Now().Add(-90 * time.Second),
		ProfileID:     "isp-home-2025-10-25",
		TunnelHealthy: true,
		Flows:         map[string]int64{"DIRECT": 3, "DESYNCED": 12, "TUNNEL": 2},
		Counters: core.Counters{
			PacketsTotal: 1000, PacketsPass: 900, PacketsDesync: 80, PacketsRedir: 18, PacketsDrop: 2,
			HandshakeOK: 40, HandshakeFail: 3,
			TunnelRx: 1 << 20, TunnelTx: 2 << 20,
			LastProbeAt: time.Now().Add(-time.Minute), LastProbeNote: "desync dead, tunnel alive",
		},
	}
	var buf bytes.Buffer
	renderSnapshot(&buf, s)
	out := buf.String()

	for _, want := range []string{
		"ACTIVE_TUNNEL_ONLY",
		"isp-home-2025-10-25",
		"tunnel:     healthy",
		"DESYNCED",
		"1000 / 900 / 80 / 18 / 2",
		"40 / 3",
		"desync dead, tunnel alive",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered output missing %q:\n%s", want, out)
		}
	}
}

func TestRenderSnapshotEmpty(t *testing.T) {
	var buf bytes.Buffer
	renderSnapshot(&buf, core.Snapshot{State: "OFF", Flows: map[string]int64{}})
	out := buf.String()
	if !strings.Contains(out, "state:      OFF") || !strings.Contains(out, "—") {
		t.Errorf("empty snapshot render broken:\n%s", out)
	}
}

func TestHumanHelpers(t *testing.T) {
	if humanBytes(512) != "512B" || humanBytes(2048) != "2.0KB" {
		t.Errorf("humanBytes: %q %q", humanBytes(512), humanBytes(2048))
	}
	if humanDur(90*time.Second) != "1m30s" || humanDur(2*time.Hour) != "2h0m" {
		t.Errorf("humanDur: %q %q", humanDur(90*time.Second), humanDur(2*time.Hour))
	}
}
