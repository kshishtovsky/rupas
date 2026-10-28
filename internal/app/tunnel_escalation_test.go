//go:build windows

package app

// Escalation-mode pipeline test (no sing-box/uTLS needed): -tunnel=on
// with an empty endpoint must NOT fail the pipeline — the TUNNEL rules are
// escalated (sni→desync, cidr/port→direct), logged and counted, and the
// NAT branch stays off (a TUNNEL-verdict flow passes as DIRECT).

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/kshishtovsky/rupas/internal/capture"
	"github.com/kshishtovsky/rupas/internal/config"
)

func TestPipelineTunnelEscalationNoEndpoint(t *testing.T) {
	lo := netip.MustParseAddr("127.0.0.1")
	tgDst := netip.MustParseAddr("149.154.167.51")
	cfg := config.Default() // tunnel section intentionally empty
	mainT := newAppFakeTransport()
	loopT := newAppFakeTransport()

	p := newPipeline(pipelineDeps{
		tpl: validTpl(), tunnel: true, tproxyPort: 20123,
		log:        discardLogger(),
		engineHook: func(eng *capture.Engine) { eng.InjectTransport(mainT, loopT) },
	})
	if err := p.Start(cfg); err != nil {
		t.Fatalf("pipeline start with empty endpoint: %v", err)
	}
	defer func() { _ = p.Stop() }()

	st := p.Stats()
	if st.TunnelMode != tunnelModeEscalated {
		t.Fatalf("mode = %q, want escalated", st.TunnelMode)
	}
	if st.TunnelEscalated != 4 { // 3 TG CIDRs + UDP relay ports
		t.Fatalf("escalated rules = %d, want 4", st.TunnelEscalated)
	}
	if st.Tunnel != nil {
		t.Fatal("no live tunnel stats may exist in escalated mode")
	}
	if asm, _ := p.TunnelHealth(); asm {
		t.Fatal("escalated mode must report no assembled tunnel")
	}

	// A TUNNEL-verdict flow (TG CIDR) is passed as DIRECT — never
	// black-holed at a dead loopback port.
	mainT.Enqueue(buildTCP4(lo, 4242, tgDst, 443, 1000, 0x02, nil), true)
	mainT.Enqueue(buildTCP4(lo, 4242, tgDst, 443, 1001, 0x18, buildClientHello("telegram.org")), true)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(mainT.Sent()) >= 2 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	sent := mainT.Sent()
	if len(sent) < 2 {
		t.Fatalf("engine did not process the flow: %d sends", len(sent))
	}
	tg4 := tgDst.As4()
	for _, pkt := range sent {
		if binary.BigEndian.Uint16(pkt[22:24]) != 443 ||
			pkt[16] != tg4[0] || pkt[17] != tg4[1] || pkt[18] != tg4[2] || pkt[19] != tg4[3] {
			t.Fatalf("packet rewritten in escalated mode: dst=%v:%d", net.IP(pkt[16:20]), binary.BigEndian.Uint16(pkt[22:24]))
		}
	}
	st = p.Stats()
	if st.Counters.PacketsRedir != 0 {
		t.Fatalf("redirect counter moved in escalated mode: %+v", st.Counters)
	}

	// Tunnel-off mode: demotion, no escalation counter.
	p2 := newPipeline(pipelineDeps{tpl: validTpl(), tunnel: false, log: discardLogger()})
	if err := p2.Start(cfg); err == nil {
		_ = p2.Stop()
	} else {
		t.Fatalf("tunnel-off pipeline: %v", err)
	}
	st2 := p2.Stats()
	if st2.TunnelMode != tunnelModeOff || st2.TunnelEscalated != 0 {
		t.Fatalf("off mode stats: %+v", st2)
	}
}
