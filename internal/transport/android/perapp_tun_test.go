//go:build !windows

package android

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-tun"
)

// Per-app routing at the TUN seam: JudgeFlow must resolve the app UID for UDP
// (the whole UDP decision is made there) and must NOT resolve it for TCP —
// relayTCP owns that resolve, and doing it twice would double the per-flow
// platform call (docs/PERAPP_ROUTING.md §2).
func TestJudgeFlowAppRuleUID(t *testing.T) {
	calls := 0
	resolve := func(network, srcIP string, srcPort int, dstIP string, dstPort int) int {
		calls++
		return 10101
	}
	e := &Engine{
		rules:      CompileRulesWithApps(perAppRules(), []AppRule{{UID: 10101, Action: "block"}}, "", nil),
		verdict:    DirectVerdict,
		logFn:      func(string) {},
		preferIPv4: true,
		uidResolve: resolve,
	}
	h := &flowHandler{engine: e}
	src := netip.MustParseAddrPort("10.0.0.2:33000")
	dst := netip.MustParseAddrPort("1.1.1.1:443")

	// UDP: the app rule blocks the flow at the netstack, no egress at all.
	if v := h.JudgeFlow(17, src, dst, nil); v.Action != tun.ActionDrop {
		t.Errorf("udp flow of a blocked uid: verdict = %v, want drop", v.Action)
	}
	if calls != 1 {
		t.Errorf("udp flow resolved the uid %d times, want 1", calls)
	}

	// TCP: accepted here, judged (and resolved) in relayTCP.
	calls = 0
	if v := h.JudgeFlow(6, src, dst, nil); v.Action != tun.ActionAccept {
		t.Errorf("tcp flow: verdict = %v, want accept", v.Action)
	}
	if calls != 0 {
		t.Errorf("tcp flow resolved the uid %d times in JudgeFlow, want 0", calls)
	}

	// A TUNNEL app rule keeps the flow alive (it is routed, not dropped).
	e.rules = CompileRulesWithApps(perAppRules(), []AppRule{{UID: 10101, Action: "tunnel"}}, "", nil)
	if v := h.JudgeFlow(17, src, dst, nil); v.Action != tun.ActionAccept {
		t.Errorf("udp flow of a tunnel uid: verdict = %v, want accept", v.Action)
	}
}
