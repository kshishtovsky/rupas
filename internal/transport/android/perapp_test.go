package android

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/kshishtovsky/rupas/internal/config"
)

// perAppRules is the fixture used by the priority tests: a DIRECT CIDR, a
// DIRECT SNI, a BLOCK port rule and TUNNEL as the default — everything the
// app rule has to beat.
func perAppRules() []config.Rule {
	return []config.Rule{
		{CIDR: "142.250.0.0/16", Action: config.ActionDirect},
		{SNI: "*.example.com", Action: config.ActionDirect},
		{Ports: "5000", Proto: config.ProtoUDP, Action: config.ActionBlock},
		{Action: config.ActionTunnel},
	}
}

func newPerAppEngine(t *testing.T, appRules []AppRule, resolve UIDResolver) (*Engine, *[]string) {
	t.Helper()
	var logs []string
	e := NewW3EngineWithRules(
		&Settings{UUID: "u", Server: "s", Port: 443, AppRules: appRules},
		func(int) bool { return true },
		func(line string) { logs = append(logs, line) },
		"", perAppRules())
	if resolve != nil {
		e.SetUIDResolver(resolve)
	}
	return e, &logs
}

func flow(dst, sni string) FlowMeta {
	return FlowMeta{Network: "tcp", Destination: netip.MustParseAddrPort(dst), SNI: sni}
}

// §6 contract: app_rules parse into Settings, with the rule index in every
// error so the screen can point at the broken row.
func TestParseSettingsAppRules(t *testing.T) {
	s, err := ParseSettings(`{"uuid":"u","server":"s","port":443,"app_rules":[` +
		`{"uid":10101,"action":"tunnel"},{"uid":10202,"action":"BLOCK"},` +
		`{"uid":10303,"action":" Direct "}]}`)
	if err != nil {
		t.Fatalf("valid app_rules rejected: %v", err)
	}
	if len(s.AppRules) != 3 {
		t.Fatalf("app_rules len = %d, want 3", len(s.AppRules))
	}
	if s.AppRules[0].UID != 10101 || s.AppRules[1].Action != "BLOCK" {
		t.Fatalf("app_rules roundtrip mismatch: %+v", s.AppRules)
	}
	// Actions are case-insensitive on the way in.
	if act, err := parseAppAction(s.AppRules[2].Action); err != nil || act != ActionDirect {
		t.Fatalf("parseAppAction(%q) = %s, %v", s.AppRules[2].Action, act, err)
	}
}

func TestParseSettingsAppRulesRejects(t *testing.T) {
	cases := map[string]struct{ in, want string }{
		"unknown action": {
			`{"uuid":"u","server":"s","port":443,"app_rules":[{"uid":1,"action":"tunnel"},{"uid":2,"action":"proxy"}]}`,
			"app_rules[1]: unknown action",
		},
		"negative uid": {
			`{"uuid":"u","server":"s","port":443,"app_rules":[{"uid":-1,"action":"tunnel"}]}`,
			"app_rules[0]: uid must be >= 0",
		},
		"empty action": {
			`{"uuid":"u","server":"s","port":443,"app_rules":[{"uid":7,"action":""}]}`,
			"app_rules[0]: unknown action",
		},
		"wrong type": {
			`{"uuid":"u","server":"s","port":443,"app_rules":[{"uid":"10101","action":"tunnel"}]}`,
			"app_rules",
		},
	}
	for name, c := range cases {
		_, err := ParseSettings(c.in)
		if err == nil {
			t.Errorf("%s: must be rejected", name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error = %q, want it to contain %q", name, err, c.want)
		}
		if !strings.HasPrefix(err.Error(), "android: settings: ") {
			t.Errorf("%s: error %q must keep the android: settings: prefix", name, err)
		}
	}
}

// A DIRECT app rule is valid input but never lands in the UID table: the Java
// side keeps such an app out of the VPN entirely (§1).
func TestCompileAppRulesSkipsDirect(t *testing.T) {
	r := CompileRulesWithApps(perAppRules(), []AppRule{
		{UID: 10101, Action: "tunnel"},
		{UID: 10202, Action: "block"},
		{UID: 10303, Action: "direct"},
		{UID: 0, Action: "tunnel"},    // "unknown owner" is never a key
		{UID: 10101, Action: "block"}, // duplicate: the first rule wins
	}, "", nil)

	if act, ok := r.appAction(10101); !ok || act != ActionTunnel {
		t.Fatalf("uid 10101 = %s, %v; want TUNNEL (first rule wins)", act, ok)
	}
	if act, ok := r.appAction(10202); !ok || act != ActionBlock {
		t.Fatalf("uid 10202 = %s, %v; want BLOCK", act, ok)
	}
	if _, ok := r.appAction(10303); ok {
		t.Fatal("a direct app rule must not be compiled into the UID table")
	}
	if _, ok := r.appAction(0); ok {
		t.Fatal("uid 0 must never be a table key")
	}
	if !r.hasAppRules() {
		t.Fatal("hasAppRules must be true")
	}
	// No app rules: nil table, zero-cost gate closed.
	if plain := CompileRulesWith(perAppRules(), "", nil); plain.hasAppRules() {
		t.Fatal("hasAppRules must be false without app rules")
	}
	if r2 := CompileRulesWithApps(nil, []AppRule{{UID: 5, Action: "direct"}}, "", nil); r2.hasAppRules() {
		t.Fatal("a direct-only app rule set must leave the UID table empty")
	}
}

// §3: app(uid) outranks cidr → sni → ports → default.
func TestDecideAppRulePriority(t *testing.T) {
	e, _ := newPerAppEngine(t, []AppRule{
		{UID: 10101, Action: "tunnel"},
		{UID: 10202, Action: "block"},
		{UID: 10303, Action: "direct"},
	}, func(string, string, int, string, int) int { return 0 })

	cases := []struct {
		name string
		m    FlowMeta
		want Action
	}{
		{"app TUNNEL beats a DIRECT cidr", FlowMeta{UID: 10101, Network: "tcp", Destination: netip.MustParseAddrPort("142.250.1.1:443")}, ActionTunnel},
		{"app TUNNEL beats a DIRECT sni", FlowMeta{UID: 10101, Network: "tcp", Destination: netip.MustParseAddrPort("1.1.1.1:443"), SNI: "www.example.com"}, ActionTunnel},
		{"app BLOCK beats the TUNNEL default", FlowMeta{UID: 10202, Network: "tcp", Destination: netip.MustParseAddrPort("8.8.8.8:443")}, ActionBlock},
		{"app BLOCK beats a DIRECT cidr", FlowMeta{UID: 10202, Network: "tcp", Destination: netip.MustParseAddrPort("142.250.1.1:443")}, ActionBlock},
		{"app DIRECT rule is not applied by the core", FlowMeta{UID: 10303, Network: "tcp", Destination: netip.MustParseAddrPort("142.250.1.1:443")}, ActionDirect},
		{"unknown uid falls through to the cidr", FlowMeta{UID: 99999, Network: "tcp", Destination: netip.MustParseAddrPort("142.250.1.1:443")}, ActionDirect},
		{"unknown uid falls through to the sni", FlowMeta{UID: 99999, Network: "tcp", Destination: netip.MustParseAddrPort("1.1.1.1:443"), SNI: "a.example.com"}, ActionDirect},
		{"unknown uid falls through to the default", FlowMeta{UID: 99999, Network: "tcp", Destination: netip.MustParseAddrPort("8.8.8.8:443")}, ActionTunnel},
		{"uid 0 keeps the pre-feature behaviour (cidr)", flow("142.250.1.1:443", ""), ActionDirect},
		{"uid 0 keeps the pre-feature behaviour (default)", flow("8.8.8.8:443", ""), ActionTunnel},
		{"uid 0 keeps the pre-feature behaviour (port)", FlowMeta{Network: "udp", Destination: netip.MustParseAddrPort("8.8.8.8:5000")}, ActionBlock},
		{"app TUNNEL beats a BLOCK port rule", FlowMeta{UID: 10101, Network: "udp", Destination: netip.MustParseAddrPort("8.8.8.8:5000")}, ActionTunnel},
	}
	for _, c := range cases {
		if got := e.decide(c.m); got != c.want {
			t.Errorf("%s: decide = %s, want %s", c.name, got, c.want)
		}
	}
}

// An app rule is a final pre-decision: it outranks SNI, so the flow must not
// pay the ClientHello peek at all.
func TestDecidePreAppRuleIsFinal(t *testing.T) {
	e, _ := newPerAppEngine(t, []AppRule{
		{UID: 10101, Action: "tunnel"},
		{UID: 10202, Action: "block"},
	}, nil)

	for uid, want := range map[int]Action{10101: ActionTunnel, 10202: ActionBlock} {
		act, final := e.decidePre(FlowMeta{UID: uid, Network: "tcp", Destination: netip.MustParseAddrPort("8.8.8.8:443")})
		if !final || act != want {
			t.Errorf("uid %d: decidePre = %s final=%v, want %s final=true", uid, act, final, want)
		}
	}
	// No UID: the table decides, and with domain rules compiled the verdict
	// is not final (the ClientHello may still classify the flow).
	if act, final := e.decidePre(flow("8.8.8.8:443", "")); final || act != ActionTunnel {
		t.Errorf("uid 0: decidePre = %s final=%v, want %s final=false", act, final, ActionTunnel)
	}
}

// §2: the UID resolve is a no-op unless per-app rules are configured.
func TestResolveUIDGatedOnAppRules(t *testing.T) {
	calls := 0
	resolve := func(network, srcIP string, srcPort int, dstIP string, dstPort int) int {
		calls++
		if network == "tcp" && srcIP == "10.0.0.2" && dstIP == "1.1.1.1" && srcPort == 41000 && dstPort == 443 {
			return 10101
		}
		return -1
	}
	m := FlowMeta{
		Network:     "tcp",
		Source:      netip.MustParseAddrPort("10.0.0.2:41000"),
		Destination: netip.MustParseAddrPort("1.1.1.1:443"),
	}

	// No per-app rules: zero platform calls, UID stays unknown.
	e, _ := newPerAppEngine(t, nil, resolve)
	if got := e.resolveUID(m); got != 0 {
		t.Fatalf("uid = %d, want 0 without app rules", got)
	}
	if calls != 0 {
		t.Fatalf("platform resolver called %d times without app rules, want 0", calls)
	}

	// Per-app rules present: one call, and the answer is normalised
	// (-1/0 → 0 = "unknown", §7.4).
	e, _ = newPerAppEngine(t, []AppRule{{UID: 10101, Action: "tunnel"}}, resolve)
	if got := e.resolveUID(m); got != 10101 {
		t.Fatalf("uid = %d, want 10101", got)
	}
	if calls != 1 {
		t.Fatalf("platform resolver called %d times, want 1", calls)
	}
	if got := e.resolveUID(FlowMeta{Network: "tcp", Source: netip.MustParseAddrPort("10.0.0.3:1"), Destination: netip.MustParseAddrPort("1.1.1.1:443")}); got != 0 {
		t.Fatalf("uid = %d, want 0 for an unresolved flow", got)
	}

	// No resolver at all (dev host / API < 29 build): honest degradation.
	e, _ = newPerAppEngine(t, []AppRule{{UID: 10101, Action: "tunnel"}}, nil)
	if got := e.resolveUID(m); got != 0 {
		t.Fatalf("uid = %d, want 0 without a resolver", got)
	}
}

// One log line per flow, in the shape the acceptance log looks for.
func TestLogAppRule(t *testing.T) {
	e, logs := newPerAppEngine(t, []AppRule{
		{UID: 10101, Action: "tunnel"},
		{UID: 10202, Action: "block"},
	}, nil)

	e.logAppRule(FlowMeta{UID: 10101, Network: "tcp", Destination: netip.MustParseAddrPort("1.1.1.1:443")})
	e.logAppRule(FlowMeta{UID: 10202, Network: "udp", Destination: netip.MustParseAddrPort("1.1.1.1:443")})
	e.logAppRule(FlowMeta{UID: 99999, Network: "tcp", Destination: netip.MustParseAddrPort("1.1.1.1:443")})
	e.logAppRule(FlowMeta{UID: 0, Network: "tcp", Destination: netip.MustParseAddrPort("1.1.1.1:443")})

	if len(*logs) != 2 {
		t.Fatalf("logged %d lines, want 2 (only the matching uids): %q", len(*logs), *logs)
	}
	if !strings.Contains((*logs)[0], "app uid=10101 → TUNNEL") {
		t.Errorf("log line = %q, want it to contain %q", (*logs)[0], "app uid=10101 → TUNNEL")
	}
	if !strings.Contains((*logs)[1], "app uid=10202 → BLOCK") {
		t.Errorf("log line = %q, want it to contain %q", (*logs)[1], "app uid=10202 → BLOCK")
	}
}

// The gate must stay free: with no per-app rules the decision path allocates
// nothing per flow, and neither does a UID lookup when rules exist. The engine
// here carries no settings, so the measurement covers the rule table plus the
// UID stage only (isEndpoint has its own pre-existing cost).
func TestDecideZeroAlloc(t *testing.T) {
	plain := &Engine{rules: CompileRulesWith(perAppRules(), "", nil), verdict: DirectVerdict, logFn: func(string) {}}
	withApps := &Engine{rules: CompileRulesWithApps(perAppRules(), []AppRule{{UID: 10101, Action: "tunnel"}}, "", nil),
		verdict: DirectVerdict, logFn: func(string) {}}

	m := FlowMeta{Network: "tcp", Destination: netip.MustParseAddrPort("142.250.1.1:443")}
	if got := testing.AllocsPerRun(200, func() { plain.decide(m) }); got != 0 {
		t.Errorf("decide without app rules: %v allocs/op, want 0", got)
	}
	if got := testing.AllocsPerRun(200, func() { plain.resolveUID(m) }); got != 0 {
		t.Errorf("resolveUID without app rules: %v allocs/op, want 0", got)
	}

	hit := m
	hit.UID = 10101
	if got := testing.AllocsPerRun(200, func() { withApps.decide(hit) }); got != 0 {
		t.Errorf("decide with an app rule hit: %v allocs/op, want 0", got)
	}
	if got := testing.AllocsPerRun(200, func() { _, _ = withApps.decidePre(hit) }); got != 0 {
		t.Errorf("decidePre with an app rule hit: %v allocs/op, want 0", got)
	}
	if _, final := withApps.decidePre(hit); !final {
		t.Error("decidePre must be final on an app rule hit")
	}
}

// The UID stage must not disturb the table itself: same flow, same answer,
// with and without app rules compiled.
func TestTableUnchangedByAppRules(t *testing.T) {
	withApps := CompileRulesWithApps(perAppRules(), []AppRule{{UID: 1, Action: "block"}}, "", nil)
	plain := CompileRulesWith(perAppRules(), "", nil)
	for _, dst := range []string{"142.250.1.1:443", "8.8.8.8:443", "1.1.1.1:5000"} {
		m := FlowMeta{Network: "tcp", Destination: netip.MustParseAddrPort(dst)}
		if a, b := withApps.Decide(m), plain.Decide(m); a != b {
			t.Errorf("%s: table decision changed by app rules: %s vs %s", dst, a, b)
		}
	}
}

func BenchmarkDecideNoAppRules(b *testing.B) {
	plain := CompileRulesWith(perAppRules(), "", nil)
	m := FlowMeta{Network: "tcp", Destination: netip.MustParseAddrPort("142.250.1.1:443")}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = plain.Decide(m)
	}
}

func BenchmarkAppActionHit(b *testing.B) {
	r := CompileRulesWithApps(perAppRules(), []AppRule{{UID: 10101, Action: "tunnel"}}, "", nil)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = r.appAction(10101)
	}
}
