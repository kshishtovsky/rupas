package rules

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kshishtovsky/rupas/internal/config"
	"github.com/kshishtovsky/rupas/internal/geoip"
)

// tracePolicy is the fixture used by the stage tests: one rule per stage plus
// a wildcard domain and a proto-scoped QUIC block.
func tracePolicy() []config.Rule {
	return []config.Rule{
		{CIDR: "10.0.0.0/8", Action: config.ActionDirect},
		{CIDR: "91.108.0.0/16", Action: config.ActionTunnel},
		{SNI: "discord.com", Action: config.ActionTunnel},
		{SNI: "*.googlevideo.com", Action: config.ActionDesync},
		{Ports: "443", Proto: config.ProtoUDP, Action: config.ActionBlock},
		{Ports: "53", Action: config.ActionDirect},
		{Action: config.ActionTunnel},
	}
}

func mustTrace(t *testing.T, rules []config.Rule, query string) Trace {
	t.Helper()
	tr, err := TestRoute(rules, query)
	if err != nil {
		t.Fatalf("TestRoute(%q): %v", query, err)
	}
	return tr
}

func TestTestRouteStage1CIDR(t *testing.T) {
	tr := mustTrace(t, tracePolicy(), "91.108.4.1")
	if tr.Stage != StageIP || tr.StageName != "IP-адреса" {
		t.Fatalf("stage = %d/%q, want 1/IP-адреса", tr.Stage, tr.StageName)
	}
	if tr.Matcher != "91.108.0.0/16" {
		t.Errorf("matcher = %q, want 91.108.0.0/16", tr.Matcher)
	}
	if tr.Action != config.ActionTunnel {
		t.Errorf("action = %v, want TUNNEL", tr.Action)
	}
	// The domain stage never applies to an IP query (§5.5).
	if !strings.Contains(tr.Note, "домены не проверяются для IP") {
		t.Errorf("note = %q, want the IP/domain remark", tr.Note)
	}
}

func TestTestRouteStage2ExactAndWildcard(t *testing.T) {
	exact := mustTrace(t, tracePolicy(), "discord.com")
	if exact.Stage != StageDomain || exact.StageName != "Домены" {
		t.Fatalf("exact: stage = %d/%q, want 2/Домены", exact.Stage, exact.StageName)
	}
	if exact.Matcher != "discord.com" || exact.Action != config.ActionTunnel {
		t.Errorf("exact: matcher/action = %q/%v", exact.Matcher, exact.Action)
	}

	wild := mustTrace(t, tracePolicy(), "r1---sn-abc.googlevideo.com")
	if wild.Stage != StageDomain || wild.Matcher != "*.googlevideo.com" {
		t.Fatalf("wildcard: stage/matcher = %d/%q", wild.Stage, wild.Matcher)
	}
	if wild.Action != config.ActionDesync {
		t.Errorf("wildcard action = %v, want DESYNC", wild.Action)
	}

	// Label boundary: "notgooglevideo.com" is not a *.googlevideo.com host.
	other := mustTrace(t, tracePolicy(), "notgooglevideo.com")
	if other.Stage != StageDefault {
		t.Errorf("boundary: stage = %d, want 4 (default)", other.Stage)
	}
}

func TestTestRouteStage3Ports(t *testing.T) {
	// A plain probe means TCP: the udp-scoped QUIC block must NOT decide it.
	tr := mustTrace(t, tracePolicy(), "8.8.8.8:443")
	if tr.Stage == StagePort && tr.Matcher == "ports 443/udp" {
		t.Errorf("plain :443 probe picked the udp QUIC block (action %v); it must evaluate TCP", tr.Action)
	}

	// An explicit /udp probe is what the QUIC block answers.
	tr = mustTrace(t, tracePolicy(), "8.8.8.8:443/udp")
	if tr.Stage != StagePort || tr.Matcher != "ports 443/udp" {
		t.Fatalf("udp probe: stage/matcher = %d/%q, want 3/ports 443/udp", tr.Stage, tr.Matcher)
	}
	if tr.Action != config.ActionBlock {
		t.Errorf("udp probe: action = %v, want BLOCK", tr.Action)
	}

	// Exact-port hit on the unscoped bucket.
	tr = mustTrace(t, tracePolicy(), "8.8.8.8:53")
	if tr.Stage != StagePort || tr.Matcher != "ports 53" || tr.Action != config.ActionDirect {
		t.Errorf("dns: stage/matcher/action = %d/%q/%v", tr.Stage, tr.Matcher, tr.Action)
	}
}

// TestTestRouteBareIPIsTCP is the regression for the QUIC-block leak: a bare
// IP probe used to walk the udp bucket, so "1.1.1.1" answered BLOCK.
func TestTestRouteBareIPIsTCP(t *testing.T) {
	tr := mustTrace(t, tracePolicy(), "1.1.1.1")
	if tr.Action == config.ActionBlock {
		t.Fatalf("bare IP resolved to BLOCK via the udp QUIC rule; want the TCP view")
	}
	if tr.Stage != StageDefault {
		t.Errorf("stage = %d, want 4 (default)", tr.Stage)
	}
}

// TestTestRouteRuleSetWarningOutsideNote: a missing geoip table is a remark
// about the RULE SET, so it rides Trace.Warning and never decorates every
// per-query Note.
func TestTestRouteRuleSetWarningOutsideNote(t *testing.T) {
	rules := []config.Rule{
		{GeoIP: "zz", Action: config.ActionDirect},
		{Action: config.ActionTunnel},
	}
	tr := mustTrace(t, rules, "example.com")
	if tr.Warning == "" {
		t.Fatalf("warning = empty, want the missing geoip table remark")
	}
	if strings.Contains(tr.Note, "geoip") {
		t.Errorf("note = %q, must not carry the rule-set remark", tr.Note)
	}
	// A readable rule set carries no warning at all.
	if ok := mustTrace(t, tracePolicy(), "example.com"); ok.Warning != "" {
		t.Errorf("warning = %q on a healthy rule set, want empty", ok.Warning)
	}
}

func TestTestRouteStage4Default(t *testing.T) {
	tr := mustTrace(t, tracePolicy(), "example.com")
	if tr.Stage != StageDefault || tr.StageName != "по умолчанию" {
		t.Fatalf("stage = %d/%q, want 4/по умолчанию", tr.Stage, tr.StageName)
	}
	// The default stage carries no matcher: the screen renders its own copy.
	if tr.Matcher != "" {
		t.Errorf("matcher = %q, want empty on the default stage", tr.Matcher)
	}
	if tr.Action != config.ActionTunnel {
		t.Errorf("action = %v, want TUNNEL", tr.Action)
	}
	// A domain query has no port: the port stage must be reported as skipped,
	// not evaluated against an invented 443.
	if !strings.Contains(tr.Note, "порты не проверяются") {
		t.Errorf("note = %q, want the port remark", tr.Note)
	}
}

func TestTestRouteDangerousDefaultNote(t *testing.T) {
	rules := []config.Rule{
		{CIDR: "10.0.0.0/8", Action: config.ActionDirect},
		{Action: config.ActionDirect},
	}
	tr := mustTrace(t, rules, "example.com")
	if tr.Action != config.ActionDirect {
		t.Fatalf("action = %v, want DIRECT", tr.Action)
	}
	if !strings.Contains(tr.Note, "реальный IP не скрыт") {
		t.Errorf("note = %q, want the DIRECT-default warning", tr.Note)
	}
}

// TestTestRouteIPSkipsDomainRules pins the §5.5 rule: a domain rule can never
// decide an IP probe.
func TestTestRouteIPSkipsDomainRules(t *testing.T) {
	rules := []config.Rule{
		{SNI: "*.googlevideo.com", Action: config.ActionDesync},
		{CIDR: "10.0.0.0/8", Action: config.ActionDirect},
		{Action: config.ActionTunnel},
	}
	tr := mustTrace(t, rules, "1.2.3.4")
	if tr.Stage != StageDefault || tr.Action != config.ActionTunnel {
		t.Fatalf("IP probe: stage/action = %d/%v, want 4/TUNNEL", tr.Stage, tr.Action)
	}
}

// TestTestRouteMostSpecificCIDRWins checks the longest-prefix rule against the
// engine's own table, not just against the tracer.
func TestTestRouteMostSpecificCIDRWins(t *testing.T) {
	rules := []config.Rule{
		{CIDR: "10.0.0.0/8", Action: config.ActionDirect},
		{CIDR: "10.1.0.0/16", Action: config.ActionTunnel},
		{Action: config.ActionDirect},
	}
	tr := mustTrace(t, rules, "10.1.2.3")
	if tr.Matcher != "10.1.0.0/16" || tr.Action != config.ActionTunnel {
		t.Fatalf("matcher/action = %q/%v, want 10.1.0.0/16 TUNNEL", tr.Matcher, tr.Action)
	}
}

// TestTestRouteMatchesEngine cross-checks the tracer against the hot-path
// table for every interesting probe: the screen must never disagree with the
// daemon.
func TestTestRouteMatchesEngine(t *testing.T) {
	rules := tracePolicy()
	table, err := Compile(&config.Config{
		Profile: "trace-crosscheck",
		Rules:   rules,
		Desync:  config.DesyncParams{Strategy: "fake", TTL: 13, Repeats: 1},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	cases := []struct {
		query string
		ip    string
		sni   string
		port  uint16
		proto string
	}{
		{"91.108.4.1", "91.108.4.1", "", 443, config.ProtoTCP},
		{"91.108.4.1", "91.108.4.1", "", 443, config.ProtoUDP},
		{"10.1.2.3", "10.1.2.3", "", 443, config.ProtoTCP},
		{"8.8.8.8:443", "8.8.8.8", "", 443, config.ProtoUDP},
		{"8.8.8.8:53", "8.8.8.8", "", 53, config.ProtoUDP},
		{"discord.com", "1.2.3.4", "discord.com", 443, config.ProtoTCP},
		{"r1---sn-abc.googlevideo.com", "1.2.3.4", "r1---sn-abc.googlevideo.com", 443, config.ProtoTCP},
		{"example.com", "1.2.3.4", "example.com", 443, config.ProtoTCP},
	}
	for _, c := range cases {
		ip := netip.MustParseAddr(c.ip).As16()
		want := table.MatchProto(ip, c.sni, c.port, c.proto)
		// The trace evaluates an unspecified transport as TCP, so the probe
		// must name the transport the engine call is using.
		q := c.query
		if c.proto != "" && strings.Contains(q, ":") {
			q += "/" + c.proto
		}
		got := mustTrace(t, rules, q)
		if got.Action != want {
			t.Errorf("%s (proto %q): trace says %v, engine says %v (stage %d matcher %q)",
				q, c.proto, got.Action, want, got.Stage, got.Matcher)
		}
	}
}

func TestTestRouteProtoScopedSNI(t *testing.T) {
	rules := []config.Rule{
		{SNI: "quic.example", Proto: config.ProtoUDP, Action: config.ActionBlock},
		{SNI: "quic.example", Proto: config.ProtoTCP, Action: config.ActionDirect},
		{Action: config.ActionTunnel},
	}
	tr := mustTrace(t, rules, "quic.example")
	if tr.Action != config.ActionDirect {
		t.Errorf("domain probe is TCP: action = %v, want DIRECT (the udp rule must not fire)", tr.Action)
	}
}

func TestTestRouteInvalidRules(t *testing.T) {
	cases := []struct {
		name  string
		rules []config.Rule
	}{
		{"overlapping ports", []config.Rule{
			{Ports: "1000-2000", Action: config.ActionDirect},
			{Ports: "1500", Action: config.ActionTunnel},
		}},
		{"two matchers", []config.Rule{
			{CIDR: "10.0.0.0/8", SNI: "a.com", Action: config.ActionDirect},
		}},
		{"missing action", []config.Rule{{SNI: "a.com"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := TestRoute(c.rules, "example.com"); err == nil {
				t.Fatal("want a validation error")
			}
		})
	}
	if _, err := TestRoute(tracePolicy(), "   "); err == nil {
		t.Fatal("want an error for an empty query")
	}
}

func TestTestRouteGeoIPFromCache(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "geoip-ru.txt"), []byte("203.0.113.0/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rules := []config.Rule{
		{GeoIP: "ru", Action: config.ActionDirect},
		{Action: config.ActionTunnel},
	}
	geo := geoip.Params{Dir: dir}
	tr, err := TestRouteWithGeo(rules, "203.0.113.9", geo)
	if err != nil {
		t.Fatalf("TestRouteWithGeo: %v", err)
	}
	if tr.Stage != StageIP || tr.Matcher != "geoip: ru" || tr.Action != config.ActionDirect {
		t.Fatalf("geoip hit: stage/matcher/action = %d/%q/%v", tr.Stage, tr.Matcher, tr.Action)
	}

	// No cache → the rule is skipped with a note, never downloaded.
	empty := t.TempDir()
	tr, err = TestRouteWithGeo(rules, "203.0.113.9", geoip.Params{Dir: empty})
	if err != nil {
		t.Fatalf("TestRouteWithGeo (no cache): %v", err)
	}
	if tr.Stage != StageDefault {
		t.Fatalf("no-cache stage = %d, want 4", tr.Stage)
	}
	if !strings.Contains(tr.Warning, "geoip") {
		t.Errorf("warning = %q, want a geoip remark", tr.Warning)
	}
}

func TestTraceJSONShape(t *testing.T) {
	b, err := json.Marshal(mustTrace(t, tracePolicy(), "discord.com"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"stage":2`, `"stageName":"Домены"`, `"matcher":"discord.com"`, `"action":"TUNNEL"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("trace JSON %s misses %s", b, want)
		}
	}
}
