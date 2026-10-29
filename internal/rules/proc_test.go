package rules

import (
	"testing"

	"github.com/kshishtovsky/rupas/internal/config"
)

// procTable compiles rules into a table over a minimal valid config.
func procTable(t *testing.T, rules ...config.Rule) *Table {
	t.Helper()
	tbl, err := Compile(&config.Config{Profile: "proc-test", Rules: rules})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return tbl
}

// TestMatchProcAppStageFirst pins the resolution order of PLAN-0.8 §1.1:
// app → cidr → sni → port → default. A process rule means "all traffic of
// this process", so it outranks destination matches; an unmatched or
// unknown (empty) app falls through to them.
func TestMatchProcAppStageFirst(t *testing.T) {
	tbl := procTable(t,
		config.Rule{App: "Steam.EXE", Action: config.ActionDirect}, // normalized in Validate
		config.Rule{CIDR: "1.2.3.0/24", Action: config.ActionTunnel},
		config.Rule{SNI: "store.steampowered.com", Action: config.ActionBlock},
	)
	if !tbl.HasApps() {
		t.Fatal("HasApps = false, want true")
	}
	cases := []struct {
		name, sni, app string
		ip             [16]byte
		want           config.Action
	}{
		{"app outranks cidr and sni", "store.steampowered.com", "steam.exe", v4(1, 2, 3, 4), config.ActionDirect},
		{"app misses, cidr fires", "", "other.exe", v4(1, 2, 3, 4), config.ActionTunnel},
		{"app misses, sni fires", "store.steampowered.com", "other.exe", v4(9, 9, 9, 9), config.ActionBlock},
		{"no app, cidr fires", "", "", v4(1, 2, 3, 4), config.ActionTunnel},
		{"no app, sni fires", "store.steampowered.com", "", v4(9, 9, 9, 9), config.ActionBlock},
		{"no app, nothing matches", "", "", v4(9, 9, 9, 9), config.ActionDirect},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tbl.MatchProc(c.ip, c.sni, 443, config.ProtoTCP, c.app); got != c.want {
				t.Errorf("MatchProc(app=%q, sni=%q) = %v, want %v", c.app, c.sni, got, c.want)
			}
		})
	}
}

// TestMatchProcProtoScope: a proto-scoped app rule never fires for the
// other transport, and an unscoped app rule answers both.
func TestMatchProcProtoScope(t *testing.T) {
	tbl := procTable(t,
		config.Rule{App: "discord.exe", Proto: config.ProtoUDP, Action: config.ActionBlock},
		config.Rule{App: "steam.exe", Proto: config.ProtoTCP, Action: config.ActionTunnel},
		config.Rule{App: "both.exe", Action: config.ActionDirect},
	)
	if !tbl.HasApps() {
		t.Fatal("HasApps = false, want true")
	}
	cases := []struct {
		name, proto, app string
		want             config.Action
	}{
		{"udp rule on udp", config.ProtoUDP, "discord.exe", config.ActionBlock},
		{"udp rule not on tcp", config.ProtoTCP, "discord.exe", config.ActionDirect},
		{"tcp rule on tcp", config.ProtoTCP, "steam.exe", config.ActionTunnel},
		{"tcp rule not on udp", config.ProtoUDP, "steam.exe", config.ActionDirect},
		{"unscoped rule on tcp", config.ProtoTCP, "both.exe", config.ActionDirect},
		{"unscoped rule on udp", config.ProtoUDP, "both.exe", config.ActionDirect},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := tbl.MatchProc(v4(9, 9, 9, 9), "", 443, c.proto, c.app); got != c.want {
				t.Errorf("MatchProc(proto=%q, app=%q) = %v, want %v", c.proto, c.app, got, c.want)
			}
		})
	}
}

// TestMatchProcDuplicateFirstWins: two rules for the same (name, proto)
// key — the first one decides, as in every other stage.
func TestMatchProcDuplicateFirstWins(t *testing.T) {
	tbl := procTable(t,
		config.Rule{App: "steam.exe", Action: config.ActionDirect},
		config.Rule{App: "STEAM.exe", Action: config.ActionBlock},
	)
	if got := tbl.MatchProc(v4(9, 9, 9, 9), "", 443, config.ProtoTCP, "steam.exe"); got != config.ActionDirect {
		t.Errorf("duplicate app key: got %v, want the first rule's DIRECT", got)
	}
}

// TestMatchProcZeroAlloc guards the hot path: MatchProc must not allocate,
// app stage included.
func TestMatchProcZeroAlloc(t *testing.T) {
	tbl := procTable(t,
		config.Rule{App: "steam.exe", Action: config.ActionDirect},
		config.Rule{CIDR: "10.0.0.0/8", Action: config.ActionTunnel},
	)
	ip := v4(10, 0, 0, 1)
	if n := testing.AllocsPerRun(100, func() {
		tbl.MatchProc(ip, "store.steampowered.com", 443, config.ProtoTCP, "steam.exe")
	}); n != 0 {
		t.Errorf("MatchProc allocates %.2f objects per call, want 0", n)
	}
}

// TestAppRuleJSON covers the JSON face: the field decodes, is lower-cased,
// and still obeys the one-matcher rule.
func TestAppRuleJSON(t *testing.T) {
	rules, err := config.ParseRulesJSON([]byte(`[{"app":"Steam.EXE","action":"direct"}]`))
	if err != nil {
		t.Fatalf("ParseRulesJSON: %v", err)
	}
	if rules[0].App != "steam.exe" {
		t.Errorf("app = %q, want lower-case \"steam.exe\"", rules[0].App)
	}
	for _, src := range []string{
		`[{"app":"steam.exe","cidr":"10.0.0.0/8","action":"direct"}]`,
		`[{"app":"C:\\Steam\\steam.exe","action":"direct"}]`,
	} {
		if _, err := config.ParseRulesJSON([]byte(src)); err == nil {
			t.Errorf("ParseRulesJSON(%s) = nil error, want a validation error", src)
		}
	}
	// The YAML face too: `app:` must decode, and normalization is the same.
	cfg, err := config.Unmarshal([]byte("profile: p\nrules:\n  - app: Steam.EXE\n    proto: udp\n    action: direct\n"))
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if got := cfg.Rules[0].App; got != "steam.exe" {
		t.Errorf("yaml app = %q, want lower-case \"steam.exe\"", got)
	}
}
