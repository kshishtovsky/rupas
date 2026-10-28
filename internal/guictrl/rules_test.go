package guictrl

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kshishtovsky/rupas/internal/config"
)

// savedOffline tolerates the "daemon unreachable" warning: the save contract
// keeps the file on disk and only reports that reload is unconfirmed.
func savedOffline(t *testing.T, err error) {
	t.Helper()
	if err != nil && !errors.Is(err, ErrDaemonDown) {
		t.Fatalf("save: %v", err)
	}
}

// newRulesController points a Controller at a throwaway config (no daemon:
// the reload call fails, which the save contract tolerates).
func newRulesController(t *testing.T, body string) (*Controller, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rupas.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := New(Options{ConfigPath: path, Pipe: `\\.\pipe\rupas-test-nonexistent`})
	if err != nil {
		t.Fatal(err)
	}
	return c, path
}

const rulesFixture = `profile: owner
rules:
  - cidr: 10.0.0.0/8
    action: direct
  - cidr: 149.154.160.0/20
    action: tunnel
  - geoip: ru
    action: direct
  - sni: discord.com
    action: tunnel
  - sni: '*.googlevideo.com'
    action: desync
  - ports: '443'
    proto: udp
    action: block
  - action: tunnel
desync:
  strategy: fake
  ttl: 13
  repeats: 1
tunnel:
  protocol: vless
  address: 203.0.113.7
  port: 443
  uuid: 11111111-2222-3333-4444-555555555555
  reality_public_key: pub
  sni: camouflage.example
`

func TestLoadRulesView(t *testing.T) {
	c, _ := newRulesController(t, rulesFixture)
	view, err := c.LoadRules()
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	if view.Error != "" {
		t.Errorf("unexpected engine error: %s", view.Error)
	}
	// 6 matching rules + the default pulled into its own zone.
	if len(view.Rules) != 6 {
		t.Fatalf("got %d rule views, want 6", len(view.Rules))
	}
	if view.Default.Action != "TUNNEL" || view.Default.Index != 6 {
		t.Errorf("default = %+v, want TUNNEL at index 6", view.Default)
	}
	if view.StageCounts != [3]int{3, 2, 1} {
		t.Errorf("stage counts = %v, want [3 2 1]", view.StageCounts)
	}
	if view.Rules[0].Kind != KindCIDR || view.Rules[0].Human == "" {
		t.Errorf("cidr row = %+v, want a kind and a human hint", view.Rules[0])
	}
	if view.Rules[1].Human != "4096 адресов" {
		t.Errorf("/20 hint = %q, want 4096 адресов", view.Rules[1].Human)
	}
	if view.Rules[2].Kind != KindGeoIP || view.Rules[2].Matcher != "ru" {
		t.Errorf("geoip row = %+v, want kind geoip + raw matcher", view.Rules[2])
	}
	if view.Rules[4].Kind != KindSNI || view.Rules[4].Matcher != "*.googlevideo.com" {
		t.Errorf("wildcard row = %+v", view.Rules[4])
	}
	if view.Rules[5].Kind != KindPorts || !strings.Contains(view.Rules[5].Human, "udp") {
		t.Errorf("ports row = %+v, want a udp hint", view.Rules[5])
	}
}

func TestTestRouteGUI(t *testing.T) {
	c, _ := newRulesController(t, rulesFixture)
	out, err := c.TestRoute("r1---sn-abc.googlevideo.com")
	if err != nil {
		t.Fatalf("TestRoute: %v", err)
	}
	var tr struct {
		Stage     int    `json:"stage"`
		StageName string `json:"stageName"`
		Matcher   string `json:"matcher"`
		Action    string `json:"action"`
	}
	if err := json.Unmarshal([]byte(out), &tr); err != nil {
		t.Fatalf("trace JSON %q: %v", out, err)
	}
	if tr.Stage != 2 || tr.StageName != "Домены" || tr.Matcher != "*.googlevideo.com" || tr.Action != "DESYNC" {
		t.Fatalf("trace = %+v, want stage 2 / *.googlevideo.com / DESYNC", tr)
	}
}

func TestSaveRulesKeepsTunnelAndApplies(t *testing.T) {
	c, path := newRulesController(t, rulesFixture)
	const rulesJSON = `[
		{"cidr":"198.51.100.0/24","action":"direct"},
		{"sni":"example.com","action":"desync"},
		{"action":"block"}
	]`
	savedOffline(t, c.SaveRules(rulesJSON))
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("reload saved config: %v", err)
	}
	if len(cfg.Rules) != 3 || cfg.Rules[0].CIDR != "198.51.100.0/24" || cfg.Rules[2].Action != config.ActionBlock {
		t.Errorf("rules not replaced: %+v", cfg.Rules)
	}
	// Everything else must survive the rule edit.
	if cfg.Profile != "owner" || cfg.Tunnel.Address != "203.0.113.7" || cfg.Desync.TTL != 13 {
		t.Errorf("unrelated config sections lost: %+v", cfg)
	}
}

func TestSaveRulesRejectsInvalid(t *testing.T) {
	c, path := newRulesController(t, rulesFixture)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	err = c.SaveRules(`[{"ports":"1000-2000","action":"direct"},{"ports":"1500","action":"tunnel"}]`)
	if err == nil {
		t.Fatal("want an overlap rejection")
	}
	if !strings.Contains(err.Error(), "overlap") {
		t.Errorf("error = %q, want the overlap message", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("config changed despite a rejected rule set")
	}
}

func TestApplyPresets(t *testing.T) {
	c, path := newRulesController(t, rulesFixture)
	savedOffline(t, c.ApplyPreset("all-direct"))
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Rules) != 1 || cfg.Rules[0].Action != config.ActionDirect {
		t.Errorf("all-direct rules = %+v", cfg.Rules)
	}

	savedOffline(t, c.ApplyPreset(PresetOwner))
	cfg, err = config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Rules) < 40 || cfg.Rules[len(cfg.Rules)-1].Action != config.ActionTunnel {
		t.Errorf("owner preset should be the production policy, got %d rules", len(cfg.Rules))
	}
	if cfg.Tunnel.Address != "203.0.113.7" {
		t.Error("preset must not touch the tunnel")
	}

	if err := c.ApplyPreset("nope"); err == nil {
		t.Error("want an error for an unknown preset")
	}
}
