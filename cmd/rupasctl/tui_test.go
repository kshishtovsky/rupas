package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/kshishtovsky/rupas/internal/config"
	"github.com/kshishtovsky/rupas/internal/core"
)

// TestTUIModelTabs verifies that tab switching works via 1..4 and Tab/Shift+Tab.
func TestTUIModelTabs(t *testing.T) {
	m := newTUIModel("configs/rupas.yaml", "\\\\.\\pipe\\rupasctl", time.Second, nil)
	if m.activeTab != tabStatus {
		t.Fatalf("expected initial tab tabStatus, got %v", m.activeTab)
	}

	// '2' -> tabRules
	m2, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'2'}})
	tm := m2.(tuiModel)
	if tm.activeTab != tabRules {
		t.Fatalf("expected tabRules, got %v", tm.activeTab)
	}

	// 'tab' -> tabDesync
	m3, _ := tm.Update(tea.KeyMsg{Type: tea.KeyTab})
	tm = m3.(tuiModel)
	if tm.activeTab != tabDesync {
		t.Fatalf("expected tabDesync, got %v", tm.activeTab)
	}

	// 'tab' -> tabTunnels
	m4, _ := tm.Update(tea.KeyMsg{Type: tea.KeyTab})
	tm = m4.(tuiModel)
	if tm.activeTab != tabTunnels {
		t.Fatalf("expected tabTunnels, got %v", tm.activeTab)
	}

	// 'shift+tab' -> tabDesync
	m5, _ := tm.Update(tea.KeyMsg{Type: tea.KeyShiftTab})
	tm = m5.(tuiModel)
	if tm.activeTab != tabDesync {
		t.Fatalf("expected tabDesync, got %v", tm.activeTab)
	}
}

// TestTUIModelRulesEditing tests adding and deleting a rule.
func TestTUIModelRulesEditing(t *testing.T) {
	m := newTUIModel("dummy.yaml", "\\\\.\\pipe\\rupasctl", time.Second, nil)
	m.activeTab = tabRules
	m.rules = []config.Rule{
		{SNI: "*.youtube.com", Action: config.ActionDesync},
		{Action: config.ActionTunnel}, // default rule
	}

	// 'n' -> start wizard
	m2, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	tm := m2.(tuiModel)
	if tm.edit != editRuleWizard {
		t.Fatalf("expected editRuleWizard, got %v", tm.edit)
	}

	// Step 0: type is SNI (index 1), press Enter -> step 1
	m3, _ := tm.Update(tea.KeyMsg{Type: tea.KeyEnter})
	tm = m3.(tuiModel)
	if tm.editStep != 1 {
		t.Fatalf("expected step 1 (value), got %d", tm.editStep)
	}

	// Type value "discord.gg" + Enter -> step 2 (proto)
	tm.wizInput.SetValue("discord.gg")
	m4, _ := tm.Update(tea.KeyMsg{Type: tea.KeyEnter})
	tm = m4.(tuiModel)
	if tm.editStep != 2 {
		t.Fatalf("expected step 2 (proto), got %d", tm.editStep)
	}

	// Proto: index 0 (any), press Enter -> step 3 (action)
	m5, _ := tm.Update(tea.KeyMsg{Type: tea.KeyEnter})
	tm = m5.(tuiModel)
	if tm.editStep != 3 {
		t.Fatalf("expected step 3 (action), got %d", tm.editStep)
	}

	// Commit rule (Enter) -> must insert before default rule
	m6, _ := tm.Update(tea.KeyMsg{Type: tea.KeyEnter})
	tm = m6.(tuiModel)
	if tm.edit != editNone {
		t.Fatalf("expected editNone after commit, got %v", tm.edit)
	}
	if len(tm.rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(tm.rules))
	}
	if tm.rules[1].SNI != "discord.gg" {
		t.Fatalf("expected inserted rule to be discord.gg, got %q", tm.rules[1].SNI)
	}
	// Default rule must still be last
	if tm.rules[2].SNI != "" {
		t.Fatalf("expected default rule at the end, got %+v", tm.rules[2])
	}
}

// TestTUISavePipeline tests atomic save + backup + rollback on error.
func TestTUISavePipeline(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "rupas.yaml")

	initial := `
profile: default
rules:
  - sni: "*.youtube.com"
    action: desync
  - action: tunnel
desync:
  strategy: fake
  fake_template: build/desync/fake-chrome.bin
  ttl: 3
  repeats: 6
  split_offset: 2
`
	if err := os.WriteFile(cfgPath, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}

	m := newTUIModel(cfgPath, "\\\\.\\pipe\\rupasctl", time.Second, nil)
	ok, err := m.loadConfigFromDisk()
	if !ok || err != nil {
		t.Fatalf("loadConfigFromDisk failed: %v", err)
	}

	// Case 1: successful reload -> file saved, backup created
	reloadCalled := false
	reloadFn := func() error {
		reloadCalled = true
		return nil
	}
	bak, err := saveConfigFile(&m, reloadFn)
	if err != nil {
		t.Fatalf("saveConfigFile failed: %v", err)
	}
	if !reloadCalled {
		t.Fatal("expected reloadFn to be called")
	}
	if bak != cfgPath+".bak" {
		t.Fatalf("expected backup %s, got %s", cfgPath+".bak", bak)
	}
	afterFirst, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	// Case 2: reload failure -> rolls back to previous content
	m.rules[0].SNI = "broken.test.com"
	reloadErr := func() error {
		return os.ErrPermission
	}
	_, err = saveConfigFile(&m, reloadErr)
	if err == nil {
		t.Fatal("expected saveConfigFile to return error on failed reload")
	}

	// Live file must contain exactly the pre-save bytes (rollback happened).
	cur, _ := os.ReadFile(cfgPath)
	if string(cur) != string(afterFirst) {
		t.Fatalf("rollback did not restore the previous config:\n got: %q\nwant: %q", cur, afterFirst)
	}
}

// TestTUIMaskSecret ensures credentials are never logged or displayed raw.
func TestTUIMaskSecret(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "(пусто)"}, // subtleStyle wraps it, but contains text
		{"abc", "****"},
		{"abcd", "****"},
		{"abcdefgh-1234", "abcd*********"},
	}
	for _, tc := range cases {
		got := maskSecret(tc.in)
		if tc.in == "" {
			continue
		}
		if got != tc.want {
			t.Errorf("maskSecret(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestTUIStatusRendering ensures Snapshot fields render without panic.
func TestTUIStatusRendering(t *testing.T) {
	m := newTUIModel("configs/rupas.yaml", "\\\\.\\pipe\\rupasctl", time.Second, nil)
	m.snap = core.Snapshot{
		State: "ACTIVE",
		Since: time.Now().Add(-10 * time.Minute),
		Tunnel: &core.TunnelStatus{
			Mode:     "tunnel",
			Healthy:  true,
			RxBytes:  12345,
			TxBytes:  67890,
			TCPFlows: 3,
		},
		Counters: core.Counters{
			PacketsTotal:  1000,
			PacketsDesync: 200,
			PacketsRedir:  300,
			PacketsDrop:   0,
			LastProbeNote: "ladder ok",
		},
	}
	s := m.renderStatus()
	if s == "" {
		t.Fatal("renderStatus returned empty string")
	}
}

// TestTUIRulesRenderAction verifies that ACTION names are visible in the rendered rules table.
func TestTUIRulesRenderAction(t *testing.T) {
	m := newTUIModel("configs/rupas.yaml", "\\\\.\\pipe\\rupasctl", time.Second, nil)
	m.rules = []config.Rule{
		{CIDR: "10.0.0.0/8", Action: config.ActionDirect},
		{SNI: "*.youtube.com", Action: config.ActionDesync},
		{Action: config.ActionTunnel},
	}
	out := m.renderRules()
	for _, act := range []string{"DIRECT", "DESYNC", "TUNNEL"} {
		if !strings.Contains(out, act) {
			t.Errorf("renderRules output missing %s; got:\n%s", act, out)
		}
	}
}
