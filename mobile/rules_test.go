package core

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rupas/rupas/internal/transport/android"
)

// withRules restores the package rule state after the test.
func withRules(t *testing.T) {
	t.Helper()
	mu.Lock()
	savedRules, savedSettings := ruleSet, settings
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		ruleSet, settings = savedRules, savedSettings
		mu.Unlock()
	})
}

func TestRulesJSONDefaultsToPreset(t *testing.T) {
	withRules(t)
	mu.Lock()
	ruleSet, settings = nil, nil
	mu.Unlock()

	out := RulesJSON()
	var rules []struct {
		CIDR   string `json:"cidr"`
		GeoIP  string `json:"geoip"`
		Ports  string `json:"ports"`
		Action string `json:"action"`
	}
	if err := json.Unmarshal([]byte(out), &rules); err != nil {
		t.Fatalf("RulesJSON %q is not a rule array: %v", out, err)
	}
	if len(rules) < 20 {
		t.Fatalf("default preset should be a full policy, got %d rules", len(rules))
	}
	var geo, quic bool
	for _, r := range rules {
		if r.GeoIP == "ru" {
			geo = true
		}
		if r.Ports == "443" && r.Action == "BLOCK" {
			quic = true
		}
	}
	if !geo || !quic {
		t.Errorf("default preset misses geoip:ru (%v) or the QUIC block (%v)", geo, quic)
	}
}

func TestSetRulesJSONApplies(t *testing.T) {
	withRules(t)
	if err := SetRulesJSON(`[
		{"sni":"youtube.com","action":"desync"},
		{"sni":"*.googlevideo.com","action":"desync"},
		{"cidr":"91.108.0.0/16","action":"tunnel"},
		{"action":"direct"}
	]`); err != nil {
		t.Fatalf("SetRulesJSON: %v", err)
	}
	out := RulesJSON()
	if !strings.Contains(out, `"sni":"*.googlevideo.com"`) || !strings.Contains(out, `"action":"DESYNC"`) {
		t.Errorf("rules round trip lost data: %s", out)
	}

	type trace struct {
		Stage   int    `json:"stage"`
		Matcher string `json:"matcher"`
		Action  string `json:"action"`
		Error   string `json:"error"`
	}
	probe := func(query string) trace {
		t.Helper()
		var tr trace
		raw := TestRoute(query)
		if err := json.Unmarshal([]byte(raw), &tr); err != nil {
			t.Fatalf("TestRoute(%q) = %q: %v", query, raw, err)
		}
		return tr
	}
	if tr := probe("youtube.com"); tr.Stage != 2 || tr.Action != "DESYNC" {
		t.Errorf("youtube.com: %+v, want stage 2 DESYNC", tr)
	}
	if tr := probe("91.108.4.1"); tr.Stage != 1 || tr.Action != "TUNNEL" {
		t.Errorf("91.108.4.1: %+v, want stage 1 TUNNEL", tr)
	}
	if tr := probe("example.com"); tr.Stage != 4 || tr.Action != "DIRECT" {
		t.Errorf("example.com: %+v, want stage 4 DIRECT", tr)
	}
	if tr := probe(""); tr.Error == "" {
		t.Errorf("empty query should report an error, got %+v", tr)
	}

	if err := SetRulesJSON(""); err != nil {
		t.Fatalf("clear rules: %v", err)
	}
	if !strings.Contains(RulesJSON(), `"geoip":"ru"`) {
		t.Error("clearing rules must fall back to the built-in preset")
	}
}

func TestSetRulesJSONRejectsInvalid(t *testing.T) {
	withRules(t)
	err := SetRulesJSON(`[{"sni":"a.com","proto":"quic","action":"direct"}]`)
	if err == nil {
		t.Fatal("bad proto must be rejected")
	}
	if !strings.Contains(err.Error(), "rule 0") {
		t.Errorf("error = %q, want the rule index", err)
	}
	err = SetRulesJSON(`[{"ports":"1000-2000","action":"direct"},{"ports":"1500","action":"tunnel"}]`)
	if err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("overlapping ports must be rejected, got %v", err)
	}
}

func TestSetRulesRefusedWhileRunning(t *testing.T) {
	withRules(t)
	// A non-nil engine is all the guard looks at, so any pointer will do:
	// no engine is started in unit tests.
	mu.Lock()
	engine = &android.Engine{}
	mu.Unlock()
	defer func() {
		mu.Lock()
		engine = nil
		mu.Unlock()
	}()
	if err := SetRulesJSON(`[{"action":"direct"}]`); err == nil {
		t.Fatal("changing rules while the engine runs must be refused")
	}
}
