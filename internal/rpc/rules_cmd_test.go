package rpc

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const rulesCmdConfig = `profile: owner
rules:
  - cidr: 10.0.0.0/8
    action: direct
  - sni: youtube.com
    action: desync
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
`

// newRulesServer builds a Server over a throwaway config file, with the
// reload hook recording calls.
func newRulesServer(t *testing.T, body string) (*Server, string, *int) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rupas.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	reloads := 0
	srv := New("rupas-test", Deps{
		Reload:     func() error { reloads++; return nil },
		ConfigPath: path,
	})
	return srv, path, &reloads
}

// dispatchJSON runs one command and decodes the reply.
func dispatchJSON(t *testing.T, s *Server, cmd string) (Response, []byte) {
	t.Helper()
	resp := s.dispatch(cmd)
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	return resp, raw
}

func TestRulesCommand(t *testing.T) {
	srv, _, _ := newRulesServer(t, rulesCmdConfig)
	resp, raw := dispatchJSON(t, srv, "rules")
	if !resp.OK {
		t.Fatalf("rules failed: %s", resp.Error)
	}
	// The payload is the §10 rule array with upper-case action names.
	for _, want := range []string{`"cidr":"10.0.0.0/8"`, `"action":"DIRECT"`, `"sni":"*.googlevideo.com"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("rules payload %s misses %s", raw, want)
		}
	}
}

func TestRouteTestCommand(t *testing.T) {
	srv, _, _ := newRulesServer(t, rulesCmdConfig)
	resp, _ := dispatchJSON(t, srv, "route-test r1---sn-abc.googlevideo.com")
	if !resp.OK {
		t.Fatalf("route-test failed: %s", resp.Error)
	}
	raw, _ := json.Marshal(resp.Data)
	for _, want := range []string{`"stage":2`, `"stageName":"Домены"`, `"matcher":"*.googlevideo.com"`, `"action":"DESYNC"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("trace %s misses %s", raw, want)
		}
	}

	resp, _ = dispatchJSON(t, srv, "route-test 10.1.2.3")
	if !resp.OK {
		t.Fatalf("route-test ip failed: %s", resp.Error)
	}
	raw, _ = json.Marshal(resp.Data)
	if !strings.Contains(string(raw), `"stage":1`) {
		t.Errorf("IP probe should resolve at stage 1: %s", raw)
	}

	if resp, _ := dispatchJSON(t, srv, "route-test"); resp.OK {
		t.Error("route-test without a query must fail")
	}
}

func TestRulesSetCommand(t *testing.T) {
	srv, path, reloads := newRulesServer(t, rulesCmdConfig)
	rulesJSON := `[{"cidr":"198.51.100.0/24","action":"direct"},{"action":"block"}]`
	resp, _ := dispatchJSON(t, srv, "rules-set "+rulesJSON)
	if !resp.OK {
		t.Fatalf("rules-set failed: %s", resp.Error)
	}
	if *reloads != 1 {
		t.Errorf("reload calls = %d, want 1", *reloads)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "198.51.100.0/24") || strings.Contains(string(data), "googlevideo") {
		t.Errorf("config not rewritten:\n%s", data)
	}
	if !strings.Contains(string(data), "profile: owner") {
		t.Errorf("unrelated config sections lost:\n%s", data)
	}
	// Backup of the previous file exists (rollback source).
	if _, err := os.Stat(path + ".bak"); err != nil {
		t.Errorf("backup missing: %v", err)
	}

	// Invalid rule set: refused with the offending index, file untouched.
	before, _ := os.ReadFile(path)
	resp, _ = dispatchJSON(t, srv, `rules-set [{"ports":"1000-2000","action":"direct"},{"ports":"1500","action":"tunnel"}]`)
	if resp.OK {
		t.Fatal("overlapping ports must be refused")
	}
	if !strings.Contains(resp.Error, "rule 1") {
		t.Errorf("error = %q, want the offending rule index", resp.Error)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Error("config changed despite a rejected rule set")
	}

	if resp, _ := dispatchJSON(t, srv, "rules-set"); resp.OK {
		t.Error("rules-set without a payload must fail")
	}
}

func TestRulesSetRollsBackWhenReloadRefused(t *testing.T) {
	srv, path, _ := newRulesServer(t, rulesCmdConfig)
	srv.deps.Reload = func() error { return errors.New("daemon says no") }

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := dispatchJSON(t, srv, `rules-set [{"action":"direct"}]`)
	if resp.OK {
		t.Fatal("a refused reload must fail the command")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("config must be rolled back when the daemon refuses the reload")
	}
}

func TestRulesCommandsNotWired(t *testing.T) {
	srv := New("rupas-test", Deps{})
	for _, cmd := range []string{"rules", "route-test example.com", `rules-set [{"action":"direct"}]`} {
		resp, _ := dispatchJSON(t, srv, cmd)
		if resp.OK {
			t.Errorf("%s should fail without wiring", cmd)
		}
	}
}

func TestUnknownCommandMentionsRules(t *testing.T) {
	srv := New("rupas-test", Deps{})
	resp, _ := dispatchJSON(t, srv, "nope")
	if resp.OK {
		t.Fatal("unknown command must fail")
	}
	for _, want := range []string{"rules", "rules-set", "route-test"} {
		if !strings.Contains(resp.Error, want) {
			t.Errorf("error %q should advertise %q", resp.Error, want)
		}
	}
}
