package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestActionUnmarshal(t *testing.T) {
	tests := []struct {
		in      string
		want    Action
		wantErr bool
	}{
		{"desync", ActionDesync, false},
		{"tunnel", ActionTunnel, false},
		{"direct", ActionDirect, false},
		{"block", ActionBlock, false},
		{"  DIRECT ", ActionDirect, false},
		{"Desync", ActionDesync, false},
		{"proxy", 0, true},
	}
	for _, tt := range tests {
		var a Action
		err := yaml.Unmarshal([]byte(tt.in), &a)
		if tt.wantErr {
			if err == nil {
				t.Errorf("Unmarshal(%q): expected error, got %v", tt.in, a)
			}
			continue
		}
		if err != nil {
			t.Errorf("Unmarshal(%q): unexpected error %v", tt.in, err)
			continue
		}
		if a != tt.want {
			t.Errorf("Unmarshal(%q) = %v, want %v", tt.in, a, tt.want)
		}
	}
}

func TestActionStringRoundTrip(t *testing.T) {
	for _, a := range []Action{ActionDesync, ActionTunnel, ActionDirect, ActionBlock} {
		out, err := yaml.Marshal(a)
		if err != nil {
			t.Fatalf("Marshal(%v): %v", a, err)
		}
		var back Action
		if err := yaml.Unmarshal(out, &back); err != nil {
			t.Fatalf("Unmarshal(%q): %v", out, err)
		}
		if back != a {
			t.Errorf("round trip %v -> %q -> %v", a, out, back)
		}
	}
}

const validYAML = `
profile: test-profile
rules:
  - sni: www.youtube.com
    action: desync
  - sni: "*.googlevideo.com"
    action: desync
  - cidr: 149.154.160.0/20
    action: tunnel
  - ports: "50000-65535"
    action: tunnel
  - action: direct
desync:
  strategy: fake
  fake_template: chrome-124-pq.bin
  ttl: 13
  ttl_margin: 2
  repeats: 6
tunnel:
  protocol: vless
  address: vps.example.com
  port: 443
  uuid: 11111111-2222-3333-4444-555555555555
  reality_public_key: pbk-key
  reality_short_id: abcd
  sni: cloudflare.com
exclusions:
  cidrs:
    - 203.0.113.0/24
  domains:
    - sberbank.ru
`

func TestUnmarshalValid(t *testing.T) {
	cfg, err := Unmarshal([]byte(validYAML))
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if cfg.Profile != "test-profile" {
		t.Errorf("profile = %q", cfg.Profile)
	}
	if len(cfg.Rules) != 5 {
		t.Fatalf("rules len = %d, want 5", len(cfg.Rules))
	}
	if cfg.Rules[1].SNI != "*.googlevideo.com" || cfg.Rules[1].Action != ActionDesync {
		t.Errorf("wildcard rule = %+v", cfg.Rules[1])
	}
	if cfg.Desync.TTL != 13 || cfg.Desync.Strategy != "fake" {
		t.Errorf("desync = %+v", cfg.Desync)
	}
	if cfg.Tunnel.Protocol != "vless" || cfg.Tunnel.Port != 443 {
		t.Errorf("tunnel = %+v", cfg.Tunnel)
	}
	if cfg.Tunnel.UDPMode != "xudp" || cfg.Tunnel.Fingerprint != "chrome" {
		t.Errorf("tunnel defaults not applied: %+v", cfg.Tunnel)
	}
	if len(cfg.Exclusions.CIDRs) != 1 || len(cfg.Exclusions.Domains) != 1 {
		t.Errorf("exclusions = %+v", cfg.Exclusions)
	}
}

func TestUnmarshalErrors(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"unknown field", "profile: p\nbogus: 1\n", "field bogus"},
		{"empty profile", "rules: []\n", "profile is empty"},
		{"bad action", "profile: p\nrules:\n  - sni: a.com\n    action: maybe\n", "invalid action"},
		{"missing action", "profile: p\nrules:\n  - sni: a.com\n", "missing action"},
		{"two matchers", "profile: p\nrules:\n  - sni: a.com\n    cidr: 1.2.3.0/24\n    action: direct\n", "at most one"},
		{"bad cidr", "profile: p\nrules:\n  - cidr: 1.2.3.4/33\n    action: direct\n", "bad cidr"},
		{"bad sni char", "profile: p\nrules:\n  - sni: \"a!.com\"\n    action: direct\n", "invalid sni"},
		{"bad sni star pos", "profile: p\nrules:\n  - sni: \"a.*b.com\"\n    action: direct\n", "invalid sni"},
		{"bad port high", "profile: p\nrules:\n  - ports: \"70000\"\n    action: direct\n", "bad port"},
		{"bad port range", "profile: p\nrules:\n  - ports: \"100-200,150-250\"\n    action: direct\n", "overlapping"},
		{"two defaults", "profile: p\nrules:\n  - {action: direct}\n  - {action: tunnel}\n", "multiple default"},
		{"bad desync strategy", validDesync("strategy: bogus"), "not one of"},
		{"bad desync ttl", validDesync("ttl: 64"), "out of range"},
		{"bad desync repeats", validDesync("repeats: 0"), "must be >= 1"},
		{"bad tunnel proto", validTunnel("protocol: vmess"), "only \"vless\""},
		{"tunnel missing field", validTunnel("uuid: \"\""), "tunnel requires"},
		{"bad exclusion cidr", "profile: p\nexclusions:\n  cidrs: [\"nope\"]\n", "exclusion cidr"},
		{"bad proto", "profile: p\nrules:\n  - ports: \"443\"\n    proto: sctp\n    action: block\n", "proto"},
		{"proto on default rule", "profile: p\nrules:\n  - proto: udp\n    action: block\n", "default rule"},
		{"proto needs matcher", "profile: p\nrules:\n  - proto: udp\n    action: block\n  - {action: direct}\n", "default rule"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Unmarshal([]byte(tt.yaml))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.want)
			}
		})
	}
}

// TestUnmarshalProtoRule validates the proto selector and the block action
// end-to-end through the YAML schema (PRD §5 QUIC block).
func TestUnmarshalProtoRule(t *testing.T) {
	const yml = `profile: p
rules:
  - ports: "443"
    proto: udp
    action: block
  - ports: "8080"
    proto: TCP
    action: tunnel
  - action: direct
`
	cfg, err := Unmarshal([]byte(yml))
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if cfg.Rules[0].Proto != ProtoUDP || cfg.Rules[0].Action != ActionBlock {
		t.Errorf("rule 0 = %+v, want proto udp + block", cfg.Rules[0])
	}
	// Selector is case-insensitive and normalized to lower case.
	if cfg.Rules[1].Proto != ProtoTCP || cfg.Rules[1].Action != ActionTunnel {
		t.Errorf("rule 1 = %+v, want proto tcp + tunnel", cfg.Rules[1])
	}
}

// TestRepoConfigsLoad parses the repository's real config files (strict
// schema): the committed example always, the user's rupas.yaml when it
// exists locally (gitignored; contents are never logged). The QUIC block
// rule (PRD §5) must be present in both.
func TestRepoConfigsLoad(t *testing.T) {
	for _, p := range []string{"../../configs/rupas.example.yaml", "../../configs/rupas.yaml"} {
		if _, err := os.Stat(p); err != nil {
			t.Logf("%s absent, skipping", p)
			continue
		}
		cfg, err := Load(p)
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		found := false
		for _, r := range cfg.Rules {
			if r.Ports == "443" && r.Proto == ProtoUDP && r.Action == ActionBlock {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no udp/443 block rule (PRD §5 QUIC fallback)", p)
		}
	}
}

// validDesync returns a config whose desync block has the key from the
// given "key: value" patch replaced (e.g. "strategy: bogus").
func validDesync(patch string) string {
	return "profile: p\nrules:\n  - sni: a.com\n    action: desync\ndesync:\n" +
		block("strategy: fake\nttl: 13\nrepeats: 2", patch)
}

// validTunnel returns a config whose tunnel block has the key from the
// given "key: value" patch replaced (e.g. "protocol: vmess").
func validTunnel(patch string) string {
	return "profile: p\ntunnel:\n" +
		block("protocol: vless\naddress: v.example.com\nport: 443\nuuid: u\nreality_public_key: k\nsni: s.example.com", patch)
}

// block re-indents defaults as a nested YAML mapping and replaces the
// line whose key matches the patch's key with the patch itself.
func block(defaults, patch string) string {
	key := strings.SplitN(patch, ":", 2)[0]
	var lines []string
	for _, l := range strings.Split(defaults, "\n") {
		if strings.HasPrefix(l, key+":") {
			continue
		}
		lines = append(lines, "  "+l)
	}
	lines = append(lines, "  "+patch)
	return strings.Join(lines, "\n") + "\n"
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rupas.yaml")
	if err := os.WriteFile(path, []byte(validYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Profile != "test-profile" {
		t.Errorf("profile = %q", cfg.Profile)
	}

	if _, err := Load(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("Load(missing): expected error")
	}
}

func TestDefaultValid(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Default().Validate(): %v", err)
	}
}

func TestDefaultContent(t *testing.T) {
	cfg := Default()
	// Structural invariants (the wave-7 SNI list may grow): every rule
	// has exactly one matcher or is THE default rule, which is last and
	// DIRECT; key rules are pinned below.
	for i, r := range cfg.Rules {
		matchers := 0
		for _, s := range []string{r.CIDR, r.SNI, r.Ports} {
			if s != "" {
				matchers++
			}
		}
		if matchers > 1 {
			t.Errorf("rule %d has %d matchers: %+v", i, matchers, r)
		}
		if matchers == 0 && i != len(cfg.Rules)-1 {
			t.Errorf("default rule at %d is not last", i)
		}
		if matchers == 0 && r.Action != ActionDirect {
			t.Errorf("default action = %v, want DIRECT", r.Action)
		}
	}
	pin := []Rule{
		{SNI: "www.youtube.com", Action: ActionDesync},
		{SNI: "*.googlevideo.com", Action: ActionDesync},
		{CIDR: "149.154.160.0/20", Action: ActionTunnel},
		{CIDR: "91.108.0.0/16", Action: ActionTunnel},
		{Ports: "50000-65535", Action: ActionTunnel},
	}
	for _, w := range pin {
		found := false
		for _, r := range cfg.Rules {
			if r == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("pinned rule %+v missing from Default()", w)
		}
	}
	if cfg.Desync.TTL != 13 || cfg.Desync.TTLMargin != 2 || cfg.Desync.Repeats != 6 {
		t.Errorf("desync params = %+v", cfg.Desync)
	}
}

func TestParsePortSpec(t *testing.T) {
	tests := []struct {
		in      string
		want    []PortRange
		wantErr bool
	}{
		{"443", []PortRange{{443, 443}}, false},
		{"50000-65535", []PortRange{{50000, 65535}}, false},
		{"53, 123", []PortRange{{53, 53}, {123, 123}}, false},
		{"100-200,300-400", []PortRange{{100, 200}, {300, 400}}, false},
		{"300-400,100-200", []PortRange{{100, 200}, {300, 400}}, false},
		{"0", nil, true},
		{"70000", nil, true},
		{"200-100", nil, true},
		{"100-200,150-250", nil, true},
		{"100-200,200", nil, true},
		{"", nil, true},
		{"abc", nil, true},
		{"1-2-3", nil, true},
	}
	for _, tt := range tests {
		got, err := ParsePortSpec(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParsePortSpec(%q): expected error, got %v", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePortSpec(%q): %v", tt.in, err)
			continue
		}
		if len(got) != len(tt.want) {
			t.Errorf("ParsePortSpec(%q) = %v, want %v", tt.in, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("ParsePortSpec(%q)[%d] = %v, want %v", tt.in, i, got[i], tt.want[i])
			}
		}
	}
}
