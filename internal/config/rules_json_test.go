package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseRulesJSONValid(t *testing.T) {
	const src = `[
		{"cidr":"10.0.0.0/8","action":"direct"},
		{"geoip":"RU","action":"direct"},
		{"sni":"*.Googlevideo.COM","action":"desync"},
		{"sni":"discord.com","action":"tunnel","proto":"tcp"},
		{"ports":"3478","action":"tunnel","proto":"udp"},
		{"ports":"50000-65535","action":"tunnel","proto":"udp"},
		{"action":"tunnel"}
	]`
	rules, err := ParseRulesJSON([]byte(src))
	if err != nil {
		t.Fatalf("ParseRulesJSON: %v", err)
	}
	if len(rules) != 7 {
		t.Fatalf("got %d rules, want 7", len(rules))
	}
	// Normalization: geoip country code and SNI are lower-cased by Validate.
	if rules[1].GeoIP != "ru" {
		t.Errorf("geoip = %q, want ru", rules[1].GeoIP)
	}
	if rules[2].SNI != "*.googlevideo.com" {
		t.Errorf("sni = %q, want lower-case", rules[2].SNI)
	}
	if rules[2].Action != ActionDesync {
		t.Errorf("action = %v, want DESYNC", rules[2].Action)
	}
	if rules[4].Proto != ProtoUDP {
		t.Errorf("proto = %q, want udp", rules[4].Proto)
	}
	if rules[6].Action != ActionTunnel || rules[6].CIDR != "" || rules[6].SNI != "" {
		t.Errorf("default rule decoded wrong: %+v", rules[6])
	}
}

func TestParseRulesJSONErrors(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"bad proto", `[{"sni":"a.com","proto":"quic","action":"direct"}]`, `rule 0: proto "quic"`},
		{"two matchers", `[{"cidr":"10.0.0.0/8","sni":"a.com","action":"direct"}]`,
			"rule 0: at most one of cidr/sni/ports/geoip"},
		{"missing action", `[{"sni":"a.com"}]`, "rule 0: missing action"},
		{"bad action", `[{"sni":"a.com","action":"allow"}]`, `rule 0: invalid action "allow"`},
		{"bad cidr", `[{"cidr":"10.0.0.0/33","action":"direct"}]`, `rule 0: bad cidr "10.0.0.0/33"`},
		{"bad port", `[{"ports":"0","action":"direct"}]`, "rule 0: bad port spec"},
		{"two defaults", `[{"action":"direct"},{"action":"tunnel"}]`, "multiple default rules"},
		{"unknown field", `[{"sni":"a.com","action":"direct","matcher":"x"}]`, "unknown field"},
		{"not an array", `{"sni":"a.com"}`, "rules json"},
		{"port overlap", `[{"ports":"1000-2000","action":"direct"},{"ports":"1500","action":"tunnel"}]`,
			"port"},
		{"port overlap within one rule", `[{"ports":"1000-2000,1500","action":"direct"}]`, "overlapping ranges"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseRulesJSON([]byte(c.src))
			if err == nil {
				t.Fatalf("want error containing %q, got nil", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error = %q, want it to contain %q", err, c.want)
			}
		})
	}
}

func TestParseRulesJSONPortOverlapNamesBothRules(t *testing.T) {
	const src = `[
		{"sni":"a.com","action":"direct"},
		{"ports":"50000-65535","action":"tunnel"},
		{"ports":"443","action":"block"},
		{"ports":"60000-65000","action":"direct"}
	]`
	_, err := ParseRulesJSON([]byte(src))
	if err == nil {
		t.Fatal("want overlap error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "rule 3") || !strings.Contains(msg, "rule 1") {
		t.Fatalf("error must name both conflicting rules, got %q", msg)
	}
}

func TestParseRulesJSONProtoScopedPortsMayShare(t *testing.T) {
	// Same port under different protocol scopes is legal (udp:443 block next
	// to tcp:443 tunnel).
	const src = `[
		{"ports":"443","proto":"udp","action":"block"},
		{"ports":"443","proto":"tcp","action":"tunnel"}
	]`
	if _, err := ParseRulesJSON([]byte(src)); err != nil {
		t.Fatalf("proto-scoped spans must not collide: %v", err)
	}
}

func TestParseRulesJSONEmptyArray(t *testing.T) {
	rules, err := ParseRulesJSON([]byte(`[]`))
	if err != nil {
		t.Fatalf("empty array: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("got %d rules, want 0", len(rules))
	}
}

func TestRulesJSONRoundTrip(t *testing.T) {
	in := []Rule{
		{CIDR: "91.108.0.0/16", Action: ActionTunnel},
		{SNI: "*.googlevideo.com", Action: ActionDesync},
		{GeoIP: "ru", Action: ActionDirect},
		{Ports: "3478", Proto: ProtoUDP, Action: ActionTunnel},
		{Action: ActionTunnel},
	}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// The wire shape is the §10 contract: lower-case matcher keys and the
	// canonical upper-case action name (what the UI chips show).
	if !strings.Contains(string(data), `"action":"TUNNEL"`) {
		t.Fatalf("action must marshal as its canonical name, got %s", data)
	}
	out, err := ParseRulesJSON(data)
	if err != nil {
		t.Fatalf("ParseRulesJSON(marshal(rules)): %v", err)
	}
	if len(out) != len(in) {
		t.Fatalf("round trip: got %d rules, want %d", len(out), len(in))
	}
	for i := range in {
		if out[i] != in[i] {
			t.Errorf("rule %d: got %+v, want %+v", i, out[i], in[i])
		}
	}
}

func TestActionJSON(t *testing.T) {
	for _, c := range []struct {
		in   string
		want Action
	}{
		{`"direct"`, ActionDirect},
		{`"TUNNEL"`, ActionTunnel},
		{`"Desync"`, ActionDesync},
		{`"block"`, ActionBlock},
	} {
		var a Action
		if err := json.Unmarshal([]byte(c.in), &a); err != nil {
			t.Fatalf("unmarshal %s: %v", c.in, err)
		}
		if a != c.want {
			t.Errorf("%s: got %v, want %v", c.in, a, c.want)
		}
	}
	var a Action
	if err := json.Unmarshal([]byte(`"allow"`), &a); err == nil {
		t.Fatal("want error for an unknown action")
	}
}

func TestSaveRulesFileKeepsRestOfConfig(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/rupas.yaml"
	src := `profile: unit
rules:
  - sni: a.com
    action: direct
desync:
  strategy: fake
  ttl: 13
  repeats: 1
`
	if err := writeFileAtomic(path, []byte(src)); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	rules := []Rule{
		{CIDR: "10.0.0.0/8", Action: ActionDirect},
		{Action: ActionTunnel},
	}
	if err := SaveRulesFile(path, rules); err != nil {
		t.Fatalf("SaveRulesFile: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if cfg.Profile != "unit" || cfg.Desync.TTL != 13 {
		t.Errorf("unrelated sections lost: %+v", cfg)
	}
	if len(cfg.Rules) != 2 || cfg.Rules[0].CIDR != "10.0.0.0/8" || cfg.Rules[1].Action != ActionTunnel {
		t.Errorf("rules not saved: %+v", cfg.Rules)
	}
	if _, err := Load(path + ".bak"); err != nil {
		t.Errorf("backup missing or unreadable: %v", err)
	}
}
