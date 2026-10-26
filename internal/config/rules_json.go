// rules_json.go — the JSON face of the routing rule list used by the
// Routing screen (docs/ROUTING_UI.md §10): decode, then validate with the
// engine's own rules so the UI cannot save a config the daemon would
// refuse. Every error names the offending rule index.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// validationProfile / validationDesync make a bare rule list validatable:
// Config.Validate requires a profile name and a complete desync profile
// whenever a DESYNC rule is present. Neither value reaches a live config.
const validationProfile = "rules-validation"

var validationDesync = DesyncParams{Strategy: "fake", TTL: 13, TTLMargin: 0, Repeats: 1}

// jsonRule is the wire shape of one rule (§10): exactly one of
// cidr/sni/ports/geoip, an optional proto scope and a mandatory action.
// An empty matcher makes the rule the default one.
type jsonRule struct {
	CIDR   string `json:"cidr,omitempty"`
	SNI    string `json:"sni,omitempty"`
	Ports  string `json:"ports,omitempty"`
	GeoIP  string `json:"geoip,omitempty"`
	Proto  string `json:"proto,omitempty"`
	Action string `json:"action"`
}

// ParseAction parses the textual action name (desync|tunnel|direct|block,
// case-insensitive).
func ParseAction(s string) (Action, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "desync":
		return ActionDesync, nil
	case "tunnel":
		return ActionTunnel, nil
	case "direct":
		return ActionDirect, nil
	case "block":
		return ActionBlock, nil
	}
	return ActionInvalid, fmt.Errorf("invalid action %q (want desync|tunnel|direct|block)", s)
}

// MarshalJSON encodes the action as its canonical upper-case name ("DIRECT",
// "TUNNEL", "DESYNC", "BLOCK") — the form the UI chips and the RPC rule
// payload speak, and the form ParseRulesJSON accepts back. YAML keeps the
// lower-case names for config ergonomics (MarshalYAML).
func (a Action) MarshalJSON() ([]byte, error) {
	switch a {
	case ActionDesync, ActionTunnel, ActionDirect, ActionBlock:
		return []byte(`"` + a.String() + `"`), nil
	}
	return nil, fmt.Errorf("config: cannot marshal invalid action %d", uint8(a))
}

// UnmarshalJSON decodes "desync" / "tunnel" / "direct" / "block" in any case
// (the upper-case canonical names included), matching UnmarshalYAML.
func (a *Action) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	act, err := ParseAction(s)
	if err != nil {
		return err
	}
	*a = act
	return nil
}

// ParseRulesJSON decodes a JSON array of rules and validates it with the
// engine's rules (Config.Validate plus the port-overlap check the table
// compiler performs). Unknown fields are rejected. The returned rules are
// normalized (SNI lower-cased, proto trimmed) exactly as a YAML load would
// leave them.
func ParseRulesJSON(data []byte) ([]Rule, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var raw []jsonRule
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("config: rules json: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("config: rules json: trailing data after the array")
	}
	rules := make([]Rule, len(raw))
	for i, jr := range raw {
		if strings.TrimSpace(jr.Action) == "" {
			return nil, fmt.Errorf("config: rule %d: missing action", i)
		}
		action, err := ParseAction(jr.Action)
		if err != nil {
			return nil, fmt.Errorf("config: rule %d: %v", i, err)
		}
		rules[i] = Rule{
			CIDR:   jr.CIDR,
			SNI:    jr.SNI,
			Ports:  jr.Ports,
			GeoIP:  jr.GeoIP,
			Proto:  jr.Proto,
			Action: action,
		}
	}
	if err := ValidateRules(rules); err != nil {
		return nil, err
	}
	return rules, nil
}

// ValidateRules validates a standalone rule list — the same checks a YAML
// load runs — by handing it to Config.Validate on a temporary config, then
// rejecting overlapping port spans (which the table compiler treats as a
// fatal ambiguity). Normalization (lower-case SNI, trimmed proto) is applied
// in place: the slice shares its backing array with the caller.
func ValidateRules(rules []Rule) error {
	tmp := Config{Profile: validationProfile, Rules: rules, Desync: validationDesync}
	if err := tmp.Validate(); err != nil {
		return err
	}
	return checkPortOverlaps(tmp.Rules)
}

// portSpan is one parsed port range plus the rule it came from.
type portSpan struct {
	lo, hi uint16
	spec   string
	rule   int
}

// checkPortOverlaps mirrors rules.sortAndCheck: spans inside one protocol
// bucket must be disjoint, because the resolution between two overlapping
// spans of the same protocol would be arbitrary. Spans of different scopes
// may share ports by design (udp:443 next to tcp:443).
func checkPortOverlaps(rules []Rule) error {
	buckets := map[string][]portSpan{
		ProtoAny: nil,
		ProtoTCP: nil,
		ProtoUDP: nil,
	}
	for i, r := range rules {
		if r.Ports == "" {
			continue
		}
		spans, err := ParsePortSpec(r.Ports)
		if err != nil {
			return fmt.Errorf("config: rule %d: %v", i, err)
		}
		for _, s := range spans {
			buckets[r.Proto] = append(buckets[r.Proto], portSpan{
				lo: s.Lo, hi: s.Hi, spec: r.Ports, rule: i,
			})
		}
	}
	// Fixed iteration order keeps the reported conflict deterministic.
	for _, proto := range []string{ProtoAny, ProtoTCP, ProtoUDP} {
		spans := buckets[proto]
		if len(spans) < 2 {
			continue
		}
		sort.SliceStable(spans, func(i, j int) bool {
			if spans[i].lo != spans[j].lo {
				return spans[i].lo < spans[j].lo
			}
			return spans[i].rule < spans[j].rule
		})
		for i := 1; i < len(spans); i++ {
			if spans[i].lo <= spans[i-1].hi {
				return fmt.Errorf("config: rule %d: ports %q overlap rule %d (%q, [%d,%d] and [%d,%d])",
					spans[i].rule, spans[i].spec, spans[i-1].rule, spans[i-1].spec,
					spans[i-1].lo, spans[i-1].hi, spans[i].lo, spans[i].hi)
			}
		}
	}
	return nil
}

// SaveRulesFile rewrites the YAML config at path with a new rule set and
// keeps everything else (tunnel, exclusions, geoip, desync) intact: the
// candidate is written to a temp file, validated by a full config load,
// backed up to path+".bak" and moved into place atomically. The caller
// reloads the daemon afterwards and rolls back from path+".bak" when the
// reload is refused (TUI save contract).
func SaveRulesFile(path string, rules []Rule) error {
	cfg, err := Load(path)
	if err != nil {
		return err
	}
	cfg.Rules = rules
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("config: marshal: %w", err)
	}
	return writeFileAtomic(path, data)
}

// writeFileAtomic installs data at path through a validated temp file and a
// .bak of the previous contents (the daemon reload path owns the rollback).
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if _, err := Load(tmp); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("config: rules not saved, config would be invalid: %w", err)
	}
	if _, err := os.Stat(path); err == nil {
		_ = os.Rename(path, path+".bak")
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return nil
}
