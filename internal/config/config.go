// Package config defines the Rupas runtime configuration: routing rules
// (CIDR / SNI / port / default actions), desync parameters, the
// VLESS-Reality tunnel endpoint and exclusions, plus YAML loading and
// validation. See docs/SYSTEM_DESIGN.md §4.2-4.3 and docs/PRD.md §5.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Action is the decision the core applies to a matched flow.
type Action uint8

const (
	// ActionInvalid is the zero value; it must not appear in a valid config.
	ActionInvalid Action = iota
	// ActionDesync modifies the TLS handshake in flight (fake/split/disorder).
	ActionDesync
	// ActionTunnel routes the flow through the VLESS-Reality endpoint.
	ActionTunnel
	// ActionDirect passes the flow through untouched.
	ActionDirect
)

// String returns the canonical upper-case action name.
func (a Action) String() string {
	switch a {
	case ActionDesync:
		return "DESYNC"
	case ActionTunnel:
		return "TUNNEL"
	case ActionDirect:
		return "DIRECT"
	default:
		return "INVALID"
	}
}

// MarshalYAML encodes the action as a lower-case YAML string.
func (a Action) MarshalYAML() (any, error) {
	switch a {
	case ActionDesync, ActionTunnel, ActionDirect:
		return strings.ToLower(a.String()), nil
	default:
		return nil, fmt.Errorf("config: cannot marshal invalid action %d", uint8(a))
	}
}

// UnmarshalYAML decodes "desync" / "tunnel" / "direct" (case-insensitive).
func (a *Action) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "desync":
		*a = ActionDesync
	case "tunnel":
		*a = ActionTunnel
	case "direct":
		*a = ActionDirect
	default:
		return fmt.Errorf("config: invalid action %q (want desync|tunnel|direct)", s)
	}
	return nil
}

// DesyncParams carries the calibrated desync profile (SYSTEM_DESIGN §4.3).
type DesyncParams struct {
	// Strategy is one of DesyncStrategies().
	Strategy     string `yaml:"strategy"`
	FakeTemplate string `yaml:"fake_template"`
	// TTL is the calibrated fake-packet TTL (binary-searched by the prober).
	TTL int `yaml:"ttl"`
	// TTLMargin is added to the calibrated TTL.
	TTLMargin int `yaml:"ttl_margin"`
	// Repeats is the number of fake ClientHello injections per attempt.
	Repeats int `yaml:"repeats"`
	// SplitOffset is the byte offset for split-based strategies (optional).
	SplitOffset int `yaml:"split_offset,omitempty"`
}

// TunnelEndpoint describes the VLESS+Reality exit node (PRD §5, US-5).
// It may be left empty at load time and attached later at runtime.
type TunnelEndpoint struct {
	Protocol    string `yaml:"protocol"` // must be "vless"
	Address     string `yaml:"address"`
	Port        uint16 `yaml:"port"`
	UUID        string `yaml:"uuid"`
	RealityPBK  string `yaml:"reality_public_key"`
	RealitySID  string `yaml:"reality_short_id"`
	SNI         string `yaml:"sni"`
	Fingerprint string `yaml:"fingerprint"` // uTLS client fingerprint
	UDPMode     string `yaml:"udp_mode"`    // xudp
}

// Exclusions are destinations that are always DIRECT: the VPS endpoint
// itself, RU banking subnets and similar (PRD §5, last row).
type Exclusions struct {
	CIDRs   []string `yaml:"cidrs"`
	Domains []string `yaml:"domains"`
}

// Rule routes traffic to an Action by exactly one matcher: cidr, sni or
// ports. A rule with no matcher is the default rule (at most one allowed).
// Resolution order is fixed by SYSTEM_DESIGN §4.2: CIDR → SNI → port → default.
type Rule struct {
	CIDR   string `yaml:"cidr,omitempty"`
	SNI    string `yaml:"sni,omitempty"`   // exact name or "*.suffix" wildcard
	Ports  string `yaml:"ports,omitempty"` // "443", "50000-65535", "53,123"
	Action Action `yaml:"action"`
}

// Config is the root configuration object.
type Config struct {
	Profile    string         `yaml:"profile"`
	Rules      []Rule         `yaml:"rules"`
	Desync     DesyncParams   `yaml:"desync"`
	Tunnel     TunnelEndpoint `yaml:"tunnel"`
	Exclusions Exclusions     `yaml:"exclusions"`
}

var desyncStrategies = []string{"fake", "fake_split", "multisplit", "disorder", "disorder2"}

// DesyncStrategies returns the supported desync strategy names.
func DesyncStrategies() []string {
	return append([]string(nil), desyncStrategies...)
}

// Load reads, decodes and validates a YAML config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	return Unmarshal(data)
}

// Unmarshal decodes and validates YAML config bytes. Unknown fields are
// rejected so typos fail fast.
func Unmarshal(data []byte) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("config: decode: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate checks structural constraints and normalizes SNI entries to
// lower case. It mutates the config only for that normalization.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.Profile) == "" {
		return errors.New("config: profile is empty")
	}
	defaults := 0
	needDesync := false
	for i := range c.Rules {
		r := &c.Rules[i]
		matchers := 0
		for _, s := range []string{r.CIDR, r.SNI, r.Ports} {
			if s != "" {
				matchers++
			}
		}
		if matchers > 1 {
			return fmt.Errorf("config: rule %d: at most one of cidr/sni/ports is allowed", i)
		}
		if r.Action == ActionInvalid {
			return fmt.Errorf("config: rule %d: missing action", i)
		}
		switch {
		case r.CIDR != "":
			if _, _, err := net.ParseCIDR(r.CIDR); err != nil {
				return fmt.Errorf("config: rule %d: bad cidr %q: %v", i, r.CIDR, err)
			}
		case r.SNI != "":
			r.SNI = strings.ToLower(r.SNI)
			if err := validateSNI(r.SNI); err != nil {
				return fmt.Errorf("config: rule %d: %v", i, err)
			}
		case r.Ports != "":
			if _, err := ParsePortSpec(r.Ports); err != nil {
				return fmt.Errorf("config: rule %d: %v", i, err)
			}
		default:
			defaults++
		}
		if r.Action == ActionDesync {
			needDesync = true
		}
	}
	if defaults > 1 {
		return errors.New("config: multiple default rules")
	}
	for i, cidr := range c.Exclusions.CIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("config: exclusion cidr %d: bad %q: %v", i, cidr, err)
		}
	}
	for i, d := range c.Exclusions.Domains {
		c.Exclusions.Domains[i] = strings.ToLower(d)
		if err := validateSNI(c.Exclusions.Domains[i]); err != nil {
			return fmt.Errorf("config: exclusion domain %d: %v", i, err)
		}
	}
	if needDesync {
		if !validStrategy(c.Desync.Strategy) {
			return fmt.Errorf("config: desync.strategy %q is not one of %v",
				c.Desync.Strategy, desyncStrategies)
		}
		if c.Desync.TTL < 1 || c.Desync.TTL > 32 {
			return fmt.Errorf("config: desync.ttl %d out of range [1,32]", c.Desync.TTL)
		}
		if c.Desync.TTLMargin < 0 {
			return fmt.Errorf("config: desync.ttl_margin %d is negative", c.Desync.TTLMargin)
		}
		if c.Desync.Repeats < 1 {
			return fmt.Errorf("config: desync.repeats %d must be >= 1", c.Desync.Repeats)
		}
	}
	// The tunnel is either fully unspecified or fully specified; it can be
	// attached at runtime (QR import, PRD US-5) after load.
	if c.Tunnel != (TunnelEndpoint{}) {
		if c.Tunnel.Protocol != "vless" {
			return fmt.Errorf("config: tunnel.protocol %q: only \"vless\" is supported", c.Tunnel.Protocol)
		}
		if c.Tunnel.Address == "" || c.Tunnel.Port == 0 || c.Tunnel.UUID == "" ||
			c.Tunnel.RealityPBK == "" || c.Tunnel.SNI == "" {
			return errors.New("config: tunnel requires address, port, uuid, reality_public_key and sni")
		}
		if c.Tunnel.UDPMode == "" {
			c.Tunnel.UDPMode = "xudp"
		}
		if c.Tunnel.Fingerprint == "" {
			c.Tunnel.Fingerprint = "chrome"
		}
	}
	return nil
}

func validStrategy(s string) bool {
	for _, v := range desyncStrategies {
		if v == s {
			return true
		}
	}
	return false
}

// validateSNI accepts lower-case DNS names with an optional leading "*.".
func validateSNI(s string) error {
	name := s
	if strings.HasPrefix(name, "*.") {
		name = name[2:]
	}
	if name == "" || strings.Contains(name, "*") {
		return fmt.Errorf("invalid sni %q", s)
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			return fmt.Errorf("invalid sni %q: empty label", s)
		}
		for _, c := range label {
			ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
			if !ok {
				return fmt.Errorf("invalid sni %q: bad char %q", s, c)
			}
		}
	}
	return nil
}
