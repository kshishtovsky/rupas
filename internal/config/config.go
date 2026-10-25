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
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// vlessFlowVision is the standard VLESS+Reality flow.
const vlessFlowVision = "xtls-rprx-vision"

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
	// ActionBlock drops the matched packet (PRD §5: block QUIC/UDP so
	// browsers fall back to TCP). Never re-injected.
	ActionBlock
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
	case ActionBlock:
		return "BLOCK"
	default:
		return "INVALID"
	}
}

// MarshalYAML encodes the action as a lower-case YAML string.
func (a Action) MarshalYAML() (any, error) {
	switch a {
	case ActionDesync, ActionTunnel, ActionDirect, ActionBlock:
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
	case "block":
		*a = ActionBlock
	default:
		return fmt.Errorf("config: invalid action %q (want desync|tunnel|direct|block)", s)
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

// TunnelEndpoint is the legacy single-endpoint tunnel description (waves ≤4).
// It is still accepted for backwards compatibility and migrated to a
// TunnelConfig (kind vless_reality) by Config.Validate; new configurations
// should use the wave-5 `tunnels:` section (Endpoint/TunnelConfig below).
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

// Endpoint kinds (wave 5): one value per user-facing transport.
const (
	// KindVLESSTCP is VLESS over plain TCP+TLS (no Reality camouflage).
	KindVLESSTCP = "vless_tcp"
	// KindVLESSXHTTP is VLESS over the XHTTP transport (Xray "xhttp",
	// mode packet-up/stream-up/stream-one) — carried by Rupas' own client,
	// sing-box v1.14 has no XHTTP transport.
	KindVLESSXHTTP = "vless_xhttp"
	// KindVLESSReality is VLESS+Reality (waves ≤4 default).
	KindVLESSReality = "vless_reality"
	// KindHysteria2 is Hysteria2 over QUIC (UDP).
	KindHysteria2 = "hysteria2"
)

// EndpointKinds returns the supported tunnel endpoint kinds.
func EndpointKinds() []string {
	return []string{KindVLESSTCP, KindVLESSXHTTP, KindVLESSReality, KindHysteria2}
}

// Endpoint describes one user-side tunnel exit (wave 5). Fields are shared
// across kinds; Validate enforces the per-kind subset and applies defaults.
type Endpoint struct {
	Kind string `yaml:"kind"`
	Host string `yaml:"host"`
	Port uint16 `yaml:"port"`
	// UUID authenticates VLESS kinds.
	UUID string `yaml:"uuid,omitempty"`
	// Password authenticates hysteria2.
	Password string `yaml:"password,omitempty"`
	// SNI is the TLS server name (camouflage domain).
	SNI string `yaml:"sni,omitempty"`
	// ALPN lists the offered protocols (default per kind).
	ALPN []string `yaml:"alpn,omitempty"`
	// Fingerprint is the uTLS client fingerprint (default chrome).
	Fingerprint string `yaml:"fingerprint,omitempty"`
	// Flow is the VLESS flow ("": none, "xtls-rprx-vision" for Reality).
	Flow string `yaml:"flow,omitempty"`
	// Path is the XHTTP path prefix (vless_xhttp only).
	Path string `yaml:"path,omitempty"`
	// Mode is the XHTTP mode (vless_xhttp only; default packet-up).
	Mode string `yaml:"mode,omitempty"`
	// XPadding is the XHTTP X-Padding length range "min-max" (vless_xhttp
	// only; default 100-1000).
	XPadding string `yaml:"x_padding_bytes,omitempty"`
	// RealityPBK/RealitySID authenticate vless_reality.
	RealityPBK string `yaml:"reality_public_key,omitempty"`
	RealitySID string `yaml:"reality_short_id,omitempty"`
	// UDPMode selects the VLESS UDP packet encoding (xudp|packetaddr;
	// default xudp).
	UDPMode string `yaml:"udp_mode,omitempty"`
	// Mux toggles sing-mux multiplexing (h2mux; one long-lived TLS
	// connection carries every stream) on VLESS endpoints. Needs SERVER
	// support (sing-box server; xray does NOT demux sing-mux — live-
	// verified wave 6: every stream dies with EOF ~1.3 s against xray).
	// Default off; set "on" against sing-box servers.
	Mux string `yaml:"mux,omitempty"`
	// MuxPadding enables sing-mux padding (anti-length-analysis; needs
	// server support — xray ≥ 1.8.6 / sing-box). Default off.
	MuxPadding bool `yaml:"mux_padding,omitempty"`
}

// IsZero reports whether no meaningful field of the endpoint is set.
func (e Endpoint) IsZero() bool {
	return e.Kind == "" && e.Host == "" && e.Port == 0 && e.UUID == "" &&
		e.Password == "" && e.SNI == "" && len(e.ALPN) == 0 && e.Fingerprint == "" &&
		e.Flow == "" && e.Path == "" && e.Mode == "" && e.XPadding == "" &&
		e.RealityPBK == "" && e.RealitySID == "" && e.UDPMode == ""
}

// SingBoxKind reports whether the endpoint kind is carried by the embedded
// sing-box engine (everything except vless_xhttp, which Rupas' own XHTTP
// client carries).
func (e Endpoint) SingBoxKind() bool { return e.Kind != KindVLESSXHTTP }

// SupportsUDP reports whether the kind can carry UDP flows (used to decide
// whether the UDP fallback chain exists).
func (e Endpoint) SupportsUDP() bool {
	switch e.Kind {
	case KindVLESSTCP, KindVLESSReality, KindHysteria2:
		return true
	}
	return false
}

var endpointKinds = map[string]bool{
	KindVLESSTCP: true, KindVLESSXHTTP: true, KindVLESSReality: true, KindHysteria2: true,
}

var xhttpModes = map[string]bool{
	"packet-up": true, "stream-up": true, "stream-one": true, "auto": true,
}

// Validate checks the per-kind subset and applies defaults (fingerprint,
// ALPN, XHTTP mode/padding, UDP mode). It mutates the endpoint only for
// that normalization.
func (e *Endpoint) Validate() error {
	if !endpointKinds[e.Kind] {
		return fmt.Errorf("tunnel endpoint kind %q: want one of %v", e.Kind, EndpointKinds())
	}
	if e.Host == "" {
		return errors.New("tunnel endpoint: host is empty")
	}
	if e.Port == 0 {
		return errors.New("tunnel endpoint: port is empty")
	}
	if e.SNI == "" {
		return errors.New("tunnel endpoint: sni is empty")
	}
	switch e.Kind {
	case KindVLESSTCP, KindVLESSXHTTP, KindVLESSReality:
		if e.UUID == "" {
			return errors.New("tunnel endpoint: uuid is empty")
		}
		switch e.Flow {
		case "", "xtls-rprx-vision":
		default:
			return fmt.Errorf("tunnel endpoint: flow %q: only \"\" or \"xtls-rprx-vision\" are supported", e.Flow)
		}
	default: // hysteria2
		if e.Password == "" {
			return errors.New("tunnel endpoint: password is empty")
		}
	}
	if e.Kind == KindVLESSReality && e.RealityPBK == "" {
		return errors.New("tunnel endpoint: reality_public_key is empty")
	}
	if e.Kind == KindVLESSXHTTP {
		if e.Path == "" {
			return errors.New("tunnel endpoint: path is empty")
		}
		if e.Mode == "" {
			e.Mode = "packet-up"
		}
		if !xhttpModes[e.Mode] {
			return fmt.Errorf("tunnel endpoint: mode %q: want packet-up|stream-up|stream-one|auto", e.Mode)
		}
		if e.XPadding == "" {
			e.XPadding = "100-1000"
		}
		if _, _, err := ParsePaddingRange(e.XPadding); err != nil {
			return fmt.Errorf("tunnel endpoint: %v", err)
		}
	}
	// Defaults.
	if e.Fingerprint == "" {
		e.Fingerprint = "chrome"
	}
	if len(e.ALPN) == 0 {
		if e.Kind == KindHysteria2 {
			e.ALPN = []string{"h3"}
		} else {
			e.ALPN = []string{"h2", "http/1.1"}
		}
	}
	if e.Kind != KindHysteria2 && e.UDPMode == "" {
		e.UDPMode = "xudp"
	}
	return nil
}

// ParsePaddingRange parses "N" or "N-M" into (lo, hi, err).
func ParsePaddingRange(s string) (int, int, error) {
	loHi := strings.SplitN(s, "-", 2)
	lo, err := strconv.Atoi(strings.TrimSpace(loHi[0]))
	if err != nil || lo < 0 {
		return 0, 0, fmt.Errorf("bad x_padding_bytes %q", s)
	}
	hi := lo
	if len(loHi) == 2 {
		hi, err = strconv.Atoi(strings.TrimSpace(loHi[1]))
		if err != nil || hi < lo {
			return 0, 0, fmt.Errorf("bad x_padding_bytes %q", s)
		}
	}
	return lo, hi, nil
}

// TunnelConfig is the wave-5 multi-transport tunnel plan: TCP flows (e.g.
// Telegram) ride TCP, UDP pseudo-sessions (e.g. Discord voice) ride UDP,
// and Fallback is the secondary TCP path tried when the primary dial fails
// (SYSTEM_DESIGN §6). Endpoints may be nil; at least one must be set.
type TunnelConfig struct {
	// TCP carries TCP streams (the §6 marker rides it).
	TCP *Endpoint `yaml:"tcp,omitempty"`
	// UDP carries UDP pseudo-sessions (nil → TCP's endpoint, when it
	// supports UDP).
	UDP *Endpoint `yaml:"udp,omitempty"`
	// Fallback is the backup TCP path (dialed when TCP's dial fails).
	Fallback *Endpoint `yaml:"fallback,omitempty"`
	// XHTTPFallbackInChain opts a vless_xhttp fallback endpoint into the
	// automatic TCP dial chain. Default false (wave 6, live finding F3):
	// on TSPU networks the XHTTP port is commonly blackholed outright and a
	// dead fallback adds a full dial-timeout penalty to every attempt, so
	// the automatic chain is [tcp → hysteria2-tcp] and the XHTTP client
	// stays a manual/diagnostic path.
	XHTTPFallbackInChain bool `yaml:"xhttp_fallback_in_chain,omitempty"`
}

// Configured reports whether any endpoint is set.
func (tc TunnelConfig) Configured() bool {
	return tc.TCP != nil || tc.UDP != nil || tc.Fallback != nil
}

// Validate validates every set endpoint.
func (tc TunnelConfig) Validate() error {
	for name, e := range map[string]*Endpoint{"tcp": tc.TCP, "udp": tc.UDP, "fallback": tc.Fallback} {
		if e == nil {
			continue
		}
		if err := e.Validate(); err != nil {
			return fmt.Errorf("config: tunnels.%s: %v", name, err)
		}
	}
	return nil
}

// legacyEndpoint migrates a waves-≤4 TunnelEndpoint to an Endpoint.
func legacyEndpoint(t TunnelEndpoint) *Endpoint {
	return &Endpoint{
		Kind:        KindVLESSReality,
		Host:        t.Address,
		Port:        t.Port,
		UUID:        t.UUID,
		SNI:         t.SNI,
		Fingerprint: t.Fingerprint,
		Flow:        vlessFlowVision,
		RealityPBK:  t.RealityPBK,
		RealitySID:  t.RealitySID,
		UDPMode:     t.UDPMode,
	}
}

// Exclusions are destinations that are always DIRECT: the VPS endpoint
// itself, RU banking subnets and similar (PRD §5, last row).
type Exclusions struct {
	CIDRs   []string `yaml:"cidrs"`
	Domains []string `yaml:"domains"`
}

// Rule routes traffic to an Action by exactly one matcher: cidr, sni or
// ports. A rule with no matcher is the default rule (at most one allowed).
// Proto narrows the rule to one transport protocol ("tcp" | "udp"); empty
// matches both. Resolution order is fixed by SYSTEM_DESIGN §4.2:
// CIDR → SNI → port → default.
type Rule struct {
	CIDR   string `yaml:"cidr,omitempty"`
	SNI    string `yaml:"sni,omitempty"`   // exact name or "*.suffix" wildcard
	Ports  string `yaml:"ports,omitempty"` // "443", "50000-65535", "53,123"
	Proto  string `yaml:"proto,omitempty"` // "", "tcp" or "udp"
	Action Action `yaml:"action"`
}

// Transport protocol selector values for Rule.Proto.
const (
	// ProtoAny is the empty selector: the rule matches both transports.
	ProtoAny = ""
	// ProtoTCP matches TCP flows only.
	ProtoTCP = "tcp"
	// ProtoUDP matches UDP datagrams only (e.g. QUIC — PRD §5).
	ProtoUDP = "udp"
)

// ProtoOK reports whether selector s is valid.
func ProtoOK(s string) bool {
	switch s {
	case ProtoAny, ProtoTCP, ProtoUDP:
		return true
	}
	return false
}

// Config is the root configuration object.
type Config struct {
	Profile    string         `yaml:"profile"`
	Rules      []Rule         `yaml:"rules"`
	Desync     DesyncParams   `yaml:"desync"`
	Tunnel     TunnelEndpoint `yaml:"tunnel"`  // legacy single endpoint (≤ wave 4)
	Tunnels    *TunnelConfig  `yaml:"tunnels"` // wave-5 multi-transport plan
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
		r.Proto = strings.ToLower(strings.TrimSpace(r.Proto))
		if !ProtoOK(r.Proto) {
			return fmt.Errorf("config: rule %d: proto %q: want %q, %q or %q",
				i, r.Proto, ProtoAny, ProtoTCP, ProtoUDP)
		}
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
			if r.Proto != "" {
				// A matcher-less rule IS the default rule; the table has
				// a single default action with no proto dimension.
				return fmt.Errorf("config: rule %d: proto %q is not allowed on the default rule (set cidr/sni/ports)", i, r.Proto)
			}
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
	// attached at runtime (QR import, PRD US-5) after load. Wave 5 accepts
	// both the legacy single endpoint (migrated to kind vless_reality) and
	// the multi-transport `tunnels:` section — but never both at once.
	legacy := c.Tunnel != (TunnelEndpoint{})
	if legacy && c.Tunnels != nil {
		return errors.New("config: tunnel (legacy) and tunnels are both set; use one")
	}
	if legacy {
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
	if c.Tunnels != nil && c.Tunnels.Configured() {
		if err := c.Tunnels.Validate(); err != nil {
			return err
		}
	} else {
		// An absent or bare-empty `tunnels:` section is the documented
		// "no endpoint" default (see rupas.example.yaml).
		c.Tunnels = nil
	}
	return nil
}

// TunnelPlan returns the effective wave-5 tunnel plan: the `tunnels:` section
// when present, otherwise the legacy single endpoint migrated to a
// vless_reality plan (TCP and UDP ride the same endpoint), otherwise the
// empty (unconfigured) plan.
func (c *Config) TunnelPlan() TunnelConfig {
	if c.Tunnels != nil {
		return *c.Tunnels
	}
	if c.Tunnel != (TunnelEndpoint{}) {
		ep := legacyEndpoint(c.Tunnel)
		return TunnelConfig{TCP: ep, UDP: &Endpoint{
			Kind: ep.Kind, Host: ep.Host, Port: ep.Port, UUID: ep.UUID, SNI: ep.SNI,
			ALPN: append([]string(nil), ep.ALPN...), Fingerprint: ep.Fingerprint,
			Flow: ep.Flow, RealityPBK: ep.RealityPBK, RealitySID: ep.RealitySID,
			UDPMode: ep.UDPMode,
		}}
	}
	return TunnelConfig{}
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
