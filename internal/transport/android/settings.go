package android

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rupas/rupas/internal/config"
)

// Settings is the W3 tunnel endpoint description delivered by the Java
// side through core.SetSettings as JSON of the exact shape:
//
//	{"uuid":"…","server":"host","port":443,"sni":"…",
//	 "public_key":"…","short_id":"…","fallback":true}
//
// public_key/short_id switch the endpoint kind to VLESS+Reality; without
// them the endpoint is plain VLESS over TCP+TLS. fallback=true allows the
// honest escalation of TUNNEL flows to DIRECT when the socks dial fails;
// fallback=false drops them instead.
//
// Universal endpoint support: the optional "links" array carries standard
// share links (vless://, hysteria2://, hy2://, trojan://) in dial order —
// the first is the primary carrier, the rest are fallbacks. When links is
// set it fully replaces the legacy flat fields.
//
// prefer_ipv4 (optional, default TRUE) — PreferIPv4 mode: IPv6 flows are
// fast-dropped at the TUN and DNS AAAA queries are answered with an empty
// NOERROR, forcing every app onto IPv4. The server fleet has no IPv6
// egress today, so v6 targets through the tunnel are guaranteed death;
// this flag turns "works only sometimes" into "works always". Send false
// in the settings JSON to disable once the server gains working IPv6.
type Settings struct {
	UUID      string `json:"uuid"`
	Server    string `json:"server"`
	Port      uint16 `json:"port"`
	SNI       string `json:"sni"`
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id"`
	Fallback  bool   `json:"fallback"`
	// PreferIPv4: nil (absent in JSON) means enabled.
	PreferIPv4 *bool `json:"prefer_ipv4,omitempty"`
	// Links: share links in dial order (optional; replaces the flat fields).
	Links []string `json:"links,omitempty"`
	// Rules: the routing rule set edited in the app's Routing screen
	// (optional). When absent or empty the core compiles the built-in W3
	// preset (android.DefaultRules) — the pre-screen behaviour. Rules are
	// read at the next Start, so a change requires a VPN restart.
	Rules []config.Rule `json:"rules,omitempty"`
	// AppRules: the per-app rules of the Routing screen's 4th stage
	// (docs/PERAPP_ROUTING.md §6). Java resolves package→uid before Start;
	// DIRECT entries never reach the core (they are applied with
	// VpnService.addDisallowedApplication, outside the VPN), so what the
	// core sees is the TUNNEL/BLOCK subset. Absent/empty means no per-app
	// rules: the core then never calls Platform.ResolveUID.
	AppRules []AppRule `json:"app_rules,omitempty"`
	// Adblock: the built-in ads/trackers filter (v0.4.0). Absent means
	// "no filter configured" — the engine blocks nothing; a present object
	// defaults to ads=true, trackers=false.
	Adblock *AdblockSettings `json:"adblock,omitempty"`
}

// AppRule is one per-application routing rule. UID, not package name, is the
// wire identity: Java maps package→uid at establish() time, because a UID
// changes when the app is reinstalled. Action ∈ {direct, tunnel, block}
// (case-insensitive).
type AppRule struct {
	UID    int    `json:"uid"`
	Action string `json:"action"`
}

// parseAppAction maps a Settings app-rule action onto the decision set.
// DIRECT is a valid settings value — it is applied by the Java side
// (addDisallowedApplication) and never compiled into the UID table, because
// such an app creates no flow in the netstack at all.
func parseAppAction(s string) (Action, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "direct":
		return ActionDirect, nil
	case "tunnel":
		return ActionTunnel, nil
	case "block":
		return ActionBlock, nil
	default:
		return ActionDirect, fmt.Errorf("unknown action %q (want direct, tunnel or block)", s)
	}
}

// PreferIPv4Enabled reports the effective PreferIPv4 mode; absent field →
// enabled.
func (s *Settings) PreferIPv4Enabled() bool {
	return s == nil || s.PreferIPv4 == nil || *s.PreferIPv4
}

// ParseSettings decodes and validates the SetSettings JSON. Unknown fields
// are rejected: the wire shape is fixed by the §3 contract.
func ParseSettings(data string) (*Settings, error) {
	dec := json.NewDecoder(bytes.NewReader([]byte(data)))
	dec.DisallowUnknownFields()
	var s Settings
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("android: settings: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("android: settings: trailing data after JSON object")
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// Validate checks the mandatory fields: either share links (parsed and
// validated by Endpoints) or the legacy flat triple uuid/server/port.
func (s *Settings) Validate() error {
	if s == nil {
		return fmt.Errorf("android: settings: nil")
	}
	if len(s.Rules) > 0 {
		// The Routing screen sends the same rule shape the desktop config
		// uses; validate it with the engine's own rules so a bad rule set is
		// refused at SetSettings instead of at the next Start.
		if err := config.ValidateRules(s.Rules); err != nil {
			return fmt.Errorf("android: settings: %w", err)
		}
	}
	// Per-app rules are validated entry by entry with the index in the
	// message: the screen edits a list, and "rule 3 is broken" is what the
	// owner can act on. DIRECT entries are valid here — the Java side
	// applies them outside the VPN (addDisallowedApplication).
	for i, ar := range s.AppRules {
		if ar.UID < 0 {
			return fmt.Errorf("android: settings: app_rules[%d]: uid must be >= 0 (got %d)", i, ar.UID)
		}
		if _, err := parseAppAction(ar.Action); err != nil {
			return fmt.Errorf("android: settings: app_rules[%d]: %w", i, err)
		}
	}
	// Whitelist entries are validated here, at SetSettings time, so a broken
	// domain never reaches the compiled matcher.
	if s.Adblock != nil {
		if err := s.Adblock.validate(); err != nil {
			return err
		}
	}
	switch {
	case len(s.Links) > 0:
		if _, err := s.Endpoints(); err != nil {
			return err
		}
		return nil
	case s.UUID == "" && s.Server == "" && s.Adblock != nil:
		// Zero enabled profiles, filter on: a valid document with no endpoint.
		// The tunnel stays off (Fallback → rules go direct) and adblock must
		// keep working — clearing the whole settings would kill it too.
		return nil
	case s.UUID == "":
		return fmt.Errorf("android: settings: uuid is required")
	case s.Server == "":
		return fmt.Errorf("android: settings: server is required")
	case s.Port == 0:
		return fmt.Errorf("android: settings: port is required")
	}
	return nil
}

// Kind returns the sing-box outbound kind of the LEGACY flat endpoint
// (vless_reality when Reality keys are present, vless_tcp otherwise).
// With links the per-endpoint Kind field is authoritative instead.
func (s *Settings) Kind() string {
	if s.PublicKey != "" {
		return "vless_reality"
	}
	return "vless_tcp"
}

// ServerAddr returns the server host:port.
func (s *Settings) ServerAddr() string {
	return fmt.Sprintf("%s:%d", s.Server, s.Port)
}

// HasEndpoint reports whether the settings carry any dial target at all. Zero
// enabled profiles in the app produce a document with the filter but no
// endpoint: that is a valid "tunnel off" state, not a broken config.
func (s *Settings) HasEndpoint() bool {
	return s != nil && (len(s.Links) > 0 || (s.UUID != "" && s.Server != ""))
}

// Endpoints returns the dial chain: share links when present, otherwise
// the single legacy flat endpoint. The first endpoint is the primary
// carrier, the rest are fallbacks.
func (s *Settings) Endpoints() ([]Endpoint, error) {
	if len(s.Links) == 0 {
		return []Endpoint{s.legacyEndpoint()}, nil
	}
	eps := make([]Endpoint, 0, len(s.Links))
	for i, raw := range s.Links {
		e, err := ParseShareLink(raw)
		if err != nil {
			return nil, fmt.Errorf("link %d: %w", i, err)
		}
		eps = append(eps, e)
	}
	return eps, nil
}

// legacyEndpoint converts the flat fields into one vless endpoint.
func (s *Settings) legacyEndpoint() Endpoint {
	e := Endpoint{
		Kind:      KindVLESS,
		Host:      s.Server,
		Port:      s.Port,
		UUID:      s.UUID,
		SNI:       s.SNI,
		Transport: transportTCP,
	}
	if s.PublicKey != "" {
		e.Security = secReality
		e.PBK = s.PublicKey
		e.SID = s.ShortID
		e.Flow = vlessFlowVision
		e.Fingerprint = "chrome"
	} else {
		e.Security = secTLS
	}
	return e
}
