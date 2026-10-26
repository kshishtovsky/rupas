package android

import (
	"bytes"
	"encoding/json"
	"fmt"
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
type Settings struct {
	UUID      string `json:"uuid"`
	Server    string `json:"server"`
	Port      uint16 `json:"port"`
	SNI       string `json:"sni"`
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id"`
	Fallback  bool   `json:"fallback"`
	// Links: share links in dial order (optional; replaces the flat fields).
	Links []string `json:"links,omitempty"`
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
	switch {
	case s == nil:
		return fmt.Errorf("android: settings: nil")
	case len(s.Links) > 0:
		if _, err := s.Endpoints(); err != nil {
			return err
		}
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
		Kind:     KindVLESS,
		Host:     s.Server,
		Port:     s.Port,
		UUID:     s.UUID,
		SNI:      s.SNI,
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
