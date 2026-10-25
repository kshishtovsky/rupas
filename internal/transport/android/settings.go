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
type Settings struct {
	UUID      string `json:"uuid"`
	Server    string `json:"server"`
	Port      uint16 `json:"port"`
	SNI       string `json:"sni"`
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id"`
	Fallback  bool   `json:"fallback"`
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

// Validate checks the mandatory fields.
func (s *Settings) Validate() error {
	switch {
	case s == nil:
		return fmt.Errorf("android: settings: nil")
	case s.UUID == "":
		return fmt.Errorf("android: settings: uuid is required")
	case s.Server == "":
		return fmt.Errorf("android: settings: server is required")
	case s.Port == 0:
		return fmt.Errorf("android: settings: port is required")
	}
	return nil
}

// Kind returns the sing-box outbound kind: vless_reality when Reality keys
// are present, vless_tcp otherwise.
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
