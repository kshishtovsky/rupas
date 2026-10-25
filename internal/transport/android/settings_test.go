package android

import "testing"

func TestParseSettingsValid(t *testing.T) {
	s, err := ParseSettings(`{"uuid":"b4f1","server":"vps.example.com","port":443,"sni":"camo.example","public_key":"PBK","short_id":"0123","fallback":true}`)
	if err != nil {
		t.Fatal(err)
	}
	if s.UUID != "b4f1" || s.Server != "vps.example.com" || s.Port != 443 ||
		s.SNI != "camo.example" || s.PublicKey != "PBK" || s.ShortID != "0123" || !s.Fallback {
		t.Fatalf("roundtrip mismatch: %+v", s)
	}
	if s.Kind() != "vless_reality" {
		t.Fatalf("kind = %s, want vless_reality", s.Kind())
	}
	if s.ServerAddr() != "vps.example.com:443" {
		t.Fatalf("serverAddr = %s", s.ServerAddr())
	}
}

func TestParseSettingsPlainVLESS(t *testing.T) {
	s, err := ParseSettings(`{"uuid":"u","server":"10.0.0.1","port":12341,"sni":"s","fallback":false}`)
	if err != nil {
		t.Fatal(err)
	}
	if s.Kind() != "vless_tcp" {
		t.Fatalf("kind = %s, want vless_tcp", s.Kind())
	}
	if s.Fallback {
		t.Fatal("fallback must default to false when omitted")
	}
}

func TestParseSettingsRejects(t *testing.T) {
	cases := map[string]string{
		"not json":         `{{{`,
		"trailing":         `{"uuid":"u","server":"s","port":1} garbage`,
		"unknown field":    `{"uuid":"u","server":"s","port":1,"host":"x"}`,
		"missing uuid":     `{"server":"s","port":1}`,
		"missing server":   `{"uuid":"u","port":1}`,
		"missing port":     `{"uuid":"u","server":"s"}`,
		"port out of rage": `{"uuid":"u","server":"s","port":0}`,
	}
	for name, in := range cases {
		if _, err := ParseSettings(in); err == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
}
