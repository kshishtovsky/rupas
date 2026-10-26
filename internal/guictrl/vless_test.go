package guictrl

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/rupas/rupas/internal/config"
)

func yamlMarshal(v any) ([]byte, error)                  { return yaml.Marshal(v) }
func loadConfigForTest(p string) (*config.Config, error) { return config.Load(p) }

func TestParseVlessLink(t *testing.T) {
	cases := []struct {
		name    string
		link    string
		wantErr bool
		check   func(t *testing.T, v VlessLink)
	}{
		{
			name: "reality tcp",
			link: "vless://0f4e1c2d-3b5a-4c6d-8e9f-aabbccddeeff@example.net:443?security=reality&pbk=PBK123&sid=AB12&sni=camo.example.net&type=tcp#my%20server",
			check: func(t *testing.T, v VlessLink) {
				if v.UUID != "0f4e1c2d-3b5a-4c6d-8e9f-aabbccddeeff" || v.Server != "example.net" || v.Port != 443 {
					t.Fatalf("authority: %+v", v)
				}
				if v.PublicKey != "PBK123" || v.ShortID != "AB12" || v.SNI != "camo.example.net" {
					t.Fatalf("params: %+v", v)
				}
				if v.Fallback || v.Warning != "" {
					t.Fatalf("flags: %+v", v)
				}
			},
		},
		{
			name: "no pbk → fallback flag",
			link: "vless://uuid@1.2.3.4:8443?sni=a.net",
			check: func(t *testing.T, v VlessLink) {
				if !v.Fallback {
					t.Fatal("want fallback=true without pbk")
				}
			},
		},
		{
			name: "xhttp transport ok",
			link: "vless://uuid@h:443?type=xhttp",
			check: func(t *testing.T, v VlessLink) {
				if v.Transport != "xhttp" || v.Warning != "" {
					t.Fatalf("%+v", v)
				}
			},
		},
		{
			name: "ws transport warning",
			link: "vless://uuid@h:443?type=ws",
			check: func(t *testing.T, v VlessLink) {
				if v.Warning == "" {
					t.Fatal("want warning for unsupported transport")
				}
			},
		},
		{
			name: "ipv6 host",
			link: "vless://uuid@[2001:db8::1]:443?pbk=k",
			check: func(t *testing.T, v VlessLink) {
				if v.Server != "[2001:db8::1]" || v.Port != 443 {
					t.Fatalf("ipv6: %+v", v)
				}
			},
		},
		{name: "empty", link: "", wantErr: true},
		{name: "not vless", link: "https://example.net", wantErr: true},
		{name: "no port", link: "vless://uuid@host", wantErr: true},
		{name: "no at", link: "vless://host:443", wantErr: true},
		{name: "bad port", link: "vless://u@h:99999", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := ParseVlessLink(tc.link)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got %+v", v)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			tc.check(t, v)
		})
	}
}

// presetConfig must survive the engine's own validation (config.Load) both
// with an endpoint (reality and plain) and in desync-only mode.
func TestPresetConfigValidates(t *testing.T) {
	inputs := []EndpointInput{
		{Host: "vps.example.net", Port: 443, UUID: "0f4e1c2d-3b5a-4c6d-8e9f-aabbccddeeff", SNI: "vps.example.net", PBK: "pbk", SID: "ab", DPI: true},
		{Host: "vps.example.net", Port: 12341, UUID: "0f4e1c2d-3b5a-4c6d-8e9f-aabbccddeeff", SNI: "vps.example.net", DPI: true},
		{DPI: true}, // desync-only skip path
	}
	for i, in := range inputs {
		cfg := presetConfig(in)
		data, err := yamlMarshal(cfg)
		if err != nil {
			t.Fatalf("case %d marshal: %v", i, err)
		}
		p := filepath.Join(t.TempDir(), "rupas.yaml")
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConfigForTest(p); err != nil {
			t.Fatalf("case %d validation: %v\n%s", i, err, data)
		}
	}
}
