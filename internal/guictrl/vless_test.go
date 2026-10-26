package guictrl

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/rupas/rupas/internal/config"
)

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
		{name: "empty", link: "", wantErr: true},
		{name: "not vless", link: "https://example.net", wantErr: true},
		{name: "no port", link: "vless://uuid@host", wantErr: true},
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

// TestChannelsToPlan covers the Android-W3-parity links flow: parsing by the
// core sharelink parser, role assignment in dial order, warnings for
// unsupported links, and a config that passes engine validation.
func TestChannelsToPlan(t *testing.T) {
	blob := "vless://0f4e1c2d-3b5a-4c6d-8e9f-aabbccddeeff@vps.example.net:443?security=reality&pbk=PBK&sid=AB&sni=camo.net&type=tcp#primary\n" +
		"hysteria2://hy2secret@vps.example.net:53552?sni=camo.net&insecure=0#voice\n" +
		"vless://0f4e1c2d-3b5a-4c6d-8e9f-aabbccddeeff@vps.example.net:4443?security=tls&sni=camo.net&type=xhttp&path=/xp&host=camo.net#fallback\n" +
		"trojan://pass@trojan.example.net:443?security=tls&sni=t.net#ignored\n"

	tcp, udp, fb, warnings, err := channelsToPlan(blob)
	if err != nil {
		t.Fatalf("channelsToPlan: %v", err)
	}
	if tcp == nil || tcp.Kind != "vless_reality" || tcp.RealityPBK != "PBK" {
		t.Fatalf("tcp: %+v", tcp)
	}
	if udp == nil || udp.Kind != "hysteria2" || udp.Password != "hy2secret" {
		t.Fatalf("udp: %+v", udp)
	}
	if fb == nil || fb.Kind != "vless_xhttp" || fb.Path != "/xp" || fb.HTTPHost != "camo.net" {
		t.Fatalf("fallback: %+v", fb)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings: %v", warnings)
	}

	cfg := presetConfig(true)
	cfg.Tunnels = &config.TunnelConfig{TCP: tcp, UDP: udp, Fallback: fb}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "rupas.yaml")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(p); err != nil {
		t.Fatalf("validation: %v\n%s", err, data)
	}
}

// presetConfig must survive engine validation in desync-only mode too.
func TestPresetConfigValidates(t *testing.T) {
	cfg := presetConfig(true)
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "rupas.yaml")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(p); err != nil {
		t.Fatalf("validation: %v\n%s", err, data)
	}
	// RU services must be direct before the geoip rule.
	for _, r := range cfg.Rules {
		if r.GeoIP != "" {
			t.Fatal("RU services must come before geoip: ru")
		}
		if r.SNI == "vk.com" {
			if r.Action != config.ActionDirect {
				t.Fatalf("vk.com action: %v", r.Action)
			}
			break
		}
	}
}
