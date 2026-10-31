package guictrl

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kshishtovsky/rupas/internal/config"
	"gopkg.in/yaml.v3"
)

const testPSK = "3f1c8a5e9b7d2406c1d3e5f7089a2b4c6d8e0f1a3b5c7d9e0f2a4b6c8d0e1f3a"

func tmnLink(query string) string {
	return "tmn://" + testPSK + "@45.67.202.247:18443?sni=mylifemyrulesonline.ru&conns=4&profile=off&insecure=0" + query + "#tmn"
}

// TestParseTMNChannel: tmn:// is a first-class TCP channel (kind tmn, role
// tcp, no warning) — it must not fall into the "unsupported" branch.
func TestParseTMNChannel(t *testing.T) {
	cases := []struct {
		name, link, wantName string
		wantPort             int
	}{
		{"ip host + cover sni", tmnLink(""), "tmn", 18443},
		{"domain host", "tmn://" + testPSK + "@tmn.example.net:443#box", "box", 443},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chans, err := ParseChannels(tc.link)
			if err != nil {
				t.Fatalf("ParseChannels: %v", err)
			}
			if len(chans) != 1 {
				t.Fatalf("channels: %+v", chans)
			}
			ch := chans[0]
			if ch.Kind != "tmn" || ch.Role != "tcp" || ch.Warning != "" {
				t.Fatalf("kind/role/warning: %+v", ch)
			}
			if ch.Name != tc.wantName || ch.Port != tc.wantPort {
				t.Fatalf("name/port: %+v", ch)
			}
		})
	}
}

// TestTMNPlanOrdering: dial order decides the roles — a tmn link becomes the
// primary TCP endpoint, hysteria2 next to it stays the UDP carrier.
func TestTMNPlanOrdering(t *testing.T) {
	blob := tmnLink("") + "\n" +
		"hysteria2://hy2secret@vps.example.net:53552?sni=camo.net#voice\n"

	tcp, udp, fb, warnings, err := channelsToPlan(blob)
	if err != nil {
		t.Fatalf("channelsToPlan: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings: %v", warnings)
	}
	if tcp == nil || tcp.Kind != config.KindTMN || tcp.Host != "45.67.202.247" || tcp.Port != 18443 {
		t.Fatalf("tcp: %+v", tcp)
	}
	if tcp.SNI != "mylifemyrulesonline.ru" || tcp.PSK != testPSK || tcp.Conns != 4 {
		t.Fatalf("tcp tmn fields: %+v", tcp)
	}
	if udp == nil || udp.Kind != "hysteria2" || udp.Password != "hy2secret" {
		t.Fatalf("udp: %+v", udp)
	}
	if fb != nil {
		t.Fatalf("fallback: %+v", fb)
	}

	cfg := presetConfig(true)
	cfg.Tunnels = &config.TunnelConfig{TCP: tcp, UDP: udp}
	p := filepath.Join(t.TempDir(), "rupas.yaml")
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(p); err != nil {
		t.Fatalf("validation: %v\n%s", err, data)
	}
}

// TestSaveLinksTMNExclusion: the TMN client's own TLS connection to the
// endpoint must be pinned DIRECT, or WinDivert sends it back into the tunnel
// (docs/TMN_INTEGRATION.md §5) — and the pin must merge with, not replace,
// what the config already carries.
func TestSaveLinksTMNExclusion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rupas.yaml")
	body := `profile: owner
rules:
  - cidr: 10.0.0.0/8
    action: direct
exclusions:
  cidrs: [45.67.202.247/32]
  domains: [MyLifeMyRulesOnline.ru, spiderssense.com]
desync:
  strategy: fake
  ttl: 7
  ttl_margin: 2
  repeats: 6
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := New(Options{Pipe: `\\.\pipe\rupas-guictrl-test-absent`, ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	// No daemon: ErrDaemonDown still means "written to disk".
	if _, err := c.SaveLinks(tmnLink("")); err != nil && !errors.Is(err, ErrDaemonDown) {
		t.Fatalf("SaveLinks: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("saved config does not load: %v", err)
	}
	if got := cfg.Exclusions.Domains; len(got) != 2 {
		t.Fatalf("domains: %v", got) // no duplicate of the endpoint SNI
	}
	var hasSNI, hasSpider bool
	for _, d := range cfg.Exclusions.Domains {
		hasSNI = hasSNI || d == "mylifemyrulesonline.ru"
		hasSpider = hasSpider || d == "spiderssense.com"
	}
	if !hasSNI || !hasSpider {
		t.Fatalf("domains: %v", cfg.Exclusions.Domains)
	}
	var ipPins int
	for _, c := range cfg.Exclusions.CIDRs {
		if c == "45.67.202.247/32" {
			ipPins++
		}
	}
	if ipPins != 1 {
		t.Fatalf("cidrs: %v", cfg.Exclusions.CIDRs)
	}
	if got := appendUniq([]string{"A.b"}, "a.B"); len(got) != 1 {
		t.Fatalf("appendUniq is case-sensitive: %v", got)
	}
}
