package config

import (
	"fmt"
	"strings"
	"testing"
)

// validEndpoint returns a valid endpoint of the given kind.
func validEndpoint(kind string) Endpoint {
	e := Endpoint{
		Kind: kind, Host: "vps.example.net", Port: 443, SNI: "vps.example.net",
		UUID: "11111111-2222-3333-4444-555555555555",
	}
	switch kind {
	case KindVLESSXHTTP:
		e.Path = "/steamVideo"
	case KindVLESSReality:
		e.RealityPBK = "PUBKEYBASE64URL"
	case KindHysteria2:
		e.Password = "sekret"
	case KindTMN:
		e.PSK = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	}
	return e
}

// TestEndpointValidatePerKind covers validation + defaults of all 4 kinds.
func TestEndpointValidatePerKind(t *testing.T) {
	for _, kind := range EndpointKinds() {
		e := validEndpoint(kind)
		if err := e.Validate(); err != nil {
			t.Fatalf("kind %s: rejected: %v", kind, err)
		}
		// Defaults.
		if e.Fingerprint != "chrome" {
			t.Errorf("kind %s: fingerprint default = %q", kind, e.Fingerprint)
		}
		wantALPN := []string{"h2", "http/1.1"}
		if kind == KindHysteria2 {
			wantALPN = []string{"h3"}
		}
		if len(e.ALPN) != len(wantALPN) || e.ALPN[0] != wantALPN[0] {
			t.Errorf("kind %s: alpn default = %v, want %v", kind, e.ALPN, wantALPN)
		}
		if kind != KindHysteria2 && e.UDPMode != "xudp" {
			t.Errorf("kind %s: udp_mode default = %q", kind, e.UDPMode)
		}
	}
	// XHTTP defaults.
	x := validEndpoint(KindVLESSXHTTP)
	if err := x.Validate(); err != nil {
		t.Fatal(err)
	}
	if x.Mode != "packet-up" || x.XPadding != "100-1000" {
		t.Errorf("xhttp defaults: mode=%q x_padding=%q", x.Mode, x.XPadding)
	}

	// Per-kind required fields.
	cases := []struct {
		name string
		mut  func(*Endpoint)
		want string
	}{
		{"bad kind", func(e *Endpoint) { e.Kind = "vmess" }, `kind "vmess"`},
		{"no host", func(e *Endpoint) { e.Host = "" }, "host is empty"},
		{"no port", func(e *Endpoint) { e.Port = 0 }, "port is empty"},
		{"no sni", func(e *Endpoint) { e.SNI = "" }, "sni is empty"},
		{"vless no uuid", func(e *Endpoint) { e.UUID = "" }, "uuid is empty"},
		{"bad flow", func(e *Endpoint) { e.Flow = "weird" }, "flow"},
		{"reality no pbk", func(e *Endpoint) {
			e.Kind = KindVLESSReality
			e.RealityPBK = ""
		}, "reality_public_key"},
		{"hy2 no password", func(e *Endpoint) {
			e.Kind = KindHysteria2
			e.Password = ""
		}, "password is empty"},
		{"xhttp no path", func(e *Endpoint) {
			e.Kind = KindVLESSXHTTP
			e.Path = ""
		}, "path is empty"},
		{"xhttp bad mode", func(e *Endpoint) {
			e.Kind = KindVLESSXHTTP
			e.Path = "/x"
			e.Mode = "weird"
		}, "mode"},
		{"xhttp bad padding", func(e *Endpoint) {
			e.Kind = KindVLESSXHTTP
			e.Path = "/x"
			e.XPadding = "1000-100"
		}, "x_padding_bytes"},
		{"tmn no psk", func(e *Endpoint) {
			e.Kind = KindTMN
			e.PSK = ""
		}, "psk"},
		{"tmn short psk", func(e *Endpoint) {
			e.Kind = KindTMN
			e.PSK = "0011"
		}, "psk"},
		{"tmn conns out of range", func(e *Endpoint) {
			e.Kind = KindTMN
			e.PSK = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
			e.Conns = 9
		}, "conns"},
	}
	for _, c := range cases {
		e := validEndpoint(KindVLESSTCP)
		c.mut(&e)
		err := e.Validate()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want error containing %q", c.name, err, c.want)
		}
	}
}

// TestTunnelsYAMLRoundTrip loads a full wave-5 YAML (the example layout)
// and checks the parsed plan.
func TestTunnelsYAMLRoundTrip(t *testing.T) {
	yaml := `
profile: tunnels-test
rules:
  - cidr: 149.154.160.0/20
    action: tunnel
  - action: direct
tunnels:
  tcp:
    kind: vless_tcp
    host: myvps.example
    port: 12341
    uuid: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
    sni: myvps.example
    alpn: [h2, http/1.1]
    fingerprint: chrome
  udp:
    kind: hysteria2
    host: myvps.example
    port: 53552
    password: "testpassword123"
    sni: myvps.example
    alpn: [h3]
  fallback:
    kind: vless_xhttp
    host: myvps.example
    port: 4443
    uuid: ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb
    sni: myvps.example
    path: /steamVideo
    mode: packet-up
    x_padding_bytes: 100-1000
`
	cfg, err := Unmarshal([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	plan := cfg.TunnelPlan()
	if !plan.Configured() {
		t.Fatal("plan not configured")
	}
	if plan.TCP == nil || plan.TCP.Kind != KindVLESSTCP || plan.TCP.Port != 12341 ||
		plan.TCP.UUID != "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" {
		t.Errorf("tcp endpoint = %+v", plan.TCP)
	}
	if plan.TCP.Flow != "" {
		t.Errorf("tcp flow = %q, must stay empty (no Vision in the link)", plan.TCP.Flow)
	}
	if plan.UDP == nil || plan.UDP.Kind != KindHysteria2 || plan.UDP.Password != "testpassword123" ||
		len(plan.UDP.ALPN) != 1 || plan.UDP.ALPN[0] != "h3" {
		t.Errorf("udp endpoint = %+v", plan.UDP)
	}
	if plan.Fallback == nil || plan.Fallback.Kind != KindVLESSXHTTP || plan.Fallback.Path != "/steamVideo" ||
		plan.Fallback.Mode != "packet-up" || plan.Fallback.XPadding != "100-1000" {
		t.Errorf("fallback endpoint = %+v", plan.Fallback)
	}
}

// TestTunnelsLegacyMigration checks that the wave-≤4 `tunnel:` section
// still loads and migrates to a vless_reality plan on BOTH paths.
func TestTunnelsLegacyMigration(t *testing.T) {
	yaml := `
profile: legacy
rules:
  - action: direct
tunnel:
  protocol: vless
  address: 203.0.113.10
  port: 443
  uuid: 11111111-2222-3333-4444-555555555555
  reality_public_key: PUB
  reality_short_id: "0123abcd"
  sni: www.example.com
  fingerprint: chrome
  udp_mode: xudp
`
	cfg, err := Unmarshal([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	plan := cfg.TunnelPlan()
	if !plan.Configured() || plan.TCP == nil || plan.UDP == nil || plan.Fallback != nil {
		t.Fatalf("legacy plan = %+v", plan)
	}
	for name, e := range map[string]*Endpoint{"tcp": plan.TCP, "udp": plan.UDP} {
		if e.Kind != KindVLESSReality || e.Host != "203.0.113.10" || e.RealityPBK != "PUB" || e.Flow != "xtls-rprx-vision" {
			t.Errorf("legacy %s = %+v", name, e)
		}
	}
}

// TestTunnelsBothSectionsRejected: legacy tunnel + new tunnels is ambiguous.
func TestTunnelsBothSectionsRejected(t *testing.T) {
	yaml := `
profile: both
rules:
  - action: direct
tunnel:
  protocol: vless
  address: a
  port: 1
  uuid: u
  reality_public_key: k
  sni: s
tunnels:
  tcp:
    kind: vless_tcp
    host: a
    port: 1
    uuid: u
    sni: s
`
	if _, err := Unmarshal([]byte(yaml)); err == nil || !strings.Contains(err.Error(), "both set") {
		t.Fatalf("got %v, want both-set error", err)
	}
}

// TestTunnelsEmptySectionAllowed: a bare `tunnels:` section is the
// documented "no endpoint" default, not an error.
func TestTunnelsEmptySectionAllowed(t *testing.T) {
	yaml := `
profile: empty
rules:
  - action: direct
tunnels: {}
`
	cfg, err := Unmarshal([]byte(yaml))
	if err != nil {
		t.Fatalf("bare tunnels section rejected: %v", err)
	}
	if cfg.TunnelPlan().Configured() {
		t.Fatal("empty section must not produce a plan")
	}
}

// TestParsePaddingRange pins the X-Padding range parser.
func TestParsePaddingRange(t *testing.T) {
	for _, c := range []struct {
		in         string
		lo, hi     int
		shouldFail bool
	}{
		{"100-1000", 100, 1000, false},
		{"256", 256, 256, false},
		{"1000-100", 0, 0, true},
		{"abc", 0, 0, true},
		{"-5", 0, 0, true},
	} {
		lo, hi, err := ParsePaddingRange(c.in)
		if c.shouldFail {
			if err == nil {
				t.Errorf("ParsePaddingRange(%q) accepted", c.in)
			}
			continue
		}
		if err != nil || lo != c.lo || hi != c.hi {
			t.Errorf("ParsePaddingRange(%q) = %d,%d,%v", c.in, lo, hi, err)
		}
	}
}

// TestTunnelMuxAndChainFlags parses the wave-6 knobs: per-endpoint mux and
// the xhttp-in-chain opt-in.
func TestTunnelMuxAndChainFlags(t *testing.T) {
	cfg, err := Unmarshal([]byte(`
profile: p
rules:
  - action: direct
tunnels:
  tcp:
    kind: vless_tcp
    host: 203.0.113.10
    port: 12341
    uuid: 0f4e1c2d-3b5d-4e6f-8a9b-0c1d2e3f4a5b
    sni: vps.example.net
    mux: "on"
    mux_padding: true
  udp:
    kind: hysteria2
    host: 203.0.113.10
    port: 53552
    password: "pw"
    sni: vps.example.net
  fallback:
    kind: vless_xhttp
    host: 203.0.113.10
    port: 4443
    uuid: 0f4e1c2d-3b5d-4e6f-8a9b-0c1d2e3f4a5b
    sni: vps.example.net
    path: /x
  xhttp_fallback_in_chain: true
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	plan := cfg.Tunnels
	if plan == nil || plan.TCP == nil {
		t.Fatal("no tcp endpoint")
	}
	if plan.TCP.Mux != "on" || !plan.TCP.MuxPadding {
		t.Errorf("mux flags: %+v", plan.TCP)
	}
	if !plan.XHTTPFallbackInChain {
		t.Error("xhttp_fallback_in_chain not parsed")
	}
}

// MuxConns: размер пула mux-соединений. Одно TLS-соединение упирается в своё
// окно (замер: 227 из 540 Мбит/с при RTT 55 мс), четыре дают полосу маршрута.
func TestTunnelMuxConns(t *testing.T) {
	base := `
profile: p
rules:
  - action: direct
tunnels:
  tcp:
    kind: vless_reality
    host: 203.0.113.10
    port: 12341
    uuid: 0f4e1c2d-3b5d-4e6f-8a9b-0c1d2e3f4a5b
    sni: vps.example.net
    reality_public_key: AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLL
    reality_short_id: 999e2fd9
%s`
	cases := []struct {
		name  string
		extra string
		want  int
		fail  bool
	}{
		{"по умолчанию 1", "", 1, false},
		{"явно 4", "    mux: \"on\"\n    mux_conns: 4\n", 4, false},
		{"явно 7", "    mux: \"on\"\n    mux_conns: 7\n", 7, false},
		{"верхняя граница 8", "    mux: \"on\"\n    mux_conns: 8\n", 8, false},
		{"выше границы", "    mux: \"on\"\n    mux_conns: 9\n", 0, true},
		{"отрицательное", "    mux: \"on\"\n    mux_conns: -1\n", 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := Unmarshal([]byte(fmt.Sprintf(base, c.extra)))
			if c.fail {
				if err == nil {
					t.Fatalf("ждали ошибку валидации для mux_conns")
				}
				return
			}
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if cfg.Tunnels == nil || cfg.Tunnels.TCP == nil {
				t.Fatal("no tcp endpoint")
			}
			if got := cfg.Tunnels.TCP.MuxConns; got != c.want {
				t.Fatalf("mux_conns = %d, ждали %d", got, c.want)
			}
		})
	}
}

// MuxConns не должен влиять на не-mux конфиг: без mux соединение одно на поток.
func TestTunnelMuxConnsIgnoredWithoutMux(t *testing.T) {
	cfg, err := Unmarshal([]byte(`
profile: p
rules:
  - action: direct
tunnels:
  tcp:
    kind: vless_reality
    host: 203.0.113.10
    port: 12341
    uuid: 0f4e1c2d-3b5d-4e6f-8a9b-0c1d2e3f4a5b
    sni: vps.example.net
    reality_public_key: AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLL
    reality_short_id: 999e2fd9
    mux_conns: 4
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Tunnels.TCP.Mux != "" {
		t.Fatalf("mux включился сам: %q", cfg.Tunnels.TCP.Mux)
	}
}

// TestTMNEndpointDefaults pins the TMN/1 endpoint contract: hex-normalized
// PSK, pool size default, and "not carried by sing-box, no UDP" — the three
// facts the tunnel/Android carriers rely on.
func TestTMNEndpointDefaults(t *testing.T) {
	e := validEndpoint(KindTMN)
	e.PSK = strings.ToUpper(e.PSK)
	if err := e.Validate(); err != nil {
		t.Fatalf("valid tmn endpoint rejected: %v", err)
	}
	if e.Conns != 4 {
		t.Errorf("conns default = %d, want 4", e.Conns)
	}
	if e.PSK != strings.ToLower(e.PSK) {
		t.Errorf("psk not lower-cased: %q", e.PSK)
	}
	if e.SingBoxKind() {
		t.Error("tmn must not be carried by sing-box")
	}
	if e.SupportsUDP() {
		t.Error("tmn must report SupportsUDP=false (the protocol has no UDP flows)")
	}
}
