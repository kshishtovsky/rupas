package android

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestParseVLESSLinks(t *testing.T) {
	cases := []struct {
		name string
		link string
		want Endpoint
	}{
		{
			name: "tls tcp",
			link: "vless://uuid-1@example.com:443?encryption=none&security=tls&sni=example.com&fp=chrome&type=tcp#TLS",
			want: Endpoint{Kind: KindVLESS, Host: "example.com", Port: 443, UUID: "uuid-1",
				Security: secTLS, SNI: "example.com", Fingerprint: "chrome", Transport: transportTCP, Name: "TLS"},
		},
		{
			name: "reality vision",
			link: "vless://uuid-2@example.com:443?security=reality&pbk=PUBKEY&sid=abcd&fp=chrome&sni=www.example.com&flow=xtls-rprx-vision&type=tcp#R",
			want: Endpoint{Kind: KindVLESS, Host: "example.com", Port: 443, UUID: "uuid-2",
				Security: secReality, SNI: "www.example.com", Fingerprint: "chrome",
				Flow: vlessFlowVision, PBK: "PUBKEY", SID: "abcd", Transport: transportTCP, Name: "R"},
		},
		{
			name: "none security",
			link: "vless://uuid-3@10.0.0.1:8443?encryption=none&security=none&type=tcp",
			want: Endpoint{Kind: KindVLESS, Host: "10.0.0.1", Port: 8443, UUID: "uuid-3",
				Security: secNone, Transport: transportTCP},
		},
		{
			name: "ws transport",
			link: "vless://uuid-4@cdn.example.net:443?security=tls&sni=cdn.example.net&type=ws&path=%2Fwspath&host=ws.example.net#WS",
			want: Endpoint{Kind: KindVLESS, Host: "cdn.example.net", Port: 443, UUID: "uuid-4",
				Security: secTLS, SNI: "cdn.example.net", Transport: transportWS,
				Path: "/wspath", WSHost: "ws.example.net", Name: "WS"},
		},
		{
			name: "grpc transport",
			link: "vless://uuid-5@example.com:443?security=tls&type=grpc&serviceName=grpcsvc",
			want: Endpoint{Kind: KindVLESS, Host: "example.com", Port: 443, UUID: "uuid-5",
				Security: secTLS, Transport: transportGRPC, Service: "grpcsvc"},
		},
		{
			name: "xhttp transport",
			link: "vless://uuid-6@example.com:4443?security=tls&sni=example.com&type=xhttp&path=%2FsteamVideo&mode=packet-up#XH",
			want: Endpoint{Kind: KindVLESS, Host: "example.com", Port: 4443, UUID: "uuid-6",
				Security: secTLS, SNI: "example.com", Transport: transportXHTTP,
				Path: "/steamVideo", Mode: "packet-up", Name: "XH"},
		},
		{
			name: "httpupgrade",
			link: "vless://uuid-7@example.com:443?security=tls&type=httpupgrade&path=%2Fup&host=up.example.com",
			want: Endpoint{Kind: KindVLESS, Host: "example.com", Port: 443, UUID: "uuid-7",
				Security: secTLS, Transport: transportHTTPUpgrade, Path: "/up", WSHost: "up.example.com"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseShareLink(tc.link)
			if err != nil {
				t.Fatalf("ParseShareLink: %v", err)
			}
			if got.Kind != tc.want.Kind || got.Host != tc.want.Host || got.Port != tc.want.Port ||
				got.UUID != tc.want.UUID || got.Security != tc.want.Security || got.SNI != tc.want.SNI ||
				got.Fingerprint != tc.want.Fingerprint || got.Flow != tc.want.Flow ||
				got.PBK != tc.want.PBK || got.SID != tc.want.SID ||
				got.Transport != tc.want.Transport || got.Path != tc.want.Path ||
				got.WSHost != tc.want.WSHost || got.Service != tc.want.Service ||
				got.Mode != tc.want.Mode || got.Name != tc.want.Name {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestParseOtherProtocols(t *testing.T) {
	hy, err := ParseShareLink("hysteria2://passw0rd@hy.example.com:53552?sni=hy.example.com&insecure=1#HY2")
	if err != nil {
		t.Fatalf("hysteria2: %v", err)
	}
	if hy.Kind != KindHysteria2 || hy.UUID != "passw0rd" || hy.Port != 53552 || !hy.Insecure || hy.Security != secTLS {
		t.Fatalf("hysteria2 parsed wrong: %+v", hy)
	}
	tj, err := ParseShareLink("trojan://trojpass@tj.example.com:443?sni=tj.example.com&type=tcp")
	if err != nil {
		t.Fatalf("trojan: %v", err)
	}
	if tj.Kind != KindTrojan || tj.UUID != "trojpass" || tj.Security != secTLS {
		t.Fatalf("trojan parsed wrong: %+v", tj)
	}
	if _, err := ParseShareLink("ss://base64@host:443"); err == nil {
		t.Fatal("unsupported scheme accepted")
	}
	if _, err := ParseShareLink("vless://u@h:443?security=reality&type=tcp"); err == nil {
		t.Fatal("reality without pbk accepted")
	}
}

func TestParseHysteria2ALPNAndObfs(t *testing.T) {
	hy, err := ParseShareLink("hysteria2://pw@hy.example.com:53552?sni=hy.example.com&alpn=h3")
	if err != nil {
		t.Fatalf("alpn link: %v", err)
	}
	if len(hy.ALPN) != 1 || hy.ALPN[0] != "h3" {
		t.Fatalf("alpn = %v, want [h3]", hy.ALPN)
	}
	plain, err := ParseShareLink("hysteria2://pw@hy.example.com:53552?sni=hy.example.com")
	if err != nil {
		t.Fatalf("no-alpn link: %v", err)
	}
	if len(plain.ALPN) != 0 {
		t.Fatalf("no-alpn endpoint carries %v, want empty", plain.ALPN)
	}
	// obfs is rejected: silently dropping it yields a carrier that connects
	// and then speaks the wrong protocol.
	if _, err := ParseShareLink("hysteria2://pw@hy.example.com:53552?obfs=salamander&obfs-password=x"); err == nil {
		t.Fatal("obfs link accepted")
	}
}

func TestSettingsEndpointsChain(t *testing.T) {
	s, err := ParseSettings(`{"uuid":"u","server":"old.example.com","port":12341,"sni":"sni.example.com","fallback":true,
		"links":["vless://u1@p1.example.com:443?security=tls&type=tcp","vless://u2@p2.example.com:4443?security=tls&type=xhttp&path=%2Fx","hysteria2://p3@p3.example.com:53552"]}`)
	if err != nil {
		t.Fatalf("ParseSettings: %v", err)
	}
	eps, err := s.Endpoints()
	if err != nil {
		t.Fatalf("Endpoints: %v", err)
	}
	if len(eps) != 3 {
		t.Fatalf("got %d endpoints, want 3", len(eps))
	}
	if eps[0].Host != "p1.example.com" || eps[1].Host != "p2.example.com" || eps[2].Kind != KindHysteria2 {
		t.Fatalf("chain order wrong: %+v", eps)
	}
	if !eps[1].NeedsXHTTP() {
		t.Fatal("xhttp endpoint not detected")
	}
	// Legacy shape still works.
	s2, err := ParseSettings(`{"uuid":"u","server":"h","port":1,"sni":"s","fallback":true}`)
	if err != nil {
		t.Fatalf("legacy ParseSettings: %v", err)
	}
	eps2, err := s2.Endpoints()
	if err != nil || len(eps2) != 1 || eps2[0].Host != "h" || eps2[0].Security != secTLS {
		t.Fatalf("legacy endpoints wrong: %+v err=%v", eps2, err)
	}
}

func TestGeoLookup(t *testing.T) {
	dir := t.TempDir()
	list := "203.0.113.0/24\n198.51.100.0/22\n"
	if err := os.WriteFile(filepath.Join(dir, "geoip-ru.txt"), []byte(list), 0o644); err != nil {
		t.Fatal(err)
	}
	r := CompileRulesEx(dir, nil)
	if len(r.geoDirect) != 2 {
		t.Fatalf("geo table = %d entries, want 2", len(r.geoDirect))
	}
	// Inside the /24 → DIRECT (geo beats default tunnel even though the
	// SNI is unknown).
	m := FlowMeta{Destination: netip.MustParseAddrPort("203.0.113.55:443"), Network: "tcp"}
	if a := r.Decide(m); a != ActionDirect {
		t.Fatalf("203.0.113.55: got %v, want DIRECT", a)
	}
	// Inside the /22.
	m.Destination = netip.MustParseAddrPort("198.51.101.7:443")
	if a := r.Decide(m); a != ActionDirect {
		t.Fatalf("198.51.101.7: got %v, want DIRECT", a)
	}
	// Outside the table → default TUNNEL.
	m.Destination = netip.MustParseAddrPort("198.52.100.1:443")
	if a := r.Decide(m); a != ActionTunnel {
		t.Fatalf("198.52.100.1: got %v, want TUNNEL", a)
	}
	// Telegram CIDR still wins over everything (first-wins on shared
	// prefixes; and the static table is consulted before geo).
	m.Destination = netip.MustParseAddrPort("149.154.167.99:443")
	if a := r.Decide(m); a != ActionTunnel {
		t.Fatalf("telegram: got %v, want TUNNEL", a)
	}
}

func TestGeositeFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "geosite-direct.txt"),
		[]byte("# comment\nexample.net\n*.blocked.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := CompileRulesEx(dir, nil)
	m := FlowMeta{Destination: netip.MustParseAddrPort("1.2.3.4:443"), Network: "tcp", SNI: "www.example.net"}
	if a := r.Decide(m); a != ActionDirect {
		t.Fatalf("geosite suffix match failed: %v", a)
	}
}

// Mux: пул соединений в share-link (?mux=on&mux_conns=N).
func TestShareLinkVLESSMux(t *testing.T) {
	base := "vless://11111111-2222-3333-4444-555555555555@vps.example.net:443" +
		"?security=reality&sni=vps.example.net&pbk=AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLL&sid=999e2fd9&fp=chrome%s"

	cases := []struct {
		name    string
		query   string
		wantMux bool
		wantN   int
		fail    bool
	}{
		{"без mux", "", false, 1, false},
		{"mux on по умолчанию 1", "&mux=on", true, 1, false},
		{"mux on 4", "&mux=on&mux_conns=4", true, 4, false},
		{"mux on 7", "&mux=on&mux_conns=7", true, 7, false},
		{"mux off с числом", "&mux=off&mux_conns=4", false, 1, false},
		{"mux мусор", "&mux=maybe", false, 0, true},
		{"mux_conns выше границы", "&mux=on&mux_conns=9", false, 0, true},
		{"mux_conns ноль", "&mux=on&mux_conns=0", false, 0, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ep, err := ParseShareLink(fmt.Sprintf(base, c.query))
			if c.fail {
				if err == nil {
					t.Fatal("ждали ошибку")
				}
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got := ep.MuxOn(); got != c.wantMux {
				t.Fatalf("MuxOn = %v, ждали %v", got, c.wantMux)
			}
			if got := ep.MuxPool(); got != c.wantN {
				t.Fatalf("MuxPool = %d, ждали %d", got, c.wantN)
			}
		})
	}
}

// mux на xhttp отбивается: наш XHTTP-клиент не умеет мультиплексировать поток(и)
// в одно соединение, и молча его игнорировать — врать пользователю.
func TestShareLinkMuxRejectedOnXHTTP(t *testing.T) {
	_, err := ParseShareLink("vless://11111111-2222-3333-4444-555555555555@vps.example.net:443" +
		"?security=tls&sni=vps.example.net&type=xhttp&path=/x&mode=packet-up&mux=on")
	if err == nil {
		t.Fatal("ждали ошибку: mux на xhttp не поддержан")
	}
}

// Пул ограничен сверху даже если в структуре выставили больше.
func TestEndpointMuxPoolClamp(t *testing.T) {
	ep := Endpoint{Mux: "on", MuxConns: 99}
	if got := ep.MuxPool(); got != MaxMuxConns {
		t.Fatalf("MuxPool = %d, ждали %d", got, MaxMuxConns)
	}
	ep = Endpoint{Mux: "on", MuxConns: 0}
	if got := ep.MuxPool(); got != 1 {
		t.Fatalf("MuxPool = %d, ждали 1", got)
	}
}
