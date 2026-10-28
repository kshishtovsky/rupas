package rules

import (
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/kshishtovsky/rupas/internal/config"
)

// v4 builds a v4-mapped 16-byte address.
func v4(a, b, c, d byte) [16]byte {
	return [16]byte{10: 0xff, 11: 0xff, 12: a, 13: b, 14: c, 15: d}
}

func v6(s string) [16]byte {
	ip := net.ParseIP(s).To16()
	var out [16]byte
	copy(out[:], ip)
	return out
}

func TestMatchDefaultProfile(t *testing.T) {
	tbl, err := Compile(config.Default())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	tests := []struct {
		name string
		ip   [16]byte
		sni  string
		port uint16
		want config.Action
	}{
		// Telegram CIDRs (PRD appendix A, SYN-dropped IPs).
		{"tg 149.154.167.51", v4(149, 154, 167, 51), "", 443, config.ActionTunnel},
		{"tg 149.154.175.53", v4(149, 154, 175, 53), "", 80, config.ActionTunnel},
		{"tg 91.108.56.130", v4(91, 108, 56, 130), "", 5222, config.ActionTunnel},
		{"tg /32 95.161.76.100", v4(95, 161, 76, 100), "", 443, config.ActionTunnel},
		{"tg below range", v4(149, 154, 159, 1), "", 443, config.ActionDirect},
		{"tg above range", v4(149, 154, 176, 1), "", 443, config.ActionDirect},
		// SNI blocklist.
		{"yt exact", v4(142, 250, 185, 78), "www.youtube.com", 443, config.ActionDesync},
		{"discord exact", v4(162, 159, 128, 233), "discord.com", 443, config.ActionDesync},
		{"discord gateway exact", v4(162, 159, 128, 233), "gateway.discord.gg", 443, config.ActionDesync},
		{"yt wildcard", v4(142, 250, 185, 78), "r4.sn-nx57nss9.googlevideo.com", 443, config.ActionDesync},
		{"wildcard two labels deep", v4(1, 2, 3, 4), "rr2---sn-ab.googlevideo.com", 443, config.ActionDesync},
		// Wildcards match at label boundaries only.
		{"wildcard no bare apex", v4(1, 2, 3, 4), "googlevideo.com", 443, config.ActionDirect},
		// "xgateway.discord.gg" does NOT substring-match the
		// gateway.discord.gg exact entry — but the wave-7 "*.discord.gg"
		// wildcard legitimately hits the discord.gg label boundary.
		{"no exact substring", v4(1, 2, 3, 4), "xgateway.discord.gg", 443, config.ActionDesync},
		{"no sni youtube video cdn", v4(142, 250, 185, 78), "example.com", 443, config.ActionDirect},
		// Discord voice UDP range.
		{"udp 50000", v4(66, 22, 224, 1), "", 50000, config.ActionTunnel},
		{"udp 65535", v4(66, 22, 224, 1), "", 65535, config.ActionTunnel},
		{"udp 49999", v4(66, 22, 224, 1), "", 49999, config.ActionDirect},
		// Everything else direct.
		{"ru ip", v4(77, 88, 8, 8), "", 53, config.ActionDirect},
		{"github", v4(140, 82, 121, 4), "github.com", 443, config.ActionDirect},
		// CIDR wins over SNI (fixed resolution order).
		{"cidr beats sni", v4(149, 154, 167, 51), "www.youtube.com", 443, config.ActionTunnel},
		// Port wins over default but not over SNI.
		{"sni beats port", v4(1, 2, 3, 4), "www.youtube.com", 50000, config.ActionDesync},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tbl.Match(tt.ip, tt.sni, tt.port)
			if got != tt.want {
				t.Errorf("Match(%v, %q, %d) = %v, want %v",
					net.IP(tt.ip[:]).String(), tt.sni, tt.port, got, tt.want)
			}
		})
	}
}

func TestMatchIPv6(t *testing.T) {
	cfg := config.Default()
	cfg.Rules = append(cfg.Rules[:0:0], cfg.Rules...)
	cfg.Rules = append(cfg.Rules, config.Rule{CIDR: "2a03:2880::/29", Action: config.ActionTunnel})
	tbl, err := Compile(cfg)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	tests := []struct {
		name string
		ip   [16]byte
		want config.Action
	}{
		{"v6 in range", v6("2a03:2880:f123::1"), config.ActionTunnel},
		{"v6 range edge", v6("2a03:2880:7fff::"), config.ActionTunnel},
		{"v6 out of range", v6("2a03:2888::1"), config.ActionDirect},
		{"v6 unrelated", v6("2606:4700::6810:84e5"), config.ActionDirect},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tbl.Match(tt.ip, "", 443); got != tt.want {
				t.Errorf("Match(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestLongestPrefixWins(t *testing.T) {
	cfg := &config.Config{
		Profile: "lpm",
		Rules: []config.Rule{
			{CIDR: "10.0.0.0/8", Action: config.ActionTunnel},
			{CIDR: "10.1.0.0/24", Action: config.ActionDirect},
			{CIDR: "0.0.0.0/0", Action: config.ActionDesync},
			{Action: config.ActionDirect},
		},
		Desync: config.DesyncParams{Strategy: "fake", TTL: 13, Repeats: 2},
	}
	tbl, err := Compile(cfg)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	tests := []struct {
		ip   [16]byte
		want config.Action
	}{
		{v4(10, 1, 0, 5), config.ActionDirect},    // /24 beats /8
		{v4(10, 2, 0, 1), config.ActionTunnel},    // /8 beats /0
		{v4(192, 168, 1, 1), config.ActionDesync}, // /0 catch-all beats default
	}
	for _, tt := range tests {
		if got := tbl.Match(tt.ip, "", 443); got != tt.want {
			t.Errorf("Match(%v) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestExclusionsOverride(t *testing.T) {
	cfg := &config.Config{
		Profile: "excl",
		Rules: []config.Rule{
			{CIDR: "149.154.160.0/20", Action: config.ActionTunnel},
			{SNI: "www.youtube.com", Action: config.ActionDesync},
		},
		Exclusions: config.Exclusions{
			CIDRs:   []string{"149.154.175.0/24"},
			Domains: []string{"www.youtube.com"},
		},
		Desync: config.DesyncParams{Strategy: "fake", TTL: 13, Repeats: 2},
	}
	tbl, err := Compile(cfg)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	// Longer exclusion prefix wins over the broader tunnel CIDR.
	if got := tbl.Match(v4(149, 154, 175, 53), "", 443); got != config.ActionDirect {
		t.Errorf("excluded /24 = %v, want DIRECT", got)
	}
	if got := tbl.Match(v4(149, 154, 167, 51), "", 443); got != config.ActionTunnel {
		t.Errorf("non-excluded tg = %v, want TUNNEL", got)
	}
	// First insertion wins for identical SNI keys (exclusions inserted first).
	if got := tbl.Match(v4(1, 2, 3, 4), "www.youtube.com", 443); got != config.ActionDirect {
		t.Errorf("excluded domain = %v, want DIRECT", got)
	}
}

func TestDefaultRuleAction(t *testing.T) {
	cfg := &config.Config{
		Profile: "def",
		Rules:   []config.Rule{{Action: config.ActionTunnel}},
	}
	tbl, err := Compile(cfg)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if got := tbl.Match(v4(1, 2, 3, 4), "whatever.com", 1234); got != config.ActionTunnel {
		t.Errorf("default action = %v, want TUNNEL", got)
	}
}

func TestCompileErrors(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{"nil", nil, "nil config"},
		{"bad cidr", &config.Config{
			Profile: "p",
			Rules:   []config.Rule{{CIDR: "1.2.3.4/40", Action: config.ActionDirect}},
		}, "bad cidr"},
		{"multiple defaults", &config.Config{
			Profile: "p",
			Rules: []config.Rule{
				{Action: config.ActionDirect},
				{Action: config.ActionTunnel},
			},
		}, "multiple default"},
		{"bad ports", &config.Config{
			Profile: "p",
			Rules: []config.Rule{
				{Ports: "50000-65535", Action: config.ActionTunnel},
				{Ports: "60000-61000", Action: config.ActionDirect},
			},
		}, "overlapping"},
		{"bad exclusion", &config.Config{
			Profile:    "p",
			Exclusions: config.Exclusions{CIDRs: []string{"not-a-cidr"}},
		}, "exclusion cidr"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Compile(tt.cfg)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.want)
			}
		})
	}
}

// TestMatchZeroAllocs is the hot-path gate: Match must never allocate.
// SNI is passed as an uncopied substring of a larger buffer.
func TestMatchZeroAllocs(t *testing.T) {
	tbl, err := Compile(config.Default())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	tg := v4(149, 154, 167, 51)
	other := v4(77, 88, 8, 8)
	ip6 := v6("2a03:2880::1")
	// Simulate a ClientHello fragment: SNI is a window into a big buffer.
	sniBuf := "\x16\x03\x01\x02\x00www.youtube.com\x00\x00trailing-payload-junk"
	sniYT := sniBuf[5:20] // "www.youtube.com", no copy

	allocs := testing.AllocsPerRun(1000, func() {
		tbl.Match(tg, sniYT, 443)            // CIDR tunnel hit
		tbl.Match(other, sniYT, 443)         // exact SNI hit
		tbl.Match(other, wildcardSNI(), 443) // wildcard-suffix SNI hit
		tbl.Match(other, "", 50000)          // port-table hit
		tbl.Match(other, "", 53)             // fallthrough to default
		tbl.Match(ip6, "", 443)              // v6 trie walk
	})
	if allocs != 0 {
		t.Fatalf("Match allocates %.2f objects/iter, want 0", allocs)
	}
}

// wildcardSNI returns a wildcard-matching SNI built from a shared buffer
// so the zero-alloc test exercises substring-based wildcard lookups.
var wildcardBuf = "prefix-junk-r4.sn-nx57nss9.googlevideo.com-suffix-junk"

func wildcardSNI() string { return wildcardBuf[13:44] }

func TestMatchConcurrent(t *testing.T) {
	tbl, err := Compile(config.Default())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 20000; i++ {
				tbl.Match(v4(149, 154, 167, 51), "www.youtube.com", 443)
				tbl.Match(v4(byte(g), 1, 2, 3), wildcardBuf[13:44], 50000)
			}
		}(g)
	}
	wg.Wait()
}

// TestMatchProtoSpecificity locks the proto dimension: a rule scoped to
// udp fires ONLY for UDP queries, tcp only for TCP; unscoped rules match
// both; an any-query (legacy Match) sees every entry.
func TestMatchProtoSpecificity(t *testing.T) {
	cfg := &config.Config{
		Profile: "proto",
		Rules: []config.Rule{
			{Ports: "443", Proto: config.ProtoUDP, Action: config.ActionBlock},
			{Ports: "8080", Proto: config.ProtoTCP, Action: config.ActionTunnel},
			{CIDR: "10.0.0.0/8", Proto: config.ProtoUDP, Action: config.ActionTunnel},
			{SNI: "udp-only.example.com", Proto: config.ProtoUDP, Action: config.ActionBlock},
			{SNI: "*.any-proto.example", Action: config.ActionTunnel},
			{Action: config.ActionDirect},
		},
	}
	tbl, err := Compile(cfg)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	ip := v4(93, 184, 216, 34)
	ten := v4(10, 1, 2, 3)
	tests := []struct {
		name  string
		ip    [16]byte
		sni   string
		port  uint16
		proto string
		want  config.Action
	}{
		{"udp 443 blocked", ip, "", 443, config.ProtoUDP, config.ActionBlock},
		{"tcp 443 ignores udp rule", ip, "", 443, config.ProtoTCP, config.ActionDirect},
		{"any 443 sees block", ip, "", 443, config.ProtoAny, config.ActionBlock},
		{"tcp 8080 tunnel", ip, "", 8080, config.ProtoTCP, config.ActionTunnel},
		{"udp 8080 ignores tcp rule", ip, "", 8080, config.ProtoUDP, config.ActionDirect},
		{"udp cidr hit", ten, "", 1234, config.ProtoUDP, config.ActionTunnel},
		{"tcp skips udp cidr (default)", ten, "", 1234, config.ProtoTCP, config.ActionDirect},
		{"udp sni hit", ip, "udp-only.example.com", 9999, config.ProtoUDP, config.ActionBlock},
		{"tcp skips udp sni", ip, "udp-only.example.com", 9999, config.ProtoTCP, config.ActionDirect},
		{"tcp any-proto wildcard", ip, "a.any-proto.example", 9999, config.ProtoTCP, config.ActionTunnel},
		{"udp any-proto wildcard", ip, "a.any-proto.example", 9999, config.ProtoUDP, config.ActionTunnel},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tbl.MatchProto(tt.ip, tt.sni, tt.port, tt.proto); got != tt.want {
				t.Errorf("MatchProto(%v, %q, %d, %q) = %v, want %v",
					tt.ip, tt.sni, tt.port, tt.proto, got, tt.want)
			}
		})
	}
	// Legacy Match (any-proto) still answers and sees scoped entries.
	if got := tbl.Match(ip, "", 443); got != config.ActionBlock {
		t.Errorf("Match any 443 = %v, want BLOCK", got)
	}
}

// TestCIDRBeatsScopedPorts locks §4.2 order across the proto dimension:
// a CIDR rule resolves BEFORE a proto-scoped ports rule, so UDP:443 to a
// TG CIDR stays TUNNEL even with the QUIC block on udp/443 (PRD §5).
func TestCIDRBeatsScopedPorts(t *testing.T) {
	cfg := &config.Config{
		Profile: "cidr-vs-quic",
		Rules: []config.Rule{
			{CIDR: "149.154.160.0/20", Action: config.ActionTunnel},
			{Ports: "443", Proto: config.ProtoUDP, Action: config.ActionBlock},
			{Action: config.ActionDirect},
		},
	}
	tbl, err := Compile(cfg)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	tg := v4(149, 154, 167, 51)
	other := v4(93, 184, 216, 34)
	if got := tbl.MatchProto(tg, "", 443, config.ProtoUDP); got != config.ActionTunnel {
		t.Errorf("udp 443 inside TG CIDR = %v, want TUNNEL (CIDR before ports)", got)
	}
	if got := tbl.MatchProto(tg, "", 443, config.ProtoTCP); got != config.ActionTunnel {
		t.Errorf("tcp 443 inside TG CIDR = %v, want TUNNEL", got)
	}
	if got := tbl.MatchProto(other, "", 443, config.ProtoUDP); got != config.ActionBlock {
		t.Errorf("udp 443 outside TG CIDR = %v, want BLOCK", got)
	}
	if got := tbl.MatchProto(other, "", 443, config.ProtoTCP); got != config.ActionDirect {
		t.Errorf("tcp 443 outside TG CIDR = %v, want DIRECT (default)", got)
	}
}

// TestCompileScopedPortOverlap: overlapping spans are an error only within
// the same proto scope; udp:443 and tcp:443 coexist.
func TestCompileScopedPortOverlap(t *testing.T) {
	base := []config.Rule{
		{Ports: "443", Proto: config.ProtoUDP, Action: config.ActionBlock},
		{Ports: "443", Proto: config.ProtoTCP, Action: config.ActionTunnel},
		{Action: config.ActionDirect},
	}
	cfg := &config.Config{Profile: "scoped-443", Rules: base}
	if _, err := Compile(cfg); err != nil {
		t.Fatalf("same port, different scopes: unexpected error %v", err)
	}
	cfg = &config.Config{Profile: "same-scope", Rules: []config.Rule{
		{Ports: "443", Proto: config.ProtoUDP, Action: config.ActionBlock},
		{Ports: "443", Proto: config.ProtoUDP, Action: config.ActionDirect},
		{Action: config.ActionDirect},
	}}
	if _, err := Compile(cfg); err == nil || !strings.Contains(err.Error(), "overlapping") {
		t.Fatalf("same-scope overlap: expected overlapping error, got %v", err)
	}
}
