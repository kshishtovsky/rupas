package android

import (
	"net/netip"
	"testing"
)

func TestRulesCIDRv4(t *testing.T) {
	r := CompileRules()
	cases := []struct {
		dst  string
		want Action
	}{
		// LAN v4 → DIRECT.
		{"192.168.1.1:443", ActionDirect},
		{"10.1.2.3:80", ActionDirect},
		{"172.16.5.5:22", ActionDirect},
		{"169.254.169.254:80", ActionDirect},
		{"224.0.0.251:5353", ActionDirect},
		{"255.255.255.255:9", ActionDirect},
		// Telegram v4 → TUNNEL.
		{"149.154.167.51:443", ActionTunnel},
		{"149.154.160.1:5228", ActionTunnel},
		{"91.108.4.1:443", ActionTunnel},
		{"91.105.192.5:443", ActionTunnel},
		{"91.105.193.255:443", ActionTunnel},
		{"185.76.151.10:443", ActionTunnel},
		{"95.161.76.100:443", ActionTunnel},
		{"149.154.159.255:443", ActionTunnel}, // below the /20
		// Default → TUNNEL.
		{"142.250.0.1:443", ActionTunnel},
		{"1.1.1.1:53", ActionDirect}, // ports rule, see TestRulesPorts
	}
	for _, c := range cases {
		m := FlowMeta{Network: "tcp", Destination: netip.MustParseAddrPort(c.dst)}
		if got := r.Decide(m); got != c.want {
			t.Errorf("tcp %s: got %s, want %s", c.dst, got, c.want)
		}
	}
}

func TestRulesCIDRv6(t *testing.T) {
	r := CompileRules()
	cases := []struct {
		dst  string
		want Action
	}{
		// Telegram v6 → TUNNEL.
		{"[2001:67c:4e8::1]:443", ActionTunnel},
		{"[2001:b28:f23d::1]:443", ActionTunnel},
		{"[2001:b28:f23f::9]:5228", ActionTunnel},
		{"[2a0a:f280:203::1]:443", ActionTunnel},
		{"[2001:b28:f23c::1]:443", ActionTunnel}, // adjacent, not in /48s
		// LAN v6 → DIRECT.
		{"[fc00::1]:443", ActionDirect},
		{"[fd12:3456::1]:443", ActionDirect},
		{"[fe80::1]:443", ActionDirect},
		{"[ff02::1]:5353", ActionDirect},
		// Default → TUNNEL.
		{"[2001:4860:4860::8888]:443", ActionTunnel},
	}
	for _, c := range cases {
		m := FlowMeta{Network: "tcp", Destination: netip.MustParseAddrPort(c.dst)}
		if got := r.Decide(m); got != c.want {
			t.Errorf("tcp %s: got %s, want %s", c.dst, got, c.want)
		}
	}
}

func TestRulesSNI(t *testing.T) {
	r := CompileRules()
	direct := []string{
		"example.ru", "a.b.example.ru", "example.su",
		"example.xn--p1ai",     // .рф
		"москва.xn--80adxhks",  // .москва (punycode on the wire)
		"shop.xn--80asehdb",    // .онлайн
		"vk.com", "foo.vk.com", // RU services on .com
		"ok.ru", "m.ok.ru",
		"userapi.com", "cs1.userapi.com",
	}
	tunnel := []string{
		"google.com", "youtube.com",
		"vk.com.evil.example", // label-boundary: not vk.com
		"notvk.com",           // suffix must be at a label boundary
		"ru.example.com",      // "ru" as an internal label is not a zone
		"rus",                 // not the .ru zone
	}
	for _, sni := range direct {
		m := FlowMeta{Network: "tcp", Destination: netip.MustParseAddrPort("1.2.3.4:443"), SNI: sni}
		if got := r.Decide(m); got != ActionDirect {
			t.Errorf("sni %q: got %s, want DIRECT", sni, got)
		}
	}
	for _, sni := range tunnel {
		m := FlowMeta{Network: "tcp", Destination: netip.MustParseAddrPort("1.2.3.4:443"), SNI: sni}
		if got := r.Decide(m); got != ActionTunnel {
			t.Errorf("sni %q: got %s, want TUNNEL", sni, got)
		}
	}
}

func TestRulesRealECHForcesTunnel(t *testing.T) {
	r := CompileRules()
	m := FlowMeta{
		Network:     "tcp",
		Destination: netip.MustParseAddrPort("1.2.3.4:443"),
		SNI:         "discord.com",
		ECH:         true, // real ECH (payload > 1 byte) — inspector set
	}
	if got := r.Decide(m); got != ActionTunnel {
		t.Errorf("real ECH: got %s, want TUNNEL", got)
	}
}

func TestRulesPorts(t *testing.T) {
	r := CompileRules()
	// DNS :53 (tcp+udp) → DIRECT.
	if got := r.Decide(FlowMeta{Network: "udp", Destination: netip.MustParseAddrPort("8.8.8.8:53")}); got != ActionDirect {
		t.Errorf("udp/53: got %s, want DIRECT", got)
	}
	if got := r.Decide(FlowMeta{Network: "tcp", Destination: netip.MustParseAddrPort("8.8.8.8:53")}); got != ActionDirect {
		t.Errorf("tcp/53: got %s, want DIRECT", got)
	}
	// QUIC udp:443 → BLOCK (moved here from W2PolicyVerdict).
	if got := r.Decide(FlowMeta{Network: "udp", Destination: netip.MustParseAddrPort("8.8.8.8:443")}); got != ActionBlock {
		t.Errorf("udp/443: got %s, want BLOCK", got)
	}
	// tcp:443 to a non-RU dst stays TUNNEL (default).
	if got := r.Decide(FlowMeta{Network: "tcp", Destination: netip.MustParseAddrPort("8.8.8.8:443")}); got != ActionTunnel {
		t.Errorf("tcp/443: got %s, want TUNNEL", got)
	}
}

func TestRulesMatchOrder(t *testing.T) {
	r := CompileRules()
	// CIDR beats ports: Telegram DC on udp:443 → TUNNEL, not QUIC-block.
	if got := r.Decide(FlowMeta{Network: "udp", Destination: netip.MustParseAddrPort("149.154.167.51:443")}); got != ActionTunnel {
		t.Errorf("TG udp/443: got %s, want TUNNEL (CIDR precedes ports)", got)
	}
	// CIDR beats ports: LAN NTP/DNS to a router → DIRECT.
	if got := r.Decide(FlowMeta{Network: "udp", Destination: netip.MustParseAddrPort("192.168.1.1:443")}); got != ActionDirect {
		t.Errorf("LAN udp/443: got %s, want DIRECT (CIDR precedes ports)", got)
	}
	// SNI beats ports: vk.com:53 → DIRECT via SNI (same action, but the
	// TG CIDR path must not be shadowed by SNI: TG IP with RU-looking SNI
	// still TUNNELs).
	if got := r.Decide(FlowMeta{Network: "tcp", Destination: netip.MustParseAddrPort("91.108.4.1:443"), SNI: "vk.com"}); got != ActionTunnel {
		t.Errorf("TG CIDR + RU SNI: got %s, want TUNNEL (CIDR precedes SNI)", got)
	}
}

func TestW2PolicyVerdictStillPinned(t *testing.T) {
	// The old wave-2 verdict is kept for NewEngine compatibility.
	if got := W2PolicyVerdict(FlowMeta{Network: "udp", Destination: netip.MustParseAddrPort("8.8.8.8:443")}); got != ActionBlock {
		t.Errorf("W2 QUIC block regressed: %s", got)
	}
}

func TestDecidePreSkipsPeek(t *testing.T) {
	r := CompileRules()
	// Conclusive without SNI: LAN, DNS, QUIC, TG CIDR.
	if a, final := r.DecidePre(FlowMeta{Network: "tcp", Destination: netip.MustParseAddrPort("192.168.0.10:445")}); !final || a != ActionDirect {
		t.Errorf("LAN pre-decide: %s final=%v", a, final)
	}
	if a, final := r.DecidePre(FlowMeta{Network: "tcp", Destination: netip.MustParseAddrPort("91.108.4.1:443")}); !final || a != ActionTunnel {
		t.Errorf("TG pre-decide: %s final=%v", a, final)
	}
	// Not conclusive: default TUNNEL needs the SNI first.
	if _, final := r.DecidePre(FlowMeta{Network: "tcp", Destination: netip.MustParseAddrPort("1.2.3.4:443")}); final {
		t.Error("default-rule flow must not be final before the SNI peek")
	}
}

// TestIsTelegramAddr: the direct tail must recognise every Telegram DC range,
// including the v6 ones and a 4-in-6 mapped address. A miss here makes the
// engine escalate a TG flow into the TSPU blackhole (6 s dead dial per flow).
func TestIsTelegramAddr(t *testing.T) {
	for _, c := range telegramCIDRs {
		p := netip.MustParsePrefix(c)
		addr := p.Addr()
		if p.Bits() < addr.BitLen() {
			addr = netip.PrefixFrom(p.Addr(), p.Bits()).Addr()
		}
		if !isTelegramAddr(addr) {
			t.Errorf("%s (from %s) not recognised", addr, c)
		}
	}
	if !isTelegramAddr(netip.MustParseAddr("::ffff:149.154.167.41")) {
		t.Error("4-in-6 mapped TG address not recognised")
	}
	for _, a := range []string{"8.8.8.8", "93.184.216.34", "2001:4860:4860::8888"} {
		if isTelegramAddr(netip.MustParseAddr(a)) {
			t.Errorf("%s wrongly classified as Telegram", a)
		}
	}
}
