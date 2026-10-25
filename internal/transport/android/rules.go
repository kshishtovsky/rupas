// Package android: W3 routing rules (SYSTEM_DESIGN §4/§7, PRD ru §5).
//
// The rule set is compiled once at Start into immutable tables and then
// matched per flow with zero allocation. Match order is fixed and mirrors
// the desktop config (configs/rupas.yaml): CIDR → SNI/domain → ports →
// default. The seam (FlowMeta/Verdict) is unchanged; the inspected SNI/ECH
// fields ride in FlowMeta.
package android

import (
	"net/netip"
	"strings"
)

// prefixRule is one immutable CIDR table entry.
type prefixRule struct {
	prefix netip.Prefix
	action Action
}

// Rules is the compiled, immutable routing table of the W3 policy.
type Rules struct {
	cidr []prefixRule
	// directDomains: domain or parent domain (label-boundary match) whose
	// flows stay DIRECT (RU services on non-RU TLDs).
	directDomains []string
	// directZones: rightmost labels that make any domain DIRECT (RU zones).
	directZones map[string]struct{}
	// defaultAction for flows nothing matched (W3 policy: TUNNEL).
	defaultAction Action
}

// Telegram CIDR ranges (v4+v6) — IP-blackholed by the RU TSPU, must ride
// the tunnel (parity with configs/rupas.yaml).
var telegramCIDRs = []string{
	"149.154.160.0/20",
	"91.108.0.0/16",
	"91.105.192.0/23",
	"185.76.151.0/24",
	"95.161.76.100/32",
	"2001:67c:4e8::/48",
	"2001:b28:f23d::/48",
	"2001:b28:f23f::/48",
	"2a0a:f280:203::/48",
}

// LAN prefixes (v4+v6) that must never leave the device.
var lanCIDRs = []string{
	// v4: RFC1918, link-local, multicast (+ broadcast class D/E edge).
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",
	"224.0.0.0/4",
	"255.255.255.255/32",
	// v6: unique-local, link-local, multicast.
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
}

// ruZones are the rightmost labels of RU-national zones (Cyrillic zones
// appear punycode-encoded on the wire; parity with the desktop rules).
var ruZones = []string{
	"ru",
	"su",
	"xn--p1ai",     // .рф
	"xn--80adxhks", // .москва
	"xn--80asehdb", // .онлайн
	"xn--d1acj3b",  // .дети
	"xn--90ais",    // .бел
}

// ruServicesOnCom: RU services living on .com — the VPS xray refuses
// CONNECT to RU IP ranges, so tunneling them is guaranteed breakage.
var ruServicesOnCom = []string{"vk.com", "ok.ru", "userapi.com"}

// CompileRules builds the immutable W3 policy table (PRD ru §5 parity):
//
//	LAN (v4+v6)                                  → DIRECT
//	Telegram CIDRs                               → TUNNEL
//	RU zones / RU services on .com (by SNI)      → DIRECT
//	DNS :53 (tcp+udp)                            → DIRECT
//	QUIC udp:443                                 → BLOCK
//	everything else                              → TUNNEL
func CompileRules() *Rules {
	r := &Rules{
		directZones:   make(map[string]struct{}, len(ruZones)),
		directDomains: append([]string(nil), ruServicesOnCom...),
		defaultAction: ActionTunnel,
	}
	for _, zone := range ruZones {
		r.directZones[zone] = struct{}{}
	}
	for _, cidr := range lanCIDRs {
		r.cidr = append(r.cidr, prefixRule{netip.MustParsePrefix(cidr), ActionDirect})
	}
	for _, cidr := range telegramCIDRs {
		r.cidr = append(r.cidr, prefixRule{netip.MustParsePrefix(cidr), ActionTunnel})
	}
	return r
}

// Default returns the default action (W3: TUNNEL).
func (r *Rules) Default() Action { return r.defaultAction }

// decideCIDR walks the CIDR table (first match wins). ok=false when no
// prefix matched.
func (r *Rules) decideCIDR(addr netip.Addr) (action Action, ok bool) {
	for _, rule := range r.cidr {
		if rule.prefix.Contains(addr) {
			return rule.action, true
		}
	}
	return ActionDirect, false
}

// DecidePre matches everything that does not need the ClientHello:
// CIDR table and ports. The second return reports whether the decision is
// final — when false the caller must inspect SNI and call Decide again.
func (r *Rules) DecidePre(m FlowMeta) (action Action, final bool) {
	if a, ok := r.decideCIDR(m.Destination.Addr()); ok {
		return a, true
	}
	// Ports (evaluated after CIDR, before default — §4.2 order).
	switch {
	case m.Destination.Port() == 53: // DNS (tcp+udp)
		return ActionDirect, true
	case m.Network == "udp" && m.Destination.Port() == 443: // QUIC
		return ActionBlock, true
	}
	return r.defaultAction, false
}

// Decide matches a flow against the full table. m.SNI (lower-case, no
// trailing dot) and m.ECH are filled by the caller for TCP flows after the
// ClientHello peek; UDP flows pass SNI="".
func (r *Rules) Decide(m FlowMeta) Action {
	if a, ok := r.decideCIDR(m.Destination.Addr()); ok {
		return a
	}
	// Real ECH hides the inner SNI — such flows can never be classified
	// by SNI and go to the tunnel (desktop parity; GREASE is filtered by
	// the inspector and never sets FlowMeta.ECH).
	if m.ECH {
		return ActionTunnel
	}
	if sni := m.SNI; sni != "" {
		if r.matchSNI(sni) {
			return ActionDirect
		}
	}
	switch {
	case m.Destination.Port() == 53:
		return ActionDirect
	case m.Network == "udp" && m.Destination.Port() == 443:
		return ActionBlock
	}
	return r.defaultAction
}

// matchSNI reports whether sni is a RU zone or a RU service domain.
// Matching is at label boundaries: "a.vk.com" matches "vk.com",
// "notvk.com" does not.
func (r *Rules) matchSNI(sni string) bool {
	domain := strings.ToLower(strings.TrimSuffix(sni, "."))
	if domain == "" {
		return false
	}
	if _, ok := r.directZones[lastLabel(domain)]; ok {
		return true
	}
	for _, d := range r.directDomains {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return true
		}
	}
	return false
}

func lastLabel(domain string) string {
	if i := strings.LastIndexByte(domain, '.'); i >= 0 {
		return domain[i+1:]
	}
	return domain
}
