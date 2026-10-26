// Package android: W3 routing rules (SYSTEM_DESIGN §4/§7, PRD ru §5).
//
// The rule set is compiled once at Start into immutable tables and then
// matched per flow with zero allocation. Match order is fixed and mirrors
// the desktop config (configs/rupas.yaml): CIDR → SNI/domain → ports →
// default. The seam (FlowMeta/Verdict) is unchanged; the inspected SNI/ECH
// fields ride in FlowMeta.
package android

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rupas/rupas/internal/geoip"
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
	// geoDirect: country CIDR table (geoip:ru parity with the desktop),
	// v4 only, sorted for binary search. Flows whose destination falls
	// into the table go DIRECT regardless of SNI.
	geoDirect []geoEntry
	// defaultAction for flows nothing matched (W3 policy: TUNNEL).
	defaultAction Action
}

// geoEntry is one sorted geoip table row: network address (big-endian v4)
// + prefix bits. Lookup walks candidate prefix lengths longest-first and
// binary-searches — no allocations in the hot path.
type geoEntry struct {
	addr uint32
	bits int
	act  Action
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

// ruServicesOnCom: RU services living on foreign TLDs (.com/.net) - the
// VPS xray refuses CONNECT to RU IP ranges, so tunneling them is
// guaranteed breakage. Desktop parity (configs/rupas.yaml): the Yandex
// speedtest/CDN hosts and the Steam content network live on .net/.com too.
var ruServicesOnCom = []string{
	"vk.com", "ok.ru", "userapi.com",
	"yandex.net", "ya.ru",
	"steamcontent.com", "steamserver.net", "steampipe.akamaized.net",
	"steamstatic.com", "steampowered.com",
}

// CompileRules builds the immutable W3 policy table without geo tables
// (tests, offline builds). See CompileRulesEx for the full table.
func CompileRules() *Rules {
	return compileRules("", nil)
}

// CompileRulesEx builds the policy table enriched with the country CIDR
// table (geoip parity) cached under filesDir, plus an optional local
// geosite file (filesDir/geosite-direct.txt: one domain per line, '#'
// comments - every listed domain and its subdomains go DIRECT). Both are
// best-effort: a failed geoip download degrades to the zone/domain rules,
// it never blocks the transport start.
func CompileRulesEx(filesDir string, logf func(string)) *Rules {
	return compileRules(filesDir, logf)
}

func compileRules(filesDir string, logf func(string)) *Rules {
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
	r.loadGeoTables(filesDir, logf)
	return r
}

// loadGeoTables enriches the table with the country CIDR list (geoip
// parity, cached in filesDir) and the optional local geosite file. Both
// are best-effort: failures are logged and the table keeps working with
// zones/domains only.
func (r *Rules) loadGeoTables(filesDir string, logf func(string)) {
	if filesDir == "" {
		return
	}
	prefixes, err := geoip.List(geoip.Params{Dir: filesDir}, "ru")
	if err != nil {
		if logf != nil {
			logf("geoip: country table unavailable (" + err.Error() + "); zone/domain rules only")
		}
	} else {
		n := r.setGeoTable(prefixes, ActionDirect)
		if logf != nil {
			logf(fmt.Sprintf("geoip: ru table loaded: %d prefixes direct", n))
		}
	}
	if gs, err := loadGeositeFile(filepath.Join(filesDir, "geosite-direct.txt")); err != nil {
		if logf != nil && !errors.Is(err, fs.ErrNotExist) {
			logf("geosite: local file skipped: " + err.Error())
		}
	} else if len(gs) > 0 {
		r.directDomains = append(r.directDomains, gs...)
		if logf != nil {
			logf(fmt.Sprintf("geosite: %d direct domains from geosite-direct.txt", len(gs)))
		}
	}
}

// setGeoTable installs the v4 part of a parsed country table as DIRECT,
// sorted for binary search; returns the number of installed entries.
func (r *Rules) setGeoTable(prefixes []netip.Prefix, act Action) int {
	r.geoDirect = r.geoDirect[:0]
	for _, p := range prefixes {
		a := p.Addr().Unmap()
		if !a.Is4() {
			continue // the capture is v4-first; v6 falls to zone/default rules
		}
		b4 := a.As4()
		r.geoDirect = append(r.geoDirect, geoEntry{
			addr: binary.BigEndian.Uint32(b4[:]),
			bits: p.Bits(),
			act:  act,
		})
	}
	sort.Slice(r.geoDirect, func(i, j int) bool {
		if r.geoDirect[i].addr != r.geoDirect[j].addr {
			return r.geoDirect[i].addr < r.geoDirect[j].addr
		}
		return r.geoDirect[i].bits < r.geoDirect[j].bits
	})
	return len(r.geoDirect)
}

// loadGeositeFile reads a local domain list (one domain per line, '#'
// comments, "*.suffix" entries allowed and treated as bare suffixes —
// matching is at label boundaries anyway).
func loadGeositeFile(path string) ([]string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path built from the app-private dir
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		line = strings.TrimPrefix(line, "*.")
		if line != "" {
			out = append(out, strings.ToLower(line))
		}
	}
	return out, nil
}

// Default returns the default action (W3: TUNNEL).
func (r *Rules) Default() Action { return r.defaultAction }

// decideCIDR walks the static CIDR table (first match wins), then the
// sorted geo table (longest prefix wins via candidate-length walk +
// binary search). ok=false when nothing matched.
func (r *Rules) decideCIDR(addr netip.Addr) (action Action, ok bool) {
	for _, rule := range r.cidr {
		if rule.prefix.Contains(addr) {
			return rule.action, true
		}
	}
	if a, ok := r.decideGeo(addr); ok {
		return a, true
	}
	return ActionDirect, false
}

// decideGeo looks up the sorted country table: for every prefix length
// from /32 down to /8, mask the address and binary-search the table.
func (r *Rules) decideGeo(addr netip.Addr) (action Action, ok bool) {
	if len(r.geoDirect) == 0 {
		return ActionDirect, false
	}
	a := addr.Unmap()
	if !a.Is4() {
		return ActionDirect, false // v6 table is not loaded (see setGeoTable)
	}
	b4 := a.As4()
	key := binary.BigEndian.Uint32(b4[:])
	for bits := 32; bits >= 8; bits-- {
		mask := uint32(^uint32(0) << (32 - bits))
		e := geoEntry{addr: key & mask, bits: bits}
		i := sort.Search(len(r.geoDirect), func(i int) bool {
			g := r.geoDirect[i]
			if g.addr != e.addr {
				return g.addr > e.addr
			}
			return g.bits >= e.bits
		})
		if i < len(r.geoDirect) && r.geoDirect[i] == e {
			return r.geoDirect[i].act, true
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
