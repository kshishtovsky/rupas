// Package android: W3 routing rules (SYSTEM_DESIGN §4/§7, PRD ru §5).
//
// The rule set is compiled once at Start into immutable tables and then
// matched per flow with zero allocation. The resolution order is the desktop
// engine's (internal/rules, docs/ROUTING_UI.md §2): CIDR/geoip → SNI (exact →
// wildcard) → ports → default. Inside one stage the FIRST rule wins on a
// duplicate key, and the CIDR stage resolves longest-prefix-first.
//
// Where the rules come from: settings.Rules (the Routing screen), or — when
// the settings carry none — the historical W3 preset (DefaultRules). An empty
// rule list therefore keeps the pre-Routing-screen behaviour unchanged.
// The seam (FlowMeta/Verdict) is untouched; the inspected SNI/ECH fields ride
// in FlowMeta.
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
	"sync"

	"github.com/kshishtovsky/rupas/internal/config"
	"github.com/kshishtovsky/rupas/internal/geoip"
)

// prefixRule is one immutable CIDR table entry.
type prefixRule struct {
	prefix netip.Prefix
	action Action
	// proto is the rule's transport scope: "" (both), "tcp" or "udp".
	proto string
}

// ruleKey is a SNI-map key: the lower-case name plus its proto scope.
type ruleKey struct {
	name  string
	proto string
}

// portSpan is one inclusive port range with its action.
type portSpan struct {
	lo, hi uint16
	action Action
}

// Rules is the compiled, immutable routing table of the W3 policy.
type Rules struct {
	// cidr is sorted longest-prefix-first, so the first containing entry is
	// the most specific one (the desktop trie's longest-prefix rule).
	cidr []prefixRule
	// sniExact maps a full lower-case domain to an action; sniWild maps the
	// suffix after "*." and matches at label boundaries only. On a duplicate
	// key the first rule wins.
	sniExact map[ruleKey]Action
	sniWild  map[ruleKey]Action
	// Port tables: the proto-scoped bucket is consulted before the any-proto
	// one, so the more specific scope wins.
	portsAny, portsTCP, portsUDP []portSpan
	// geoDirect: country CIDR table (geoip parity with the desktop), v4 only,
	// sorted for binary search. Entries keep the action and scope of the rule
	// that pulled the country in.
	geoDirect []geoEntry
	// appByUID holds the per-app rules (docs/PERAPP_ROUTING.md §3): the
	// most specific stage, consulted by Engine.decide/decidePre BEFORE the
	// table. nil when no per-app rule was configured — the hot path then
	// pays a single nil-map branch. Immutable after compile, so no lock.
	appByUID map[int]Action
	// defaultAction for flows nothing matched (W3 policy: TUNNEL).
	defaultAction Action
}

// geoEntry is one sorted geoip table row: network address (big-endian v4) +
// prefix bits. Lookup walks candidate prefix lengths longest-first and
// binary-searches — no allocations in the hot path.
type geoEntry struct {
	addr  uint32
	bits  int
	act   Action
	proto string
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

// isTelegramAddr reports whether addr is one of the Telegram DC ranges the
// RU TSPU blackholes (parsed once; a bad literal is skipped, never fatal).
func isTelegramAddr(addr netip.Addr) bool {
	telegramOnce.Do(func() {
		for _, c := range telegramCIDRs {
			if p, err := netip.ParsePrefix(c); err == nil {
				telegramPrefixes = append(telegramPrefixes, p.Masked())
			}
		}
	})
	addr = addr.Unmap()
	for _, p := range telegramPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

var (
	telegramOnce     sync.Once
	telegramPrefixes []netip.Prefix
)

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

// DefaultRules returns the historical W3 policy as a rule list: LAN → DIRECT,
// Telegram CIDRs → TUNNEL, geoip:ru plus the RU zones and RU services →
// DIRECT, DNS → DIRECT, QUIC (udp:443) → BLOCK, everything else → TUNNEL.
//
// It is the compile source when the settings carry no rules and the rule set
// the Android Routing screen starts from, so the screen can never show a
// policy the core does not actually apply.
func DefaultRules() []config.Rule {
	out := make([]config.Rule, 0,
		len(lanCIDRs)+len(telegramCIDRs)+1+len(ruZones)+2*len(ruServicesOnCom)+3)
	for _, cidr := range lanCIDRs {
		out = append(out, config.Rule{CIDR: cidr, Action: config.ActionDirect})
	}
	for _, cidr := range telegramCIDRs {
		out = append(out, config.Rule{CIDR: cidr, Action: config.ActionTunnel})
	}
	out = append(out, config.Rule{GeoIP: "ru", Action: config.ActionDirect})
	for _, zone := range ruZones {
		out = append(out, config.Rule{SNI: "*." + zone, Action: config.ActionDirect})
	}
	for _, svc := range ruServicesOnCom {
		out = append(out,
			config.Rule{SNI: svc, Action: config.ActionDirect},
			config.Rule{SNI: "*." + svc, Action: config.ActionDirect})
	}
	return append(out,
		config.Rule{Ports: "53", Action: config.ActionDirect},
		config.Rule{Ports: "443", Proto: config.ProtoUDP, Action: config.ActionBlock},
		config.Rule{Action: config.ActionTunnel},
	)
}

// CompileRules builds the immutable W3 policy table from the default preset
// without geo tables (tests, offline builds). See CompileRulesEx for the full
// table and CompileRulesWith for a caller-supplied rule set.
func CompileRules() *Rules {
	return compileRules("", nil, nil, nil)
}

// CompileRulesEx builds the policy table enriched with the country CIDR
// table (geoip parity) cached under filesDir, plus an optional local
// geosite file (filesDir/geosite-direct.txt: one domain per line, '#' and
// lines are comments - every listed domain and its subdomains go DIRECT). Both
// are best-effort: a failed geoip download degrades to the zone/domain rules,
// it never blocks the transport start.
func CompileRulesEx(filesDir string, logf func(string)) *Rules {
	return compileRules(filesDir, logf, nil, nil)
}

// CompileRulesWith compiles a caller-supplied rule set (the Routing screen's
// rules from Settings). An empty ruleSet falls back to DefaultRules, so a core
// started without rules behaves exactly like the pre-screen builds.
func CompileRulesWith(ruleSet []config.Rule, filesDir string, logf func(string)) *Rules {
	return compileRules(filesDir, logf, ruleSet, nil)
}

// CompileRulesWithApps is CompileRulesWith plus the per-app UID rules
// (Settings.AppRules). The app rules land in their own table consulted ahead
// of every other stage (docs/PERAPP_ROUTING.md §3); without them the compiled
// table is indistinguishable from CompileRulesWith's.
func CompileRulesWithApps(ruleSet []config.Rule, appRules []AppRule, filesDir string, logf func(string)) *Rules {
	return compileRules(filesDir, logf, ruleSet, appRules)
}

// compileRules compiles a rule list into the immutable table. A rule that
// cannot be understood on this platform is skipped rather than fatal: the core
// must start even if one entry turns out to be unusable (the screen and
// Settings validation reject the obviously broken before it gets here).
func compileRules(filesDir string, logf func(string), ruleSet []config.Rule, appRules []AppRule) *Rules {
	if len(ruleSet) == 0 {
		ruleSet = DefaultRules()
	}
	r := &Rules{
		sniExact:      make(map[ruleKey]Action, len(ruleSet)),
		sniWild:       make(map[ruleKey]Action, len(ruleSet)),
		defaultAction: ActionTunnel,
	}
	desync := 0
	for _, cr := range ruleSet {
		act := ruleAction(cr.Action)
		if cr.Action == config.ActionDesync {
			desync++
		}
		proto := strings.ToLower(strings.TrimSpace(cr.Proto))
		switch {
		case cr.CIDR != "":
			p, err := netip.ParsePrefix(strings.TrimSpace(cr.CIDR))
			if err != nil {
				continue
			}
			r.cidr = append(r.cidr, prefixRule{prefix: normPrefix(p), action: act, proto: proto})
		case cr.SNI != "":
			r.addDomain(strings.ToLower(strings.TrimSpace(cr.SNI)), proto, act)
		case cr.Ports != "":
			spans, err := config.ParsePortSpec(cr.Ports)
			if err != nil {
				continue
			}
			dst := &r.portsAny
			switch proto {
			case config.ProtoTCP:
				dst = &r.portsTCP
			case config.ProtoUDP:
				dst = &r.portsUDP
			}
			for _, s := range spans {
				*dst = append(*dst, portSpan{lo: s.Lo, hi: s.Hi, action: act})
			}
		case cr.GeoIP != "":
			// Country tables are expanded in loadGeoTables: they need the
			// cache directory and stay best-effort.
		default:
			r.defaultAction = act
		}
	}
	// Longest prefix first; the stable sort keeps the first-rule-wins
	// tie-break on identical prefixes.
	sort.SliceStable(r.cidr, func(i, j int) bool { return r.cidr[i].prefix.Bits() > r.cidr[j].prefix.Bits() })
	r.loadGeoTables(filesDir, logf, ruleSet)
	r.compileAppRules(appRules)
	if desync > 0 && logf != nil {
		logf(fmt.Sprintf("rules: %d desync rule(s) routed via the tunnel (android has no desync engine)", desync))
	}
	return r
}

// ruleAction maps a desktop action onto the Android decision set. Android has
// no desync engine (W3), so a DESYNC rule degrades to TUNNEL — the traffic
// still leaves through the VPS, which is the honest working equivalent — and
// the compile log names the count.
func ruleAction(a config.Action) Action {
	switch a {
	case config.ActionTunnel, config.ActionDesync:
		return ActionTunnel
	case config.ActionBlock:
		return ActionBlock
	default:
		return ActionDirect
	}
}

// addDomain registers a SNI rule: a "*." prefix becomes a wildcard-suffix
// entry, anything else an exact entry. The first registration of a key wins.
func (r *Rules) addDomain(name, proto string, act Action) {
	if name == "" {
		return
	}
	if suffix, ok := strings.CutPrefix(name, "*."); ok {
		key := ruleKey{name: suffix, proto: proto}
		if _, exists := r.sniWild[key]; !exists {
			r.sniWild[key] = act
		}
		return
	}
	key := ruleKey{name: name, proto: proto}
	if _, exists := r.sniExact[key]; !exists {
		r.sniExact[key] = act
	}
}

// loadGeoTables enriches the table with the country CIDR lists referenced by
// the geoip rules (cached in filesDir) and the optional local geosite file.
// Both are best-effort: failures are logged and the table keeps working with
// the CIDR/zone/domain rules.
func (r *Rules) loadGeoTables(filesDir string, logf func(string), ruleSet []config.Rule) {
	if filesDir == "" {
		return
	}
	for _, cr := range ruleSet {
		if cr.GeoIP == "" {
			continue
		}
		proto := strings.ToLower(strings.TrimSpace(cr.Proto))
		prefixes, err := geoip.List(geoip.Params{Dir: filesDir}, cr.GeoIP)
		if err != nil {
			if logf != nil {
				logf("geoip: country table " + cr.GeoIP + " unavailable (" + err.Error() + "); rule skipped")
			}
			continue
		}
		n := r.addGeoTable(prefixes, ruleAction(cr.Action), proto)
		if logf != nil {
			logf(fmt.Sprintf("geoip: %s table loaded: %d prefixes → %s", cr.GeoIP, n, ruleAction(cr.Action)))
		}
	}
	if gs, err := loadGeositeFile(filepath.Join(filesDir, "geosite-direct.txt")); err != nil {
		if logf != nil && !errors.Is(err, fs.ErrNotExist) {
			logf("geosite: local file skipped: " + err.Error())
		}
	} else if len(gs) > 0 {
		for _, d := range gs {
			// A geosite entry means "this domain and its subdomains".
			r.addDomain(d, "", ActionDirect)
			r.addDomain("*."+d, "", ActionDirect)
		}
		if logf != nil {
			logf(fmt.Sprintf("geosite: %d direct domains from geosite-direct.txt", len(gs)))
		}
	}
}

// addGeoTable installs the v4 part of a parsed country table, sorted for
// binary search; returns the number of installed entries.
func (r *Rules) addGeoTable(prefixes []netip.Prefix, act Action, proto string) int {
	before := len(r.geoDirect)
	for _, p := range prefixes {
		a := p.Addr().Unmap()
		if !a.Is4() {
			continue // the capture is v4-first; v6 falls to zone/default rules
		}
		b4 := a.As4()
		r.geoDirect = append(r.geoDirect, geoEntry{
			addr:  binary.BigEndian.Uint32(b4[:]),
			bits:  p.Bits(),
			act:   act,
			proto: proto,
		})
	}
	sort.SliceStable(r.geoDirect, func(i, j int) bool {
		if r.geoDirect[i].addr != r.geoDirect[j].addr {
			return r.geoDirect[i].addr < r.geoDirect[j].addr
		}
		return r.geoDirect[i].bits < r.geoDirect[j].bits
	})
	return len(r.geoDirect) - before
}

// loadGeositeFile reads a local domain list (one domain per line, '#' starts
// a comment, "*.suffix" entries allowed and treated as bare suffixes —
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

// compileAppRules builds the per-app UID table (docs/PERAPP_ROUTING.md §5).
// Only TUNNEL and BLOCK are compiled: a DIRECT rule is applied by the Java
// side via VpnService.addDisallowedApplication, so such an app has no flow in
// the netstack at all and a table entry would be dead weight. UID 0 means
// "unknown owner" — it is never a valid key. An unusable entry is skipped
// (Settings.Validate rejects it before Start).
func (r *Rules) compileAppRules(appRules []AppRule) {
	if len(appRules) == 0 {
		return
	}
	m := make(map[int]Action, len(appRules))
	for _, ar := range appRules {
		if ar.UID <= 0 {
			continue
		}
		act, err := parseAppAction(ar.Action)
		if err != nil || act == ActionDirect {
			continue
		}
		if _, exists := m[ar.UID]; !exists { // first rule wins, as in every stage
			m[ar.UID] = act
		}
	}
	if len(m) > 0 {
		r.appByUID = m
	}
}

// appAction resolves the per-app rule for an app UID. The second return is
// false when no rule covers the UID (including the no-app-rules case, where
// the nil map answers instantly). Zero allocation: one int-keyed lookup.
func (r *Rules) appAction(uid int) (Action, bool) {
	if r == nil || r.appByUID == nil || uid <= 0 {
		return ActionDirect, false
	}
	act, ok := r.appByUID[uid]
	return act, ok
}

// hasAppRules reports whether any per-app rule is compiled. It is the gate
// for the UID resolve: without per-app rules the core never calls into the
// platform, so the hot path keeps its pre-feature cost (one nil compare).
func (r *Rules) hasAppRules() bool {
	return r != nil && len(r.appByUID) > 0
}

// decideCIDR walks the CIDR table longest-prefix-first (the first match after
// the sort is the most specific one), then the sorted geo table.
func (r *Rules) decideCIDR(addr netip.Addr, network string) (action Action, ok bool) {
	addr = addr.Unmap()
	for _, rule := range r.cidr {
		if rule.proto != "" && rule.proto != network {
			continue
		}
		if rule.prefix.Contains(addr) {
			return rule.action, true
		}
	}
	if a, ok := r.decideGeo(addr, network); ok {
		return a, true
	}
	return ActionDirect, false
}

// decideGeo looks up the sorted country table: for every prefix length from
// /32 down to /8, mask the address and binary-search the table. A
// proto-scoped row answers only its own protocol.
func (r *Rules) decideGeo(addr netip.Addr, network string) (action Action, ok bool) {
	if len(r.geoDirect) == 0 {
		return ActionDirect, false
	}
	a := addr.Unmap()
	if !a.Is4() {
		return ActionDirect, false // v6 table is not loaded (see addGeoTable)
	}
	b4 := a.As4()
	key := binary.BigEndian.Uint32(b4[:])
	for bits := 32; bits >= 8; bits-- {
		mask := uint32(^uint32(0) << (32 - bits))
		want := geoEntry{addr: key & mask, bits: bits}
		i := sort.Search(len(r.geoDirect), func(i int) bool {
			g := r.geoDirect[i]
			if g.addr != want.addr {
				return g.addr > want.addr
			}
			return g.bits >= want.bits
		})
		// Several rules may expand onto the same prefix; the
		// proto-compatible row wins, and among those the first rule (the
		// sort is stable) does.
		for ; i < len(r.geoDirect) && r.geoDirect[i].addr == want.addr && r.geoDirect[i].bits == want.bits; i++ {
			if g := r.geoDirect[i]; g.proto == "" || g.proto == network {
				return g.act, true
			}
		}
	}
	return ActionDirect, false
}

// DecidePre matches everything that does not need the ClientHello: CIDR table
// and ports. The second return reports whether the decision is final — when
// false the caller must inspect SNI and call Decide again. A port match is
// final only when the rule set has no domain rules, because the SNI stage
// outranks ports.
func (r *Rules) DecidePre(m FlowMeta) (action Action, final bool) {
	if a, ok := r.decideCIDR(m.Destination.Addr(), m.Network); ok {
		return a, true
	}
	if a, ok := r.matchPorts(m.Destination.Port(), m.Network); ok && !r.hasDomainRules() {
		return a, true
	}
	return r.defaultAction, false
}

// Decide matches a flow against the full table. m.SNI (lower-case, no
// trailing dot) and m.ECH are filled by the caller for TCP flows after the
// ClientHello peek; UDP flows pass SNI="".
func (r *Rules) Decide(m FlowMeta) Action {
	if a, ok := r.decideCIDR(m.Destination.Addr(), m.Network); ok {
		return a
	}
	// Real ECH hides the inner SNI — such flows can never be classified
	// by SNI and go to the tunnel (desktop parity; GREASE is filtered by
	// the inspector and never sets FlowMeta.ECH).
	if m.ECH {
		return ActionTunnel
	}
	if m.SNI != "" {
		if a, ok := r.matchSNI(m.SNI, m.Network); ok {
			return a
		}
	}
	if a, ok := r.matchPorts(m.Destination.Port(), m.Network); ok {
		return a
	}
	return r.defaultAction
}

// matchSNI resolves the domain stage: the exact name first, then progressively
// shorter label suffixes against the wildcard table (the desktop order:
// "a.vk.com" matches "*.vk.com", "notvk.com" does not). The exact-protocol
// entry wins over its unscoped twin.
func (r *Rules) matchSNI(sni, network string) (Action, bool) {
	domain := strings.ToLower(strings.TrimSuffix(sni, "."))
	if domain == "" {
		return ActionDirect, false
	}
	if a, ok := lookupDomain(r.sniExact, domain, network); ok {
		return a, true
	}
	for i := 0; i < len(domain); i++ {
		if domain[i] == '.' {
			if a, ok := lookupDomain(r.sniWild, domain[i+1:], network); ok {
				return a, true
			}
		}
	}
	return ActionDirect, false
}

// lookupDomain probes m for (name, network) and then for the unscoped entry.
func lookupDomain(m map[ruleKey]Action, name, network string) (Action, bool) {
	if a, ok := m[ruleKey{name: name, proto: network}]; ok {
		return a, true
	}
	if network != "" {
		if a, ok := m[ruleKey{name: name}]; ok {
			return a, true
		}
	}
	return ActionDirect, false
}

// matchPorts resolves the port stage: the scoped bucket first, then the
// unscoped one. Spans are walked in rule order, so the first rule wins on a
// shared port.
func (r *Rules) matchPorts(port uint16, network string) (Action, bool) {
	var scoped []portSpan
	switch network {
	case "tcp":
		scoped = r.portsTCP
	case "udp":
		scoped = r.portsUDP
	}
	for _, s := range scoped {
		if port >= s.lo && port <= s.hi {
			return s.action, true
		}
	}
	for _, s := range r.portsAny {
		if port >= s.lo && port <= s.hi {
			return s.action, true
		}
	}
	return ActionDirect, false
}

// hasDomainRules reports whether any SNI rule is compiled: without one the
// port stage is conclusive before the ClientHello peek.
func (r *Rules) hasDomainRules() bool {
	return len(r.sniExact) > 0 || len(r.sniWild) > 0
}

// normPrefix masks a parsed prefix and folds v4-mapped (::ffff:a.b.c.d)
// prefixes into the plain v4 space, so Contains works for unmapped queries.
func normPrefix(p netip.Prefix) netip.Prefix {
	if p.Addr().Is4In6() {
		bits := p.Bits() - 96
		if bits < 0 {
			bits = 0
		}
		return netip.PrefixFrom(p.Addr().Unmap(), bits).Masked()
	}
	return p.Masked()
}
