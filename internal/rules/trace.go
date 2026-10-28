// trace.go — cold-path route tracer for the Routing screen
// (docs/ROUTING_UI.md §5.5, §10): answers "куда уйдёт этот домен/IP" by
// replaying the fixed engine resolution order over a rule list and reporting
// the stage and the matcher that decided.
//
// The hot path (Match / MatchProto) is untouched: it stays allocation-free.
// TestRoute is a UI path, it may allocate and it may read the geoip cache
// from disk.
package rules

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/kshishtovsky/rupas/internal/config"
	"github.com/kshishtovsky/rupas/internal/geoip"
)

// Stage numbers of the fixed resolution order (SYSTEM_DESIGN §4.2):
// 1 CIDR/geoip, 2 SNI (exact → wildcard), 3 ports, 4 default.
const (
	// StageIP is the CIDR / geoip stage.
	StageIP = 1
	// StageDomain is the SNI stage (exact match, then wildcard suffixes).
	StageDomain = 2
	// StagePort is the port stage.
	StagePort = 3
	// StageDefault is the default rule (the one with no matcher).
	StageDefault = 4
)

// stageName is the display name of a stage carried by Trace.StageName. The
// copy is the single RU wording of docs/ROUTING_UI.md §9, shared by the
// Windows and Android screens so the trace line reads the same everywhere.
func stageName(stage int) string {
	switch stage {
	case StageIP:
		return "IP-адреса"
	case StageDomain:
		return "Домены"
	case StagePort:
		return "Порты"
	case StageDefault:
		return "по умолчанию"
	}
	return ""
}

// Trace is the outcome of one probe: the stage that decided, the matcher
// that fired, the resulting action and an optional note about what was NOT
// evaluated (RU copy, shown as-is by the screen).
//
// StageName is the display name of the stage ("IP-адреса", "Домены",
// "Порты", "по умолчанию"). Matcher is the raw matcher value —
// "10.0.0.0/8", "geoip: ru", "*.googlevideo.com", "ports 443/udp" — shown
// verbatim in a monospace line; it is EMPTY when the default rule decided
// (stage 4), so the screen renders its own "по умолчанию" copy.
type Trace struct {
	Stage     int           `json:"stage"`
	StageName string        `json:"stageName"`
	Matcher   string        `json:"matcher"`
	Action    config.Action `json:"action"`
	Note      string        `json:"note,omitempty"`
	// Warning carries a remark about the RULE SET, not about this query
	// (e.g. a geoip table is missing from the cache, so that rule could not
	// be evaluated). The screen shows it once above the result, never as the
	// per-query note: it would otherwise decorate every single probe.
	Warning string `json:"warning,omitempty"`
}

// TestRoute resolves query (a domain, an IP, or "host:port") against rules
// exactly as the engine would and reports the deciding stage. Geoip rules are
// expanded from the cache under the default "build" directory only; a
// missing table is reported in Note instead of being downloaded (the trace
// path must answer instantly).
func TestRoute(rules []config.Rule, query string) (Trace, error) {
	return TestRouteWithGeo(rules, query, geoip.Params{})
}

// TestRouteWithGeo is TestRoute with an explicit geoip cache location (the
// daemon and the Android core pass their own build/files directory).
func TestRouteWithGeo(rules []config.Rule, query string, geo geoip.Params) (Trace, error) {
	m, err := buildTraceModel(rules, geo)
	if err != nil {
		return Trace{}, err
	}
	q, err := parseTraceQuery(query)
	if err != nil {
		return Trace{}, err
	}
	if q.hasIP {
		return m.resolveIP(q), nil
	}
	return m.resolveDomain(q), nil
}

// traceQuery is the parsed probe: either an IP (with an optional port) or a
// domain name (with an optional port). proto is the transport the probe is
// asking about: empty means "not specified", which the resolvers treat as TCP
// (a plain probe means ordinary web traffic, never QUIC).
type traceQuery struct {
	ip      netip.Addr
	hasIP   bool
	domain  string
	port    uint16
	hasPort bool
	proto   string
}

// parseTraceQuery accepts "example.com", "example.com:443", "1.2.3.4",
// "1.2.3.4:443", "[2001:db8::1]:443" and a "/tcp" or "/udp" suffix on the
// port form ("1.2.3.4:443/udp") to probe a transport explicitly.
func parseTraceQuery(raw string) (traceQuery, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return traceQuery{}, errors.New("rules: empty query")
	}
	proto := ""
	if base, p, ok := strings.Cut(s, "/"); ok {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != config.ProtoTCP && p != config.ProtoUDP {
			return traceQuery{}, fmt.Errorf("rules: bad transport %q in query (want tcp or udp)", p)
		}
		s, proto = strings.TrimSpace(base), p
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return traceQuery{ip: ap.Addr().Unmap(), hasIP: true, port: ap.Port(), hasPort: true, proto: proto}, nil
	}
	if addr, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		return traceQuery{ip: addr.Unmap(), hasIP: true, proto: proto}, nil
	}
	host := s
	if h, p, err := net.SplitHostPort(s); err == nil {
		host = h
		if n, perr := strconv.ParseUint(p, 10, 16); perr == nil && n > 0 {
			return traceQuery{domain: normDomain(host), port: uint16(n), hasPort: true, proto: proto}, nil
		}
	}
	host = normDomain(host)
	if host == "" {
		return traceQuery{}, fmt.Errorf("rules: bad query %q", raw)
	}
	return traceQuery{domain: host, proto: proto}, nil
}

// normDomain lower-cases a host name and drops the trailing root dot.
func normDomain(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

// traceCIDR is one compiled CIDR entry: the prefix, the action, the matcher
// text the UI shows and the protocol scope it was registered under.
type traceCIDR struct {
	prefix  netip.Prefix
	action  config.Action
	matcher string
	proto   string
}

// traceDomain is one compiled SNI entry (exact or wildcard suffix).
type traceDomain struct {
	action  config.Action
	matcher string
}

// traceKey is the SNI map key: the (lower-case) name plus its proto scope.
type traceKey struct {
	name  string
	proto string
}

// tracePort is one compiled port span.
type tracePort struct {
	lo, hi  uint16
	action  config.Action
	matcher string
}

// traceModel is the tracer's replica of the decision table with the
// provenance (matcher text) the hot table deliberately does not carry.
type traceModel struct {
	cidr  []traceCIDR // sorted longest prefix first
	exact map[traceKey]traceDomain
	wild  map[traceKey]traceDomain
	// ports is indexed by proto scope (config.ProtoAny/ProtoTCP/ProtoUDP).
	ports map[string][]tracePort
	def config.Action
	// hasDefault reports whether the rule list carried an explicit default
	// rule; without one the table falls back to DIRECT.
	hasDefault bool
	// notes carry non-fatal remarks about the RULE SET (unavailable geoip
	// table, …). They are reported as Trace.Warning once, never mixed into
	// the per-query Note.
	notes []string
}

// buildTraceModel validates rules and compiles the provenance-carrying
// replica. Validation reuses the engine's own rules, so an invalid rule set
// is rejected here with the same messages the daemon would produce.
func buildTraceModel(ruleSet []config.Rule, geo geoip.Params) (*traceModel, error) {
	if err := config.ValidateRules(ruleSet); err != nil {
		return nil, err
	}
	m := &traceModel{
		exact:      map[traceKey]traceDomain{},
		wild:       map[traceKey]traceDomain{},
		ports:      map[string][]tracePort{},
		def: config.ActionDirect,
	}
	for _, proto := range []string{config.ProtoAny, config.ProtoTCP, config.ProtoUDP} {
		m.ports[proto] = nil
	}
	for _, r := range ruleSet {
		switch {
		case r.CIDR != "":
			p, err := netip.ParsePrefix(r.CIDR)
			if err != nil {
				return nil, fmt.Errorf("rules: rule cidr %q: %v", r.CIDR, err)
			}
			m.cidr = append(m.cidr, traceCIDR{
				prefix: normPrefix(p), action: r.Action, matcher: r.CIDR, proto: r.Proto,
			})
		case r.GeoIP != "":
			prefixes, err := traceGeoPrefixes(geo, r.GeoIP)
			if err != nil {
				m.notes = append(m.notes, fmt.Sprintf("geoip: таблица %q недоступна — правило пропущено", r.GeoIP))
				continue
			}
			for _, p := range prefixes {
				m.cidr = append(m.cidr, traceCIDR{
					prefix: normPrefix(p), action: r.Action,
					matcher: "geoip: " + r.GeoIP, proto: r.Proto,
				})
			}
		case r.SNI != "":
			m.addDomain(r.SNI, r.Proto, traceDomain{action: r.Action, matcher: r.SNI})
		case r.Ports != "":
			spans, err := config.ParsePortSpec(r.Ports)
			if err != nil {
				return nil, fmt.Errorf("rules: rule ports %q: %v", r.Ports, err)
			}
			for _, s := range spans {
				m.ports[r.Proto] = append(m.ports[r.Proto], tracePort{
					lo: s.Lo, hi: s.Hi, action: r.Action,
					matcher: portMatcher(r.Ports, r.Proto),
				})
			}
		default:
			m.def = r.Action
			m.hasDefault = true
		}
	}
	// Longest prefix first: the first hit is the most specific one, which is
	// what the trie's longest-prefix walk resolves. Stable sort keeps the
	// engine's first-rule-wins tie-break on identical prefixes.
	sort.SliceStable(m.cidr, func(i, j int) bool {
		return m.cidr[i].prefix.Bits() > m.cidr[j].prefix.Bits()
	})
	return m, nil
}

// addDomain registers an SNI rule; on a duplicate key the first rule wins
// (compile.go addSNI).
func (m *traceModel) addDomain(name, proto string, d traceDomain) {
	if suffix, ok := strings.CutPrefix(name, "*."); ok {
		k := traceKey{name: suffix, proto: proto}
		if _, exists := m.wild[k]; !exists {
			m.wild[k] = d
		}
		return
	}
	k := traceKey{name: name, proto: proto}
	if _, exists := m.exact[k]; !exists {
		m.exact[k] = d
	}
}

// resolveIP walks stages 1 → 3 → 4 for an IP probe. The domain stage is
// skipped by definition (§5.5).
func (m *traceModel) resolveIP(q traceQuery) Trace {
	warn := joinNotes(m.notes)
	notes := []string{"домены не проверяются для IP"}
	if a, matcher, ok := m.matchCIDR(q.ip, probeProto(q)); ok {
		return Trace{Stage: StageIP, StageName: stageName(StageIP), Matcher: matcher, Action: a,
			Note: joinNotes(notes), Warning: warn}
	}
	port, hasPort := q.port, q.hasPort
	if !hasPort {
		port = 443
		// A bare IP probe means ordinary web traffic. The assumed port is
		// TCP-only on purpose: walking the udp bucket here would answer the
		// QUIC-block rule ("udp/443 → BLOCK") for every bare IP, inventing a
		// verdict the engine would not make for a normal TCP flow.
		notes = append(notes, "порт не указан — принят 443/tcp")
	}
	if m.hasPortRules() {
		if a, matcher, ok := m.matchPort(port, probeProto(q)); ok {
			return Trace{Stage: StagePort, StageName: stageName(StagePort), Matcher: matcher,
				Action: a, Note: joinNotes(notes), Warning: warn}
		}
	}
	return Trace{Stage: StageDefault, StageName: stageName(StageDefault),
		Action: m.def, Note: joinNotes(append(notes, m.defaultNote())), Warning: warn}
}

// resolveDomain walks stages 2 → 3 → 4 for a domain probe. Ports take part
// only when the query carries one: a domain alone has no transport port, and
// substituting 443 would invent a decision the engine never makes.
func (m *traceModel) resolveDomain(q traceQuery) Trace {
	warn := joinNotes(m.notes)
	notes := []string(nil)
	if a, matcher, ok := m.matchDomain(q.domain, config.ProtoTCP); ok {
		return Trace{Stage: StageDomain, StageName: stageName(StageDomain), Matcher: matcher,
			Action: a, Note: joinNotes(notes), Warning: warn}
	}
	switch {
	case q.hasPort && m.hasPortRules():
		if a, matcher, ok := m.matchPort(q.port, probeProto(q)); ok {
			return Trace{Stage: StagePort, StageName: stageName(StagePort), Matcher: matcher,
				Action: a, Note: joinNotes(notes), Warning: warn}
		}
	case m.hasPortRules():
		notes = append(notes, "порты не проверяются: в запросе нет порта")
	}
	return Trace{Stage: StageDefault, StageName: stageName(StageDefault),
		Action: m.def, Note: joinNotes(append(notes, m.defaultNote())), Warning: warn}
}

// defaultNote explains the default stage: an absent default rule (the engine
// then falls back to DIRECT) and the dangerous DIRECT default of §9 ("По
// умолчанию DIRECT — реальный IP не скрыт").
func (m *traceModel) defaultNote() string {
	notes := make([]string, 0, 1)
	if !m.hasDefault {
		notes = append(notes, "правила по умолчанию нет — движок направит трафик напрямую")
	}
	if m.def == config.ActionDirect {
		notes = append(notes, "По умолчанию DIRECT — реальный IP не скрыт")
	}
	return joinNotes(notes)
}

// joinNotes joins the non-empty remarks with "; " so an absent hint never
// leaves a dangling separator in the UI line.
func joinNotes(parts []string) string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, "; ")
}

// matchCIDR returns the action and matcher of the most specific prefix
// containing addr whose proto scope answers proto ("" = unknown query
// protocol, matches every scope, like Match).
func (m *traceModel) matchCIDR(addr netip.Addr, proto string) (config.Action, string, bool) {
	addr = addr.Unmap()
	for _, e := range m.cidr {
		if proto != "" && e.proto != "" && e.proto != proto {
			continue
		}
		if e.prefix.Contains(addr) {
			return e.action, e.matcher, true
		}
	}
	return config.ActionInvalid, "", false
}

// matchDomain resolves the SNI stage: exact name first, then progressively
// shorter label suffixes against the wildcard table (MatchProto order). A
// proto-scoped entry is tried before its unscoped twin.
func (m *traceModel) matchDomain(domain, proto string) (config.Action, string, bool) {
	domain = normDomain(domain)
	if domain == "" {
		return config.ActionInvalid, "", false
	}
	if d, ok := lookupDomain(m.exact, domain, proto); ok {
		return d.action, d.matcher, true
	}
	for i := 0; i < len(domain); i++ {
		if domain[i] == '.' {
			if d, ok := lookupDomain(m.wild, domain[i+1:], proto); ok {
				return d.action, d.matcher, true
			}
		}
	}
	return config.ActionInvalid, "", false
}

// lookupDomain probes the map for (name, proto) and then for the unscoped
// entry; the exact-protocol scope wins.
func lookupDomain(m map[traceKey]traceDomain, name, proto string) (traceDomain, bool) {
	if d, ok := m[traceKey{name: name, proto: proto}]; ok {
		return d, true
	}
	if proto != "" {
		if d, ok := m[traceKey{name: name}]; ok {
			return d, true
		}
	}
	return traceDomain{}, false
}

// probeProto is the transport a probe is evaluated against. A probe that does
// not name one means ordinary web traffic: TCP. Without this the udp-scoped
// QUIC-block rule would decide every plain probe and answer BLOCK for targets
// the engine actually tunnels over TCP.
func probeProto(q traceQuery) string {
	if q.proto != "" {
		return q.proto
	}
	return config.ProtoTCP
}

// matchPort resolves the port stage: the scoped bucket first, then the
// unscoped one; an unknown query protocol walks any → tcp → udp (matchPort).
func (m *traceModel) matchPort(port uint16, proto string) (config.Action, string, bool) {
	buckets := []string{config.ProtoAny, config.ProtoTCP, config.ProtoUDP}
	switch proto {
	case config.ProtoTCP:
		buckets = []string{config.ProtoTCP, config.ProtoAny}
	case config.ProtoUDP:
		buckets = []string{config.ProtoUDP, config.ProtoAny}
	}
	for _, b := range buckets {
		for _, s := range m.ports[b] {
			if port >= s.lo && port <= s.hi {
				return s.action, s.matcher, true
			}
		}
	}
	return config.ActionInvalid, "", false
}

// hasPortRules reports whether the rule set has any port matcher at all: with
// none, the port stage cannot decide and the trace skips it silently.
func (m *traceModel) hasPortRules() bool {
	for _, spans := range m.ports {
		if len(spans) > 0 {
			return true
		}
	}
	return false
}

// portMatcher renders a port rule as the screen shows it: "ports 443/udp",
// "ports 50000-65535", "ports 53,123/tcp".
func portMatcher(spec, proto string) string {
	if proto == "" {
		return "ports " + spec
	}
	return "ports " + spec + "/" + proto
}

// normPrefix normalizes a parsed prefix: masked, and v4-mapped (::ffff:a.b.c.d)
// prefixes folded into the plain v4 space so Contains works for unmapped
// queries.
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

// traceGeoPrefixes reads a country table from the geoip cache. It never
// downloads: the trace must answer even while the daemon is offline.
func traceGeoPrefixes(params geoip.Params, cc string) ([]netip.Prefix, error) {
	params = params.WithDefaults()
	path := filepath.Join(params.Dir, "geoip-"+strings.ToLower(strings.TrimSpace(cc))+".txt")
	f, err := os.Open(path) //nolint:gosec // cache path from local params
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return geoip.Parse(f)
}
