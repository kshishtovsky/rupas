package rules

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/kshishtovsky/rupas/internal/config"
	"github.com/kshishtovsky/rupas/internal/geoip"
)

// Compile builds an immutable decision Table from a validated config.
// Exclusions (VPS endpoint, RU banking subnets, ...) are inserted into
// the CIDR/SNI tables as DIRECT entries before the rules, so a longer
// exclusion prefix wins over a broader rule prefix, and identical
// prefixes keep the first-inserted action.
func Compile(cfg *config.Config) (*Table, error) {
	if cfg == nil {
		return nil, errors.New("rules: nil config")
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("rules: invalid config: %w", err)
	}
	t := &Table{
		apps:     make(map[appKey]config.Action),
		sniExact: make(map[sniKey]config.Action),
		sniWild:  make(map[sniKey]config.Action),
		def:      config.ActionDirect,
	}
	for i, cidr := range cfg.Exclusions.CIDRs {
		if err := t.insertCIDR(cidr, config.ActionDirect, protoAnyID); err != nil {
			return nil, fmt.Errorf("rules: exclusion cidr %d: %w", i, err)
		}
	}
	for _, d := range cfg.Exclusions.Domains {
		t.addSNI(d, config.ActionDirect, protoAnyID)
	}
	defaults := 0
	var spansAny, spansTCP, spansUDP []portSpan
	for i, r := range cfg.Rules {
		proto, err := protoIDOf(r.Proto)
		if err != nil {
			return nil, fmt.Errorf("rules: rule %d: %v", i, err)
		}
		switch {
		case r.App != "":
			// First rule wins on a duplicate (name, proto) key, like
			// addSNI; r.App is already lower-case (Validate).
			k := appKey{app: r.App, proto: proto}
			if _, exists := t.apps[k]; !exists {
				t.apps[k] = r.Action
			}
		case r.CIDR != "":
			if err := t.insertCIDR(r.CIDR, r.Action, proto); err != nil {
				return nil, fmt.Errorf("rules: rule %d: bad cidr %q: %v", i, r.CIDR, err)
			}
		case r.GeoIP != "":
			prefixes, err := geoip.List(geoip.Params{
				Dir:         geoipDir(cfg),
				RefreshDays: geoIPRefresh(cfg),
				Mirrors:     geoIPMirrors(cfg),
			}, r.GeoIP)
			if err != nil {
				return nil, fmt.Errorf("rules: rule %d: geoip %s: %w", i, r.GeoIP, err)
			}
			for _, pfx := range prefixes {
				// Longest-prefix match makes bulk insertion order-safe;
				// first-wins keeps any earlier rule (exclusions, Telegram
				// CIDRs) on a shared prefix.
				if err := t.insertCIDR(pfx.String(), r.Action, proto); err != nil {
					return nil, fmt.Errorf("rules: rule %d: geoip %s: bad %q: %v",
						i, r.GeoIP, pfx, err)
				}
			}
		case r.SNI != "":
			t.addSNI(r.SNI, r.Action, proto)
		case r.Ports != "":
			rs, err := config.ParsePortSpec(r.Ports)
			if err != nil {
				return nil, fmt.Errorf("rules: rule %d: %v", i, err)
			}
			dst := &spansAny
			switch proto {
			case protoTCPID:
				dst = &spansTCP
			case protoUDPID:
				dst = &spansUDP
			}
			for _, pr := range rs {
				*dst = append(*dst, portSpan{lo: pr.Lo, hi: pr.Hi, act: r.Action})
			}
		default:
			defaults++
			t.def = r.Action
		}
	}
	if defaults > 1 {
		return nil, errors.New("rules: multiple default rules")
	}
	// Overlap is an error only WITHIN a bucket: same-protocol spans must
	// be disjoint (ambiguous resolution), while spans of different scopes
	// may share ports by design (e.g. udp:443 block next to tcp:443).
	for name, spans := range map[string][]portSpan{"ports": spansAny, "tcp ports": spansTCP, "udp ports": spansUDP} {
		if err := sortAndCheck(spans); err != nil {
			return nil, fmt.Errorf("rules: %s: %v", name, err)
		}
	}
	t.ports, t.portsTCP, t.portsUDP = spansAny, spansTCP, spansUDP
	return t, nil
}

// geoipDir/geoIPRefresh/geoIPMirrors read the optional `geoip:` section,
// falling back to the package defaults when it is absent or partial.
func geoipDir(cfg *config.Config) string {
	if cfg.GeoIP != nil {
		return cfg.GeoIP.Dir
	}
	return ""
}

func geoIPRefresh(cfg *config.Config) int {
	if cfg.GeoIP != nil {
		return cfg.GeoIP.RefreshDays
	}
	return 0
}

func geoIPMirrors(cfg *config.Config) []string {
	if cfg.GeoIP != nil {
		return cfg.GeoIP.Mirrors
	}
	return nil
}

// sortAndCheck sorts spans by lo and rejects overlaps (the resolution
// within one bucket would otherwise be order-dependent).
func sortAndCheck(spans []portSpan) error {
	if len(spans) < 2 {
		return nil
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].lo < spans[j].lo })
	for i := 1; i < len(spans); i++ {
		if spans[i].lo <= spans[i-1].hi {
			return fmt.Errorf("overlapping port spans [%d,%d] and [%d,%d]",
				spans[i-1].lo, spans[i-1].hi, spans[i].lo, spans[i].hi)
		}
	}
	return nil
}

// addSNI registers sni (already validated and lower-cased) as an exact
// entry or, for "*.suffix" form, as a wildcard-suffix entry, scoped to
// proto. On a duplicate key the first registration wins.
func (t *Table) addSNI(sni string, act config.Action, proto protoID) {
	key := sniKey{sni: sni, proto: proto}
	if suffix, ok := strings.CutPrefix(sni, "*."); ok {
		key.sni = suffix
		if _, exists := t.sniWild[key]; !exists {
			t.sniWild[key] = act
		}
		return
	}
	if _, exists := t.sniExact[key]; !exists {
		t.sniExact[key] = act
	}
}
