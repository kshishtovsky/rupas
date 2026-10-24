package rules

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/rupas/rupas/internal/config"
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
		sniExact: make(map[string]config.Action),
		sniWild:  make(map[string]config.Action),
		def:      config.ActionDirect,
	}
	for i, cidr := range cfg.Exclusions.CIDRs {
		if err := t.insertCIDR(cidr, config.ActionDirect); err != nil {
			return nil, fmt.Errorf("rules: exclusion cidr %d: %w", i, err)
		}
	}
	for _, d := range cfg.Exclusions.Domains {
		t.addSNI(d, config.ActionDirect)
	}
	defaults := 0
	var spans []portSpan
	for i, r := range cfg.Rules {
		switch {
		case r.CIDR != "":
			if err := t.insertCIDR(r.CIDR, r.Action); err != nil {
				return nil, fmt.Errorf("rules: rule %d: bad cidr %q: %v", i, r.CIDR, err)
			}
		case r.SNI != "":
			t.addSNI(r.SNI, r.Action)
		case r.Ports != "":
			rs, err := config.ParsePortSpec(r.Ports)
			if err != nil {
				return nil, fmt.Errorf("rules: rule %d: %v", i, err)
			}
			for _, pr := range rs {
				spans = append(spans, portSpan{lo: pr.Lo, hi: pr.Hi, act: r.Action})
			}
		default:
			defaults++
			t.def = r.Action
		}
	}
	if defaults > 1 {
		return nil, errors.New("rules: multiple default rules")
	}
	if len(spans) > 0 {
		sort.Slice(spans, func(i, j int) bool { return spans[i].lo < spans[j].lo })
		for i := 1; i < len(spans); i++ {
			if spans[i].lo <= spans[i-1].hi {
				return nil, fmt.Errorf("rules: overlapping port spans [%d,%d] and [%d,%d]",
					spans[i-1].lo, spans[i-1].hi, spans[i].lo, spans[i].hi)
			}
		}
	}
	t.ports = spans
	return t, nil
}

// addSNI registers sni (already validated and lower-cased) as an exact
// entry or, for "*.suffix" form, as a wildcard-suffix entry. On a
// duplicate key the first registration wins.
func (t *Table) addSNI(sni string, act config.Action) {
	if suffix, ok := strings.CutPrefix(sni, "*."); ok {
		if _, exists := t.sniWild[suffix]; !exists {
			t.sniWild[suffix] = act
		}
		return
	}
	if _, exists := t.sniExact[sni]; !exists {
		t.sniExact[sni] = act
	}
}
