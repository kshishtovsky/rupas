// Package rules compiles a config into immutable decision tables used on
// the packet hot path: a binary (patricia-style) CIDR trie for IPv4 and
// IPv6, an exact-match SNI map with wildcard-suffix support, and a sorted
// port-range table. See docs/SYSTEM_DESIGN.md §4.2.
package rules

import "github.com/rupas/rupas/internal/config"

// Action is re-exported so hot-path callers do not need to import config.
type Action = config.Action

// Table is an immutable, concurrency-safe decision table. Build it with
// Compile, then call Match from any goroutine without synchronization.
type Table struct {
	root4, root6 *cidrNode
	// sniExact maps a full lower-case SNI to an action (O(1) lookup).
	sniExact map[string]config.Action
	// sniWild maps the suffix after "*." (e.g. "googlevideo.com") to an
	// action; matched at label boundaries only.
	sniWild map[string]config.Action
	// ports is sorted by lo and non-overlapping.
	ports []portSpan
	// def is the default action when nothing matches.
	def config.Action
}

type portSpan struct {
	lo, hi uint16
	act    config.Action
}

// Match resolves the action for a flow. Resolution order is fixed by
// SYSTEM_DESIGN §4.2: CIDR → SNI → port → default.
//
// ip must be a 16-byte address; IPv4 addresses must be in v4-mapped form
// (::ffff:a.b.c.d). sni must be lower case and may be an uncopied
// substring of a larger buffer. port is the transport-layer destination
// port.
//
// Match performs zero allocations; the CIDR walk is O(prefix length),
// an exact SNI hit is O(1).
func (t *Table) Match(ip [16]byte, sni string, port uint16) config.Action {
	if a, ok := t.matchCIDR(ip); ok {
		return a
	}
	if sni != "" {
		if a, ok := t.sniExact[sni]; ok {
			return a
		}
		// Wildcard suffix match: try progressively shorter label suffixes.
		// Substring slicing does not allocate.
		for i := 0; i < len(sni); i++ {
			if sni[i] == '.' {
				if a, ok := t.sniWild[sni[i+1:]]; ok {
					return a
				}
			}
		}
	}
	if a, ok := t.matchPort(port); ok {
		return a
	}
	return t.def
}

// matchPort binary-searches the sorted, non-overlapping span table.
func (t *Table) matchPort(p uint16) (config.Action, bool) {
	lo, hi := 0, len(t.ports)-1
	best := -1
	for lo <= hi {
		mid := int(uint(lo+hi) >> 1)
		if t.ports[mid].lo <= p {
			best = mid
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	if best >= 0 && p <= t.ports[best].hi {
		return t.ports[best].act, true
	}
	return 0, false
}
