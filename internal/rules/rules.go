// Package rules compiles a config into immutable decision tables used on
// the packet hot path: a binary (patricia-style) CIDR trie for IPv4 and
// IPv6, an exact-match SNI map with wildcard-suffix support, and a sorted
// port-range table. See docs/SYSTEM_DESIGN.md §4.2.
package rules

import (
	"fmt"

	"github.com/rupas/rupas/internal/config"
)

// Action is re-exported so hot-path callers do not need to import config.
type Action = config.Action

// protoID is the internal transport-protocol selector of a table entry.
type protoID uint8

const (
	protoAnyID protoID = iota // matches both transports
	protoTCPID
	protoUDPID
)

// protoIDOf converts a validated config selector ("", "tcp", "udp").
func protoIDOf(s string) (protoID, error) {
	switch s {
	case config.ProtoAny:
		return protoAnyID, nil
	case config.ProtoTCP:
		return protoTCPID, nil
	case config.ProtoUDP:
		return protoUDPID, nil
	}
	return protoAnyID, fmt.Errorf("rules: bad proto selector %q", s)
}

// protoOK reports whether an entry with selector n answers a query for q:
// an any-query matches everything; a concrete query matches its own
// protocol plus any-proto entries. A proto-scoped rule therefore NEVER
// fires for the other protocol.
func protoOK(q, n protoID) bool {
	return q == protoAnyID || n == protoAnyID || n == q
}

// sniKey is a SNI-map key: the (already lower-case) name plus the
// protocol scope it was registered under.
type sniKey struct {
	sni   string
	proto protoID
}

// Table is an immutable, concurrency-safe decision table. Build it with
// Compile, then call Match from any goroutine without synchronization.
type Table struct {
	root4, root6 *cidrNode
	// sniExact maps a full lower-case SNI to an action (O(1) lookup).
	sniExact map[sniKey]config.Action
	// sniWild maps the suffix after "*." (e.g. "googlevideo.com") to an
	// action; matched at label boundaries only.
	sniWild map[sniKey]config.Action
	// Port tables sorted by lo and non-overlapping within each bucket:
	// ports is the any-proto bucket, portsTCP/portsUDP the proto-scoped
	// ones. Scoped spans may overlap any-proto spans (and each other
	// across protocols); a scoped query consults its own bucket FIRST —
	// the more specific scope wins.
	ports, portsTCP, portsUDP []portSpan
	// def is the default action when nothing matches.
	def config.Action
}

type portSpan struct {
	lo, hi uint16
	act    config.Action
}

// Match resolves the action for a flow of unknown protocol: every table
// entry is considered regardless of its proto scope (an any-query matches
// any entry). Resolution order is fixed by SYSTEM_DESIGN §4.2:
// CIDR → SNI → port → default.
//
// Kept for compatibility; the hot path should call MatchProto with the
// real transport protocol so proto-scoped rules resolve correctly.
func (t *Table) Match(ip [16]byte, sni string, port uint16) config.Action {
	return t.MatchProto(ip, sni, port, config.ProtoAny)
}

// MatchProto resolves the action for a flow of transport protocol proto
// (config.ProtoAny / ProtoTCP / ProtoUDP). A rule scoped to proto="udp"
// matches only UDP queries and vice versa; unscoped rules match both.
//
// ip must be a 16-byte address; IPv4 addresses must be in v4-mapped form
// (::ffff:a.b.c.d). sni must be lower case and may be an uncopied
// substring of a larger buffer. port is the transport-layer destination
// port.
//
// MatchProto performs zero allocations; the CIDR walk is O(prefix length),
// an exact SNI hit is O(1).
func (t *Table) MatchProto(ip [16]byte, sni string, port uint16, proto string) config.Action {
	q, err := protoIDOf(proto)
	if err != nil {
		q = protoAnyID
	}
	if a, ok := t.matchCIDR(ip, q); ok {
		return a
	}
	if sni != "" {
		if a, ok := t.lookupSNI(t.sniExact, sni, q); ok {
			return a
		}
		// Wildcard suffix match: try progressively shorter label suffixes.
		// Substring slicing does not allocate.
		for i := 0; i < len(sni); i++ {
			if sni[i] == '.' {
				if a, ok := t.lookupSNI(t.sniWild, sni[i+1:], q); ok {
					return a
				}
			}
		}
	}
	if a, ok := t.matchPort(port, q); ok {
		return a
	}
	return t.def
}

// lookupSNI probes m for (sni, q) and, for a concrete query, the
// unscoped (sni, any) entry — the exact-protocol scope wins.
func (t *Table) lookupSNI(m map[sniKey]config.Action, sni string, q protoID) (config.Action, bool) {
	if a, ok := m[sniKey{sni: sni, proto: q}]; ok {
		return a, true
	}
	if q != protoAnyID {
		if a, ok := m[sniKey{sni: sni, proto: protoAnyID}]; ok {
			return a, true
		}
	}
	return 0, false
}

// matchPort resolves the port tables for query proto q: the scoped bucket
// first (more specific), then the any-proto bucket. An any-query walks
// any → tcp → udp in that order.
func (t *Table) matchPort(p uint16, q protoID) (config.Action, bool) {
	switch q {
	case protoTCPID:
		if a, ok := searchPorts(t.portsTCP, p); ok {
			return a, true
		}
	case protoUDPID:
		if a, ok := searchPorts(t.portsUDP, p); ok {
			return a, true
		}
	default:
		if a, ok := searchPorts(t.ports, p); ok {
			return a, true
		}
		if a, ok := searchPorts(t.portsTCP, p); ok {
			return a, true
		}
		return searchPorts(t.portsUDP, p)
	}
	return searchPorts(t.ports, p)
}

// searchPorts binary-searches a sorted, non-overlapping span table.
func searchPorts(spans []portSpan, p uint16) (config.Action, bool) {
	lo, hi := 0, len(spans)-1
	best := -1
	for lo <= hi {
		mid := int(uint(lo+hi) >> 1)
		if spans[mid].lo <= p {
			best = mid
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	if best >= 0 && p <= spans[best].hi {
		return spans[best].act, true
	}
	return 0, false
}
