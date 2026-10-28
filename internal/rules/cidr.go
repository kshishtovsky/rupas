package rules

import (
	"net"

	"github.com/kshishtovsky/rupas/internal/config"
)

// cidrNode is a node of the binary prefix trie: one child per bit value.
// A node carries an action when some inserted prefix ends exactly there.
// Path compression is unnecessary: the walk is bounded by the prefix
// length (32 steps for IPv4, 128 for IPv6) and stops at the first nil
// child, so it is effectively O(longest matching prefix).
type cidrNode struct {
	child [2]*cidrNode
	act   config.Action
	proto protoID // protocol scope of the rule that set act
	has   bool
}

// insertCIDR parses cidr and inserts act for its prefix, scoped to proto
// (protoAnyID / protoTCPID / protoUDPID). IPv4 prefixes (including
// v4-mapped notation) go into the v4 trie, IPv6 into the v6 trie. If the
// same prefix is inserted twice, the first insertion wins.
func (t *Table) insertCIDR(cidr string, act config.Action, proto protoID) error {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	ones, _ := ipnet.Mask.Size()
	ip := ipnet.IP // 4 bytes for IPv4, 16 for IPv6
	if len(ip) == net.IPv6len && isV4MappedBytes(ip) {
		// Normalize v4-mapped prefixes into the v4 trie.
		ip = ip[12:]
		if ones > 96 {
			ones -= 96
		} else {
			ones = 0
		}
	}
	if len(ip) == net.IPv4len {
		t.root4 = insertPrefix(t.root4, ip, ones, act, proto)
	} else {
		t.root6 = insertPrefix(t.root6, ip, ones, act, proto)
	}
	return nil
}

func insertPrefix(root *cidrNode, ip []byte, ones int, act config.Action, proto protoID) *cidrNode {
	if root == nil {
		root = &cidrNode{}
	}
	n := root
	bit := 0
	for _, b := range ip {
		for i := 7; i >= 0; i-- {
			if bit == ones {
				setIfFree(n, act, proto)
				return root
			}
			d := (b >> uint(i)) & 1
			if n.child[d] == nil {
				n.child[d] = &cidrNode{}
			}
			n = n.child[d]
			bit++
		}
	}
	setIfFree(n, act, proto)
	return root
}

func setIfFree(n *cidrNode, act config.Action, proto protoID) {
	if !n.has {
		n.has = true
		n.act = act
		n.proto = proto
	}
}

// matchCIDR dispatches to the v4 trie for v4-mapped addresses, else to
// the v6 trie, and returns the action of the deepest prefix whose proto
// scope answers query q.
func (t *Table) matchCIDR(ip [16]byte, q protoID) (config.Action, bool) {
	if isV4Mapped(ip) {
		return matchTrie(t.root4, ip[12:], q)
	}
	return matchTrie(t.root6, ip[:], q)
}

func isV4Mapped(ip [16]byte) bool {
	for i := 0; i < 10; i++ {
		if ip[i] != 0 {
			return false
		}
	}
	return ip[10] == 0xff && ip[11] == 0xff
}

func isV4MappedBytes(ip []byte) bool {
	for i := 0; i < 10; i++ {
		if ip[i] != 0 {
			return false
		}
	}
	return ip[10] == 0xff && ip[11] == 0xff
}

// matchTrie walks the trie bit by bit remembering the deepest node that
// carries an action whose proto scope answers query q (longest-prefix
// match; a proto-scoped node is skipped for a query of the other protocol
// and the walk continues toward shorter prefixes). Allocation-free.
func matchTrie(root *cidrNode, ip []byte, q protoID) (config.Action, bool) {
	n := root
	if n == nil {
		return 0, false
	}
	var best config.Action
	var found bool
	if n.has && protoOK(q, n.proto) {
		best, found = n.act, true
	}
	for _, b := range ip {
		for i := 7; i >= 0; i-- {
			n = n.child[(b>>uint(i))&1]
			if n == nil {
				return best, found
			}
			if n.has && protoOK(q, n.proto) {
				best, found = n.act, true
			}
		}
	}
	return best, found
}
