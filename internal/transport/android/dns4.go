package android

// PreferIPv4 DNS seam (dns4.go): minimal on-the-wire DNS handling for the
// TUN transport. When PreferIPv4 is on (the default — the server fleet has
// no IPv6 egress, so every tunneled v6 target is guaranteed death):
//
//   - UDP/53 sessions are hijacked in relayUDP (tun.go): AAAA queries are
//     answered with an empty NOERROR right here — apps fall back to A
//     records and the whole device lands on IPv4; every other query is
//     relayed transparently to the original resolver through the protected
//     dialer.
//   - IPv6 flows (TCP and UDP) are fast-dropped in JudgeFlow — apps with
//     Happy Eyeballs fail over to IPv4 instantly instead of hanging in a
//     tunnel that cannot carry them.
//
// The codec below is deliberately tiny: it only needs to recognize queries
// (QR=0) whose question section is AAAA-only and echo that section back
// with an empty answer. Questions are never compressed on the wire, so a
// linear label walk is sufficient; anything unexpected → nil (pass the
// datagram through untouched).

import (
	"encoding/binary"
)

const (
	dnsTypeA    = 1
	dnsTypeAAAA = 28
)

// dns4Response returns a synthetic empty-NOERROR response for a DNS query
// whose question section is AAAA-only, or nil when the datagram must be
// relayed upstream unchanged (not a query, mixed/other qtypes, malformed).
func dns4Response(q []byte) []byte {
	if len(q) < 12 {
		return nil
	}
	if q[2]&0x80 != 0 { // QR set: a response, not a query
		return nil
	}
	qd := binary.BigEndian.Uint16(q[4:6])
	if qd == 0 {
		return nil
	}
	off := 12
	allAAAA := true
	for i := uint16(0); i < qd; i++ {
		for {
			if off >= len(q) {
				return nil
			}
			l := int(q[off])
			off++
			if l == 0 {
				break
			}
			if l&0xC0 != 0 { // compression pointers never appear in queries
				return nil
			}
			off += l
		}
		if off+4 > len(q) {
			return nil
		}
		qt := binary.BigEndian.Uint16(q[off : off+2])
		off += 4
		if qt != dnsTypeAAAA {
			allAAAA = false
		}
	}
	if !allAAAA {
		return nil
	}
	// Synthesize: echo header+question, QR=1, RA=1, RCODE=0, all counts
	// after QDCOUNT zeroed (no answers/authority/additional — a stub
	// handles the missing EDNS OPT fine).
	resp := make([]byte, off+6)
	copy(resp, q[:off])
	resp[2] = q[2] | 0x80      // QR=1 (opcode/AA/TC/RD preserved)
	resp[3] = q[3]&0x70 | 0x80 // RA=1, RCODE=0 (AD/CD preserved)
	// resp[6..11] already zero: ANCOUNT/NSCOUNT/ARCOUNT = 0
	return resp
}

// serveDNS53 is the PreferIPv4 DNS session body: per-datagram AAAA
// filtering with transparent upstream relay for everything else.
// Defined in tun.go (the transport file) — it rides the flowHandler.
