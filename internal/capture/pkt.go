//go:build windows

// Package capture implements the Rupas packet hot path
// (docs/SYSTEM_DESIGN.md §3.2): a NETWORK-layer WinDivert receive loop that
// classifies TCP:443 flows, inspects the first TLS ClientHello, applies the
// configured verdict (DIRECT pass-through / DPI desync / NAT-redirect into
// the local tproxy) and re-injects every packet.
//
// The driver-facing surface is abstracted behind the Transport interface so
// the engine can be driven by synthetic packets in tests without the
// WinDivert driver; WinTransport is the production implementation over
// pkg/windivert.
//
// Hot-path invariants (§3.2): one goroutine per handle, batch receive
// (RecvBatch via RecvEx), sync.Pool batch/scratch buffers, zero heap
// allocations in the steady state (verified by TestAllocsPerRunZero).
package capture

import (
	"encoding/binary"

	"github.com/kshishtovsky/rupas/internal/flowtable"
)

const (
	protoTCP uint8 = 6
	protoUDP uint8 = 17

	tcpFlagFIN uint8 = 0x01
	tcpFlagSYN uint8 = 0x02
	tcpFlagRST uint8 = 0x04
	tcpFlagPSH uint8 = 0x08
	tcpFlagACK uint8 = 0x10
)

// pktInfo is a zero-allocation view of an IPv4 TCP/UDP packet. Scalar fields
// are copied onto the (caller's stack) struct; payload aliases the packet
// buffer. Production traffic is IPv4-only: the WinDivert build shipped with
// this repository strips IPv6 support (see pkg/windivert).
type pktInfo struct {
	proto   uint8
	ipLen   int // IPv4 header length in bytes (>= 20)
	trLen   int // TCP/UDP header length in bytes
	src4    [4]byte
	dst4    [4]byte
	srcPort uint16
	dstPort uint16
	seq     uint32
	ackNum  uint32
	flags   uint8 // TCP flags
	payload []byte
}

func (p *pktInfo) isTCP() bool { return p.proto == protoTCP }
func (p *pktInfo) isUDP() bool { return p.proto == protoUDP }

func (p *pktInfo) syn() bool  { return p.flags&tcpFlagSYN != 0 }
func (p *pktInfo) ack() bool  { return p.flags&tcpFlagACK != 0 }
func (p *pktInfo) fin() bool  { return p.flags&tcpFlagFIN != 0 }
func (p *pktInfo) rst() bool  { return p.flags&tcpFlagRST != 0 }
func (p *pktInfo) hdrLen() int { return p.ipLen + p.trLen }

// parsePkt decodes the IPv4+TCP/UDP headers of pkt without allocating. It
// validates only what the hot path relies on (header lengths fitting inside
// the packet); checksums are not verified — the driver already did.
func parsePkt(pkt []byte) (pktInfo, bool) {
	var p pktInfo
	if len(pkt) < 20 {
		return p, false
	}
	if pkt[0]>>4 != 4 {
		return p, false // IPv6 unsupported by this WinDivert build
	}
	p.ipLen = int(pkt[0]&0x0F) * 4
	if p.ipLen < 20 || len(pkt) < p.ipLen {
		return p, false
	}
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if total < p.ipLen || total > len(pkt) {
		return p, false
	}
	p.proto = pkt[9]
	copy(p.src4[:], pkt[12:16])
	copy(p.dst4[:], pkt[16:20])
	switch p.proto {
	case protoTCP:
		h := pkt[p.ipLen:]
		if len(h) < 20 {
			return p, false
		}
		p.trLen = int(h[12]>>4) * 4
		if p.trLen < 20 || p.ipLen+p.trLen > total {
			return p, false
		}
		p.srcPort = binary.BigEndian.Uint16(h[0:2])
		p.dstPort = binary.BigEndian.Uint16(h[2:4])
		p.seq = binary.BigEndian.Uint32(h[4:8])
		p.ackNum = binary.BigEndian.Uint32(h[8:12])
		p.flags = h[13]
		p.payload = pkt[p.ipLen+p.trLen : total]
	case protoUDP:
		h := pkt[p.ipLen:]
		if len(h) < 8 {
			return p, false
		}
		p.trLen = 8
		p.srcPort = binary.BigEndian.Uint16(h[0:2])
		p.dstPort = binary.BigEndian.Uint16(h[2:4])
		p.payload = pkt[p.ipLen+8 : total]
	default:
		return p, false
	}
	return p, true
}

// v4mapped converts an IPv4 address into the 16-byte v4-mapped form used by
// flowtable.FlowKey and rules.Table.Match. Stack-only; no allocation.
func v4mapped(a [4]byte) (b [16]byte) {
	b[10] = 0xFF
	b[11] = 0xFF
	copy(b[12:16], a[:])
	return b
}

// loopback4 is 127.0.0.1.
var loopback4 = [4]byte{127, 0, 0, 1}

// loopbackIfIdx is the interface index of the Windows loopback adapter
// ("MS TCP Loopback Interface"); constant 1 across all observed systems.
// Used when re-injecting NAT-rewritten packets destined to 127.0.0.1.
const loopbackIfIdx = 1

func isLoopback(a [4]byte) bool { return a[0] == 127 }

// flowKeyOut builds the flow-table key for an outbound (client → server)
// packet. The client is always the source of the key, so the reverse
// direction of the same connection maps to the same entry.
func flowKeyOut(p *pktInfo) (k flowtable.FlowKey) {
	k.SrcIP = v4mapped(p.src4)
	k.DstIP = v4mapped(p.dst4)
	k.SrcPort = p.srcPort
	k.DstPort = p.dstPort
	k.Proto = p.proto
	return k
}

// flowKeyIn builds the client-side key for an inbound (server → client)
// packet: swap the tuple so the client lands in the source fields.
func flowKeyIn(p *pktInfo) (k flowtable.FlowKey) {
	k.SrcIP = v4mapped(p.dst4)
	k.DstIP = v4mapped(p.src4)
	k.SrcPort = p.dstPort
	k.DstPort = p.srcPort
	k.Proto = p.proto
	return k
}
