//go:build windows

package windivert

import (
	"encoding/binary"
	"net/netip"
	"unsafe"
)

// Protocol header structures mirror WINDIVERT_IPHDR / WINDIVERT_IPV6HDR /
// WINDIVERT_ICMPHDR / WINDIVERT_TCPHDR / WINDIVERT_UDPHDR from the official
// windivert.h. They are cast-compatible with the pointers returned by
// ParsePacket, i.e. they alias packet memory directly.
//
// Multi-byte fields are stored in NETWORK byte order, exactly as they lie on
// the wire, using fixed-size arrays so they can be read/written with
// encoding/binary (the C headers rely on ntohs/ntohl helpers instead).
// Use the accessor methods (TotalLen, DstPortNum, Seq, ...) which convert;
// the raw array fields are wire bytes.

// IPHeader mirrors WINDIVERT_IPHDR (20 bytes, IPv4).
type IPHeader struct {
	VerHdrLen uint8 // Version (high nibble) | HdrLength in 32-bit words (low nibble).
	TOS       uint8
	Length    [2]byte // Total length; see TotalLen.
	ID        [2]byte // Identification; see Ident.
	FragOff0  [2]byte // Flags + fragment offset; see FragOff/MF/DF.
	TTL       uint8
	Protocol  uint8 // IPPROTO_* value.
	Checksum  [2]byte
	SrcAddr   [4]byte
	DstAddr   [4]byte
}

// Version returns the IP version nibble (4 for IPv4).
func (h *IPHeader) Version() uint8 { return h.VerHdrLen >> 4 }

// HdrLenBytes returns the IP header length in bytes (IHL * 4).
func (h *IPHeader) HdrLenBytes() int { return int(h.VerHdrLen&0x0F) * 4 }

// TotalLen returns the IPv4 total length (packet length) in host byte order.
func (h *IPHeader) TotalLen() int { return int(binary.BigEndian.Uint16(h.Length[:])) }

// SetTotalLen overwrites the total length field.
func (h *IPHeader) SetTotalLen(v uint16) { binary.BigEndian.PutUint16(h.Length[:], v) }

// Ident returns the identification field in host byte order.
func (h *IPHeader) Ident() uint16 { return binary.BigEndian.Uint16(h.ID[:]) }

// fragOffHost returns the flags/fragment-offset field in host byte order
// (the value after ntohs, i.e. a native-order read on Windows), which is
// what the WINDIVERT_IPHDR_*_FRAGOFF macros operate on:
// DF = bit 0x0040, MF = bit 0x0020, offset = & 0xFF1F.
func (h *IPHeader) fragOffHost() uint16 {
	return uint16(h.FragOff0[1])<<8 | uint16(h.FragOff0[0])
}

// FragOff returns the fragment offset (mask 0xFF1F, per the
// WINDIVERT_IPHDR_GET_FRAGOFF macro), host byte order.
func (h *IPHeader) FragOff() uint16 { return h.fragOffHost() & 0xFF1F }

// MF reports the More Fragments flag.
func (h *IPHeader) MF() bool { return h.fragOffHost()&0x0020 != 0 }

// DF reports the Don't Fragment flag.
func (h *IPHeader) DF() bool { return h.fragOffHost()&0x0040 != 0 }

// SetDF sets or clears the Don't Fragment flag (WINDIVERT_IPHDR_SET_DF).
func (h *IPHeader) SetDF(v bool) { h.setFragBit(0x0040, v) }

// SetMF sets or clears the More Fragments flag (WINDIVERT_IPHDR_SET_MF).
func (h *IPHeader) SetMF(v bool) { h.setFragBit(0x0020, v) }

func (h *IPHeader) setFragBit(mask uint16, v bool) {
	f := h.fragOffHost()
	if v {
		f |= mask
	} else {
		f &^= mask
	}
	h.FragOff0[0] = byte(f)
	h.FragOff0[1] = byte(f >> 8)
}

// SrcIP returns the source address as a netip.Addr (no allocation).
func (h *IPHeader) SrcIP() netip.Addr { return netip.AddrFrom4(h.SrcAddr) }

// DstIP returns the destination address as a netip.Addr (no allocation).
func (h *IPHeader) DstIP() netip.Addr { return netip.AddrFrom4(h.DstAddr) }

// IPv6Header mirrors WINDIVERT_IPV6HDR (40 bytes). VTCFL packs the
// Version/TrafficClass/FlowLabel bit-fields exactly as on the wire:
// byte 0: Version (high nibble) | TrafficClass (low nibble),
// byte 1: FlowLabel high nibble (low) | TrafficClass low nibble (high),
// bytes 2-3: FlowLabel low 16 bits.
// Note: the WinDivert build shipped with this repository strips IPv6
// support, so ParsePacket never returns an IPv6Header on this DLL; the type
// is kept for wire-layout parity with the upstream headers.
type IPv6Header struct {
	VTCFL    [4]byte
	Length   [2]byte // Payload length; see PayloadLen.
	NextHdr  uint8
	HopLimit uint8
	SrcAddr  [16]byte
	DstAddr  [16]byte
}

// Version returns the IP version nibble (6 for IPv6).
func (h *IPv6Header) Version() uint8 { return h.VTCFL[0] >> 4 }

// TrafficClass returns the 8-bit traffic class (bit-field accessor).
func (h *IPv6Header) TrafficClass() uint8 { return (h.VTCFL[0] << 4) | (h.VTCFL[1] >> 4) }

// FlowLabel returns the 20-bit flow label (bit-field accessor).
func (h *IPv6Header) FlowLabel() uint32 {
	return uint32(h.VTCFL[1]&0x0F)<<16 | uint32(binary.BigEndian.Uint16(h.VTCFL[2:4]))
}

// PayloadLen returns the payload length in host byte order.
func (h *IPv6Header) PayloadLen() int { return int(binary.BigEndian.Uint16(h.Length[:])) }

// SrcIP returns the source address as a netip.Addr (no allocation).
func (h *IPv6Header) SrcIP() netip.Addr { return netip.AddrFrom16(h.SrcAddr) }

// DstIP returns the destination address as a netip.Addr (no allocation).
func (h *IPv6Header) DstIP() netip.Addr { return netip.AddrFrom16(h.DstAddr) }

// ICMPHeader mirrors WINDIVERT_ICMPHDR / WINDIVERT_ICMPV6HDR (8 bytes).
type ICMPHeader struct {
	Type     uint8
	Code     uint8
	Checksum [2]byte // network byte order
	Body     [4]byte // network byte order
}

// TCPHeader mirrors WINDIVERT_TCPHDR (20 bytes). Flags packs the C
// bit-fields of the UINT16 unit (LSB-first, per MSVC):
// bits 0-3 Reserved1, bits 4-7 HdrLength (32-bit words), bit 8 FIN,
// bit 9 SYN, bit 10 RST, bit 11 PSH, bit 12 ACK, bit 13 URG,
// bits 14-15 Reserved2. Bit positions are byte-order independent.
type TCPHeader struct {
	SrcPort  [2]byte // network byte order; see SrcPortNum.
	DstPort  [2]byte // network byte order; see DstPortNum.
	SeqNum   [4]byte // network byte order; see Seq.
	AckNum   [4]byte // network byte order; see Ack.
	Flags    uint16  // packed bit-fields; see HdrLenBytes/FIN/SYN/...
	Window   [2]byte // network byte order
	Checksum [2]byte // network byte order
	UrgPtr   [2]byte // network byte order
}

// SrcPortNum returns the source port in host byte order.
func (h *TCPHeader) SrcPortNum() uint16 { return binary.BigEndian.Uint16(h.SrcPort[:]) }

// DstPortNum returns the destination port in host byte order.
func (h *TCPHeader) DstPortNum() uint16 { return binary.BigEndian.Uint16(h.DstPort[:]) }

// SetSrcPort / SetDstPort overwrite the port fields.
func (h *TCPHeader) SetSrcPort(v uint16) { binary.BigEndian.PutUint16(h.SrcPort[:], v) }
func (h *TCPHeader) SetDstPort(v uint16) { binary.BigEndian.PutUint16(h.DstPort[:], v) }

// HdrLenBytes returns the TCP data offset (header length) in bytes.
func (h *TCPHeader) HdrLenBytes() int { return int(h.Flags>>4&0x0F) * 4 }

// Seq returns the sequence number in host byte order.
func (h *TCPHeader) Seq() uint32 { return binary.BigEndian.Uint32(h.SeqNum[:]) }

// Ack returns the acknowledgment number in host byte order.
func (h *TCPHeader) Ack() uint32 { return binary.BigEndian.Uint32(h.AckNum[:]) }

// SetSeq overwrites the sequence number (network byte order on the wire).
func (h *TCPHeader) SetSeq(v uint32) { binary.BigEndian.PutUint32(h.SeqNum[:], v) }

// SetAck overwrites the acknowledgment number.
func (h *TCPHeader) SetAck(v uint32) { binary.BigEndian.PutUint32(h.AckNum[:], v) }

func (h *TCPHeader) flag(bit uint16) bool { return h.Flags&bit != 0 }
func (h *TCPHeader) setFlag(bit uint16, v bool) {
	if v {
		h.Flags |= bit
	} else {
		h.Flags &^= bit
	}
}

// FIN / SYN / RST / PSH / ACK / URG report the corresponding TCP flags.
func (h *TCPHeader) FIN() bool { return h.flag(0x0100) }
func (h *TCPHeader) SYN() bool { return h.flag(0x0200) }
func (h *TCPHeader) RST() bool { return h.flag(0x0400) }
func (h *TCPHeader) PSH() bool { return h.flag(0x0800) }
func (h *TCPHeader) ACK() bool { return h.flag(0x1000) }
func (h *TCPHeader) URG() bool { return h.flag(0x2000) }

// SetSYN / SetFIN / SetRST / SetACK / SetPSH toggle TCP flags.
func (h *TCPHeader) SetSYN(v bool) { h.setFlag(0x0200, v) }
func (h *TCPHeader) SetFIN(v bool) { h.setFlag(0x0100, v) }
func (h *TCPHeader) SetRST(v bool) { h.setFlag(0x0400, v) }
func (h *TCPHeader) SetACK(v bool) { h.setFlag(0x1000, v) }
func (h *TCPHeader) SetPSH(v bool) { h.setFlag(0x0800, v) }

// UDPHeader mirrors WINDIVERT_UDPHDR (8 bytes).
type UDPHeader struct {
	SrcPort  [2]byte // network byte order; see SrcPortNum.
	DstPort  [2]byte // network byte order; see DstPortNum.
	Length   [2]byte // network byte order; see LengthNum.
	Checksum [2]byte // network byte order
}

// SrcPortNum returns the source port in host byte order.
func (h *UDPHeader) SrcPortNum() uint16 { return binary.BigEndian.Uint16(h.SrcPort[:]) }

// DstPortNum returns the destination port in host byte order.
func (h *UDPHeader) DstPortNum() uint16 { return binary.BigEndian.Uint16(h.DstPort[:]) }

// LengthNum returns the UDP length (header + payload) in host byte order.
func (h *UDPHeader) LengthNum() int { return int(binary.BigEndian.Uint16(h.Length[:])) }

// ParsedPacket is the result of ParsePacket: pointers alias the input
// packet buffer; no data is copied.
type ParsedPacket struct {
	IPv4     *IPHeader
	IPv6     *IPv6Header
	Protocol uint8       // IPPROTO_* of the transport layer (0 if none).
	ICMP     *ICMPHeader // IPv4 ICMP (aliases packet memory).
	ICMPv6   *ICMPHeader // ICMPv6 (aliases packet memory).
	TCP      *TCPHeader
	UDP      *UDPHeader
	Data     []byte // Transport-layer payload.
	Next     []byte // Bytes after the parsed headers (e.g. second IP header).
}

// ParsePacket wraps WinDivertHelperParsePacket (pure userspace). It decodes
// IPv4/IPv6/ICMP/ICMPv6/TCP/UDP headers from a raw packet; all returned
// pointers alias p. ok is false when the packet is malformed (or the DLL is
// unavailable).
func ParsePacket(p []byte) (*ParsedPacket, bool) {
	if err := procHelperParsePacket.Find(); err != nil {
		return nil, false
	}
	if len(p) == 0 {
		return nil, false
	}
	var (
		ip4, ipv6, icmp, icmpv6, tcp, udp, data, next unsafe.Pointer
		proto                                         uint8
		dataLen, nextLen                              uint32
	)
	r1, _, _ := procHelperParsePacket.Call(
		uintptr(unsafe.Pointer(&p[0])),
		uintptr(len(p)),
		uintptr(unsafe.Pointer(&ip4)),
		uintptr(unsafe.Pointer(&ipv6)),
		uintptr(unsafe.Pointer(&proto)),
		uintptr(unsafe.Pointer(&icmp)),
		uintptr(unsafe.Pointer(&icmpv6)),
		uintptr(unsafe.Pointer(&tcp)),
		uintptr(unsafe.Pointer(&udp)),
		uintptr(unsafe.Pointer(&data)),
		uintptr(unsafe.Pointer(&dataLen)),
		uintptr(unsafe.Pointer(&next)),
		uintptr(unsafe.Pointer(&nextLen)),
	)
	if r1 == 0 {
		return nil, false
	}
	pp := &ParsedPacket{Protocol: proto}
	if ip4 != nil {
		pp.IPv4 = (*IPHeader)(ip4)
	}
	if ipv6 != nil {
		pp.IPv6 = (*IPv6Header)(ipv6)
	}
	if icmp != nil {
		pp.ICMP = (*ICMPHeader)(icmp)
	}
	if icmpv6 != nil {
		pp.ICMPv6 = (*ICMPHeader)(icmpv6)
	}
	if tcp != nil {
		pp.TCP = (*TCPHeader)(tcp)
	}
	if udp != nil {
		pp.UDP = (*UDPHeader)(udp)
	}
	if data != nil {
		pp.Data = unsafe.Slice((*byte)(data), int(dataLen))
	}
	if next != nil {
		pp.Next = unsafe.Slice((*byte)(next), int(nextLen))
	}
	return pp, true
}
