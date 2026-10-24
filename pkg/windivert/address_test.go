//go:build windows

package windivert

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unsafe"
)

// TestAddressLayout pins the WINDIVERT_ADDRESS 2.2 wire layout: total size
// 80 bytes on 64-bit and exact field offsets matching the C bit-field
// decomposition (verified against the official windivert.h and live driver).
func TestAddressLayout(t *testing.T) {
	var a Address
	if got := unsafe.Sizeof(a); got != 80 {
		t.Fatalf("unsafe.Sizeof(Address{}) = %d, want 80 (WinDivert 2.2, x64)", got)
	}
	if got := unsafe.Alignof(a); got != 8 {
		t.Fatalf("unsafe.Alignof(Address{}) = %d, want 8", got)
	}
	offs := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"Timestamp", unsafe.Offsetof(a.Timestamp), 0},
		{"Layer", unsafe.Offsetof(a.Layer), 8},
		{"Event", unsafe.Offsetof(a.Event), 9},
		{"flags", unsafe.Offsetof(a.flags), 10},
		{"Reserved1", unsafe.Offsetof(a.Reserved1), 11},
		{"Reserved2", unsafe.Offsetof(a.Reserved2), 12},
		{"Data", unsafe.Offsetof(a.Data), 16},
	}
	for _, o := range offs {
		if o.got != o.want {
			t.Errorf("offset of %s = %d, want %d", o.name, o.got, o.want)
		}
	}
	if got := unsafe.Sizeof(a.Data); got != 64 {
		t.Errorf("sizeof(union) = %d, want 64", got)
	}
}

// Union members must fit the 64-byte reserved area.
func TestUnionDataSizes(t *testing.T) {
	if got := unsafe.Sizeof(NetworkData{}); got != 8 {
		t.Errorf("sizeof(NetworkData) = %d, want 8", got)
	}
	if got := unsafe.Sizeof(FlowData{}); got > 64 {
		t.Errorf("sizeof(FlowData) = %d, exceeds union size 64", got)
	}
	if got := unsafe.Sizeof(ReflectData{}); got > 64 {
		t.Errorf("sizeof(ReflectData) = %d, exceeds union size 64", got)
	}
}

func TestAddressFlagBits(t *testing.T) {
	var a Address
	a.SetOutbound(true)
	a.SetIPChecksum(true)
	if a.flags != flagOutbound|flagIPChecksum {
		t.Fatalf("flags byte = %#02x, want %#02x", a.flags, flagOutbound|flagIPChecksum)
	}
	if !a.Outbound() || !a.IPChecksum() {
		t.Error("expected Outbound and IPChecksum set")
	}
	if a.Sniffed() || a.Loopback() || a.Impostor() || a.IPv6() || a.TCPChecksum() || a.UDPChecksum() {
		t.Error("unexpected flag bits set")
	}
	a.SetOutbound(false)
	if a.Outbound() {
		t.Error("SetOutbound(false) did not clear the bit")
	}
	a.flags = 0xFF
	if !(a.Sniffed() && a.Outbound() && a.Loopback() && a.Impostor() && a.IPv6() &&
		a.IPChecksum() && a.TCPChecksum() && a.UDPChecksum()) {
		t.Error("all-bits-set byte should make every accessor true")
	}
}

// TestParseAddressRaw decodes a hand-crafted 80-byte WINDIVERT_ADDRESS,
// including FLOW-layer union contents, and round-trips via Raw().
func TestParseAddressRaw(t *testing.T) {
	raw := make([]byte, 96)
	binary.LittleEndian.PutUint64(raw[0:8], 0x1122334455667788)
	raw[8] = LayerFlow
	raw[9] = EventFlowEstablished
	raw[10] = 0xA5 // Sniffed|Loopback|IPChecksum|UDPChecksum (bits 0,2,5,7)
	raw[11] = 0
	binary.LittleEndian.PutUint32(raw[12:16], 0xDEADBEEF)
	// FLOW union: EndpointId@0, ParentEndpointId@8, ProcessId@16,
	// LocalAddr@20 (16B), RemoteAddr@36 (16B), LocalPort@52, RemotePort@54,
	// Protocol@56; all relative to the union base at raw offset 16.
	binary.LittleEndian.PutUint64(raw[16:24], 111)
	binary.LittleEndian.PutUint64(raw[24:32], 222)
	binary.LittleEndian.PutUint32(raw[32:36], 333)
	binary.LittleEndian.PutUint32(raw[36:40], 0x0100007f) // 127.0.0.1 host order
	binary.LittleEndian.PutUint16(raw[68:70], 443)
	binary.LittleEndian.PutUint16(raw[70:72], 8443)
	raw[72] = 6 // TCP

	a, err := ParseAddress(raw)
	if err != nil {
		t.Fatalf("ParseAddress: %v", err)
	}
	if a.Timestamp != 0x1122334455667788 {
		t.Errorf("Timestamp = %#x", a.Timestamp)
	}
	if a.Layer != LayerFlow || a.Event != EventFlowEstablished {
		t.Errorf("Layer/Event = %d/%d", a.Layer, a.Event)
	}
	if a.Reserved2 != 0xDEADBEEF {
		t.Errorf("Reserved2 = %#x", a.Reserved2)
	}
	if !a.Sniffed() || a.Outbound() || !a.Loopback() || a.IPv6() || !a.IPChecksum() || !a.UDPChecksum() {
		t.Errorf("flag decode mismatch for 0xA5: %+v", a)
	}
	f := a.Flow()
	if f.EndpointID != 111 || f.ParentEndpointID != 222 || f.ProcessID != 333 {
		t.Errorf("FlowData ids = %d/%d/%d", f.EndpointID, f.ParentEndpointID, f.ProcessID)
	}
	if f.LocalAddr[0] != 0x0100007f {
		t.Errorf("LocalAddr[0] = %#x", f.LocalAddr[0])
	}
	if f.LocalPort != 443 || f.RemotePort != 8443 || f.Protocol != 6 {
		t.Errorf("FlowData ports/proto = %d/%d/%d", f.LocalPort, f.RemotePort, f.Protocol)
	}
	// The Network view aliases the same union bytes (EndpointId low 32 bits).
	if n := a.Network(); n.IfIdx != 111 {
		t.Errorf("Network().IfIdx = %d, want 111 (union aliasing broken)", n.IfIdx)
	}

	// Short buffer must fail.
	if _, err := ParseAddress(raw[:79]); err == nil {
		t.Error("ParseAddress should reject a 79-byte buffer")
	}

	// Round-trip through Raw().
	rt := a.Raw()
	got, err := ParseAddress(rt[:])
	if err != nil {
		t.Fatalf("re-ParseAddress: %v", err)
	}
	if got != a {
		t.Errorf("Raw/ParseAddress round-trip mismatch:\n got %+v\nwant %+v", got, a)
	}
	if !bytes.Equal(rt[:16], raw[:16]) {
		t.Errorf("first 16 bytes differ after round-trip: % x vs % x", rt[:16], raw[:16])
	}
}

func TestHeaderStructLayouts(t *testing.T) {
	if got := unsafe.Sizeof(IPHeader{}); got != 20 {
		t.Errorf("sizeof(IPHeader) = %d, want 20", got)
	}
	if got := unsafe.Sizeof(IPv6Header{}); got != 40 {
		t.Errorf("sizeof(IPv6Header) = %d, want 40", got)
	}
	if got := unsafe.Sizeof(TCPHeader{}); got != 20 {
		t.Errorf("sizeof(TCPHeader) = %d, want 20", got)
	}
	if got := unsafe.Sizeof(UDPHeader{}); got != 8 {
		t.Errorf("sizeof(UDPHeader) = %d, want 8", got)
	}
	if got := unsafe.Sizeof(ICMPHeader{}); got != 8 {
		t.Errorf("sizeof(ICMPHeader) = %d, want 8", got)
	}
}

// TestHeaderAccessors exercises wire-order decoding on a synthetic
// IPv4+TCP packet (no DLL needed).
func TestHeaderAccessors(t *testing.T) {
	pkt := make([]byte, 40)
	// IPv4: version 4, IHL 5, total length 40, DF set, proto TCP.
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], 40)
	binary.BigEndian.PutUint16(pkt[4:6], 0x1234) // ID
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000) // DF, offset 0
	pkt[8] = 64                                  // TTL
	pkt[9] = 6                                   // TCP
	copy(pkt[12:16], []byte{149, 154, 175, 50})  // src
	copy(pkt[16:20], []byte{91, 108, 4, 10})     // dst
	// TCP: src 51000, dst 443, SYN, data offset 5. The Flags bit-field unit
	// is read natively (LSB-first), so doff=5 is the high nibble of byte 0
	// and SYN (bit 9) is bit 0x02 of byte 1.
	binary.BigEndian.PutUint16(pkt[20:22], 51000)
	binary.BigEndian.PutUint16(pkt[22:24], 443)
	binary.BigEndian.PutUint32(pkt[24:28], 0xDEADBEEF)
	binary.BigEndian.PutUint32(pkt[28:32], 0xCAFEBABE)
	pkt[32] = 0x50 // reserved 0 | doff 5
	pkt[33] = 0x02 // SYN
	binary.BigEndian.PutUint16(pkt[34:36], 64240)

	ip := (*IPHeader)(unsafe.Pointer(&pkt[0]))
	if ip.Version() != 4 {
		t.Errorf("Version = %d", ip.Version())
	}
	if ip.HdrLenBytes() != 20 {
		t.Errorf("HdrLenBytes = %d, want 20", ip.HdrLenBytes())
	}
	if ip.TotalLen() != 40 {
		t.Errorf("TotalLen = %d, want 40", ip.TotalLen())
	}
	if ip.Ident() != 0x1234 {
		t.Errorf("Ident = %#x", ip.Ident())
	}
	if !ip.DF() || ip.MF() || ip.FragOff() != 0 {
		t.Errorf("DF/MF/FragOff = %v/%v/%d", ip.DF(), ip.MF(), ip.FragOff())
	}
	ip.SetDF(false)
	if ip.DF() {
		t.Error("SetDF(false) failed")
	}
	ip.SetMF(true)
	// Host-order value is now 0x0020 -> wire bytes [0x20, 0x00].
	if !ip.MF() || binary.BigEndian.Uint16(pkt[6:8]) != 0x2000 {
		t.Errorf("SetMF produced wire value %#06x, want 0x2000", binary.BigEndian.Uint16(pkt[6:8]))
	}
	if ip.SrcIP().String() != "149.154.175.50" || ip.DstIP().String() != "91.108.4.10" {
		t.Errorf("SrcIP/DstIP = %v/%v", ip.SrcIP(), ip.DstIP())
	}
	ip.SetTotalLen(777)
	if ip.TotalLen() != 777 || binary.BigEndian.Uint16(pkt[2:4]) != 777 {
		t.Errorf("SetTotalLen failed: %d / wire % d", ip.TotalLen(), binary.BigEndian.Uint16(pkt[2:4]))
	}

	tcp := (*TCPHeader)(unsafe.Pointer(&pkt[20]))
	if tcp.SrcPortNum() != 51000 || tcp.DstPortNum() != 443 {
		t.Errorf("ports = %d/%d", tcp.SrcPortNum(), tcp.DstPortNum())
	}
	if tcp.Seq() != 0xDEADBEEF || tcp.Ack() != 0xCAFEBABE {
		t.Errorf("seq/ack = %#x/%#x", tcp.Seq(), tcp.Ack())
	}
	if !tcp.SYN() || tcp.ACK() || tcp.FIN() || tcp.RST() || tcp.PSH() {
		t.Errorf("TCP flag decode wrong for 0x52: %+v", tcp)
	}
	if tcp.HdrLenBytes() != 20 {
		t.Errorf("TCP HdrLenBytes = %d", tcp.HdrLenBytes())
	}
	tcp.SetACK(true)
	if !tcp.SYN() || !tcp.ACK() {
		t.Error("flag setters broken")
	}
	tcp.SetSeq(1)
	tcp.SetAck(2)
	if tcp.Seq() != 1 || tcp.Ack() != 2 {
		t.Error("SetSeq/SetAck broken")
	}

	// IPv6 header bit-fields.
	var ip6 IPv6Header
	ip6.VTCFL = [4]byte{0x62, 0x34, 0x12, 0x34} // v6, TC=0x23, FL=0x41234
	if ip6.Version() != 6 {
		t.Errorf("ip6.Version = %d", ip6.Version())
	}
	if ip6.TrafficClass() != 0x23 {
		t.Errorf("TrafficClass = %#x, want 0x23", ip6.TrafficClass())
	}
	if ip6.FlowLabel() != 0x41234 {
		t.Errorf("FlowLabel = %#x, want 0x41234", ip6.FlowLabel())
	}
}

// TestSplitBatch verifies the RecvEx packet-boundary recovery: three
// back-to-back packets in one buffer, split by IP total lengths.
func TestSplitBatch(t *testing.T) {
	lens := []int{28, 40, 52}
	buf := make([]byte, 0, 160)
	for _, l := range lens {
		p := make([]byte, l)
		p[0] = 0x45
		binary.BigEndian.PutUint16(p[2:4], uint16(l))
		p[l-1] = byte(l) // marker
		buf = append(buf, p...)
	}
	packets := make([][]byte, 3)
	for i := range packets {
		packets[i] = make([]byte, 64) // dummy non-overlapping slots? no: split re-slices from base
	}
	// Build proper contiguous slots for the split call.
	slots := make([][]byte, 3)
	for i := range slots {
		slots[i] = buf[:cap(buf)] // full-span views; splitBatch re-slices anyway
	}
	if err := splitBatch(slots, unsafe.Pointer(&buf[0]), len(buf), 3); err != nil {
		t.Fatalf("splitBatch: %v", err)
	}
	for i, l := range lens {
		if len(slots[i]) != l {
			t.Fatalf("packet %d length = %d, want %d", i, len(slots[i]), l)
		}
		if slots[i][l-1] != byte(l) {
			t.Fatalf("packet %d content mismatch (marker byte)", i)
		}
	}

	// Bad version nibble must error.
	bad := make([]byte, 20)
	bad[0] = 0x55
	if err := splitBatch([][]byte{bad[:20]}, unsafe.Pointer(&bad[0]), 20, 1); err == nil {
		t.Error("splitBatch should reject IP version 5")
	}
	// Lengths not summing to total must error.
	bad2 := make([]byte, 40)
	bad2[0] = 0x45
	binary.BigEndian.PutUint16(bad2[2:4], 30)
	if err := splitBatch([][]byte{bad2[:40]}, unsafe.Pointer(&bad2[0]), 40, 1); err == nil {
		t.Error("splitBatch should reject length sum mismatch")
	}
}

func TestNewBatch(t *testing.T) {
	buf, packets, addrs := NewBatch(8, 1500)
	if len(buf) != 8*1500 || len(packets) != 8 || len(addrs) != 8 {
		t.Fatalf("NewBatch sizes: %d/%d/%d", len(buf), len(packets), len(addrs))
	}
	for i, p := range packets {
		if len(p) != 1500 {
			t.Fatalf("slot %d len = %d", i, len(p))
		}
		if i > 0 && &p[0] == &packets[i-1][0] {
			t.Fatal("slots overlap")
		}
	}
}
