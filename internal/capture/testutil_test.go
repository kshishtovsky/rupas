//go:build windows

package capture

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"

	"github.com/kshishtovsky/rupas/pkg/windivert"
)

// ---------------------------------------------------------------------------
// Synthetic packet builders (IPv4 + TCP/UDP), hand-rolled per test needs.
// ---------------------------------------------------------------------------

const (
	identDefault = 0x1234
)

// buildTCP builds an IPv4+TCP packet. Input checksums are left zero: the
// engine never validates them (the driver already did) and rewrites go
// through Transport.FixChecksums.
func buildTCP(src string, sport uint16, dst string, dport uint16, seq, ack uint32, flags byte, payload []byte) []byte {
	ip := [4]byte{10, 0, 0, 1}
	dst4 := [4]byte{10, 0, 0, 2}
	ip = parseIP4(src, ip)
	dst4 = parseIP4(dst, dst4)

	total := 20 + 20 + len(payload)
	pkt := make([]byte, total)
	// IPv4
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	binary.BigEndian.PutUint16(pkt[4:6], identDefault)
	pkt[6], pkt[7] = 0x40, 0x00 // DF
	pkt[8] = ipTTLDefault
	pkt[9] = protoTCP
	copy(pkt[12:16], ip[:])
	copy(pkt[16:20], dst4[:])
	// TCP
	th := pkt[20:]
	binary.BigEndian.PutUint16(th[0:2], sport)
	binary.BigEndian.PutUint16(th[2:4], dport)
	binary.BigEndian.PutUint32(th[4:8], seq)
	binary.BigEndian.PutUint32(th[8:12], ack)
	th[12] = 0x50 // data offset 5 words
	th[13] = flags
	binary.BigEndian.PutUint16(th[14:16], 0xFFFF) // window
	copy(th[20:], payload)
	return pkt
}

// buildUDP builds an IPv4+UDP packet.
func buildUDP(src string, sport uint16, dst string, dport uint16, payload []byte) []byte {
	src4 := parseIP4(src, [4]byte{10, 0, 0, 1})
	dst4 := parseIP4(dst, [4]byte{10, 0, 0, 2})
	total := 20 + 8 + len(payload)
	pkt := make([]byte, total)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	binary.BigEndian.PutUint16(pkt[4:6], identDefault)
	pkt[8] = ipTTLDefault
	pkt[9] = protoUDP
	copy(pkt[12:16], src4[:])
	copy(pkt[16:20], dst4[:])
	uh := pkt[20:]
	binary.BigEndian.PutUint16(uh[0:2], sport)
	binary.BigEndian.PutUint16(uh[2:4], dport)
	binary.BigEndian.PutUint16(uh[4:6], uint16(8+len(payload)))
	copy(uh[8:], payload)
	return pkt
}

func parseIP4(s string, def [4]byte) [4]byte {
	if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
		return a.As4()
	}
	return def
}

// ---------------------------------------------------------------------------
// Synthetic TLS ClientHello (must satisfy internal/inspector's parser).
// ---------------------------------------------------------------------------

// buildClientHello serializes a minimal TLS 1.3-style ClientHello record
// with a server_name extension and an optional ECH (0xfe0d) extension.
func buildClientHello(sni string, withECH bool) []byte {
	var exts []byte
	if sni != "" {
		entry := []byte{0x00, byte(len(sni) >> 8), byte(len(sni))}
		entry = append(entry, sni...)
		exts = append(exts, 0x00, 0x00, byte((len(entry)+2)>>8), byte(len(entry)+2))
		exts = append(exts, byte(len(entry)>>8), byte(len(entry))) // server_name_list length
		exts = append(exts, entry...)
	}
	if withECH {
		ech := []byte{0xDE, 0xAD, 0xBE, 0xEF}
		exts = append(exts, 0xfe, 0x0d, byte(len(ech)>>8), byte(len(ech)))
		exts = append(exts, ech...)
	}

	var body []byte
	body = append(body, 0x03, 0x03)          // legacy_version
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session_id length
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher_suites
	body = append(body, 0x01, 0x00)          // compression methods
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)

	out := make([]byte, 0, 5+4+len(body))
	out = append(out, 0x16, 0x03, 0x01, byte((4+len(body))>>8), byte(4+len(body)))
	out = append(out, 0x01, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	out = append(out, body...)
	return out
}

// ---------------------------------------------------------------------------
// Pure-Go checksum recomputation (mirrors WinDivertHelperCalcChecksums for
// the fake transport; also used to verify crafted packets in asserts).
// ---------------------------------------------------------------------------

func fold16(s uint32) uint16 {
	for s>>16 != 0 {
		s = s&0xFFFF + s>>16
	}
	return uint16(s)
}

func sum16(b []byte) uint32 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	return s
}

// fixChecksumsGo recomputes the IPv4 header and TCP/UDP checksums in place.
func fixChecksumsGo(pkt []byte, addr *windivert.Address) error {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return errors.New("not an IPv4 packet")
	}
	ipLen := int(pkt[0]&0xF) * 4
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if total > len(pkt) {
		return errors.New("total length exceeds buffer")
	}
	pkt[10], pkt[11] = 0, 0
	binary.BigEndian.PutUint16(pkt[10:12], ^fold16(sum16(pkt[:ipLen])))

	segLen := total - ipLen
	pseudo := uint32(0)
	pseudo += sum16(pkt[12:20]) // src + dst
	switch pkt[9] {
	case protoTCP:
		th := pkt[ipLen : ipLen+segLen]
		th[16], th[17] = 0, 0
		s := pseudo + uint32(protoTCP) + uint32(segLen) + sum16(th)
		binary.BigEndian.PutUint16(th[16:18], ^fold16(s))
	case protoUDP:
		uh := pkt[ipLen : ipLen+segLen]
		uh[6], uh[7] = 0, 0
		s := pseudo + uint32(protoUDP) + uint32(segLen) + sum16(uh)
		c := ^fold16(s)
		if c == 0 {
			c = 0xFFFF
		}
		binary.BigEndian.PutUint16(uh[6:8], c)
	}
	if addr != nil {
		addr.SetIPChecksum(true)
		addr.SetTCPChecksum(true)
		addr.SetUDPChecksum(true)
	}
	return nil
}

// checksumsValid re-computes the checksums of a copy and compares.
func checksumsValid(pkt []byte) bool {
	c := append([]byte(nil), pkt...)
	before := [4]byte{c[10], c[11], 0, 0}
	if c[9] == protoTCP {
		copy(before[2:], c[int(c[0]&0xF)*4+16:int(c[0]&0xF)*4+18])
	}
	if err := fixChecksumsGo(c, nil); err != nil {
		return false
	}
	if c[10] != before[0] || c[11] != before[1] {
		return false
	}
	if c[9] == protoTCP {
		ipLen := int(c[0]&0xF) * 4
		return c[ipLen+16] == before[2] && c[ipLen+17] == before[3]
	}
	return true
}

// ---------------------------------------------------------------------------
// FakeTransport: replays queued packets, records everything sent.
// ---------------------------------------------------------------------------

// SentPkt is one recorded Send.
type SentPkt struct {
	Data []byte
	Addr windivert.Address
}

// FakeTransport implements Transport without any driver.
type FakeTransport struct {
	mu       sync.Mutex
	sent     []SentPkt
	queue    [][]byte
	outbound []bool
	stopped  chan struct{}
	stopOnce sync.Once
}

func NewFakeTransport() *FakeTransport {
	return &FakeTransport{stopped: make(chan struct{})}
}

// Enqueue queues a packet for the next RecvBatch.
func (f *FakeTransport) Enqueue(pkt []byte, outbound bool) {
	f.mu.Lock()
	f.queue = append(f.queue, pkt)
	f.outbound = append(f.outbound, outbound)
	f.mu.Unlock()
}

func (f *FakeTransport) RecvBatch(packets [][]byte, addrs []windivert.Address) (int, error) {
	f.mu.Lock()
	n := len(f.queue)
	if n > len(packets) {
		n = len(packets)
	}
	for i := 0; i < n; i++ {
		copy(packets[i], f.queue[i])
		addrs[i] = windivert.Address{}
		addrs[i].SetOutbound(f.outbound[i])
	}
	f.queue = f.queue[n:]
	f.outbound = f.outbound[n:]
	f.mu.Unlock()
	if n > 0 {
		return n, nil
	}
	<-f.stopped
	return 0, ErrStopped
}

func (f *FakeTransport) Send(pkt []byte, addr *windivert.Address) error {
	f.mu.Lock()
	f.sent = append(f.sent, SentPkt{Data: append([]byte(nil), pkt...), Addr: *addr})
	f.mu.Unlock()
	return nil
}

func (f *FakeTransport) FixChecksums(pkt []byte, addr *windivert.Address) error {
	return fixChecksumsGo(pkt, addr)
}

func (f *FakeTransport) Shutdown() error {
	f.stopOnce.Do(func() { close(f.stopped) })
	return nil
}

func (f *FakeTransport) Close() error { return f.Shutdown() }

// Sent returns a copy of the recorded sends.
func (f *FakeTransport) Sent() []SentPkt {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]SentPkt(nil), f.sent...)
}

// noopTransport is allocation-free on Send — for AllocsPerRun.
type noopTransport struct{}

func (noopTransport) RecvBatch([][]byte, []windivert.Address) (int, error) { return 0, ErrStopped }
func (noopTransport) Send([]byte, *windivert.Address) error               { return nil }
func (noopTransport) FixChecksums([]byte, *windivert.Address) error        { return nil }
func (noopTransport) Shutdown() error                                      { return nil }
func (noopTransport) Close() error                                         { return nil }
