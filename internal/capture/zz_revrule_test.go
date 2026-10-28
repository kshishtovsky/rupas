//go:build windows && live

package capture

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/kshishtovsky/rupas/pkg/windivert"
)

// TestLiveReverseInjectRule: for INBOUND injections, does delivery depend
// on the injecting handle's filter matching the packet CONTENT, or only on
// the handle registering the inbound callout? Receiver: UDP socket on the
// real IP; injector handles are narrow and drained (foreign traffic only).
func TestLiveReverseInjectRule(t *testing.T) {
	if !dllAvailable(t) {
		t.Skip("WinDivert.dll not loadable")
	}
	localIP := localIPv4(t)

	udpPort := 12798
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: localIP, Port: udpPort})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	got := make(chan string, 8)
	go func() {
		buf := make([]byte, 1024)
		for {
			n, from, err := uc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			got <- string(buf[:n]) + " from " + from.String()
		}
	}()

	// Narrow drained injectors: matchH matches the packet pre-rewrite
	// (udp src 53); calloutH registers the inbound callout but its filter
	// never matches our packet (udp src 9999).
	matchH := drainPassThrough(t, "inbound and udp.SrcPort == 53")
	calloutH := drainPassThrough(t, "inbound and udp.SrcPort == 9999")
	defer matchH.Close()
	defer calloutH.Close()

	craftUDP := func(payload string) []byte {
		udp := make([]byte, 8+len(payload))
		binary.BigEndian.PutUint16(udp[0:], 53) // src port 53
		binary.BigEndian.PutUint16(udp[2:], uint16(udpPort))
		binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
		copy(udp[8:], payload)
		ip := make([]byte, 20)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:], uint16(20+len(udp)))
		ip[8] = 128
		ip[9] = 17
		copy(ip[12:16], net.IPv4(8, 8, 4, 4).To4())
		copy(ip[16:20], localIP.To4())
		ip[10] = byte(checksum(ip) >> 8)
		ip[11] = byte(checksum(ip) & 0xff)
		pseudo := make([]byte, 12)
		copy(pseudo[0:4], net.IPv4(8, 8, 4, 4).To4())
		copy(pseudo[4:8], localIP.To4())
		pseudo[8] = 17
		binary.BigEndian.PutUint16(pseudo[10:], uint16(len(udp)))
		sum := checksum(append(append([]byte{}, pseudo...), udp...))
		udp[6] = byte(sum >> 8)
		udp[7] = byte(sum & 0xff)
		return append(ip, udp...)
	}

	inject := func(name string, h *windivert.Handle) {
		var addr windivert.Address
		addr.SetOutbound(false)
		addr.SetLoopback(false)
		if na := addr.Network(); na != nil {
			na.IfIdx = 1
		}
		if err := h.Send(craftUDP("via-"+name), &addr); err != nil {
			t.Logf("[%s] send err: %v", name, err)
		}
	}
	inject("match", matchH)
	inject("callout", calloutH)

	for i := 0; i < 2; i++ {
		select {
		case s := <-got:
			t.Logf("DELIVERED: %s", s)
		case <-time.After(2 * time.Second):
			t.Log("(timeout)")
		}
	}
}

// TestLiveRevIfIdxCombos: inbound UDP to the machine's REAL IP under all
// (loop, IfIdx) combinations, with the loopback(1) and the real-NIC index
// (measured from a genuine outbound packet).
func TestLiveRevIfidxCombos(t *testing.T) {
	if !dllAvailable(t) {
		t.Skip("WinDivert.dll not loadable")
	}
	localIP := localIPv4(t)

	// Measure the real NIC IfIdx from a genuine outbound packet.
	meas, err := windivert.OpenWithFlags("outbound and ip.SrcAddr == "+localIP.String(),
		windivert.LayerNetwork, 0, windivert.FlagSniff|windivert.FlagRecvOnly)
	if err != nil {
		t.Skipf("meas open: %v", err)
	}
	measRes := make(chan uint32, 1)
	go func() {
		buf := make([]byte, 65535)
		var addr windivert.Address
		for {
			n, err := meas.Recv(buf, &addr)
			if err != nil {
				return
			}
			if n > 0 {
				select {
				case measRes <- addr.Network().IfIdx:
				default:
				}
			}
		}
	}()
	uc0, err := net.DialTimeout("udp", "8.8.8.8:53", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	uc0.Write([]byte{0x11, 0x22, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) //nolint:errcheck
	var nicIfIdx uint32
	select {
	case nicIfIdx = <-measRes:
	case <-time.After(2 * time.Second):
		t.Skip("no outbound packet captured to measure IfIdx")
	}
	uc0.Close()
	meas.Close()
	t.Logf("real NIC IfIdx=%d loopback IfIdx=1", nicIfIdx)

	udpPort := 12797
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: localIP, Port: udpPort})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	got := make(chan string, 8)
	go func() {
		buf := make([]byte, 1024)
		for {
			n, from, err := uc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			got <- string(buf[:n]) + " from " + from.String()
		}
	}()

	trueH := drainPassThrough(t, "inbound and udp.DstPort == " + itoa(uint32(udpPort)))
	defer trueH.Close()

	craft := func(payload string) []byte {
		udp := make([]byte, 8+len(payload))
		binary.BigEndian.PutUint16(udp[0:], 53)
		binary.BigEndian.PutUint16(udp[2:], uint16(udpPort))
		binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
		copy(udp[8:], payload)
		ip := make([]byte, 20)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:], uint16(20+len(udp)))
		ip[8] = 128
		ip[9] = 17
		copy(ip[12:16], net.IPv4(8, 8, 4, 4).To4())
		copy(ip[16:20], localIP.To4())
		ip[10] = byte(checksum(ip) >> 8)
		ip[11] = byte(checksum(ip) & 0xff)
		pseudo := make([]byte, 12)
		copy(pseudo[0:4], net.IPv4(8, 8, 4, 4).To4())
		copy(pseudo[4:8], localIP.To4())
		pseudo[8] = 17
		binary.BigEndian.PutUint16(pseudo[10:], uint16(len(udp)))
		sum := checksum(append(append([]byte{}, pseudo...), udp...))
		udp[6] = byte(sum >> 8)
		udp[7] = byte(sum & 0xff)
		return append(ip, udp...)
	}

	try := func(name string, loop bool, ifidx uint32) {
		var addr windivert.Address
		addr.SetOutbound(false)
		addr.SetLoopback(loop)
		if na := addr.Network(); na != nil {
			na.IfIdx = ifidx
		}
		if err := trueH.Send(craft("L"+name), &addr); err != nil {
			t.Logf("[%s] send err: %v", name, err)
		}
		select {
		case s := <-got:
			t.Logf("DELIVERED [%s]: %s", name, s)
		case <-time.After(1500 * time.Millisecond):
			t.Logf("[%s] no delivery", name)
		}
	}
	try("loop1", true, 1)
	try("noloop1", false, 1)
	try("loopNIC", true, nicIfIdx)
	try("noloopNIC", false, nicIfIdx)
}

func itoa(v uint32) string {
	if v == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// TestLiveLoopbackSocketDelivery: the decisive test — does an INBOUND
// injection toward 127.0.0.1 reach a BOUND SOCKET, and under which
// (src, IfIdx, loop) combination?
func TestLiveLoopbackSocketDelivery(t *testing.T) {
	if !dllAvailable(t) {
		t.Skip("WinDivert.dll not loadable")
	}
	localIP := localIPv4(t)
	nicIfIdx := measureNICIfIdx(t)

	udpPort := 12796
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: udpPort})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	got := make(chan string, 16)
	go func() {
		buf := make([]byte, 1024)
		for {
			n, from, err := uc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			got <- string(buf[:n]) + " from " + from.String()
		}
	}()

	trueH := drainPassThrough(t, "inbound and udp.DstPort == " + itoa(uint32(udpPort)))
	defer trueH.Close()

	craft := func(src net.IP, payload string) []byte {
		udp := make([]byte, 8+len(payload))
		binary.BigEndian.PutUint16(udp[0:], 40000)
		binary.BigEndian.PutUint16(udp[2:], uint16(udpPort))
		binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
		copy(udp[8:], payload)
		ip := make([]byte, 20)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:], uint16(20+len(udp)))
		ip[8] = 128
		ip[9] = 17
		copy(ip[12:16], src.To4())
		copy(ip[16:20], net.IPv4(127, 0, 0, 1).To4())
		ip[10] = byte(checksum(ip) >> 8)
		ip[11] = byte(checksum(ip) & 0xff)
		pseudo := make([]byte, 12)
		copy(pseudo[0:4], src.To4())
		copy(pseudo[4:8], net.IPv4(127, 0, 0, 1).To4())
		pseudo[8] = 17
		binary.BigEndian.PutUint16(pseudo[10:], uint16(len(udp)))
		sum := checksum(append(append([]byte{}, pseudo...), udp...))
		udp[6] = byte(sum >> 8)
		udp[7] = byte(sum & 0xff)
		return append(ip, udp...)
	}

	try := func(name string, src net.IP, loop bool, ifidx uint32) {
		var addr windivert.Address
		addr.SetOutbound(false)
		addr.SetLoopback(loop)
		if na := addr.Network(); na != nil {
			na.IfIdx = ifidx
		}
		if err := trueH.Send(craft(src, "c:"+name), &addr); err != nil {
			t.Logf("[%s] send err: %v", name, err)
		}
		select {
		case s := <-got:
			t.Logf("DELIVERED [%s]: %s", name, s)
		case <-time.After(1200 * time.Millisecond):
			t.Logf("[%s] no delivery", name)
		}
	}
	try("srcLocal-loop-if1", localIP, true, 1)
	try("srcLocal-noloop-if1", localIP, false, 1)
	try("src127-loop-if1", net.IPv4(127, 0, 0, 1), true, 1)
	try("srcLocal-loop-ifNIC", localIP, true, nicIfIdx)
	try("srcLocal-noloop-ifNIC", localIP, false, nicIfIdx)
}

func measureNICIfIdx(t *testing.T) uint32 {
	t.Helper()
	localIP := localIPv4(t)
	meas, err := windivert.OpenWithFlags("outbound and ip.SrcAddr == "+localIP.String(),
		windivert.LayerNetwork, 0, windivert.FlagSniff|windivert.FlagRecvOnly)
	if err != nil {
		t.Skipf("meas open: %v", err)
	}
	measRes := make(chan uint32, 1)
	go func() {
		buf := make([]byte, 65535)
		var addr windivert.Address
		for {
			n, err := meas.Recv(buf, &addr)
			if err != nil {
				return
			}
			if n > 0 {
				select {
				case measRes <- addr.Network().IfIdx:
				default:
				}
			}
		}
	}()
	uc0, err := net.DialTimeout("udp", "8.8.8.8:53", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	uc0.Write([]byte{0x11, 0x22, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) //nolint:errcheck
	var nicIfIdx uint32
	select {
	case nicIfIdx = <-measRes:
	case <-time.After(2 * time.Second):
		t.Skip("no outbound packet captured")
	}
	uc0.Close()
	meas.Close()
	return nicIfIdx
}

// TestLiveSrcVariants: which SOURCE addresses survive inbound delivery to
// the machine's real IP (IfIdx=NIC)? Own-IP sources may be martian-dropped.
func TestLiveSrcVariants(t *testing.T) {
	if !dllAvailable(t) {
		t.Skip("WinDivert.dll not loadable")
	}
	localIP := localIPv4(t)
	nicIfIdx := measureNICIfIdx(t)

	udpPort := 12795
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: udpPort})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	got := make(chan string, 16)
	go func() {
		buf := make([]byte, 1024)
		for {
			n, from, err := uc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			got <- string(buf[:n]) + " from " + from.String()
		}
	}()
	trueH := drainPassThrough(t, "inbound and udp.DstPort == "+itoa(uint32(udpPort)))
	defer trueH.Close()

	craft := func(src net.IP, payload string) []byte {
		udp := make([]byte, 8+len(payload))
		binary.BigEndian.PutUint16(udp[0:], 40001)
		binary.BigEndian.PutUint16(udp[2:], uint16(udpPort))
		binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
		copy(udp[8:], payload)
		ip := make([]byte, 20)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:], uint16(20+len(udp)))
		ip[8] = 128
		ip[9] = 17
		copy(ip[12:16], src.To4())
		copy(ip[16:20], localIP.To4())
		ip[10] = byte(checksum(ip) >> 8)
		ip[11] = byte(checksum(ip) & 0xff)
		pseudo := make([]byte, 12)
		copy(pseudo[0:4], src.To4())
		copy(pseudo[4:8], localIP.To4())
		pseudo[8] = 17
		binary.BigEndian.PutUint16(pseudo[10:], uint16(len(udp)))
		sum := checksum(append(append([]byte{}, pseudo...), udp...))
		udp[6] = byte(sum >> 8)
		udp[7] = byte(sum & 0xff)
		return append(ip, udp...)
	}
	try := func(name string, src net.IP) {
		var addr windivert.Address
		addr.SetOutbound(false)
		addr.SetLoopback(false)
		if na := addr.Network(); na != nil {
			na.IfIdx = nicIfIdx
		}
		if err := trueH.Send(craft(src, "s:"+name), &addr); err != nil {
			t.Logf("[%s] send err: %v", name, err)
		}
		select {
		case s := <-got:
			t.Logf("DELIVERED [%s]: %s", name, s)
		case <-time.After(1200 * time.Millisecond):
			t.Logf("[%s] no delivery", name)
		}
	}
	try("ownIP", localIP)
	try("loop127", net.IPv4(127, 0, 0, 1))
	try("fake198", net.IPv4(198, 18, 0, 1))
	try("ext888", net.IPv4(8, 8, 4, 4))
}
