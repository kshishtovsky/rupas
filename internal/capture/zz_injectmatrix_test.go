//go:build windows && live

package capture

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/kshishtovsky/rupas/pkg/windivert"
)

// craftIPv4TCP builds a TCP/IPv4 packet with proper checksums.
func craftIPv4TCP(src, dst net.IP, sport, dport uint16, flags byte, seq uint32) []byte {
	ipLen, tcpLen := 20, 20
	pkt := make([]byte, ipLen+tcpLen)
	pkt[0] = 0x45
	pkt[2], pkt[3] = byte(len(pkt)>>8), byte(len(pkt))
	pkt[4], pkt[5] = 0x1234>>8, 0x1234&0xff
	pkt[6] = 0x4000 >> 8 // DF
	pkt[8] = 128         // TTL
	pkt[9] = 6           // TCP
	copy(pkt[12:16], src.To4())
	copy(pkt[16:20], dst.To4())
	// IP checksum
	pkt[10], pkt[11] = 0, 0
	pkt[10] = byte(checksum(pkt[:20]) >> 8)
	pkt[11] = byte(checksum(pkt[:20]) & 0xff)

	tcp := pkt[ipLen:]
	binary.BigEndian.PutUint16(tcp[0:], sport)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	binary.BigEndian.PutUint32(tcp[4:], seq)
	tcp[12] = 128 // window size (offset/reserved nibble stays 0)
	tcp[13] = flags
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], src.To4())
	copy(pseudo[4:8], dst.To4())
	pseudo[8] = 6
	binary.BigEndian.PutUint16(pseudo[10:], uint16(tcpLen))
	sum := checksum(append(append([]byte{}, pseudo...), tcp...))
	tcp[16] = byte(sum >> 8)
	tcp[17] = byte(sum & 0xff)
	return pkt
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// TestLiveInjectLoopbackMatrix injects hand-crafted SYNs toward a real
// loopback listener under different Address flag combos and reports which
// ones the stack delivers.
func TestLiveInjectLoopbackMatrix(t *testing.T) {
	if !dllAvailable(t) {
		t.Skip("WinDivert.dll not loadable")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:12713")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	synSeen := make(chan string, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			synSeen <- "ACCEPT " + c.RemoteAddr().String()
			c.Close()
		}
	}()

	// Sniffer: any packet touching port 12713.
	type rec struct {
		desc  string
		count int
	}
	var mu sync.Mutex
	seen := map[string]*rec{}
	sniff, err := windivert.OpenWithFlags("tcp.DstPort == 12713",
		windivert.LayerNetwork, 0, windivert.FlagSniff|windivert.FlagRecvOnly)
	if err != nil {
		t.Skipf("sniffer open: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		var addr windivert.Address
		for {
			n, err := sniff.Recv(buf, &addr)
			if err != nil {
				return
			}
			p := buf[:n]
			if len(p) < 40 {
				continue
			}
			key := "src=" + net.IP(p[12:16]).String() + ":" + strconv.Itoa(int(binary.BigEndian.Uint16(p[20:22]))) +
				" flags=0x" + fmt.Sprintf("%02x", p[33]) + " Out=" + fmt.Sprint(addr.Outbound()) +
				" Loop=" + fmt.Sprint(addr.Loopback()) + " IfIdx=" + fmt.Sprint(addr.Network().IfIdx)
			mu.Lock()
			if r, ok := seen[key]; ok {
				r.count++
			} else {
				seen[key] = &rec{key, 1}
			}
			mu.Unlock()
		}
	}()

	localIP := localIPv4(t)
	variants := []struct {
		name     string
		src      net.IP
		outbound bool
		loop     bool
		ifidx    uint32
	}{
		{"src=127 Out Loop If1", net.IPv4(127, 0, 0, 1), true, true, 1},
		{"src=127 In  Loop If1", net.IPv4(127, 0, 0, 1), false, true, 1},
		{"src=loc Out Loop If1", localIP, true, true, 1},
		{"src=loc In  Loop If1", localIP, false, true, 1},
		{"src=loc Out noloop", localIP, true, false, 0},
	}
	send, err := windivert.OpenWithFlags("true", windivert.LayerNetwork, 0, 0)
	if err != nil {
		t.Skipf("send open: %v", err)
	}
	defer send.Close()
	for i, v := range variants {
		pkt := craftIPv4TCP(v.src, net.IPv4(127, 0, 0, 1), uint16(30000+i), 12713, 0x02, 1000+uint32(i))
		var addr windivert.Address
		addr.SetOutbound(v.outbound)
		addr.SetLoopback(v.loop)
		if na := addr.Network(); na != nil {
			na.IfIdx = v.ifidx
		}
		if err := send.Send(pkt, &addr); err != nil {
			t.Logf("[%s] send error: %v", v.name, err)
		}
		time.Sleep(300 * time.Millisecond)
	}
	time.Sleep(700 * time.Millisecond)
	_ = sniff.Close()
	<-done
	mu.Lock()
	t.Log("=== sniffed SYNs to 127.0.0.1:12713 ===")
	if len(seen) == 0 {
		t.Log("(none)")
	}
	for _, r := range seen {
		t.Logf("x%d %s", r.count, r.desc)
	}
	mu.Unlock()
	for {
		select {
		case s := <-synSeen:
			t.Logf("LISTENER: %s", s)
		default:
			return
		}
	}
}

func localIPv4(t *testing.T) net.IP {
	t.Helper()
	c, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP
}

// TestLiveInjectHandleMatrix isolates why the ENGINE's re-injection is
// invisible while the crafted-packet matrix worked: same packet, injected
// via a filter-matched outbound handle vs a "true" handle, inbound with
// and without the Loopback flag.
func TestLiveInjectHandleMatrix(t *testing.T) {
	if !dllAvailable(t) {
		t.Skip("WinDivert.dll not loadable")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:12713")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Logf("LISTENER ACCEPT from %s", c.RemoteAddr())
			c.Close()
		}
	}()
	type rec struct {
		desc  string
		count int
	}
	var mu sync.Mutex
	seen := map[string]*rec{}
	sniff, err := windivert.OpenWithFlags("tcp.DstPort == 12713",
		windivert.LayerNetwork, 0, windivert.FlagSniff|windivert.FlagRecvOnly)
	if err != nil {
		t.Skipf("sniffer open: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		var addr windivert.Address
		for {
			n, err := sniff.Recv(buf, &addr)
			if err != nil {
				return
			}
			p := buf[:n]
			if len(p) < 40 {
				continue
			}
			key := "sport=" + strconv.Itoa(int(binary.BigEndian.Uint16(p[20:22]))) +
				" Out=" + fmt.Sprint(addr.Outbound()) + " Loop=" + fmt.Sprint(addr.Loopback()) +
				" IfIdx=" + fmt.Sprint(addr.Network().IfIdx)
			mu.Lock()
			if r, ok := seen[key]; ok {
				r.count++
			} else {
				seen[key] = &rec{key, 1}
			}
			mu.Unlock()
		}
	}()

	localIP := localIPv4(t)
	trueH, err := windivert.OpenWithFlags("true", windivert.LayerNetwork, 0, 0)
	if err != nil {
		t.Skipf("true handle: %v", err)
	}
	defer trueH.Close()
	outH, err := windivert.OpenWithFlags("outbound and tcp and (tcp.DstPort == 443 or ip.DstAddr >= 149.154.160.0 and ip.DstAddr <= 149.154.175.255)",
		windivert.LayerNetwork, 0, 0)
	if err != nil {
		t.Skipf("outbound handle: %v", err)
	}
	defer outH.Close()

	port := uint16(31000)
	try := func(name string, h *windivert.Handle, loop bool) {
		pkt := craftIPv4TCP(localIP, net.IPv4(127, 0, 0, 1), port, 12713, 0x02, 777)
		port++
		var addr windivert.Address
		addr.SetOutbound(false)
		addr.SetLoopback(loop)
		if na := addr.Network(); na != nil {
			na.IfIdx = 1
		}
		if err := h.Send(pkt, &addr); err != nil {
			t.Logf("[%s] send err: %v", name, err)
		}
		time.Sleep(250 * time.Millisecond)
	}
	try("trueH loop", trueH, true)
	try("trueH noloop", trueH, false)
	try("outH loop", outH, true)
	try("outH noloop", outH, false)

	time.Sleep(500 * time.Millisecond)
	_ = sniff.Close()
	<-done
	mu.Lock()
	t.Log("=== sniffed ===")
	if len(seen) == 0 {
		t.Log("(none)")
	}
	for _, r := range seen {
		t.Logf("x%d %s", r.count, r.desc)
	}
	mu.Unlock()
}

// TestLiveInjectMatrix3 answers the remaining injection questions:
//   Q1: inbound injection via an "inbound"-filtered handle (filter MATCHES
//       the packet) — delivered?
//   Q2: reverse direction — inbound UDP to the machine's REAL IP via a
//       true/inbound/outbound handle — received by a bound socket?
func TestLiveInjectMatrix3(t *testing.T) {
	if !dllAvailable(t) {
		t.Skip("WinDivert.dll not loadable")
	}
	localIP := localIPv4(t)

	// Q2 receiver: UDP socket on the real IP.
	udpPort := 12799
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: localIP, Port: udpPort})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	gotUDP := make(chan string, 8)
	go func() {
		buf := make([]byte, 1024)
		for {
			n, from, err := uc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			gotUDP <- "UDP RECV " + string(buf[:n]) + " from " + from.String()
		}
	}()

	trueH, err := windivert.OpenWithFlags("true", windivert.LayerNetwork, 0, 0)
	if err != nil {
		t.Skipf("true handle: %v", err)
	}
	defer trueH.Close()
	inH, err := windivert.OpenWithFlags("inbound", windivert.LayerNetwork, 0, 0)
	if err != nil {
		t.Skipf("inbound handle: %v", err)
	}
	defer inH.Close()
	outH, err := windivert.OpenWithFlags("outbound", windivert.LayerNetwork, 0, 0)
	if err != nil {
		t.Skipf("outbound handle: %v", err)
	}
	defer outH.Close()

	// Q2: craft an inbound UDP packet src=8.8.4.4:53 dst=localIP:12799.
	craftUDP := func(payload string) []byte {
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

	tryUDP := func(name string, h *windivert.Handle) {
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
	tryUDP("true", trueH)
	tryUDP("inbound", inH)
	tryUDP("outbound", outH)
	time.Sleep(800 * time.Millisecond)
	for {
		select {
		case s := <-gotUDP:
			t.Logf("Q2 %s", s)
			continue
		default:
		}
		break
	}

	// Q1: inbound TCP SYN to 127.0.0.1:12713 via the inbound-filtered
	// handle; sniff to observe.
	ln, err := net.Listen("tcp", "127.0.0.1:12713")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepts := make(chan string, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepts <- "ACCEPT " + c.RemoteAddr().String()
			c.Close()
		}
	}()
	sniff, err := windivert.OpenWithFlags("tcp.DstPort == 12713",
		windivert.LayerNetwork, 0, windivert.FlagSniff|windivert.FlagRecvOnly)
	if err != nil {
		t.Skipf("sniffer: %v", err)
	}
	sniffs := make(chan string, 8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		var addr windivert.Address
		for {
			n, err := sniff.Recv(buf, &addr)
			if err != nil {
				return
			}
			p := buf[:n]
			if len(p) < 40 {
				continue
			}
			sniffs <- "SNIF sport=" + strconv.Itoa(int(binary.BigEndian.Uint16(p[20:22]))) +
				" Out=" + fmt.Sprint(addr.Outbound()) + " Loop=" + fmt.Sprint(addr.Loopback())
		}
	}()
	tryTCP := func(name string, h *windivert.Handle, sport uint16) {
		pkt := craftIPv4TCP(localIP, net.IPv4(127, 0, 0, 1), sport, 12713, 0x02, 999)
		var addr windivert.Address
		addr.SetOutbound(false)
		addr.SetLoopback(false)
		if na := addr.Network(); na != nil {
			na.IfIdx = 1
		}
		if err := h.Send(pkt, &addr); err != nil {
			t.Logf("[%s] send err: %v", name, err)
		}
	}
	tryTCP("true", trueH, 32001)
	tryTCP("inbound", inH, 32002)
	time.Sleep(600 * time.Millisecond)
	_ = sniff.Close()
	<-done
	for {
		select {
		case s := <-sniffs:
			t.Logf("Q1 %s", s)
			continue
		default:
		}
		break
	}
	for {
		select {
		case s := <-accepts:
			t.Logf("Q1 %s", s)
			continue
		default:
		}
		break
	}
}
