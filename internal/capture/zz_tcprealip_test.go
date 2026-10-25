//go:build windows && live

package capture

import (
	"net"
	"testing"
	"time"

	"github.com/rupas/rupas/pkg/windivert"
)

// TestLiveTCPRealIPForward: THE wave-5 forward leg in isolation. The engine
// NAT-rewrites the client SYN to  src=198.18.0.1:eph  dst=<realNIC>:tproxy,
// re-injects it INBOUND with the client-NIC IfIdx through the loopback
// handle (filter: inbound and tcp.DstPort == tproxy). Does a wildcard TCP
// listener on that port actually ACCEPT?
func TestLiveTCPRealIPForward(t *testing.T) {
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
	t.Logf("real NIC IfIdx=%d localIP=%s", nicIfIdx, localIP)

	const tproxy = uint16(12713)
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{Port: int(tproxy)}) // wildcard, like the tunnel
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

	// Loopback-handle stand-in: filter matches the injected packet content
	// (both directions, so outbound-shaped tries relay too).
	loopH := drainPassThrough(t, "tcp.DstPort == "+itoa(uint32(tproxy)))
	defer loopH.Close()

	try := func(name string, out, loop bool, ifidx uint32, dst net.IP, src net.IP) {
		pkt := craftIPv4TCP(src, dst, 34567, tproxy, 0x02, 1000)
		var addr windivert.Address
		addr.SetOutbound(out)
		addr.SetLoopback(loop)
		if na := addr.Network(); na != nil {
			na.IfIdx = ifidx
		}
		if err := loopH.Send(pkt, &addr); err != nil {
			t.Logf("[%s] send err: %v", name, err)
		}
		select {
		case s := <-accepts:
			t.Logf("DELIVERED [%s]: %s", name, s)
		case <-time.After(1500 * time.Millisecond):
			t.Logf("[%s] no accept", name)
		}
	}
	fake := net.IPv4(198, 18, 0, 1)
	try("in-noloop-NIC-realIP", false, false, nicIfIdx, localIP, fake)
	try("in-loop-NIC-realIP", false, true, nicIfIdx, localIP, fake)
	try("in-noloop-NIC-lo", false, false, nicIfIdx, net.IPv4(127, 0, 0, 1), fake)
	// Wave-4B shape: OUTBOUND + Loopback flag + IfIdx=1, dst 127.0.0.1 —
	// how a genuine local client's SYN looks on the loopback path.
	try("out-loop-1-lo", true, true, 1, net.IPv4(127, 0, 0, 1), net.IPv4(127, 0, 0, 2))
	try("out-loop-1-lo-realsrc", true, true, 1, net.IPv4(127, 0, 0, 1), localIP)
	try("out-noloop-1-lo", true, false, 1, net.IPv4(127, 0, 0, 1), net.IPv4(127, 0, 0, 2))
	try("out-loop-NIC-lo", true, true, nicIfIdx, net.IPv4(127, 0, 0, 1), net.IPv4(127, 0, 0, 2))
	try("out-loop-1-realIP", true, true, 1, localIP, fake)
}
