//go:build windows && live

package capture

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/rupas/rupas/pkg/windivert"
)

// TestLiveGenuineSYNRelay: does a GENUINE local client SYN (captured from a
// real socket, byte-identical apart from the NAT rewrite) deliver to the
// tproxy listener — unlike the hand-crafted SYNs of TestLiveTCPRealIPForward?
// Legs:
//   A) wave-4B shape: dst rewritten to 127.0.0.1:12713, re-injected with the
//      address AS CAPTURED (outbound, Loopback, IfIdx=1).
//   B) wave-5 shape: dst rewritten to <realIP>:12713, src to 198.18.0.1,
//      re-injected inbound with NIC IfIdx.
func TestLiveGenuineSYNRelay(t *testing.T) {
	if !dllAvailable(t) {
		t.Skip("WinDivert.dll not loadable")
	}
	localIP := localIPv4(t)
	const tproxy = uint16(12713)

	ln, err := net.ListenTCP("tcp", &net.TCPAddr{Port: int(tproxy)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepts := make(chan string, 8)
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

	// High-priority blocker: captures the genuine outbound loopback SYN and
	// holds it (no relay), so we own its delivery.
	blockH, err := windivert.OpenWithFlags("outbound and tcp.DstPort == "+itoa(uint32(tproxy)),
		windivert.LayerNetwork, 30000, 0)
	if err != nil {
		t.Skipf("blocker open: %v", err)
	}
	defer blockH.Close()

	captured := make(chan struct {
		pkt  []byte
		addr windivert.Address
	}, 4)
	go func() {
		buf := make([]byte, 65535)
		var addr windivert.Address
		for {
			n, err := blockH.Recv(buf, &addr)
			if err != nil {
				return
			}
			if n > 0 {
				pkt := make([]byte, n)
				copy(pkt, buf[:n])
				select {
				case captured <- struct {
					pkt  []byte
					addr windivert.Address
				}{pkt, addr}:
				default:
				}
			}
		}
	}()

	leg := func(name string, rewrite func(pkt []byte, addr *windivert.Address)) {
		// Fresh client port per leg.
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+itoa(uint32(tproxy)), 3*time.Second)
		if err == nil {
			// The genuine SYN was NOT intercepted (blocker missed it): the
			// dial would have connected straight to the listener.
			remote := c.RemoteAddr().String()
			c.Close()
			t.Fatalf("[%s] blocker did not intercept the SYN (direct connect %s)", name, remote)
		}
		select {
		case g := <-captured:
			pkt := append([]byte(nil), g.pkt...)
			addr := g.addr
			rewrite(pkt, &addr)
			if err := blockH.Send(pkt, &addr); err != nil {
				t.Logf("[%s] send err: %v", name, err)
			}
			select {
			case s := <-accepts:
				t.Logf("DELIVERED [%s]: %s", name, s)
			case <-time.After(2000 * time.Millisecond):
				t.Logf("[%s] no accept", name)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("[%s] genuine SYN not captured", name)
		}
	}

	fixSum := func(pkt []byte) {
		pkt[10], pkt[11] = 0, 0
		s := checksum(pkt[:20])
		pkt[10], pkt[11] = byte(s>>8), byte(s&0xff)
		ipLen := int(pkt[0]&0x0f) * 4
		pseudo := make([]byte, 12)
		copy(pseudo[0:4], pkt[12:16])
		copy(pseudo[4:8], pkt[16:20])
		pseudo[8] = 6
		binary.BigEndian.PutUint16(pseudo[10:], uint16(len(pkt)-ipLen))
		tcpSum := append(append([]byte{}, pseudo...), pkt[ipLen:]...)
		tcpSum[12+16], tcpSum[12+17] = 0, 0
		sum := checksum(tcpSum)
		pkt[ipLen+16], pkt[ipLen+17] = byte(sum>>8), byte(sum&0xff)
	}

	// Leg A0: byte-identical replay, untouched address — control.
	leg("A0-untouched", func(pkt []byte, addr *windivert.Address) {})

	// Leg A (wave-4B): dst → 127.0.0.1:12713; address as captured.
	leg("A-out-loopback", func(pkt []byte, addr *windivert.Address) {
		copy(pkt[16:20], []byte{127, 0, 0, 1})
		binary.BigEndian.PutUint16(pkt[20+2:], tproxy)
		fixSum(pkt)
	})

	// Leg B (wave-5): src → 198.18.0.1, dst → realIP:12713, inbound + NIC IfIdx.
	leg("B-in-NIC", func(pkt []byte, addr *windivert.Address) {
		copy(pkt[12:16], []byte{198, 18, 0, 1})
		copy(pkt[16:20], localIP.To4())
		binary.BigEndian.PutUint16(pkt[20+2:], tproxy)
		fixSum(pkt)
		addr.SetOutbound(false)
		addr.SetLoopback(false)
		if na := addr.Network(); na != nil {
			na.IfIdx, na.SubIfIdx = nicIfIdxOf(t), 0
		}
	})
}

func nicIfIdxOf(t *testing.T) uint32 {
	t.Helper()
	localIP := localIPv4(t)
	meas, err := windivert.OpenWithFlags("outbound and ip.SrcAddr == "+localIP.String(),
		windivert.LayerNetwork, 0, windivert.FlagSniff|windivert.FlagRecvOnly)
	if err != nil {
		t.Skipf("meas open: %v", err)
	}
	res := make(chan uint32, 1)
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
				case res <- addr.Network().IfIdx:
				default:
				}
			}
		}
	}()
	uc, err := net.DialTimeout("udp", "8.8.8.8:53", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	uc.Write([]byte{0x11, 0x22, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) //nolint:errcheck
	uc.Close()
	meas.Close()
	select {
	case v := <-res:
		return v
	case <-time.After(2 * time.Second):
		t.Skip("no outbound packet captured to measure IfIdx")
	}
	return 0
}
