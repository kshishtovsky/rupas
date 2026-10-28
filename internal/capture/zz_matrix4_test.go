//go:build windows && live

package capture

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/kshishtovsky/rupas/pkg/windivert"
)

// drainPassThrough opens a handle on filter and relays everything it
// captures back into the stack unchanged (so it never holds packets).
func drainPassThrough(t *testing.T, filter string) *windivert.Handle {
	t.Helper()
	h, err := windivert.OpenWithFlags(filter, windivert.LayerNetwork, 0, 0)
	if err != nil {
		t.Skipf("open %q: %v", filter, err)
	}
	go func() {
		buf := make([]byte, 65535)
		var addr windivert.Address
		for {
			n, err := h.Recv(buf, &addr)
			if err != nil {
				return
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			a := addr
			_ = h.Send(pkt, &a)
		}
	}()
	return h
}

// TestLiveInjectMatrix4 isolates the injection rule with drained handles:
// does delivery depend on (a) the handle registering the inbound callout,
// or (b) the filter matching the injected packet's content?
func TestLiveInjectMatrix4(t *testing.T) {
	if !dllAvailable(t) {
		t.Skip("WinDivert.dll not loadable")
	}
	localIP := localIPv4(t)

	// Receiver: UDP on the real IP.
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
			gotUDP <- "UDP RECV \"" + string(buf[:n]) + "\" from " + from.String()
		}
	}()

	// Candidate injectors.
	trueH := drainPassThrough(t, "true")
	inH := drainPassThrough(t, "inbound")
	mismatchH := drainPassThrough(t, "inbound and udp.DstPort == 1") // inbound callout, content never matches
	defer trueH.Close()
	defer inH.Close()
	defer mismatchH.Close()

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

	try := func(name string, h *windivert.Handle, loop bool) {
		var addr windivert.Address
		addr.SetOutbound(false)
		addr.SetLoopback(loop)
		if na := addr.Network(); na != nil {
			na.IfIdx = 1
		}
		if err := h.Send(craftUDP("via-"+name), &addr); err != nil {
			t.Logf("[%s] send err: %v", name, err)
		}
	}
	try("true-loop", trueH, true)
	try("true-noloop", trueH, false)
	try("inbound-loop", inH, true)
	try("mismatch-loop", mismatchH, true)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case s := <-gotUDP:
			t.Logf("DELIVERED %s", s)
		case <-time.After(200 * time.Millisecond):
		}
	}
	select {
	case s := <-gotUDP:
		t.Logf("DELIVERED %s", s)
	default:
	}
	_ = strconv.Itoa
	_ = fmt.Sprint
}
