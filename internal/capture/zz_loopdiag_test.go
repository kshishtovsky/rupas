//go:build windows && live

package capture

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/rupas/rupas/internal/config"
	"github.com/rupas/rupas/internal/rules"
	"github.com/rupas/rupas/pkg/windivert"
)

// TestLiveLoopbackDiag answers two questions with the real driver:
//  1. what IfIdx/flags do GENUINE loopback packets carry on this host?
//  2. does the engine's re-injected NAT packet (dst 127.0.0.1:tproxy) ever
//     appear on the loopback path, and with which address flags?
func TestLiveLoopbackDiag(t *testing.T) {
	if !dllAvailable(t) {
		t.Skip("WinDivert.dll not loadable")
	}

	// --- (1) genuine loopback traffic: dial 127.0.0.1 while sniffing ---
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	sniff, err := windivert.OpenWithFlags(
		"ip.DstAddr >= 127.0.0.0 and ip.DstAddr <= 127.255.255.255",
		windivert.LayerNetwork, 0, windivert.FlagSniff|windivert.FlagRecvOnly)
	if err != nil {
		t.Skipf("sniffer open: %v", err)
	}
	type seen struct {
		desc  string
		count int
	}
	genuine := map[string]*seen{}
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
			if len(p) < 20 {
				continue
			}
			proto := "udp"
			if p[9] == 6 {
				proto = "tcp"
			}
			key := fmt.Sprintf("%s IfIdx=%d SubIf=%d Loopback=%v Outbound=%v Impostor=%v Checksum=0x%02x%02x IPid=%d TTL=%d",
				proto, addr.Network().IfIdx, addr.Network().SubIfIdx, addr.Loopback(), addr.Outbound(),
				addr.Impostor(), p[10], p[11], uint16(p[4])<<8|uint16(p[5]), p[8])
			if s, ok := genuine[key]; ok {
				s.count++
			} else {
				genuine[key] = &seen{key, 1}
			}
		}
	}()
	// Generate loopback traffic (several dials).
	for i := 0; i < 3; i++ {
		c, err := net.DialTimeout("tcp", srv.Listener.Addr().String(), 2*time.Second)
		if err == nil {
			c.Write([]byte("GET / HTTP/1.0\r\n\r\n")) //nolint:errcheck
			buf := make([]byte, 64)
			c.SetReadDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
			c.Read(buf)                                        //nolint:errcheck
			c.Close()
		}
	}
	time.Sleep(500 * time.Millisecond)
	_ = sniff.Close()
	<-done

	t.Log("=== genuine loopback packets (dst 127/8) ===")
	if len(genuine) == 0 {
		t.Log("(none captured — loopback traffic not visible to a NETWORK-layer dst-127 filter)")
	}
	for _, s := range genuine {
		t.Logf("x%d %s", s.count, s.desc)
	}
}

// TestLiveNATReinjectDiag runs the real engine with a TG-CIDR tunnel rule,
// dials Telegram through it and sniffs the loopback path: does the
// re-injected NAT packet (dst 127.0.0.1:tproxy) appear, and does the
// tproxy listener ever see a connection?
func TestLiveNATReinjectDiag(t *testing.T) {
	if !dllAvailable(t) {
		t.Skip("WinDivert.dll not loadable")
	}
	// The tproxy stand-in.
	ln, err := net.Listen("tcp", "127.0.0.1:12713")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()

	cfg := &config.Config{
		Profile: "nat-diag",
		Rules:   []config.Rule{{CIDR: "149.154.160.0/20", Action: config.ActionTunnel}, {Action: config.ActionDirect}},
		Desync:  config.DesyncParams{Strategy: "fake", TTL: 8, Repeats: 1},
	}
	tbl, err := rules.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	eng, err := New(Options{
		Rules: tbl, Desync: cfg.Desync, FakeTemplate: testFakeTemplate,
		TProxyPort: 12713, TGCIDRs: []string{"149.154.160.0/20"},
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = eng.Run(context.Background()) }()
	defer eng.Stop()
	time.Sleep(1200 * time.Millisecond)

	// Sniff everything to/from 127.0.0.1:12713.
	type pktSeen struct {
		desc  string
		count int
	}
	var mu sync.Mutex
	toTproxy := map[string]*pktSeen{}
	sniff, err := windivert.OpenWithFlags("tcp.DstPort == 12713 or tcp.SrcPort == 12713",
		windivert.LayerNetwork, 0, windivert.FlagSniff|windivert.FlagRecvOnly)
	if err != nil {
		t.Skipf("sniffer open: %v", err)
	}
	sniffDone := make(chan struct{})
	go func() {
		defer close(sniffDone)
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
			flags := uint8(p[33])
			key := "src=" + net.IP(p[12:16]).String() + ":" + strconv.Itoa(int(uint16(p[20])<<8|uint16(p[21]))) + " dst=" + net.IP(p[16:20]).String() + ":" + strconv.Itoa(int(uint16(p[22])<<8|uint16(p[23]))) + fmt.Sprintf(" flags=0x%02x Out=%v Loop=%v IfIdx=%d Impostor=%v", flags, addr.Outbound(), addr.Loopback(), addr.Network().IfIdx, addr.Impostor())
			mu.Lock()
			if s, ok := toTproxy[key]; ok {
				s.count++
			} else {
				toTproxy[key] = &pktSeen{key, 1}
			}
			mu.Unlock()
		}
	}()

	c, dialErr := net.DialTimeout("tcp", "149.154.167.51:443", 8*time.Second)
	if dialErr == nil {
		c.Close()
	}
	time.Sleep(500 * time.Millisecond)
	_ = sniff.Close()
	<-sniffDone
	mu.Lock()
	defer mu.Unlock()
	t.Log("=== packets seen on port 12713 ===")
	if len(toTproxy) == 0 {
		t.Log("(none)")
	}
	for _, s := range toTproxy {
		t.Logf("x%d %s", s.count, s.desc)
	}
	select {
	case c := <-accepted:
		t.Logf("tproxy ACCEPTED a connection from %s", c.RemoteAddr())
		c.Close()
	default:
		t.Log("tproxy accepted nothing")
	}
	cnt := eng.Counters()
	t.Logf("engine: total=%d redir=%d tx=%d sendErr=%d", cnt.PacketsTotal, cnt.PacketsRedir, cnt.TunnelTx, eng.cnt.sendErrors.Load())
}

// TestLiveLoopbackLegs: which legs of genuine loopback traffic are visible
// at the NETWORK layer — outbound only, or inbound too? Decides where the
// reverse NAT must capture.
func TestLiveLoopbackLegs(t *testing.T) {
	if !dllAvailable(t) {
		t.Skip("WinDivert.dll not loadable")
	}
	// Local UDP echo pair on 127.0.0.1.
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port
	go func() {
		buf := make([]byte, 1024)
		for {
			n, from, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			echo.WriteToUDP(buf[:n], from) //nolint:errcheck
		}
	}()

	var out, inb int
	done := make(chan struct{})
	sniff, err := windivert.OpenWithFlags(
		fmt.Sprintf("udp and (udp.DstPort == %d or udp.SrcPort == %d)", echoPort, echoPort),
		windivert.LayerNetwork, 0, windivert.FlagSniff|windivert.FlagRecvOnly)
	if err != nil {
		t.Skipf("sniff: %v", err)
	}
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		var addr windivert.Address
		for {
			n, err := sniff.Recv(buf, &addr)
			if err != nil {
				return
			}
			if n > 0 {
				if addr.Outbound() {
					out++
				} else {
					inb++
				}
			}
		}
	}()
	cl, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	for i := 0; i < 3; i++ {
		cl.WriteToUDPAddrPort([]byte("leg-check"), netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", echoPort))) //nolint:errcheck
		buf := make([]byte, 64)
		cl.SetReadDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
		cl.ReadFromUDP(buf)                                 //nolint:errcheck
	}
	time.Sleep(400 * time.Millisecond)
	_ = sniff.Close()
	<-done
	t.Logf("loopback legs: outbound=%d inbound=%d (6 = both legs of 3 round trips)", out, inb)
}
