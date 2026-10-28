//go:build windows && live

package capture

import (
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/kshishtovsky/rupas/pkg/windivert"
)

// remotePortOf extracts the port of a host:port target.
func remotePortOf(t *testing.T, hostport string) uint16 {
	t.Helper()
	_, ps, err := net.SplitHostPort(hostport)
	if err != nil {
		t.Skipf("RUPAS_LIVE_VPS must be host:port: %v", err)
	}
	p, err := strconv.ParseUint(ps, 10, 16)
	if err != nil {
		t.Skipf("RUPAS_LIVE_VPS port: %v", err)
	}
	return uint16(p)
}

// TestLiveInboundEstablishedReplay: decisive for the design pivot. An
// outbound dial to a real remote server is ALE-authorized at connect time.
// The server's genuine inbound SYN-ACK is captured, held and replayed
// byte-identical. If the dial then completes, inbound LayerNetwork injection
// DOES deliver for outbound-authorized flows (and only new inbound
// connections/listeners are blocked) — making userspace TCP termination
// (spoofed server side) a viable path.
//
// Target: set RUPAS_LIVE_VPS=host:port (the tunnel endpoint; any remote
// TCP server that answers SYN-ACK works). Skipped when unset.
func TestLiveInboundEstablishedReplay(t *testing.T) {
	if !dllAvailable(t) {
		t.Skip("WinDivert.dll not loadable")
	}
	vps := os.Getenv("RUPAS_LIVE_VPS")
	if vps == "" {
		t.Skip("RUPAS_LIVE_VPS not set — live endpoint config is gitignored")
	}
	rport := vps
	blockH, err := windivert.OpenWithFlags("inbound and tcp.SrcPort == "+itoa(uint32(remotePortOf(t, rport))),
		windivert.LayerNetwork, 30000, 0)
	if err != nil {
		t.Skipf("blocker open: %v", err)
	}
	defer blockH.Close()

	captured := make(chan struct {
		pkt  []byte
		addr windivert.Address
	}, 8)
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

	dialed := make(chan error, 1)
	go func() {
		c, err := net.DialTimeout("tcp", vps, 6*time.Second)
		if err == nil {
			c.Close()
		}
		dialed <- err
	}()

	select {
	case g := <-captured:
		time.Sleep(200 * time.Millisecond) // hold, out of the retransmit window
		if err := blockH.Send(g.pkt, &g.addr); err != nil {
			t.Fatalf("replay send: %v", err)
		}
		t.Logf("replayed inbound SYN-ACK %d bytes IfIdx=%d Outbound=%v Loopback=%v",
			len(g.pkt), g.addr.Network().IfIdx, g.addr.Outbound(), g.addr.Loopback())
	case <-time.After(2 * time.Second):
		t.Fatal("no inbound SYN-ACK captured")
	}

	select {
	case err := <-dialed:
		if err != nil {
			t.Logf("dial did NOT complete after byte-identical inbound replay: %v", err)
			t.Log("=> inbound LayerNetwork injection is dead for TCP entirely (userspace termination NOT viable)")
		} else {
			t.Log("DIAL COMPLETED after byte-identical inbound replay: inbound injection delivers for outbound-authorized flows")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("dial never resolved")
	}
}
