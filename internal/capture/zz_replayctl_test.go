//go:build windows && live

package capture

import (
	"net"
	"testing"
	"time"

	"github.com/rupas/rupas/pkg/windivert"
)

// TestLiveReplayControl: sanity for the re-injection harness. A genuine
// outbound NON-loopback UDP (DNS) packet is captured, held, and replayed
// byte-identical. If the DNS answer arrives, the harness (address copy,
// Send semantics) is sound and loopback failures are a real host limit.
func TestLiveReplayControl(t *testing.T) {
	if !dllAvailable(t) {
		t.Skip("WinDivert.dll not loadable")
	}
	blockH, err := windivert.OpenWithFlags("outbound and udp.DstPort == 53 and tcp == 0",
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

	// A genuine DNS query via a plain UDP socket: write, then replay path.
	uc, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	// simple A query for "one.one.one.one"
	q := []byte{
		0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
		3, 'o', 'n', 'e', 3, 'o', 'n', 'e', 3, 'o', 'n', 'e', 3, 'c', 'o', 'm', 0,
		0, 1, 0, 1,
	}
	type res struct {
		n   int
		err error
	}
	done := make(chan res, 1)
	go func() {
		buf := make([]byte, 1024)
		uc.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
		n, err := uc.Read(buf)
		done <- res{n, err}
	}()
	if _, err := uc.Write(q); err != nil {
		t.Fatal(err)
	}

	select {
	case g := <-captured:
		// Replay byte-identical, address as captured.
		if err := blockH.Send(g.pkt, &g.addr); err != nil {
			t.Fatalf("replay send: %v", err)
		}
		t.Logf("replayed %d bytes, IfIdx=%d Outbound=%v Loopback=%v",
			len(g.pkt), g.addr.Network().IfIdx, g.addr.Outbound(), g.addr.Loopback())
	case <-time.After(2 * time.Second):
		t.Fatal("no DNS packet captured")
	}

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("DNS after replay failed: %v", r.err)
		}
		t.Logf("DNS ANSWER after replay: %d bytes", r.n)
	case <-time.After(4 * time.Second):
		t.Fatal("DNS answer never arrived after byte-identical replay — harness re-injection is broken")
	}
}
