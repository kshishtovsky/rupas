//go:build windows && live && with_utls

package app

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/rupas/rupas/internal/config"
	"github.com/rupas/rupas/internal/tunnel"
)

// TestLiveHy2OnlyDNS: is hysteria2 itself alive on this ISP? A DNS query
// (UDP 53 — the one UDP port this VPS egress passes) through a hy2-ONLY
// plan answers that without the STUN-egress confounder.
func TestLiveHy2OnlyDNS(t *testing.T) {
	plan := loadUserPlan(t)
	if plan.UDP == nil {
		t.Fatal("no udp endpoint")
	}
	hy2 := *plan.UDP
	p := config.TunnelConfig{TCP: &hy2, UDP: &hy2} // both paths = hy2
	tproxy := freeTCPPort(t)
	provider := &stubNAT{}
	tun := tunnel.NewTunnel(p, tproxy, tunnel.Options{
		OriginalDstProvider: provider,
		Logger:              liveTunnelLogger(),
		HealthInterval:      time.Hour,
		STUNServer:          "off",
		NoHoldFlows:         true,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tun.Start(ctx); err != nil {
		t.Fatalf("tunnel start (hy2 engine): %v", err)
	}
	defer func() { _ = tun.Stop() }()

	dnsQuery := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01}
	for _, target := range []string{"8.8.8.8:53", "1.1.1.1:53"} {
		uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		dst := netip.MustParseAddrPort(target)
		src := netip.MustParseAddrPort(uc.LocalAddr().String())
		provider.add(src, dst)
		if _, err := uc.WriteToUDPAddrPort(dnsQuery, netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", tproxy))); err != nil {
			t.Fatal(err)
		}
		uc.SetReadDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
		buf := make([]byte, 1024)
		n, _, err := uc.ReadFromUDP(buf)
		if err != nil {
			t.Logf("hy2 DNS %s: FAIL %v", target, err)
		} else {
			t.Logf("hy2 DNS %s: OK %d bytes", target, n)
		}
		uc.Close()
	}
}
