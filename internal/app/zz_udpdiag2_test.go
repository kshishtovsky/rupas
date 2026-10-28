//go:build windows && live && with_utls

package app

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/kshishtovsky/rupas/internal/config"
	"github.com/kshishtovsky/rupas/internal/tunnel"
)

func diagUDPSession(t *testing.T, udpMode, label string) {
	t.Helper()
	plan := loadUserPlan(t)
	single := *plan.TCP
	single.UDPMode = udpMode
	p := config.TunnelConfig{TCP: &single, UDP: &single}
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
		t.Fatal(err)
	}
	defer func() { _ = tun.Stop() }()

	run := func(dst netip.AddrPort, payload []byte, wait time.Duration) (int, error) {
		uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return 0, err
		}
		defer uc.Close()
		src := netip.MustParseAddrPort(uc.LocalAddr().String())
		provider.add(src, dst)
		if _, err := uc.WriteToUDPAddrPort(payload, netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", tproxy))); err != nil {
			return 0, err
		}
		uc.SetReadDeadline(time.Now().Add(wait)) //nolint:errcheck
		buf := make([]byte, 2048)
		n, _, err := uc.ReadFromUDP(buf)
		if err != nil {
			return 0, err
		}
		return n, nil
	}

	stunPayload := liveSTUN(t)
	n, err := run(netip.MustParseAddrPort("162.159.207.0:3478"), stunPayload, 10*time.Second)
	t.Logf("[%s/%s] STUN: n=%d err=%v", label, udpMode, n, err)
	dnsQuery := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01}
	n, err = run(netip.MustParseAddrPort("8.8.8.8:53"), dnsQuery, 10*time.Second)
	t.Logf("[%s/%s] DNS 8.8.8.8:53: n=%d err=%v", label, udpMode, n, err)
}

func TestLiveUDPDiagnostics(t *testing.T) {
	diagUDPSession(t, "xudp", "vless_tcp")
	diagUDPSession(t, "packetaddr", "vless_tcp")
}
