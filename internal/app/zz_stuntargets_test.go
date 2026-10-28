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

func TestLiveSTUNTargets(t *testing.T) {
	plan := loadUserPlan(t)
	single := *plan.TCP
	single.UDPMode = "xudp"
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

	trySTUN := func(host string, port uint16) {
		ips, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip4", host)
		if err != nil || len(ips) == 0 {
			t.Logf("%s: resolve failed %v", host, err)
			return
		}
		dst := netip.AddrPortFrom(ips[0], port)
		uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		src := netip.MustParseAddrPort(uc.LocalAddr().String())
		provider.add(src, dst)
		uc.WriteToUDPAddrPort(liveSTUN(t), netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", tproxy))) //nolint:errcheck
		uc.SetReadDeadline(time.Now().Add(6 * time.Second))                                                //nolint:errcheck
		buf := make([]byte, 1024)
		n, _, err := uc.ReadFromUDP(buf)
		if err != nil {
			t.Logf("STUN %s (%s): FAIL %v", host, dst, err)
		} else {
			t.Logf("STUN %s (%s): OK %d bytes", host, dst, n)
		}
		uc.Close()
	}
	trySTUN("stun.cloudflare.com", 3478)
	trySTUN("stun.l.google.com", 19302)
	trySTUN("stun.nextcloud.com", 443)
	trySTUN("stun.sipgate.net", 3478)
}
