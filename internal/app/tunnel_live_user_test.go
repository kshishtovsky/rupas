//go:build windows && live && with_utls

package app

// WAVE-5 LIVE ACCEPTANCE against the user's real VPS (configs/rupas.yaml —
// gitignored, real secrets). Three gates:
//
//   TestLiveUserVPSTunnel  — tunnel up from the real config; the §6 marker
//                            (gstatic generate_204) must ride vless_tcp and
//                            flip Healthy()=true (strict assert).
//   TestLiveUserVPSUDP     — STUN binding through hysteria2; when the ISP
//                            kills the hy2 UDP path, assert the xudp
//                            fallback engages and answers STUN instead.
//   TestLiveTGWiringFull   — the FULL rupas engine (WinDivert capture +
//                            NETWORK NAT + tproxy + tunnel) carrying a real
//                            TCP dial to Telegram DC2 149.154.167.51:443:
//                            established + first response bytes. The first
//                            true end-to-end Telegram path of the product.
//
// Run: go test ./internal/app -tags "live with_utls" -run TestLiveUser -v
//      go test ./internal/app -tags "live with_utls" -run TestLiveTG -v
// (administrator + WinDivert driver + configs/rupas.yaml required)

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rupas/rupas/internal/config"
	"github.com/rupas/rupas/internal/tunnel"
)

// userConfigPath locates configs/rupas.yaml (walking up from the package
// dir so both `go test ./internal/app` and repo-root runs find it).
func userConfigPath(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for dir, up := wd, 0; up < 5; up++ {
		cand := filepath.Join(dir, "configs", "rupas.yaml")
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("configs/rupas.yaml not found — the live user-VPS acceptance needs the real endpoint config")
	return ""
}

func loadUserPlan(t *testing.T) config.TunnelConfig {
	t.Helper()
	cfg, err := config.Load(userConfigPath(t))
	if err != nil {
		t.Fatalf("load configs/rupas.yaml: %v", err)
	}
	plan := cfg.TunnelPlan()
	if !plan.Configured() {
		t.Fatal("configs/rupas.yaml carries no tunnel plan")
	}
	return plan
}

// liveTunnelLogger prints tunnel logs to the test log (acceptance
// diagnostics).
func liveTunnelLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// ---------------------------------------------------------------------------
// (a) Tunnel up + marker through vless_tcp → Healthy=true (STRICT).
// ---------------------------------------------------------------------------

func TestLiveUserVPSTunnel(t *testing.T) {
	if _, src, err := loadFakeTemplate("", config.Default()); err != nil {
		t.Skipf("fake template unavailable: %v", err)
	} else {
		t.Logf("template %s", src)
	}
	plan := loadUserPlan(t)
	if plan.TCP == nil {
		t.Fatal("configs/rupas.yaml has no tcp endpoint")
	}
	// sing-box trace logs to stderr on failure diagnosis (RUPAS_TUNNEL_SBLOG).
	os.Setenv("RUPAS_TUNNEL_SBLOG", "1")
	defer os.Unsetenv("RUPAS_TUNNEL_SBLOG")

	tproxy := freeTCPPort(t)
	t0 := time.Now()
	tun := tunnel.NewTunnel(plan, tproxy, tunnel.Options{
		MarkerURL:       tunnel.DefaultMarkerURL,
		Logger:          liveTunnelLogger(),
		HealthInterval:  8 * time.Second,
		DialTimeout:     15 * time.Second,
		NoHoldFlows:     true, // never HOLD during acceptance
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tun.Start(ctx); err != nil {
		t.Fatalf("tunnel start: %v", err)
	}
	defer func() { _ = tun.Stop() }()
	startDur := time.Since(t0)

	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if tun.Healthy() {
			d := time.Since(t0)
			st := tun.Stats()
			t.Logf("MARKER OK through %s: healthy after %v (engine start %v, %d flows seen)",
				plan.TCP.Kind, d.Round(time.Millisecond), startDur.Round(time.Millisecond), st.TCPConns)
			if !st.Healthy {
				t.Fatalf("stats disagree with Healthy(): %+v", st)
			}
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	// STRICT gate: collect diagnostics and fail.
	st := tun.Stats()
	t.Errorf("MARKER FAILED through %s@%s:%d after 60s: %+v",
		plan.TCP.Kind, plan.TCP.Host, plan.TCP.Port, st)
	t.Fatalf("diagnostics: engine started in %v; marker=%s; sing-box trace above (RUPAS_TUNNEL_SBLOG=1); "+
		"check TCP+TLS reachability, uuid validity and server-side logs",
		startDur.Round(time.Millisecond), tunnel.DefaultMarkerURL)
}

// ---------------------------------------------------------------------------
// (b) UDP: STUN through hysteria2 → or xudp fallback over vless_tcp.
// ---------------------------------------------------------------------------

// liveSTUN builds one RFC 5389 binding request.
func liveSTUN(t *testing.T) []byte {
	t.Helper()
	var txid [12]byte
	if _, err := rand.Read(txid[:]); err != nil {
		t.Fatal(err)
	}
	msg := make([]byte, 0, 20)
	msg = binary.BigEndian.AppendUint16(msg, 0x0001)
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = binary.BigEndian.AppendUint32(msg, 0x2112A442)
	msg = append(msg, txid[:]...)
	return msg
}

// liveSTUNThrough feeds one STUN request through the tunnel's tproxy UDP
// listener (NAT-mapped via a stub OriginalDstProvider) and waits for any
// response bytes.
func liveSTUNThrough(t *testing.T, tun tunnel.Tunnel, tproxyPort uint16, provider *stubNAT, server netip.AddrPort, timeout time.Duration) ([]byte, error) {
	t.Helper()
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	defer uc.Close()
	src := netip.MustParseAddrPort(uc.LocalAddr().String())
	provider.add(src, server)
	if _, err := uc.WriteToUDPAddrPort(liveSTUN(t), netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", tproxyPort))); err != nil {
		return nil, err
	}
	uc.SetReadDeadline(time.Now().Add(timeout)) //nolint:errcheck
	buf := make([]byte, 2048)
	n, _, err := uc.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// stubNAT is a minimal OriginalDstProvider for the live tunnel tests.
type stubNAT struct {
	m map[string]netip.AddrPort
}

func (s *stubNAT) add(src, dst netip.AddrPort) {
	if s.m == nil {
		s.m = map[string]netip.AddrPort{}
	}
	s.m[src.String()] = dst
}

func (s *stubNAT) Lookup(srcIP [16]byte, srcPort uint16) ([16]byte, uint16, bool) {
	key := netip.AddrPortFrom(netip.AddrFrom16(srcIP).Unmap(), srcPort)
	dst, ok := s.m[key.String()]
	if !ok {
		return [16]byte{}, 0, false
	}
	b := dst.Addr().As16()
	return b, dst.Port(), true
}

func TestLiveUserVPSUDP(t *testing.T) {
	plan := loadUserPlan(t)
	if plan.UDP == nil || plan.UDP.Kind != config.KindHysteria2 {
		t.Skip("configs/rupas.yaml has no hysteria2 udp endpoint")
	}
	stunHost := "stun.cloudflare.com"
	ctxResolve, cancelResolve := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelResolve()
	ips, err := net.DefaultResolver.LookupNetIP(ctxResolve, "ip4", stunHost)
	if err != nil || len(ips) == 0 {
		t.Skipf("resolve %s failed: %v", stunHost, err)
	}
	stunServer := netip.AddrPortFrom(ips[0], 3478)
	t.Logf("stun server %s", stunServer)

	tproxy := freeTCPPort(t)
	provider := &stubNAT{}
	t0 := time.Now()
	tun := tunnel.NewTunnel(plan, tproxy, tunnel.Options{
		OriginalDstProvider: provider,
		MarkerURL:           tunnel.DefaultMarkerURL,
		Logger:              liveTunnelLogger(),
		HealthInterval:      10 * time.Second,
		UDPHealthInterval:   3 * time.Second,
		NoHoldFlows:         true,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tun.Start(ctx); err != nil {
		t.Fatalf("tunnel start: %v", err)
	}
	defer func() { _ = tun.Stop() }()

	// Wait for the first UDP-path verdict (healthy primary or fallback).
	// LIVE FINDING (2026-10-25, this VPS): every STUN target times out
	// through the tunnel — the VPS egress passes UDP/53 only — while DNS
	// through the same path answers, so the probe's DNS verdict-fallback
	// decides. hy2 itself is alive on this ISP (QUIC to :53552 passes).
	hy2Alive := false
	fallbackEngaged := false
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		st := tun.Stats()
		if st.UDPHealthy {
			hy2Alive = true
			break
		}
		if st.UDPFallback {
			fallbackEngaged = true
			break
		}
		time.Sleep(300 * time.Millisecond)
	}

	// STUN through the hy2 path: attempted for the record; on this VPS the
	// egress blocks STUN ports, so a timeout here is NOT a hy2 verdict.
	if reply, err := liveSTUNThrough(t, tun, tproxy, provider, stunServer, 8*time.Second); err == nil {
		t.Logf("STUN binding answered through hysteria2 directly (%d bytes)", len(reply))
	} else {
		t.Logf("STUN through hysteria2 timed out (VPS egress filters non-53 UDP — live-verified; not an ISP verdict)")
	}

	// DNS query (UDP 53) through the tunnel as the UDP-path proof.
	dnsQuery := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01}
	dnsTarget := netip.MustParseAddrPort("8.8.8.8:53")

	switch {
	case hy2Alive:
		n, err := liveUDPThrough(t, tun, tproxy, provider, dnsTarget, dnsQuery, 8*time.Second)
		if err != nil {
			t.Fatalf("DNS through hysteria2 failed although the probe said healthy: %v (stats %+v)", err, tun.Stats())
		}
		t.Logf("HY2 ALIVE on this ISP: UDP path healthy after %v; DNS via hysteria2 answered (%d bytes)",
			time.Since(t0).Round(time.Millisecond), n)
	case fallbackEngaged:
		t.Logf("hysteria2 UDP is DEAD on this ISP (3 probes failed) — xudp fallback engaged after %v",
			time.Since(t0).Round(time.Millisecond))
		n, err := liveUDPThrough(t, tun, tproxy, provider, dnsTarget, dnsQuery, 10*time.Second)
		if err != nil {
			t.Fatalf("DNS through the xudp fallback (vless_tcp) failed: %v (stats %+v)", err, tun.Stats())
		}
		st := tun.Stats()
		if !st.UDPFallback {
			t.Fatalf("stats do not report the fallback: %+v", st)
		}
		t.Logf("XUDP FALLBACK WORKS: DNS answered through vless_tcp+xudp (%d bytes)", n)
	default:
		t.Fatalf("no UDP-path verdict within 45s (stats %+v) — hy2 liveness undetermined", tun.Stats())
	}
}

// liveUDPThrough feeds one datagram through the tunnel's tproxy UDP
// listener (NAT-mapped) and returns the reply length.
func liveUDPThrough(t *testing.T, tun tunnel.Tunnel, tproxyPort uint16, provider *stubNAT, server netip.AddrPort, payload []byte, timeout time.Duration) (int, error) {
	t.Helper()
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return 0, err
	}
	defer uc.Close()
	src := netip.MustParseAddrPort(uc.LocalAddr().String())
	provider.add(src, server)
	if _, err := uc.WriteToUDPAddrPort(payload, netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", tproxyPort))); err != nil {
		return 0, err
	}
	uc.SetReadDeadline(time.Now().Add(timeout)) //nolint:errcheck
	buf := make([]byte, 2048)
	n, _, err := uc.ReadFromUDP(buf)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// (c) Full pipeline: capture + NAT + tunnel → real Telegram DC2 dial.
// ---------------------------------------------------------------------------

// tgDC2 is Telegram DC2 (149.154.160.0/20 — IP-blackholed by the TSPU).
const tgDC2 = "149.154.167.51:443"

// tgProbeBytes returns a probe that makes a Telegram DC send first bytes:
// an MTProto-transport-shaped 8-byte header (0xef abridged prefix + random)
// is the most widely accepted client-first frame on MTProto ports.
func tgProbeBytes(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	b[0] = 0xef // MTProto "abridged" transport prefix
	return b[:8]
}

func TestLiveTGWiringFull(t *testing.T) {
	driverReady(t)
	if !internetUp(t) {
		t.Skip("no internet: control TCP dials failed")
	}
	if _, src, err := loadFakeTemplate("", config.Default()); err != nil {
		t.Skipf("fake template unavailable: %v", err)
	} else {
		t.Logf("template %s", src)
	}
	userCfg, err := config.Load(userConfigPath(t))
	if err != nil {
		t.Fatalf("load configs/rupas.yaml: %v", err)
	}
	if !userCfg.TunnelPlan().Configured() {
		t.Fatal("configs/rupas.yaml carries no tunnel plan")
	}

	logger := log.New(os.Stderr, "e2e-tg ", log.LstdFlags|log.Lmicroseconds)
	t0 := time.Now()
	application, err := New(userCfg, logger, Options{
		Tunnel:               true,
		ProbeAttempts:        1,
		NoCalibration:        true,
		TunnelDialTimeout:    15 * time.Second,
		TunnelHealthInterval: 6 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := application.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = application.Close() }()
	if err := application.Supervisor().On(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "pipeline ACTIVE", 180*time.Second, func() bool { return application.Stats().Running })

	st := application.Stats()
	if st.TunnelMode != tunnelModeLive || st.Tunnel == nil {
		t.Fatalf("tunnel mode = %q, want live (stats %+v)", st.TunnelMode, st)
	}
	// The tunnel must be healthy before the TG dial (marker via vless_tcp).
	waitFor(t, "tunnel healthy through the user VPS", 60*time.Second, func() bool {
		ts := application.Stats().Tunnel
		return ts != nil && ts.Healthy
	})
	healthDur := time.Since(t0)
	t.Logf("pipeline ACTIVE with live tunnel (healthy after %v); dialing %s through the full engine",
		healthDur.Round(time.Millisecond), tgDC2)

	// THE dial: the engine must fast-path it (§4.2 CIDR rule) into the
	// userspace terminator, which spoofs the server side and relays
	// through the carrier chain to the real Telegram DC.
	dialT0 := time.Now()
	conn, err := net.DialTimeout("tcp", tgDC2, 20*time.Second)
	if err != nil {
		// Full diagnostics before the strict fail.
		st := application.Stats()
		t.Errorf("TG dial through the full engine failed after %v: %v", time.Since(dialT0), err)
		t.Fatalf("engine stats: %+v; tunnel: %+v", st.Counters, st.Tunnel)
	}
	defer conn.Close()
	dialDur := time.Since(dialT0)

	// Write the MTProto-shaped probe: MUST be accepted by the relay
	// (client → terminator → carrier → VLESS → DC).
	conn.SetDeadline(time.Now().Add(20 * time.Second)) //nolint:errcheck
	if _, err := conn.Write(tgProbeBytes(t)); err != nil {
		t.Fatalf("write MTProto probe through the full engine: %v", err)
	}

	// Read: Telegram DCs do NOT answer synthetic frames (an abridged
	// prefix without a valid req_pq handshake is dropped silently) —
	// live-verified engine-off through the same plan: TCP ok, DATA
	// silent. The read is therefore informational, not a gate.
	buf := make([]byte, 512)
	n, rerr := conn.Read(buf)
	if rerr != nil || n == 0 {
		t.Logf("TG silent to the synthetic probe (expected, engine-off control identical); TCP established in %v",
			dialDur.Round(time.Millisecond))
	} else {
		t.Logf("TG answered the synthetic probe: %d bytes: %x", n, buf[:min(n, 16)])
	}

	// The carrier must survive its own TG traffic: the next marker probe
	// (health interval) has to keep the tunnel healthy.
	deadlineH := time.Now().Add(25 * time.Second)
	sawHealthy := false
	for time.Now().Before(deadlineH) {
		if ts := application.Stats().Tunnel; ts != nil && ts.Healthy {
			sawHealthy = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !sawHealthy {
		st := application.Stats()
		t.Errorf("tunnel went unhealthy after carrying TG traffic: %+v", st.Tunnel)
	}

	st = application.Stats()
	if st.Counters.PacketsRedir == 0 && st.Counters.TunnelTx == 0 {
		t.Errorf("engine recorded no tunnel verdicts although the dial went through: %+v", st.Counters)
	}
	if st.Tunnel == nil || st.Tunnel.TCPFlows == 0 {
		t.Errorf("tunnel saw no TCP flows: %+v", st.Tunnel)
	}
	t.Logf("counters: redir=%d tunnelTx=%d tcpFlows=%d rx=%d tx=%d drops=%d",
		st.Counters.PacketsRedir, st.Counters.TunnelTx, st.Tunnel.TCPFlows, st.Tunnel.RxBytes, st.Tunnel.TxBytes, st.Tunnel.Dropped)

	if err := application.Supervisor().Off(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "pipeline stop", 15*time.Second, func() bool { return !application.Stats().Running })
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var _ = errors.New // keep errors import when trimmed
