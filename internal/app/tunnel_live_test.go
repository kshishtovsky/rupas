//go:build windows && live && with_utls

package app

// LIVE wave-4B test: rupasd's -tunnel=on path WITHOUT a real VPS (a
// structurally valid but unroutable endpoint). Asserts the honest
// degradation chain end to end on the real driver:
//
//   - the engine NAT-redirects a real Telegram dial attempt (redir moves);
//   - the marker loop through the DEAD tunnel flips health to false after
//     3 failures and HOLDs new flows (dropped counter, honest logs);
//   - a flow arriving at the tproxy without a NAT entry is closed promptly
//     (never hung);
//   - `rupasctl status`'s tunnel section reports the truth;
//   - a config with NO endpoint escalates TUNNEL rules (mode=escalated);
//   - graceful stop.
//
// KNOWN LIVE BLOCKER (capture layer, wave-3 scope, NOT fixed here — the
// hot path is off-limits in wave 4B): the NETWORK-layer NAT rewrite
// re-injects the loopback-addressed packet without the WinDivert Address
// Loopback flag, so the redirected SYN never reaches the tproxy listener
// (verified live: redir=854, tunnelConns=0). Until capture's natOutbound
// sets the loopback flag on re-injection, the through-tunnel TCP/UDP relay
// can only be exercised hermetically (TestTunnelWiringFullPath).
//
// Run with: go test ./internal/app -tags "live with_utls" -run TestLiveTunnel -v
// (administrator + WinDivert driver required; skips otherwise)

import (
	"context"
	"log"
	"net"
	"os"
	"testing"
	"time"

	"github.com/rupas/rupas/internal/config"
)

func deadEndpoint() config.TunnelEndpoint {
	return config.TunnelEndpoint{
		Protocol: "vless", Address: "203.0.113.1", Port: 443, // TEST-NET-3: unroutable
		UUID:        "00000000-0000-0000-0000-000000000000",
		RealityPBK:  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		RealitySID:  "0123abcd",
		SNI:         "www.example.com",
		Fingerprint: "chrome",
		UDPMode:     "xudp",
	}
}

func TestLiveTunnelDeadEndpoint(t *testing.T) {
	driverReady(t)
	if !internetUp(t) {
		t.Skip("no internet: control TCP dials failed")
	}
	if _, src, err := loadFakeTemplate("", config.Default()); err != nil {
		t.Skipf("fake template unavailable: %v", err)
	} else {
		t.Logf("template %s", src)
	}

	cfg := config.Default()
	cfg.Tunnel = deadEndpoint()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	logger := log.New(os.Stderr, "e2e-tunnel ", log.LstdFlags|log.Lmicroseconds)
	application, err := New(cfg, logger, Options{
		Tunnel:               true,
		ProbeAttempts:        1,
		NoCalibration:        true, // short probe cycles; tunnel degradation is under test
		TunnelDialTimeout:    8 * time.Second,
		TunnelHealthInterval: 2 * time.Second,
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
	waitFor(t, "pipeline start", 120*time.Second, func() bool { return application.Stats().Running })
	st := application.Stats()
	if st.TunnelMode != tunnelModeLive || st.Tunnel == nil {
		t.Fatalf("tunnel mode = %q, want live (a dead endpoint still starts)", st.TunnelMode)
	}
	t.Logf("pipeline up: mode=%s desync=%s", st.TunnelMode, st.Desync.Strategy)

	// 1) A real Telegram dial attempt: the engine must NAT-redirect it
	// (live proof of the TUNNEL verdict + rewrite on the real driver).
	// The TCP connect cannot complete through the loop while the
	// capture-side loopback-flag blocker stands — the dialer's own
	// bounded timeout closes the attempt; what we assert is that the
	// redirect counters moved and nothing hangs.
	go func() {
		d := &net.Dialer{Timeout: 10 * time.Second}
		if c, err := d.Dial("tcp", "149.154.167.51:443"); err == nil {
			c.Close()
		}
	}()
	waitFor(t, "engine to NAT-redirect the TG dial", 20*time.Second, func() bool {
		return application.Stats().Counters.PacketsRedir > 0
	})
	t.Logf("TG dial attempt: redir=%d (loopback delivery pending the capture-side flag fix)",
		application.Stats().Counters.PacketsRedir)

	// 2) A flow that DOES arrive at the tproxy without a NAT entry (the
	// loopback-flag blocker leaves none) must be closed promptly with the
	// drop counter — honest degradation, no hang.
	droppedBefore := application.Stats().Tunnel.Dropped
	c, err := net.DialTimeout("tcp", "127.0.0.1:12713", 5*time.Second)
	if err != nil {
		t.Fatalf("direct tproxy dial: %v", err)
	}
	c.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
	start := time.Now()
	_, werr := c.Write([]byte("GET /no-nat-entry HTTP/1.0\r\n\r\n"))
	buf := make([]byte, 64)
	_, rerr := c.Read(buf)
	c.Close()
	if werr == nil && rerr == nil {
		t.Fatal("flow without a NAT entry must be closed, not answered")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("drop path too slow: %v", d)
	}
	waitFor(t, "drop counter", 5*time.Second, func() bool {
		ts := application.Stats().Tunnel
		return ts != nil && ts.Dropped > droppedBefore
	})
	t.Logf("no-NAT-entry flow dropped and closed in %v", time.Since(start).Round(time.Millisecond))

	// 3) The marker through the dead tunnel: 3 consecutive failures flip
	// health to false and HOLD new flows (the §6 gate, live).
	waitFor(t, "tunnel marked unhealthy", 90*time.Second, func() bool {
		ts := application.Stats().Tunnel
		return ts != nil && !ts.Healthy
	})
	waitFor(t, "tunnel HELD", 30*time.Second, func() bool {
		ts := application.Stats().Tunnel
		return ts != nil && ts.Held
	})

	// 4) The status snapshot carries the honest tunnel section.
	snap := application.Snapshot()
	if snap.Tunnel == nil || snap.Tunnel.Mode != "tunnel" || snap.Tunnel.Healthy || !snap.Tunnel.Held {
		t.Fatalf("snapshot tunnel section: %+v", snap.Tunnel)
	}
	if snap.TunnelHealthy {
		t.Fatal("snapshot TunnelHealthy must be false with a dead endpoint")
	}
	for _, ev := range application.EventLog().Last(20) {
		t.Logf("event: %s", ev)
	}

	// 5) Graceful stop: engine + tunnel come down together.
	if err := application.Supervisor().Off(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "pipeline stop", 15*time.Second, func() bool { return !application.Stats().Running })
}

// TestLiveTunnelNoEndpointEscalates: -tunnel=on with an EMPTY endpoint on
// the real driver — the pipeline must come up in escalated mode (TUNNEL
// rules → sni:desync / cidr,port:direct), never black-holing flows at a
// dead loopback port.
func TestLiveTunnelNoEndpointEscalates(t *testing.T) {
	driverReady(t)
	if _, _, err := loadFakeTemplate("", config.Default()); err != nil {
		t.Skipf("fake template unavailable: %v", err)
	}
	logger := log.New(os.Stderr, "e2e-escalate ", log.LstdFlags|log.Lmicroseconds)
	application, err := New(config.Default(), logger, Options{
		Tunnel: true, NoCalibration: true, ProbeAttempts: 1,
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
	waitFor(t, "pipeline start", 120*time.Second, func() bool { return application.Stats().Running })
	st := application.Stats()
	if st.TunnelMode != tunnelModeEscalated {
		t.Fatalf("mode = %q, want escalated", st.TunnelMode)
	}
	if st.TunnelEscalated != 4 { // 3 TG CIDRs + UDP relay ports in the default profile
		t.Fatalf("escalated rules = %d, want 4", st.TunnelEscalated)
	}
	snap := application.Snapshot()
	if snap.Tunnel == nil || snap.Tunnel.Mode != "escalated" || snap.Tunnel.EscalatedRules != 4 {
		t.Fatalf("snapshot tunnel section: %+v", snap.Tunnel)
	}
	t.Logf("escalated mode live: %d TUNNEL rules rewritten (sni→desync, cidr/port→direct)", st.TunnelEscalated)
}
