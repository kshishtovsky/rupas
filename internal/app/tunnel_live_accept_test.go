//go:build windows && live && with_utls

package app

// WAVE-6 LIVE ACCEPTANCE (strict). Two gates against the user's real VPS
// (configs/rupas.yaml, gitignored):
//
//   TestLiveMixedDirect — the mixed inbound answers DIRECT SOCKS5 always
//                         (F5: never gated by terminator storm control or
//                         HOLD); HTTP data from 1.1.1.1 and api.telegram.org;
//                         TG DC answers bytes through the carrier chain.
//   TestLiveTGFullLoop  — the FULL engine (WinDivert capture + NAT/terminator
//                         + carrier chain): TCP dial to Telegram DC2
//                         149.154.167.51:443 with STRICT rx asserts — first
//                         response bytes MUST arrive at the client socket
//                         (TCP established is NOT enough), and the tunnel rx
//                         counter MUST advance; the tunnel must stay healthy
//                         after carrying TG traffic.
//
// Run: go test ./internal/app -tags "live with_utls" -run TestLiveMixedDirect -v
//      go test ./internal/app -tags "live with_utls" -run TestLiveTGFullLoop -v
// (administrator + WinDivert driver + configs/rupas.yaml required)

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/kshishtovsky/rupas/internal/config"
	"github.com/kshishtovsky/rupas/internal/tunnel"
)

// ---------------------------------------------------------------------------
// minimal SOCKS5 client (the app package cannot use tunnel-internal helpers)
// ---------------------------------------------------------------------------

func accSocks5Connect(ctx context.Context, proxyAddr, host string, port uint16) (net.Conn, error) {
	d := net.Dialer{}
	c, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dial mixed %s: %w", proxyAddr, err)
	}
	deadline, ok := ctx.Deadline()
	if ok {
		_ = c.SetDeadline(deadline)
	}
	if _, err := c.Write([]byte{0x05, 1, 0x00}); err != nil {
		c.Close()
		return nil, fmt.Errorf("greeting write: %w", err)
	}
	var g [2]byte
	if _, err := io.ReadFull(c, g[:]); err != nil {
		c.Close()
		return nil, fmt.Errorf("greeting reply: %w", err)
	}
	if g[0] != 0x05 || g[1] != 0x00 {
		c.Close()
		return nil, fmt.Errorf("greeting reply %x", g)
	}
	var req []byte
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Is4() {
			b4 := ip.As4()
			req = append([]byte{0x05, 0x01, 0x00, 0x01}, b4[:]...)
		} else {
			b16 := ip.As16()
			req = append([]byte{0x05, 0x01, 0x00, 0x04}, b16[:]...)
		}
	} else {
		if len(host) > 255 {
			c.Close()
			return nil, errors.New("host too long")
		}
		req = append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}, host...)
	}
	req = binary.BigEndian.AppendUint16(req, port)
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, fmt.Errorf("connect write: %w", err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		c.Close()
		return nil, fmt.Errorf("connect reply head: %w", err)
	}
	if head[1] != 0x00 {
		c.Close()
		return nil, fmt.Errorf("socks5 reply code %d", head[1])
	}
	var tailErr error
	switch head[3] {
	case 0x01:
		_, tailErr = io.ReadFull(c, make([]byte, 4+2))
	case 0x04:
		_, tailErr = io.ReadFull(c, make([]byte, 16+2))
	case 0x03:
		var l [1]byte
		if _, tailErr = io.ReadFull(c, l[:]); tailErr == nil {
			_, tailErr = io.ReadFull(c, make([]byte, int(l[0])+2))
		}
	default:
		tailErr = fmt.Errorf("bad atyp %d", head[3])
	}
	if tailErr != nil {
		c.Close()
		return nil, fmt.Errorf("connect reply tail: %w", tailErr)
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

// accSocks5Greeting verifies ONLY the SOCKS5 greeting exchange — no
// upstream connection is opened (F5: the mixed port itself must always
// answer, regardless of carrier health or storm state).
func accSocks5Greeting(proxyAddr string, timeout time.Duration) error {
	c, err := net.DialTimeout("tcp", proxyAddr, timeout)
	if err != nil {
		return fmt.Errorf("dial mixed %s: %w", proxyAddr, err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write([]byte{0x05, 1, 0x00}); err != nil {
		return fmt.Errorf("greeting write: %w", err)
	}
	var g [2]byte
	if _, err := io.ReadFull(c, g[:]); err != nil {
		return fmt.Errorf("greeting reply: %w", err)
	}
	if g[0] != 0x05 || g[1] != 0x00 {
		return fmt.Errorf("greeting reply %x", g)
	}
	return nil
}

// accHTTPGet fetches "http://host:port/" through the SOCKS5 proxy and
// returns the first status line; STRICT callers assert a valid HTTP/1.x
// status (bytes received).
func accHTTPGet(ctx context.Context, proxyAddr, host string, port uint16) (string, int, error) {
	c, err := accSocks5Connect(ctx, proxyAddr, host, port)
	if err != nil {
		return "", 0, err
	}
	defer c.Close()
	req := "GET / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: curl/8.0\r\nConnection: close\r\n\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		return "", 0, fmt.Errorf("write: %w", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
	buf := make([]byte, 4096)
	n, rerr := c.Read(buf)
	if n == 0 {
		return "", 0, fmt.Errorf("no response bytes (read err=%v)", rerr)
	}
	line := string(buf[:min(n, 32)])
	for i := range line {
		if line[i] == '\r' || line[i] == '\n' {
			line = line[:i]
			break
		}
	}
	return line, n, nil
}

// accTGBytes CONNECTs to the TG DC and proves RESPONSE BYTES: a completed
// TLS handshake OR crypto/tls RecordHeaderError (TG :443 fake-TLS answers
// every ClientHello with non-TLS bytes) both count; timeout/EOF do not.
func accTGBytes(ctx context.Context, proxyAddr string) (int, time.Duration, error) {
	t0 := time.Now()
	raw, err := accSocks5Connect(ctx, proxyAddr, "149.154.167.51", 443)
	if err != nil {
		return 0, time.Since(t0), err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
	tc := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "149.154.167.51",
		MinVersion:         tls.VersionTLS12,
	})
	herr := tc.Handshake()
	d := time.Since(t0)
	if herr == nil {
		st := tc.ConnectionState()
		_ = tc.Close()
		return 1 + int(st.CipherSuite%1000), d, nil // handshake completed: many bytes flowed
	}
	var rhe tls.RecordHeaderError
	if errors.As(herr, &rhe) {
		// Non-TLS first record received FROM TELEGRAM: rx bytes proven.
		return 1, d, nil
	}
	return 0, d, fmt.Errorf("no response bytes from TG DC: %w", herr)
}

// ---------------------------------------------------------------------------
// (a) mixed-direct gate (F5)
// ---------------------------------------------------------------------------

func TestLiveMixedDirect(t *testing.T) {
	plan := loadUserPlan(t)
	if plan.TCP == nil {
		t.Fatal("configs/rupas.yaml has no tcp endpoint")
	}
	os.Setenv("RUPAS_TUNNEL_SBLOG", "1")
	defer os.Unsetenv("RUPAS_TUNNEL_SBLOG")

	tproxy := freeTCPPort(t)
	provider := &stubNAT{}
	t0 := time.Now()
	tun := tunnel.NewTunnel(plan, tproxy, tunnel.Options{
		OriginalDstProvider: provider,
		MarkerURL:           tunnel.DefaultMarkerURL,
		Logger:              liveTunnelLogger(),
		HealthInterval:      8 * time.Second,
		DialTimeout:         15 * time.Second,
		NoHoldFlows:         true,
		// Wave 6: TG CIDRs must try the fallback carrier first (the app
		// fills this from the config rules in production).
		TCPFallbackFirstCIDRs: []netip.Prefix{
			netip.MustParsePrefix("149.154.160.0/20"),
			netip.MustParsePrefix("91.108.0.0/16"),
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := tun.Start(ctx); err != nil {
		t.Fatalf("tunnel start: %v", err)
	}
	defer func() { _ = tun.Stop() }()

	// Carrier chain must answer the marker (vless or hy2 fallback).
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) && !tun.Healthy() {
		time.Sleep(300 * time.Millisecond)
	}
	if !tun.Healthy() {
		t.Fatalf("marker never passed within 60s (stats %+v)", tun.Stats())
	}

	st := tun.Stats()
	mixed := st.MixedAddr
	if mixed == "" {
		t.Fatalf("Stats().MixedAddr empty — no main mixed inbound (stats %+v)", st)
	}
	t.Logf("tunnel healthy after %v; mixed inbound %s", time.Since(t0).Round(time.Millisecond), mixed)

	// F5 GATE 1: direct SOCKS5 greeting answered FAST (never gated by the
	// terminator storm control / HOLD — different layers). Greeting only:
	// no upstream carrier connection is opened.
	if err := accSocks5Greeting(mixed, 3*time.Second); err != nil {
		t.Fatalf("F5: direct SOCKS5 greeting through mixed %s failed within 3s: %v", mixed, err)
	}

	// STRICT: HTTP data from 1.1.1.1 and api.telegram.org through mixed.
	hctx, hcancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer hcancel()
	line, n, err := accHTTPGet(hctx, mixed, "1.1.1.1", 80)
	if err != nil || n == 0 {
		t.Errorf("MIXED DIRECT 1.1.1.1: no data: %v", err)
	} else if !httpStatusOK(line) {
		t.Errorf("MIXED DIRECT 1.1.1.1: bad status line %q", line)
	} else {
		t.Logf("MIXED DIRECT 1.1.1.1: %q (%d bytes)", line, n)
	}

	line, n, err = accHTTPGet(hctx, mixed, "api.telegram.org", 80)
	if err != nil || n == 0 {
		t.Errorf("MIXED DIRECT api.telegram.org: no data: %v", err)
	} else if !httpStatusOK(line) {
		t.Errorf("MIXED DIRECT api.telegram.org: bad status line %q", line)
	} else {
		t.Logf("MIXED DIRECT api.telegram.org: %q (%d bytes)", line, n)
	}

	// STRICT: the TG DC answers BYTES through the TUNNEL CHAIN (tproxy
	// listener + paced dialOrder: TG CIDR → fallback carrier first, so no
	// vless connection is burned — wave 6).
	tcConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", tproxy), 5*time.Second)
	if err != nil {
		t.Fatalf("tproxy dial: %v", err)
	}
	src := tcConn.LocalAddr().(*net.TCPAddr)
	provider.add(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(src.Port)), netip.MustParseAddrPort("149.154.167.51:443"))
	_ = tcConn.SetDeadline(time.Now().Add(25 * time.Second))
	tlsTG := tls.Client(tcConn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "149.154.167.51",
		MinVersion:         tls.VersionTLS12,
	})
	herr := tlsTG.Handshake()
	var rhe tls.RecordHeaderError
	switch {
	case herr == nil:
		_ = tlsTG.Close()
		t.Logf("CHAIN TG 149.154.167.51:443: TLS handshake completed — rx bytes proven")
	case errors.As(herr, &rhe):
		tcConn.Close()
		t.Logf("CHAIN TG 149.154.167.51:443: TG answered non-TLS bytes (fake-TLS MTProto) — rx bytes proven")
	default:
		tcConn.Close()
		t.Errorf("CHAIN TG 149.154.167.51:443: ZERO response bytes: %v (stats %+v)", herr, tun.Stats())
	}

	// F5 GATE 2 (storm): 10 rapid greeting rounds — every one must get the
	// SOCKS greeting reply within 2s (no silent accept-drop; zero upstream
	// connections, so this also proves storm silence is impossible).
	for i := 0; i < 10; i++ {
		if err := accSocks5Greeting(mixed, 2*time.Second); err != nil {
			t.Fatalf("F5 storm round %d: mixed went silent: %v", i, err)
		}
	}
	t.Logf("F5 OK: 10/10 rapid mixed greeting rounds answered")

	final := tun.Stats()
	t.Logf("final stats: healthy=%v flows=%d rx=%d tx=%d mixed=%s",
		final.Healthy, final.TCPFlows, final.RxBytes, final.TxBytes, final.MixedAddr)
}

func httpStatusOK(line string) bool {
	if len(line) < 12 {
		return false
	}
	return (line[:7] == "HTTP/1." || line[:6] == "HTTP/2") && line[8] == ' '
}

// ---------------------------------------------------------------------------
// (b) full-engine TG loop (strict rx)
// ---------------------------------------------------------------------------

func TestLiveTGFullLoop(t *testing.T) {
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

	logger := log.New(os.Stderr, "e2e-tg6 ", log.LstdFlags|log.Lmicroseconds)
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
	waitFor(t, "tunnel healthy through the user VPS", 60*time.Second, func() bool {
		ts := application.Stats().Tunnel
		return ts != nil && ts.Healthy
	})
	t.Logf("pipeline ACTIVE, tunnel healthy after %v; dialing %s through the FULL engine",
		time.Since(t0).Round(time.Millisecond), tgDC2)

	// F5 (full-engine): direct mixed greeting while the engine intercepts
	// (greeting only — the port itself must never go silent).
	mixed := application.Stats().Tunnel.MixedAddr
	if mixed == "" {
		t.Fatalf("no mixed addr in tunnel stats: %+v", application.Stats().Tunnel)
	}
	if err := accSocks5Greeting(mixed, 5*time.Second); err != nil {
		t.Errorf("F5 full-engine: direct mixed %s silent: %v", mixed, err)
	} else {
		t.Logf("F5 full-engine: direct mixed %s answers while engine ACTIVE", mixed)
	}

	rxBefore := application.Stats().Tunnel.RxBytes
	flowsBefore := application.Stats().Tunnel.TCPFlows

	// THE dial: engine fast-path → terminator → carrier chain (fallback
	// first for the TG CIDR) → real Telegram DC. STRICT: bytes must come
	// BACK to the client socket — established is not enough.
	dialT0 := time.Now()
	conn, err := net.DialTimeout("tcp", tgDC2, 25*time.Second)
	if err != nil {
		t.Fatalf("TG dial through the full engine failed after %v: %v (tunnel %+v)",
			time.Since(dialT0), application.Stats().Tunnel, err)
	}
	defer conn.Close()
	dialDur := time.Since(dialT0)

	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	tc := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "149.154.167.51",
		MinVersion:         tls.VersionTLS12,
	})
	herr := tc.Handshake()
	var rhe tls.RecordHeaderError
	switch {
	case herr == nil:
		cst := tc.ConnectionState()
		t.Logf("TG FULL LOOP: TLS handshake completed through the engine in %v (cipher %d) — rx bytes proven",
			time.Since(dialT0).Round(time.Millisecond), cst.CipherSuite)
		_ = tc.Close()
	case errors.As(herr, &rhe):
		t.Logf("TG FULL LOOP: TG answered non-TLS bytes (fake-TLS MTProto) in %v — rx bytes proven",
			time.Since(dialT0).Round(time.Millisecond))
	default:
		t.Fatalf("TG FULL LOOP FAILED: TCP established in %v but ZERO response bytes: %v (tunnel %+v)",
			dialDur.Round(time.Millisecond), herr, application.Stats().Tunnel)
	}

	// STRICT counters: the tunnel relay counted the flow AND the bytes.
	ts := application.Stats().Tunnel
	if ts.TCPFlows <= flowsBefore {
		t.Errorf("tunnel TCPFlows did not advance: before=%d after=%d", flowsBefore, ts.TCPFlows)
	}
	if ts.RxBytes <= rxBefore {
		t.Errorf("tunnel RxBytes did not advance (rx before=%d after=%d) — no return traffic counted", rxBefore, ts.RxBytes)
	} else {
		t.Logf("tunnel rx advanced: %d → %d bytes", rxBefore, ts.RxBytes)
	}
	// The terminator path feeds packets (TunnelTx), not NAT redirects
	// (PacketsRedir is the legacy tproxy-leg counter).
	if cs := application.Stats().Counters; cs.PacketsRedir == 0 && cs.TunnelTx == 0 {
		t.Errorf("engine recorded no tunnel-verdict packets: %+v", cs)
	}

	// The carrier must survive TG traffic: marker healthy within 30s.
	deadlineH := time.Now().Add(30 * time.Second)
	sawHealthy := false
	for time.Now().Before(deadlineH) {
		if ts := application.Stats().Tunnel; ts != nil && ts.Healthy {
			sawHealthy = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !sawHealthy {
		t.Errorf("tunnel went unhealthy after carrying TG traffic: %+v", application.Stats().Tunnel)
	}

	// Second dial (the TG client always reconnects): TG's fake-TLS
	// responder rate-limits rapid probes from one exit (~1 in 5 answers
	// EOF — live-verified), so retry a few times: at least ONE must
	// deliver bytes.
	secondOK := false
	for attempt := 0; attempt < 3 && !secondOK; attempt++ {
		conn2, err := net.DialTimeout("tcp", tgDC2, 25*time.Second)
		if err != nil {
			t.Logf("TG second dial attempt %d: dial err %v", attempt, err)
			continue
		}
		_ = conn2.SetDeadline(time.Now().Add(12 * time.Second))
		tc2 := tls.Client(conn2, &tls.Config{InsecureSkipVerify: true, ServerName: "149.154.167.51", MinVersion: tls.VersionTLS12})
		herr2 := tc2.Handshake()
		var rhe2 tls.RecordHeaderError
		switch {
		case herr2 == nil:
			_ = tc2.Close()
			secondOK = true
			t.Logf("TG second dial: full TLS handshake — rx ok (attempt %d)", attempt)
		case errors.As(herr2, &rhe2):
			secondOK = true
			t.Logf("TG second dial: non-TLS answer bytes — rx ok (attempt %d)", attempt)
		default:
			t.Logf("TG second dial attempt %d: no bytes (%v) — TG fake-TLS rate limit, retrying", attempt, herr2)
		}
		conn2.Close()
		if !secondOK {
			time.Sleep(1500 * time.Millisecond)
		}
	}
	if !secondOK {
		t.Errorf("TG second dial: ZERO response bytes after 3 attempts (tunnel %+v)", application.Stats().Tunnel)
	}

	if err := application.Supervisor().Off(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "pipeline stop", 15*time.Second, func() bool { return !application.Stats().Running })
}
