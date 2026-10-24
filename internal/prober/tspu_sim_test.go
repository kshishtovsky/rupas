package prober

// Local TSPU emulator (SYSTEM_DESIGN §12 "Integration: эмулятор ТСПУ"):
// a TCP endpoint that reads the ClientHello, parses the SNI via
// internal/inspector and, per policy, either completes a real TLS
// handshake (allowed), holds the connection silently (SNI blackhole —
// the probe times out after CH, lab fact) or aborts with RST
// (RST-inject mode); plus UDP endpoints that answer (alive) or stay
// silent (dead). Everything runs on 127.0.0.1 — no Internet access.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/rupas/rupas/internal/inspector"
)

// tspu is the emulator instance.
type tspu struct {
	t *testing.T

	blackhole map[string]bool // sni → silent drop after CH (timeout)
	rst       map[string]bool // sni → RST right after CH

	ln         net.Listener
	tcpPort    uint16
	udpAlive   uint16
	udpDead    uint16
	tlsCfg     *tls.Config
	packetConns []net.PacketConn

	mu       sync.Mutex
	stopping bool
	held     map[net.Conn]struct{} // silently held blackhole conns
	wg       sync.WaitGroup
}

// startTSPU launches the emulator on loopback with the lab-derived
// policies and registers cleanup with t.
func startTSPU(t *testing.T) *tspu {
	t.Helper()
	e := &tspu{
		t: t,
		blackhole: map[string]bool{
			"www.youtube.com": true, // lab: timeout after CH
			"manifest.googlevideo.com": true,
		},
		rst: map[string]bool{
			"discord.com": true, // RST-inject mode
		},
		held: make(map[net.Conn]struct{}),
	}
	e.tlsCfg = selfSignedTLSConfig(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tspu: tcp listen: %v", err)
	}
	e.ln = ln
	e.tcpPort = uint16(ln.Addr().(*net.TCPAddr).Port)
	e.wg.Add(1)
	go e.acceptLoop(ln)

	e.udpAlive = e.listenUDP(true)
	e.udpDead = e.listenUDP(false)

	t.Cleanup(e.stop)
	return e
}

// listenUDP binds a UDP socket that answers STUN requests (alive) or
// swallows them silently (dead) and returns its port.
func (e *tspu) listenUDP(alive bool) uint16 {
	e.t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		e.t.Fatalf("tspu: udp listen: %v", err)
	}
	e.packetConns = append(e.packetConns, pc)
	e.wg.Add(1)
	go e.udpLoop(pc, alive)
	return uint16(pc.LocalAddr().(*net.UDPAddr).Port)
}

func (e *tspu) stop() {
	e.mu.Lock()
	e.stopping = true
	held := make([]net.Conn, 0, len(e.held))
	for c := range e.held {
		held = append(held, c)
	}
	e.mu.Unlock()
	_ = e.ln.Close()
	for _, pc := range e.packetConns {
		_ = pc.Close()
	}
	for _, c := range held {
		_ = c.Close()
	}
	e.wg.Wait()
}

func (e *tspu) acceptLoop(ln net.Listener) {
	defer e.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		e.mu.Lock()
		if e.stopping {
			e.mu.Unlock()
			conn.Close()
			return
		}
		e.wg.Add(1)
		e.mu.Unlock()
		go e.handle(conn)
	}
}

// handle reads one ClientHello, classifies by SNI and applies the
// policy: hold / RST / complete a real TLS handshake.
func (e *tspu) handle(conn net.Conn) {
	defer e.wg.Done()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	s := inspector.NewStream()
	buf := make([]byte, 4096)
	var pre []byte
	var sni string
	for len(pre) < 16<<10 {
		n, err := conn.Read(buf)
		if n > 0 {
			pre = append(pre, buf[:n]...)
			res, perr := s.Feed(buf[:n])
			if res.SNIFound {
				sni = string(res.SNI)
				break
			}
			if perr != nil && !errors.Is(perr, inspector.ErrNeedMore) {
				break // not a TLS ClientHello
			}
		}
		if err != nil {
			return // client vanished before a full CH
		}
	}
	switch {
	case e.blackhole[sni]:
		// Silent drop: no FIN, no RST, no response — the probe must hit
		// its handshake deadline (lab SNI-blackhole signature).
		e.mu.Lock()
		e.held[conn] = struct{}{}
		e.mu.Unlock()
	case e.rst[sni]:
		// Injected RST: abortive close fires immediately after the CH.
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		_ = conn.Close()
	default:
		e.serveTLS(conn, pre)
	}
}

// serveTLS replays the already-consumed ClientHello bytes into a real
// crypto/tls server handshake (the "allowed" path).
func (e *tspu) serveTLS(conn net.Conn, pre []byte) {
	tc := tls.Server(&prefixedConn{Conn: conn, pre: pre}, e.tlsCfg)
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	_ = tc.Handshake()
	_ = tc.Close()
}

func (e *tspu) udpLoop(pc net.PacketConn, alive bool) {
	defer e.wg.Done()
	buf := make([]byte, 2048)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if !alive {
			continue // silent drop
		}
		if n < 20 {
			continue // not a STUN-ish request
		}
		// STUN binding success response: 0x0101, len 0, magic + txid.
		resp := make([]byte, 16)
		resp[0], resp[1], resp[2], resp[3] = 0x01, 0x01, 0x00, 0x00
		copy(resp[4:16], buf[4:16])
		_, _ = pc.WriteTo(resp, addr)
	}
}

// prefixedConn replays bytes already read from the connection before the
// TLS server takes over.
type prefixedConn struct {
	net.Conn
	pre []byte
}

func (c *prefixedConn) Read(p []byte) (int, error) {
	if len(c.pre) > 0 {
		n := copy(p, c.pre)
		c.pre = c.pre[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func selfSignedTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("tspu: keygen: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tspu-sim"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("tspu: cert: %v", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

// testClassifier returns a fast-paced classifier against loopback.
func testClassifier(tr Transport) *Classifier {
	c := NewClassifier(tr)
	c.TLSPort = 0 // set per-test
	c.HandshakeTimeout = 500 * time.Millisecond
	c.AttemptDelay = 20 * time.Millisecond
	c.UDPTimeout = 300 * time.Millisecond
	c.UDPAttempts = 2
	return c
}

func TestClassifierAgainstTSPU(t *testing.T) {
	e := startTSPU(t)
	c := testClassifier(&RealTransport{Timeout: 2 * time.Second})
	c.TLSPort = e.tcpPort

	t.Run("allowed SNI completes browser-like handshake", func(t *testing.T) {
		if v := c.ProbeSNI("127.0.0.1", "github.com"); v != SNIOpen {
			t.Fatalf("ProbeSNI(github.com) = %v, want SNIOpen", v)
		}
	})
	t.Run("blackholed SNI times out after ClientHello", func(t *testing.T) {
		if v := c.ProbeSNI("127.0.0.1", "www.youtube.com"); v != SNIDrop {
			t.Fatalf("ProbeSNI(www.youtube.com) = %v, want SNIDrop", v)
		}
	})
	t.Run("RST-injected SNI resets fast", func(t *testing.T) {
		rep := c.ProbeSNIContext(context.Background(), "127.0.0.1", "discord.com")
		if rep.Verdict != SNIRSTInject {
			t.Fatalf("verdict = %v, want SNIRSTInject (attempts: %+v)", rep.Verdict, rep.Attempts)
		}
		for i, a := range rep.Attempts {
			if a.DialErr != "" {
				continue
			}
			if !a.Reset || a.Elapsed >= c.HandshakeTimeout {
				t.Fatalf("attempt %d: reset=%v elapsed=%v, want fast reset", i, a.Reset, a.Elapsed)
			}
		}
	})
	t.Run("open TCP port", func(t *testing.T) {
		if v := c.ProbeIP("127.0.0.1", e.tcpPort); v != IPOpen {
			t.Fatalf("ProbeIP(open) = %v, want IPOpen", v)
		}
	})
	t.Run("UDP alive answers STUN", func(t *testing.T) {
		if !c.ProbeUDP("127.0.0.1", e.udpAlive) {
			t.Fatal("ProbeUDP(alive) = false, want true")
		}
	})
	t.Run("UDP dead stays silent", func(t *testing.T) {
		if c.ProbeUDP("127.0.0.1", e.udpDead) {
			t.Fatal("ProbeUDP(dead) = true, want false")
		}
	})
}

// funcTransport lets tests mix real loopback dials with scripted errors.
type funcTransport struct {
	dial func(ip string, port uint16) (Conn, error)
}

func (f funcTransport) Dial(ip string, port uint16) (Conn, error) {
	return f.dial(ip, port)
}

func TestProbeIPVerdicts(t *testing.T) {
	t.Run("timeout dial yields SynDrop", func(t *testing.T) {
		c := testClassifier(funcTransport{func(string, uint16) (Conn, error) {
			return nil, timeoutErr()
		}})
		c.AttemptDelay = 0
		if v := c.ProbeIP("192.0.2.1", 443); v != IPSynDrop {
			t.Fatalf("ProbeIP(timeout) = %v, want IPSynDrop", v)
		}
	})
	t.Run("refused dial yields Unknown", func(t *testing.T) {
		c := testClassifier(funcTransport{func(string, uint16) (Conn, error) {
			return nil, errors.New("dial tcp: connection refused")
		}})
		c.AttemptDelay = 0
		if v := c.ProbeIP("127.0.0.1", 1); v != IPUnknown {
			t.Fatalf("ProbeIP(refused) = %v, want IPUnknown", v)
		}
	})
	t.Run("successful dial yields Open", func(t *testing.T) {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		c := testClassifier(funcTransport{func(string, uint16) (Conn, error) {
			return a, nil
		}})
		c.AttemptDelay = 0
		if v := c.ProbeIP("127.0.0.1", 443); v != IPOpen {
			t.Fatalf("ProbeIP(open) = %v, want IPOpen", v)
		}
	})
}

func timeoutErr() error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: errDeadline{}}
}

type errDeadline struct{}

func (errDeadline) Error() string   { return "i/o timeout" }
func (errDeadline) Timeout() bool   { return true }
func (errDeadline) Temporary() bool { return true }

func TestClassifyParallel(t *testing.T) {
	e := startTSPU(t)
	real := &RealTransport{Timeout: 2 * time.Second}
	// The IP blackhole is scripted: 192.0.2.1 always times out (a SYN
	// drop cannot be reproduced on loopback).
	tr := funcTransport{func(ip string, port uint16) (Conn, error) {
		if ip == "192.0.2.1" {
			return nil, timeoutErr()
		}
		return real.Dial(ip, port)
	}}
	c := testClassifier(tr)
	c.TLSPort = e.tcpPort

	targets := Targets{
		SNI: []SNITarget{
			{IP: "127.0.0.1", SNI: "www.youtube.com"},
			{IP: "127.0.0.1", SNI: "discord.com"},
			{IP: "127.0.0.1", SNI: "github.com"},
		},
		IP: []IPTarget{
			{IP: "127.0.0.1", Port: e.tcpPort},
			{IP: "192.0.2.1", Port: 443},
		},
		UDP: []UDPEndpoint{
			{IP: "127.0.0.1", Port: e.udpAlive},
			{IP: "127.0.0.1", Port: e.udpDead},
		},
	}
	res := c.Classify(context.Background(), targets)

	if len(res.SNIBlocked) != 2 {
		t.Fatalf("SNIBlocked = %v, want both blocked names", res.SNIBlocked)
	}
	got := map[string]bool{}
	for _, s := range res.SNIBlocked {
		got[s] = true
	}
	if !got["www.youtube.com"] || !got["discord.com"] {
		t.Fatalf("SNIBlocked = %v, want youtube+discord", res.SNIBlocked)
	}
	if len(res.IPBlackhole) != 1 || res.IPBlackhole[0] != "192.0.2.1" {
		t.Fatalf("IPBlackhole = %v, want [192.0.2.1]", res.IPBlackhole)
	}
	if len(res.UDPDead) != 1 || res.UDPDead[0].Port != e.udpDead {
		t.Fatalf("UDPDead = %v, want dead endpoint", res.UDPDead)
	}
	if res.CheckedAt.IsZero() {
		t.Fatal("CheckedAt not set")
	}
}

// mockInjector models the lab TTL window: success(t) = t >= threshold,
// strictly monotone (threshold 12 reproduces the measured window [12,∞)).
type mockInjector struct {
	threshold int
	mu        sync.Mutex
	calls     []int
}

func (m *mockInjector) InjectAndHandshake(ip, sni string, fakeTTL uint8) (bool, error) {
	m.mu.Lock()
	m.calls = append(m.calls, int(fakeTTL))
	m.mu.Unlock()
	return int(fakeTTL) >= m.threshold, nil
}

func (m *mockInjector) callCount(ttl int) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, c := range m.calls {
		if c == ttl {
			n++
		}
	}
	return n
}

func TestCalibrateTTLLabWindow(t *testing.T) {
	m := &mockInjector{threshold: 12} // lab: fake TTL window [12,∞)
	cal, err := CalibrateTTL(context.Background(), m, "142.251.153.4", "www.youtube.com", DefaultTTLOptions())
	if err != nil {
		t.Fatalf("CalibrateTTL: %v", err)
	}
	if cal.Star != 12 {
		t.Fatalf("Star = %d, want 12 (lab t*)", cal.Star)
	}
	if cal.Effective != 14 { // 12 + margin 2
		t.Fatalf("Effective = %d, want 14", cal.Effective)
	}
	if !cal.Verified {
		t.Fatal("Verified = false, want true (success(11) must fail)")
	}
	if cal.Iterations > DefaultTTLIterations {
		t.Fatalf("Iterations = %d, budget is %d", cal.Iterations, DefaultTTLIterations)
	}
	m.mu.Lock()
	calls := append([]int(nil), m.calls...)
	m.mu.Unlock()
	for _, c := range calls {
		if c < DefaultTTLLo || c > DefaultTTLHi {
			t.Fatalf("probe outside [1,32]: %d", c)
		}
	}
	// Working points must be confirmed 3/3; a failing point aborts its
	// evaluation after one attempt (TTL 11 fails twice: once during the
	// search and once during the minimality verification).
	for _, ok := range []int{DefaultTTLHi, 16, 12} {
		if n := m.callCount(ok); n != 3 {
			t.Fatalf("TTL %d evaluated %d times, want 3 (3/3 criterion)", ok, n)
		}
	}
	if n := m.callCount(11); n != 2 {
		t.Fatalf("TTL 11 evaluated %d times, want 2 (fail-fast in search + verification)", n)
	}
}

func TestCalibrateTTLEdgeCases(t *testing.T) {
	t.Run("no window", func(t *testing.T) {
		m := &mockInjector{threshold: 33} // nothing ever works
		_, err := CalibrateTTL(context.Background(), m, "1.2.3.4", "sni", DefaultTTLOptions())
		if !errors.Is(err, ErrNoTTLWindow) {
			t.Fatalf("err = %v, want ErrNoTTLWindow", err)
		}
	})
	t.Run("unwired injector aborts", func(t *testing.T) {
		_, err := CalibrateTTL(context.Background(), UnwiredInjector{}, "1.2.3.4", "sni", DefaultTTLOptions())
		if !errors.Is(err, ErrNotWired) {
			t.Fatalf("err = %v, want ErrNotWired", err)
		}
	})
	t.Run("margin zero", func(t *testing.T) {
		opt := DefaultTTLOptions()
		opt.Margin = 0
		cal, err := CalibrateTTL(context.Background(), &mockInjector{threshold: 12}, "1.2.3.4", "sni", opt)
		if err != nil {
			t.Fatalf("CalibrateTTL: %v", err)
		}
		if cal.Effective != cal.Star {
			t.Fatalf("Effective = %d, want == Star %d", cal.Effective, cal.Star)
		}
	})
	t.Run("effective clamped to Hi", func(t *testing.T) {
		opt := DefaultTTLOptions()
		opt.Margin = 5
		opt.Hi = 20
		cal, err := CalibrateTTL(context.Background(), &mockInjector{threshold: 18}, "1.2.3.4", "sni", opt)
		if err != nil {
			t.Fatalf("CalibrateTTL: %v", err)
		}
		if cal.Star != 18 || cal.Effective != 20 {
			t.Fatalf("Star=%d Effective=%d, want 18/20 (clamped)", cal.Star, cal.Effective)
		}
	})
	t.Run("budget exhaustion keeps a working star", func(t *testing.T) {
		opt := DefaultTTLOptions()
		opt.MaxIterations = 2 // window check + one search step only
		cal, err := CalibrateTTL(context.Background(), &mockInjector{threshold: 12}, "1.2.3.4", "sni", opt)
		if err != nil {
			t.Fatalf("CalibrateTTL: %v", err)
		}
		if cal.Star < 12 {
			t.Fatalf("Star = %d, want a value that satisfies the criterion (>=12)", cal.Star)
		}
		if cal.Verified {
			t.Fatal("Verified = true with exhausted budget, want false")
		}
	})
	t.Run("context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := CalibrateTTL(ctx, &mockInjector{threshold: 12}, "1.2.3.4", "sni", DefaultTTLOptions())
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	})
}

func TestToDesyncParams(t *testing.T) {
	t.Run("calibrated window selects fake", func(t *testing.T) {
		r := &Result{TTL: 14, TTLMargin: 2}
		p := r.ToDesyncParams()
		if p.Strategy != StrategyFake {
			t.Fatalf("strategy = %q, want fake", p.Strategy)
		}
		if p.TTL != 14 || p.TTLMargin != 2 || p.Repeats != DefaultRepeats || p.FakeTemplate != DefaultFakeTemplate {
			t.Fatalf("params = %+v", p)
		}
	})
	t.Run("no window falls back to fake_split", func(t *testing.T) {
		r := &Result{}
		p := r.ToDesyncParams()
		if p.Strategy != StrategyFakeSplit {
			t.Fatalf("strategy = %q, want fake_split", p.Strategy)
		}
		if p.TTL != 0 {
			t.Fatalf("TTL = %d, want 0 (uncalibrated signal)", p.TTL)
		}
	})
	t.Run("explicit strategy preserved", func(t *testing.T) {
		r := &Result{TTL: 14, Strategy: "multisplit"}
		if p := r.ToDesyncParams(); p.Strategy != "multisplit" {
			t.Fatalf("strategy = %q, want multisplit", p.Strategy)
		}
	})
}

func TestResultApplyCalibration(t *testing.T) {
	r := &Result{}
	r.ApplyCalibration(Calibration{Star: 12, Effective: 14, Margin: 2})
	if r.TTL != 14 || r.TTLMargin != 2 || r.Strategy != StrategyFake {
		t.Fatalf("result = %+v", r)
	}
}

// TestBrowserLikeClientHello pins the probe fingerprint: the emulator
// only accepts the handshake when the CH parses as TLS with SNI via
// internal/inspector — this exercises the uTLS path end to end.
func TestBrowserLikeClientHello(t *testing.T) {
	e := startTSPU(t)
	c := testClassifier(&RealTransport{Timeout: 2 * time.Second})
	c.TLSPort = e.tcpPort
	rep := c.ProbeSNIContext(context.Background(), "127.0.0.1", "vk.ru")
	if rep.Verdict != SNIOpen {
		t.Fatalf("verdict = %v, want SNIOpen; attempts: %+v", rep.Verdict, rep.Attempts)
	}
	if len(rep.Attempts) != 1 || rep.Attempts[0].HandshakeErr != "" {
		t.Fatalf("expected one clean attempt, got %+v", rep.Attempts)
	}
	// The emulator routed vk.ru through the TLS-server branch precisely
	// because internal/inspector parsed a server_name out of the uTLS
	// ClientHello; unknown/unparsed traffic would not complete.
}
