package android

// redialConn + carrier-health unit tests: the xray-refusal failover
// (live finding 2026-10-26) — a carrier that dies before its first payload
// byte must be switched away from WITH the written request replayed, and
// put on a cooldown so subsequent flows skip it (desktop orderedChain
// parity). Pure in-memory stubs, no network.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	boxLog "github.com/sagernet/sing-box/log"
)

// stubConn is a scripted net.Conn: reads drain script then EOF; writes are
// recorded for replay assertions.
type stubConn struct {
	script  []byte
	written bytes.Buffer
	off     int
	closed  bool
}

func (c *stubConn) Read(b []byte) (int, error) {
	if c.off >= len(c.script) {
		return 0, io.EOF
	}
	n := copy(b, c.script[c.off:])
	c.off += n
	return n, nil
}

func (c *stubConn) Write(b []byte) (int, error)        { return c.written.Write(b) }
func (c *stubConn) Close() error                       { c.closed = true; return nil }
func (c *stubConn) LocalAddr() net.Addr                { return nil }
func (c *stubConn) RemoteAddr() net.Addr               { return nil }
func (c *stubConn) SetDeadline(t time.Time) error      { return nil }
func (c *stubConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *stubConn) SetWriteDeadline(t time.Time) error { return nil }

func dest() netip.AddrPort { return netip.MustParseAddrPort("93.184.216.34:443") }

// stubEngine builds an engine over scripted carriers; produce[i] is called
// on every dial of carrier i and returns the conn (or error) for the flow.
func stubEngine(t *testing.T, logs *[]string, produce ...func() (net.Conn, error)) *Engine {
	t.Helper()
	e := &Engine{logFn: func(line string) {
		if logs != nil {
			*logs = append(*logs, line)
		}
	}}
	for _, p := range produce {
		p := p
		e.carriers = append(e.carriers, tcpCarrier{
			name: "stub",
			dial: func(_ context.Context, _ netip.AddrPort) (net.Conn, error) { return p() },
		})
	}
	e.health = make([]carrierHealth, len(e.carriers))
	return e
}

func ok(script string) func() (net.Conn, error) {
	return func() (net.Conn, error) { return &stubConn{script: []byte(script)}, nil }
}

func refused() func() (net.Conn, error) {
	return func() (net.Conn, error) { return nil, errors.New("refused") }
}

func TestRefusalFailoverReplaysRequest(t *testing.T) {
	var logs []string
	var c1 *stubConn
	e := stubEngine(t, &logs,
		refused(), // carrier 0: refusal EOF
		func() (net.Conn, error) { c1 = &stubConn{script: []byte("HTTP/1.1 204")}; return c1, nil },
	)

	conn, err := e.dialChain(dest())
	if err != nil {
		t.Fatalf("dialChain: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], []byte("HTTP/1.1 204")) {
		t.Fatalf("read after failover: n=%d err=%v %q", n, err, buf[:n])
	}
	// The alive carrier must have received the request bytes (replay).
	if got := c1.written.String(); got != "GET / HTTP/1.1\r\n\r\n" {
		t.Fatalf("replay missing on carrier 1: %q", got)
	}
	// The refusal must have demoted carrier 0 for cooldown.
	if e.health[0].down.Load() == 0 {
		t.Fatal("carrier 0 not demoted after refusal")
	}
	if e.health[1].down.Load() != 0 {
		t.Fatal("carrier 1 must stay healthy")
	}
}

func TestCooldownSkipsDeadCarrier(t *testing.T) {
	e := stubEngine(t, nil,
		ok(""),         // dial OK, refusal EOF on read
		ok("OK-OK-OK"), // alive
	)

	// Two refused flows put carrier 0 on cooldown and skip it afterwards.
	for i := 0; i < 2; i++ {
		conn, err := e.dialChain(dest())
		if err != nil {
			t.Fatalf("dialChain %d: %v", i, err)
		}
		buf := make([]byte, 8)
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		conn.Close()
	}
	if got := e.carrierOrder(); got[0] != 1 {
		t.Fatalf("carrierOrder after cooldown: %v, want carrier 1 first", got)
	}
}

func TestSuccessResetsAndKeepsOrder(t *testing.T) {
	e := stubEngine(t, nil,
		ok("OK-OK-OK"),
		ok("OK-OK-OK"),
	)
	conn, err := e.dialChain(dest())
	if err != nil {
		t.Fatalf("dialChain: %v", err)
	}
	buf := make([]byte, 8)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	conn.Close()
	if e.health[0].down.Load() != 0 {
		t.Fatal("healthy carrier must not be demoted")
	}
	if got := e.carrierOrder(); got[0] != 0 {
		t.Fatalf("healthy primary must stay first, got %v", got)
	}
}

// TestBenchKeepsProvenPrimaryFirst: a single pre-payload death (soft 10s
// bench) must not divert new flows into a carrier that has never delivered
// a byte — live 2026-10-29 (Rostelecom): reality worked, xhttp/hysteria2
// never returned anything, and every bench of the primary blackholed all
// traffic for 10s.
func TestBenchKeepsProvenPrimaryFirst(t *testing.T) {
	e := stubEngine(t, nil,
		ok("OK-OK-OK"), // carrier 0 delivers payload -> proven
		ok("OK-OK-OK"),
	)
	conn, err := e.dialChain(dest())
	if err != nil {
		t.Fatalf("dialChain: %v", err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 8)); err != nil {
		t.Fatalf("read: %v", err)
	}
	conn.Close()

	e.markCarrierFail(0, errors.New("pre-payload death"))
	if got := e.carrierOrder(); got[0] != 0 {
		t.Fatalf("a proven carrier on soft cooldown must stay first, got %v", got)
	}
	// The unproven secondary still gets tried right after it, and once it
	// delivers payload a live proven secondary outranks the benched primary.
	e.markCarrierSuccess(1)
	if got := e.carrierOrder(); got[0] != 1 {
		t.Fatalf("a proven healthy carrier must outrank a benched one, got %v", got)
	}
}

// TestCarrierDialTimeout: a carrier whose dial never returns must not stall
// the flow. Without the per-dial budget the SOCKS handshake deadline (10s)
// held every new connection open — the "10s and nothing loads" blackout.
func TestCarrierDialTimeout(t *testing.T) {
	old := carrierDialTimeout
	carrierDialTimeout = 100 * time.Millisecond
	defer func() { carrierDialTimeout = old }()

	hang := func(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	e := &Engine{}
	e.carriers = []tcpCarrier{{name: "blackhole", dial: hang}}
	e.health = make([]carrierHealth, 1)

	started := time.Now()
	if _, err := e.dialChain(dest()); err == nil {
		t.Fatal("a blackholed carrier must fail the dial")
	}
	if spent := time.Since(started); spent > time.Second {
		t.Fatalf("dial stalled %v, want ~%v", spent, carrierDialTimeout)
	}
}

// TestDirectTailStaysLast: the bench is a steering hint BETWEEN tunnel
// carriers. Once reality was benched, direct (proven, healthy) won rank 0 and
// every new flow went out unprotected — for the sites the tunnel exists for
// that reads as "the app died", and the hole lasted carrierCooldownSoft = 10s
// (live Android log 2026-10-29: 23:16:31 down, then blank until 23:17:13).
func TestDirectTailStaysLast(t *testing.T) {
	var logs []string
	e := stubEngine(t, &logs, ok(""), ok(""))
	e.carriers[1].name, e.carriers[1].tail = "direct", true
	// Both carriers delivered payload at some point; only reality is benched.
	e.markCarrierSuccess(0)
	e.markCarrierSuccess(1)
	e.markCarrierFail(0, errors.New("EOF"))

	order := e.carrierOrder()
	if len(order) != 2 || order[1] != 1 {
		t.Fatalf("order = %v, want direct tail last", order)
	}
	if e.health[1].down.Load() != 0 {
		t.Fatal("the escalation tail must never be benched")
	}
	for _, line := range logs {
		if strings.Contains(line, "direct: down") {
			t.Fatalf("benched the tail: %s", line)
		}
	}
}

func TestCooldownExpiryRetriesPrimary(t *testing.T) {
	e := stubEngine(t, nil,
		ok("OK"),
		ok("OK"),
	)
	// A long-expired cooldown must not affect the order.
	e.health[0].down.Store(time.Now().Add(-time.Hour).UnixNano())
	if got := e.carrierOrder(); got[0] != 0 {
		t.Fatalf("expired cooldown ignored, got %v", got)
	}
}

func TestConsecutiveFailsEscalateCooldown(t *testing.T) {
	e := stubEngine(t, nil,
		ok(""),
		ok("OK-OK-OK"),
	)
	remaining := func(idx int) time.Duration {
		d := time.Until(time.Unix(0, e.health[idx].down.Load()))
		if d < 0 {
			return 0
		}
		return d
	}
	// First pre-payload death: soft bench (~10s, not the full minute).
	e.markCarrierFail(0, io.EOF)
	if got := remaining(0); got <= 5*time.Second || got > carrierCooldownSoft {
		t.Fatalf("first fail cooldown = %v, want ~%v", got, carrierCooldownSoft)
	}
	// Second consecutive death: still soft.
	e.markCarrierFail(0, io.EOF)
	if got := remaining(0); got <= 5*time.Second || got > carrierCooldownSoft {
		t.Fatalf("second fail cooldown = %v, want ~%v", got, carrierCooldownSoft)
	}
	// Third consecutive death: the full storm bench.
	e.markCarrierFail(0, io.EOF)
	if got := remaining(0); got <= carrierCooldown-5*time.Second {
		t.Fatalf("third fail cooldown = %v, want ~%v", got, carrierCooldown)
	}
	// Any success resets the consecutive counter to soft again.
	e.markCarrierSuccess(1)
	e.markCarrierSuccess(0)
	if e.health[0].fails.Load() != 0 {
		t.Fatalf("success must reset the fail counter, got %d", e.health[0].fails.Load())
	}
	e.markCarrierFail(0, io.EOF)
	if got := remaining(0); got <= 5*time.Second || got > carrierCooldownSoft {
		t.Fatalf("post-success cooldown = %v, want ~%v", got, carrierCooldownSoft)
	}
}

func TestCarrierStatesActiveAndCooldown(t *testing.T) {
	e := stubEngine(t, nil,
		ok("OK"),
		ok("OK"),
	)
	// Fresh engine, no payload yet: carrier 0 is the head of the order.
	states := e.CarrierStates()
	if len(states) != 2 || states[0].State != "active" || states[1].State != "ready" {
		t.Fatalf("fresh states: %+v", states)
	}

	// A payload through carrier 1 commits it as active.
	e.markCarrierSuccess(1)
	states = e.CarrierStates()
	if states[1].State != "active" || states[0].State != "ready" {
		t.Fatalf("after success: %+v", states)
	}

	// The proven active carrier going on cooldown keeps the lead: the
	// unproven carrier must not be promoted into a path that never worked.
	e.health[1].down.Store(time.Now().Add(time.Minute).UnixNano())
	states = e.CarrierStates()
	if states[1].State != "active" || states[0].State != "ready" {
		t.Fatalf("benched proven carrier must keep the lead: %+v", states)
	}

	// With nothing proven yet a benched carrier is labelled "cooldown".
	fresh := stubEngine(t, nil, ok("OK"), ok("OK"))
	fresh.markCarrierFail(0, io.EOF)
	states = fresh.CarrierStates()
	if states[0].State != "cooldown" || states[1].State != "active" {
		t.Fatalf("fresh cooldown states: %+v", states)
	}

	// Expiry gives the lead back to the last committed carrier.
	e.health[1].down.Store(0)
	states = e.CarrierStates()
	if states[1].State != "active" || states[0].State != "ready" {
		t.Fatalf("after expiry: %+v", states)
	}
}

func TestReplayCapCommitsUploadFlow(t *testing.T) {
	var c1Dials int
	e := stubEngine(t, nil,
		ok(""), // carrier 0: dial OK, refusal EOF on read; the flow is upload-shaped
		func() (net.Conn, error) { c1Dials++; return &stubConn{script: []byte("OK")}, nil },
	)
	conn, err := e.dialChain(dest())
	if err != nil {
		t.Fatalf("dialChain: %v", err)
	}
	defer conn.Close()

	// 17 KB written with zero bytes received: past the replay cap — the
	// flow commits (upload), the read EOF must surface as-is.
	big := make([]byte, replayCap+1024)
	if _, err := conn.Write(big); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 8)
	if _, err := conn.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("read err after commit: %v (want EOF, no failover)", err)
	}
	if c1Dials != 0 {
		t.Fatal("upload flow must not switch carriers")
	}
}

func TestAllCarriersDownError(t *testing.T) {
	e := stubEngine(t, nil,
		refused(),
		refused(),
	)
	_, err := e.dialChain(dest())
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("all 2 carriers failed")) {
		t.Fatalf("want aggregate dial error, got %v", err)
	}
	// Both carriers must be demoted; the order still returns a full chain
	// (all cooling → plain order, the chain is never starved).
	if got := e.carrierOrder(); len(got) != 2 {
		t.Fatalf("order must keep every carrier, got %v", got)
	}
}

func TestRelayLogDropsInfoLevel(t *testing.T) {
	var lines []string
	w := &relayLogWriter{fn: func(line string) { lines = append(lines, line) }}
	w.WriteMessage(boxLog.LevelInfo, "inbound connection from 127.0.0.1:60088")
	w.WriteMessage(boxLog.LevelDebug, "debug detail")
	w.WriteMessage(boxLog.LevelWarn, "router: failed to search process")
	if len(lines) != 1 || !bytes.Contains([]byte(lines[0]), []byte("failed to search process")) {
		t.Fatalf("only warn must reach the journal, got %q", lines)
	}
}

func TestRelayLogDedupSuppressesRefusalStorm(t *testing.T) {
	var lines []string
	w := &relayLogWriter{fn: func(line string) { lines = append(lines, line) }}
	for i := 0; i < 5; i++ {
		w.WriteMessage(boxLog.LevelError, fmt.Sprintf(
			"ERROR[%04d] [%d 295ms] connection: connection download closed: unknown version: 72",
			i, 1000+i))
	}
	// A different message must pass through immediately, flushing the count.
	w.WriteMessage(boxLog.LevelWarn, "router: match[0] inbound=x => route(y)")
	// lines: the first refusal (emitted), the suppressed-flush, the router line.
	if len(lines) != 3 {
		t.Fatalf("want first + flush + passthrough, got %d: %q", len(lines), lines)
	}
	if !bytes.Contains([]byte(lines[0]), []byte("unknown version")) {
		t.Fatalf("first message missing: %q", lines[0])
	}
	if !bytes.Contains([]byte(lines[1]), []byte("4 identical")) {
		t.Fatalf("flush line missing counter: %q", lines[1])
	}
	if !bytes.Contains([]byte(lines[2]), []byte("route(y)")) {
		t.Fatalf("passthrough missing: %q", lines[2])
	}
}
