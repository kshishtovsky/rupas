//go:build windows

package capture

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rupas/rupas/internal/config"
	"github.com/rupas/rupas/internal/core"
	"github.com/rupas/rupas/internal/rules"
	"github.com/rupas/rupas/pkg/windivert"
)

// ---------------------------------------------------------------------------
// Wave 9: send failures must be observable and self-healing.
//
// A refused WinDivert send means the packet is GONE — for DIRECT traffic
// that is silent loss, TCP retransmits and the owner's "network freezes for
// a few seconds, then recovers". The old code bumped a counter nobody read.
// ---------------------------------------------------------------------------

// failTransport refuses every Send and records FixChecksums calls.
type failTransport struct {
	mu      sync.Mutex
	sends   int
	err     error
	healthy bool
}

func (f *failTransport) RecvBatch([][]byte, []windivert.Address) (int, error) {
	return 0, ErrStopped
}

func (f *failTransport) Send([]byte, *windivert.Address) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sends++
	if f.healthy {
		return nil
	}
	if f.err == nil {
		f.err = errors.New("windivert: send queue full")
	}
	return f.err
}

func (f *failTransport) FixChecksums([]byte, *windivert.Address) error { return nil }
func (f *failTransport) Shutdown() error                               { return nil }
func (f *failTransport) Close() error                                  { return nil }

// captureLogger swaps the default slog logger for a buffer-backed one and
// returns the buffer plus a restore func.
func captureLogger(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&lockedWriter{buf: &buf}, &slog.HandlerOptions{Level: slog.LevelDebug})))
	return &buf, func() { slog.SetDefault(prev) }
}

// lockedWriter serialises buffer writes (the engine may log from any
// goroutine).
type lockedWriter struct {
	mu  sync.Mutex
	buf *bytes.Buffer
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func newSendFailEngine(t *testing.T, tr Transport) *Engine {
	t.Helper()
	cfg := &config.Config{
		Profile: "test",
		Rules:   []config.Rule{{Action: config.ActionDirect}},
		Desync:  testDesyncParams("fake", 0),
	}
	tbl, err := rules.Compile(cfg)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	e, err := New(Options{
		Rules:        tbl,
		Desync:       testDesyncParams("fake", 0),
		FakeTemplate: testFakeTemplate,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e.InjectTransport(tr, nil)
	return e
}

func testPkt() []byte {
	return buildTCP(testClientIP, testClientPort, testServerIP, 443, 1000, 2000, 0x18, []byte("hello"))
}

// TestSendFailuresBurstWarnsAndPauses: a run of failures trips exactly one
// rate-limited WARN per burst, counts every failure and takes one catch-up
// pause per burst.
func TestSendFailuresBurstWarnsAndPauses(t *testing.T) {
	logs, restore := captureLogger(t)
	defer restore()

	tr := &failTransport{}
	e := newSendFailEngine(t, tr)
	pkt := testPkt()
	addr := outboundAddr()

	// Below the burst threshold: counted, no pause, no WARN.
	for i := 0; i < sendErrBurst-1; i++ {
		e.passVerdict(pkt, &addr, core.VerdictPass)
	}
	if got := e.cnt.sendErrors.Load(); got != sendErrBurst-1 {
		t.Fatalf("sendErrors = %d, want %d", got, sendErrBurst-1)
	}
	if got := e.cnt.sendPauses.Load(); got != 0 {
		t.Fatalf("sendPauses = %d before the burst threshold, want 0 (no latency cost in the normal path)", got)
	}
	if strings.Contains(logs.String(), "send failures") {
		t.Fatal("WARN logged before the burst threshold")
	}

	// The threshold packet trips the throttle: pause + WARN.
	start := time.Now()
	e.passVerdict(pkt, &addr, core.VerdictPass)
	if got := e.cnt.sendPauses.Load(); got != 1 {
		t.Fatalf("sendPauses = %d after the burst, want 1", got)
	}
	if elapsed := time.Since(start); elapsed < sendErrPause {
		t.Fatalf("no catch-up pause: the throttled send took %v, want ≥ %v", elapsed, sendErrPause)
	}
	if !strings.Contains(logs.String(), "send failures") {
		t.Fatalf("no WARN after %d consecutive failures; log: %s", sendErrBurst, logs.String())
	}

	// Second burst: another pause, but the WARN is rate-limited.
	before := strings.Count(logs.String(), "send failures")
	for i := 0; i < sendErrBurst; i++ {
		e.passVerdict(pkt, &addr, core.VerdictPass)
	}
	if got := e.cnt.sendPauses.Load(); got != 2 {
		t.Fatalf("sendPauses = %d after two bursts, want 2", got)
	}
	if after := strings.Count(logs.String(), "send failures"); after != before {
		t.Fatalf("WARN not rate-limited: %d → %d lines within %v", before, after, sendErrWarnEvery)
	}

	// Visibility: the loss shows up in the cross-module counters that
	// `rupasctl status` renders.
	snap := e.Counters()
	if snap.SendErrors != e.cnt.sendErrors.Load() {
		t.Fatalf("Snapshot SendErrors = %d, engine has %d", snap.SendErrors, e.cnt.sendErrors.Load())
	}
	if snap.SendPauses != 2 {
		t.Fatalf("Snapshot SendPauses = %d, want 2", snap.SendPauses)
	}
}

// TestSendFailureBurstResetsOnSuccess: a success clears the burst, so a
// spurious failure now and then never accumulates into a pause.
func TestSendFailureBurstResetsOnSuccess(t *testing.T) {
	_, restore := captureLogger(t)
	defer restore()

	tr := &failTransport{}
	e := newSendFailEngine(t, tr)
	pkt := testPkt()
	addr := outboundAddr()

	for round := 0; round < 4; round++ {
		for i := 0; i < sendErrBurst-1; i++ {
			e.passVerdict(pkt, &addr, core.VerdictPass)
		}
		tr.mu.Lock()
		tr.healthy = true // one good send between bursts
		tr.mu.Unlock()
		e.passVerdict(pkt, &addr, core.VerdictPass)
		tr.mu.Lock()
		tr.healthy = false
		tr.mu.Unlock()
	}
	if got := e.cnt.sendPauses.Load(); got != 0 {
		t.Fatalf("sendPauses = %d with a success between bursts, want 0", got)
	}
	if got := e.cnt.sendErrBurst.Load(); got != 0 {
		t.Fatalf("burst counter = %d after a successful send, want 0 (a success must clear it)", got)
	}
	if got := e.cnt.sendErrors.Load(); got != 4*(sendErrBurst-1) {
		t.Fatalf("sendErrors = %d, want %d (every failure counted)", got, 4*(sendErrBurst-1))
	}
}

// TestHealthySendPathTakesNoPause: the steady state must not pay for the
// throttle — 10k successful re-injections, no pause counter, no sleep.
func TestHealthySendPathTakesNoPause(t *testing.T) {
	tr := &failTransport{healthy: true}
	e := newSendFailEngine(t, tr)
	pkt := testPkt()
	addr := outboundAddr()

	start := time.Now()
	for i := 0; i < 10000; i++ {
		e.passVerdict(pkt, &addr, core.VerdictPass)
	}
	elapsed := time.Since(start)
	if got := e.cnt.sendPauses.Load(); got != 0 {
		t.Fatalf("sendPauses = %d on a healthy path, want 0", got)
	}
	if got := e.cnt.sendErrors.Load(); got != 0 {
		t.Fatalf("sendErrors = %d on a healthy path, want 0", got)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("10k healthy re-injections took %v: the throttle leaked into the normal path", elapsed)
	}
}

// TestSnapshotSendCountersSerialised: the new counters survive the JSON
// round trip `rupasctl status` uses (they are part of core.Counters, not a
// capture-private field).
func TestSnapshotSendCountersSerialised(t *testing.T) {
	var c counters
	c.sendErrors.Store(7)
	c.sendPauses.Store(3)
	snap := c.snapshot()
	if snap.SendErrors != 7 || snap.SendPauses != 3 {
		t.Fatalf("snapshot = {errors:%d pauses:%d}, want {7,3}", snap.SendErrors, snap.SendPauses)
	}
}
