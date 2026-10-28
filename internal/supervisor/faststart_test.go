package supervisor

import (
	"context"
	"io"
	"log"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kshishtovsky/rupas/internal/config"
)

// staticFastStart always offers (or withholds) the persisted profile.
type staticFastStart struct {
	fs    *FastStart
	calls atomic.Int64
}

func (s *staticFastStart) QuickStart() *FastStart {
	s.calls.Add(1)
	return s.fs
}

// revalProber records both cycle kinds; Run is the full classification,
// Revalidate the §7.3 background control probe.
type revalProber struct {
	runRes     ProfileResult
	runErr     error
	runCalls   atomic.Int64
	revalRes   ProfileResult
	revalErr   error
	revalCalls atomic.Int64
}

func (p *revalProber) Run(ctx context.Context) (ProfileResult, error) {
	p.runCalls.Add(1)
	if ctx.Err() != nil {
		return ProfileResult{}, ctx.Err()
	}
	return p.runRes, p.runErr
}

func (p *revalProber) Revalidate(ctx context.Context) (ProfileResult, error) {
	p.revalCalls.Add(1)
	if ctx.Err() != nil {
		return ProfileResult{}, ctx.Err()
	}
	return p.revalRes, p.revalErr
}

var _ RevalidatingProber = (*revalProber)(nil)

func fastStartDeps(t *testing.T, p Pipeline, pr Prober, fs FastStarter) *Supervisor {
	t.Helper()
	h := fastHysteresis()
	h.DeescalateStable = 30 * time.Millisecond
	s := New(Deps{
		Pipeline:   p,
		Prober:     pr,
		Config:     config.Default(),
		Logger:     log.New(io.Discard, "", 0),
		EventLog:   NewEventLog(100),
		Hysteresis: h,
		FastStart:  fs,
	})
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func profileDesync() config.DesyncParams {
	return config.DesyncParams{Strategy: "fake", TTL: 12, TTLMargin: 2, Repeats: 6}
}

func TestFastStartGoesActiveWithoutFullProbing(t *testing.T) {
	fp := &fakePipeline{}
	pr := &revalProber{revalRes: ProfileResult{ProfileID: "unit", DesyncAlive: true, TunnelOK: true, Note: "revalidated ok"}}
	fs := &staticFastStart{fs: &FastStart{Desync: profileDesync(), ProfileID: "unit", Note: "persisted profile"}}
	s := fastStartDeps(t, fp, pr, fs)

	if err := s.On(); err != nil {
		t.Fatal(err)
	}
	waitForState(t, s, StateActive, time.Second)

	if got := pr.runCalls.Load(); got != 0 {
		t.Fatalf("full probe cycles = %d, want 0 (fast start must skip PROBING)", got)
	}
	// Revalidation is a background control probe kicked off after the state
	// flips, so the counter is observable only eventually.
	deadline := time.Now().Add(time.Second)
	for pr.revalCalls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if got := pr.revalCalls.Load(); got != 1 {
		t.Fatalf("revalidation calls = %d, want 1", got)
	}
	if starts, _ := fp.stats(); starts != 1 {
		t.Fatalf("pipeline starts = %d, want 1", starts)
	}
	if got := fp.lastCfg.Desync; got.TTL != 12 || got.TTLMargin != 2 || got.Strategy != "fake" {
		t.Fatalf("pipeline started with %+v, want the persisted profile", got)
	}
	snap := s.Snapshot()
	if snap.ProfileID != "unit" {
		t.Fatalf("snapshot profile = %q", snap.ProfileID)
	}
	// Once the confirming revalidation lands, the note reflects it and
	// ACTIVE holds (no re-probing).
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(s.Snapshot().Counters.LastProbeNote, "revalidated ok") {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if note := s.Snapshot().Counters.LastProbeNote; !strings.Contains(note, "revalidated ok") {
		t.Fatalf("last probe note = %q, want the revalidation confirmation", note)
	}
	time.Sleep(30 * time.Millisecond)
	if got := pr.runCalls.Load(); got != 0 {
		t.Fatalf("full probe cycles after revalidation = %d, want 0", got)
	}
}

func TestFastStartRevalidationFailureRunsFullCalibration(t *testing.T) {
	fp := &fakePipeline{}
	pr := &revalProber{
		runRes:   ProfileResult{ProfileID: "unit", DesyncAlive: true, TunnelOK: true, Note: "recalibrated"},
		revalRes: ProfileResult{ProfileID: "unit", DesyncAlive: false, Note: "control probe failed"},
	}
	fs := &staticFastStart{fs: &FastStart{Desync: profileDesync(), ProfileID: "unit", Note: "persisted profile"}}
	s := fastStartDeps(t, fp, pr, fs)

	if err := s.On(); err != nil {
		t.Fatal(err)
	}
	// Fast start first, then the failed control probe must route through
	// DEGRADED → PROBING → full Run → ACTIVE (§7.3 recalibration).
	waitForState(t, s, StateActive, 3*time.Second)

	if got := pr.revalCalls.Load(); got < 1 {
		t.Fatalf("revalidation calls = %d, want >=1", got)
	}
	// The failed control probe must have triggered full re-classification
	// (the de-escalation stability gate may run the mock probe a few
	// times until the 30 ms window passes — every cycle is a full Run).
	if got := pr.runCalls.Load(); got < 1 {
		t.Fatalf("full probe cycles = %d, want >=1 (the recalibration)", got)
	}
	if starts, _ := fp.stats(); starts != 1 {
		t.Fatalf("pipeline starts = %d, want 1 (running pipeline is kept)", starts)
	}
	if note := s.Snapshot().Counters.LastProbeNote; note != "recalibrated" {
		t.Fatalf("last probe note = %q, want the recalibration note", note)
	}
}

func TestFastStartAbsentProfileKeepsProbingPath(t *testing.T) {
	fp := &fakePipeline{}
	pr := &revalProber{runRes: ProfileResult{ProfileID: "unit", DesyncAlive: true, TunnelOK: true, Note: "probed"}}
	fs := &staticFastStart{fs: nil} // no profile on disk
	s := fastStartDeps(t, fp, pr, fs)

	if err := s.On(); err != nil {
		t.Fatal(err)
	}
	// The mock probe is instant, so PROBING may be too short to observe;
	// the observable contract is: no QuickStart hit, exactly one full
	// probe cycle, no revalidation.
	waitForState(t, s, StateActive, time.Second)
	if got := fs.calls.Load(); got != 1 {
		t.Fatalf("QuickStart calls = %d, want 1", got)
	}
	if got := pr.runCalls.Load(); got != 1 {
		t.Fatalf("full probe cycles = %d, want 1", got)
	}
	if got := pr.revalCalls.Load(); got != 0 {
		t.Fatalf("revalidation calls = %d, want 0 (classic path)", got)
	}
	if starts, _ := fp.stats(); starts != 1 {
		t.Fatalf("pipeline starts = %d, want 1", starts)
	}
	if got := fp.lastCfg.Desync; got.Strategy == "fake" && got.TTL == 12 && got.TTLMargin == 2 {
		t.Fatalf("pipeline must start with the config desync, not the profile: %+v", got)
	}
}

func TestNoFastStarterKeepsProbingPath(t *testing.T) {
	fp := &fakePipeline{}
	pr := &revalProber{runRes: ProfileResult{ProfileID: "unit", DesyncAlive: true, TunnelOK: true, Note: "probed"}}
	s := fastStartDeps(t, fp, pr, nil)

	if err := s.On(); err != nil {
		t.Fatal(err)
	}
	waitForState(t, s, StateActive, time.Second)
	if got := pr.runCalls.Load(); got != 1 {
		t.Fatalf("full probe cycles = %d, want 1", got)
	}
	if got := pr.revalCalls.Load(); got != 0 {
		t.Fatalf("revalidation calls = %d, want 0", got)
	}
}
