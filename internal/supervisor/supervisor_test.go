package supervisor

import (
	"context"
	"errors"
	"io"
	"log"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rupas/rupas/internal/config"
	"github.com/rupas/rupas/internal/core"
)

// fakePipeline records Start/Stop calls.
type fakePipeline struct {
	mu       sync.Mutex
	starts   int
	stops    int
	startErr error
	lastCfg  *config.Config
}

func (f *fakePipeline) Start(cfg *config.Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.starts++
	f.lastCfg = cfg
	return f.startErr
}

func (f *fakePipeline) Stop() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stops++
	return nil
}

func (f *fakePipeline) stats() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.starts, f.stops
}

// scriptProber replays a scripted list of results (last one repeats).
type scriptProber struct {
	mu     sync.Mutex
	script []ProfileResult
	errs   []error
	calls  atomic.Int64
	delay  time.Duration
}

func (p *scriptProber) Run(ctx context.Context) (ProfileResult, error) {
	i := int(p.calls.Add(1)) - 1
	if p.delay > 0 {
		select {
		case <-time.After(p.delay):
		case <-ctx.Done():
			return ProfileResult{}, ctx.Err()
		}
	} else if ctx.Err() != nil {
		return ProfileResult{}, ctx.Err()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var (
		res ProfileResult
		err error
	)
	if i < len(p.script) {
		res = p.script[i]
	} else if len(p.script) > 0 {
		res = p.script[len(p.script)-1] // last result repeats
	}
	if i < len(p.errs) {
		err = p.errs[i]
	}
	return res, err
}

func okDesync(note string) ProfileResult {
	return ProfileResult{ProfileID: "test-profile", DesyncAlive: true, TunnelOK: true, Note: note}
}

// fastHysteresis shrinks every timing so integration tests run in ms.
func fastHysteresis() Hysteresis {
	return Hysteresis{
		EscalateFails:    3,
		EscalateWindow:   30 * time.Second,
		DeescalateStable: 300 * time.Millisecond,
		BackoffSteps:     []time.Duration{5 * time.Millisecond, 10 * time.Millisecond, 20 * time.Millisecond},
		Jitter:           0,
	}
}

func newTestSup(t *testing.T, h Hysteresis, p Pipeline, pr Prober) *Supervisor {
	t.Helper()
	s := New(Deps{
		Pipeline:   p,
		Prober:     pr,
		Config:     config.Default(),
		Logger:     log.New(io.Discard, "", 0),
		EventLog:   NewEventLog(100),
		Hysteresis: h,
	})
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func waitForState(t *testing.T, s *Supervisor, want State, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if State(s.Snapshot().State) == want {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("state=%s, want %s (within %v); note=%q", s.Snapshot().State, want, timeout, s.Snapshot().Counters.LastProbeNote)
}

func TestInitialSnapshotIsOff(t *testing.T) {
	s := New(Deps{Config: config.Default(), Logger: log.New(io.Discard, "", 0)})
	snap := s.Snapshot()
	if snap.State != "OFF" {
		t.Fatalf("want OFF snapshot before Start, got %+v", snap)
	}
	if len(snap.Flows) == 0 && snap.Flows == nil {
		t.Fatal("Flows map must be non-nil for JSON marshalling")
	}
}

func TestLifecycleOnOff(t *testing.T) {
	pipe := &fakePipeline{}
	prober := &scriptProber{script: []ProfileResult{okDesync("open")}}
	s := newTestSup(t, fastHysteresis(), pipe, prober)

	if err := s.On(); err != nil {
		t.Fatal(err)
	}
	waitForState(t, s, StateActive, 5*time.Second)

	starts, _ := pipe.stats()
	if starts != 1 {
		t.Fatalf("pipeline starts=%d, want 1", starts)
	}
	snap := s.Snapshot()
	if snap.ProfileID != "test-profile" || !snap.TunnelHealthy {
		t.Fatalf("snapshot not updated by probe: %+v", snap)
	}

	if err := s.Off(); err != nil {
		t.Fatal(err)
	}
	waitForState(t, s, StateOff, 5*time.Second)
	_, stops := pipe.stats()
	if stops != 1 {
		t.Fatalf("pipeline stops=%d, want 1", stops)
	}
}

func TestEscalationAndRecovery(t *testing.T) {
	pipe := &fakePipeline{}
	// Three failures escalate, then a green probe recovers (after the
	// 300ms stability gate blocks the first premature attempt). Probe
	// failure = Run returns an error.
	probeFail := errors.New("probe timeout")
	prober := &scriptProber{
		script: []ProfileResult{{}, {}, {}, okDesync("recovered")},
		errs:   []error{probeFail, probeFail, probeFail},
	}
	s := newTestSup(t, fastHysteresis(), pipe, prober)

	_ = s.On()
	waitForState(t, s, StateDegraded, 5*time.Second) // 3 fails in window → escalate
	waitForState(t, s, StateActive, 10*time.Second)  // backoff reprobe + stable gate → recover

	starts, stops := pipe.stats()
	if starts != 1 || stops != 0 {
		t.Fatalf("pipeline starts=%d stops=%d, want 1/0 (recovery must not restart pipeline)", starts, stops)
	}
	if s.DroppedEvents() != 0 {
		t.Fatalf("dropped events: %d", s.DroppedEvents())
	}
}

func TestNetChangeDegradesAndRecovers(t *testing.T) {
	pipe := &fakePipeline{}
	prober := &scriptProber{script: []ProfileResult{okDesync("open")}}
	s := newTestSup(t, fastHysteresis(), pipe, prober)

	_ = s.On()
	waitForState(t, s, StateActive, 5*time.Second)

	s.Notify(core.EventNetChange, "default route via new NIC")
	waitForState(t, s, StateDegraded, 5*time.Second)
	waitForState(t, s, StateActive, 10*time.Second)

	s.Notify(core.EventResume, "power resume")
	waitForState(t, s, StateDegraded, 5*time.Second)
	waitForState(t, s, StateActive, 10*time.Second)
}

func TestDegradationEventEscalates(t *testing.T) {
	pipe := &fakePipeline{}
	prober := &scriptProber{script: []ProfileResult{okDesync("open")}}
	s := newTestSup(t, fastHysteresis(), pipe, prober)

	_ = s.On()
	waitForState(t, s, StateActive, 5*time.Second)
	s.Notify(core.EventDegradation, "handshake fail ratio 0.6")
	waitForState(t, s, StateDegraded, 5*time.Second)
}

func TestDesyncDeathMovesToTunnelOnly(t *testing.T) {
	pipe := &fakePipeline{}
	prober := &scriptProber{script: []ProfileResult{okDesync("open"),
		{ProfileID: "test-profile", DesyncAlive: false, TunnelOK: true, Note: "desync dead"}}}
	s := newTestSup(t, fastHysteresis(), pipe, prober)

	_ = s.On()
	waitForState(t, s, StateActive, 5*time.Second)
	_ = s.ForceProbe()
	waitForState(t, s, StateActiveTunnelOnly, 5*time.Second)
	if s.Snapshot().State != "ACTIVE_TUNNEL_ONLY" {
		t.Fatalf("snapshot state %q", s.Snapshot().State)
	}
}

func TestReloadSwapsConfigAndRestartsPipeline(t *testing.T) {
	pipe := &fakePipeline{}
	prober := &scriptProber{script: []ProfileResult{okDesync("open")}}
	s := newTestSup(t, fastHysteresis(), pipe, prober)

	_ = s.On()
	waitForState(t, s, StateActive, 5*time.Second)

	cfg2 := config.Default()
	cfg2.Profile = "reloaded-profile"
	if err := s.Reload(cfg2); err != nil {
		t.Fatal(err)
	}
	waitForState(t, s, StateActive, 5*time.Second)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		pipe.mu.Lock()
		cfg := pipe.lastCfg
		starts := pipe.starts
		pipe.mu.Unlock()
		if cfg != nil && cfg.Profile == "reloaded-profile" && starts >= 2 {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("pipeline was not restarted with the reloaded config")
}

func TestPipelineStartFailureDegrades(t *testing.T) {
	pipe := &fakePipeline{startErr: errors.New("driver not loaded")}
	prober := &scriptProber{script: []ProfileResult{okDesync("open")}}
	s := newTestSup(t, fastHysteresis(), pipe, prober)

	_ = s.On()
	waitForState(t, s, StateDegraded, 5*time.Second)
	_ = s.Off()
	waitForState(t, s, StateOff, 5*time.Second)
}

// TestConcurrentAccess hammers Notify/Snapshot/On/Off from several
// goroutines; run with -race.
func TestConcurrentAccess(t *testing.T) {
	pipe := &fakePipeline{}
	prober := &scriptProber{script: []ProfileResult{okDesync("open")}, delay: time.Millisecond}
	s := newTestSup(t, fastHysteresis(), pipe, prober)

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			evs := []core.Event{core.EventNetChange, core.EventResume, core.EventDegradation}
			for j := 0; j < 200; j++ {
				s.Notify(evs[j%len(evs)], "storm")
				_ = s.Snapshot()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			_ = s.On()
			_ = s.Snapshot()
			_ = s.Off()
		}
	}()
	wg.Wait()
	_ = s.Close()
	_ = s.Close() // idempotent
}

// TestJitterBounds verifies delays stay inside [0.8d, 1.2d] with a seeded
// source.
func TestJitterBounds(t *testing.T) {
	s := New(Deps{
		Config: config.Default(),
		Logger: log.New(io.Discard, "", 0),
		Hysteresis: Hysteresis{
			BackoffSteps: []time.Duration{5 * time.Second},
			Jitter:       0.2,
		},
		Rand: rand.New(rand.NewPCG(42, 7)),
	})
	base := 10 * time.Second
	for i := 0; i < 500; i++ {
		d := s.jitter(base)
		if d < 8*time.Second || d > 12*time.Second {
			t.Fatalf("jitter out of bounds: %v", d)
		}
	}
	if s.jitter(0) != 0 {
		t.Fatal("zero base must stay zero")
	}
}

func TestEventLogRing(t *testing.T) {
	l := NewEventLog(3)
	for i := 0; i < 5; i++ {
		l.Append("line")
	}
	if l.Len() != 3 {
		t.Fatalf("len=%d, want 3", l.Len())
	}
	got := l.Last(2)
	if len(got) != 2 {
		t.Fatalf("Last(2)=%d lines", len(got))
	}
	all := l.Last(0)
	if len(all) != 3 {
		t.Fatalf("Last(0)=%d lines, want all 3", len(all))
	}
}
