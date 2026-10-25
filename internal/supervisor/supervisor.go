package supervisor

import (
	"context"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rupas/rupas/internal/config"
	"github.com/rupas/rupas/internal/core"
)

// Pipeline is the capture/tunnel engine lifecycle. Implemented by the
// capture/tunnel integration (not this package): Start must be idempotent
// from the supervisor's point of view only in the sense that the
// supervisor tracks running state itself and calls Start at most once per
// run segment.
type Pipeline interface {
	Start(cfg *config.Config) error
	Stop() error
}

// Prober classifies the network (TSPU behaviour, TTL window, tunnel
// health) and returns a calibrated profile result. Implemented by the
// prober package; the result type lives here so both sides agree.
type Prober interface {
	Run(ctx context.Context) (ProfileResult, error)
}

// ProfileResult is what one Prober.Run cycle produced (LOCAL definition —
// the real prober constructs it; see SYSTEM_DESIGN §4.3, §7).
type ProfileResult struct {
	// ProfileID identifies the calibrated profile (e.g. "isp-home-2025-10-25").
	ProfileID string
	// DesyncAlive reports whether desync strategies still bypass the TSPU.
	DesyncAlive bool
	// TunnelOK reports the tunnel health marker result.
	TunnelOK bool
	// Note is a human-readable summary for the snapshot/CLI.
	Note string
}

// Logger is the minimal logging sink the supervisor needs (*log.Logger
// satisfies it).
type Logger interface {
	Printf(format string, v ...any)
}

// Deps wires the supervisor to its environment. Pipeline and Prober are
// the seams the capture/prober/tunnel integration plugs into.
type Deps struct {
	Pipeline   Pipeline
	Prober     Prober
	Config     *config.Config
	Logger     Logger
	EventLog   *EventLog
	Hysteresis Hysteresis // zero value → DefaultHysteresis
	// TunnelHealth reports the live tunnel marker health (Tunnel.Healthy,
	// §6). When set, the event loop polls it every TunnelCheckInterval;
	// TunnelCheckFails consecutive unhealthy polls inject a degradation
	// event (§8: any state → DEGRADED) under which the tunnel holds TG
	// flows (dropped with a counter) instead of escalating them to direct.
	// Nil disables the watch. The callback must be cheap and non-blocking;
	// "no tunnel assembled" must report true (healthy) so an absent tunnel
	// never degrades the machine.
	TunnelHealth func() bool
	// TunnelCheckInterval overrides the poll period (0 → 30 s, §6).
	TunnelCheckInterval time.Duration
	// Now overrides the clock (tests only); nil → time.Now.
	Now func() time.Time
	// Rand overrides the jitter source (tests only); nil → math/rand/v2.
	Rand *rand.Rand
}

// Tunnel check defaults (§6: marker every 30 s, 3 consecutive failures =
// down). The tunnel-side health loop flips Healthy() after its own 3×30 s
// failures; this watch converts that into a supervisor event.
const (
	DefaultTunnelCheckInterval = 30 * time.Second
	// TunnelCheckFails is the consecutive unhealthy polls that fire the
	// degradation event (mirrors HealthFailThreshold; with the default
	// interval the tunnel itself is already down by then).
	TunnelCheckFails = 3
)

// Supervisor owns the state machine, the probe/pipeline side effects and
// the authoritative core.Snapshot (behind an atomic pointer, §2).
type Supervisor struct {
	deps  Deps
	hyst  Hysteresis
	evlog *EventLog
	log   Logger
	now   func() time.Time

	events chan event
	// probeGen tags in-flight probes so stale results are dropped.
	probeGen atomic.Int64
	dropped  atomic.Uint64

	snap atomic.Pointer[core.Snapshot]

	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	startOnce sync.Once
	closeOnce sync.Once
	startErr  error
}

// New builds a Supervisor. Call Start to launch the event loop.
func New(deps Deps) *Supervisor {
	if deps.Logger == nil {
		deps.Logger = log.New(io.Discard, "", 0)
	}
	if deps.EventLog == nil {
		deps.EventLog = NewEventLog(100)
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	s := &Supervisor{
		deps:   deps,
		hyst:   deps.Hysteresis.withDefaults(),
		evlog:  deps.EventLog,
		log:    deps.Logger,
		now:    deps.Now,
		events: make(chan event, 256),
	}
	s.snap.Store(&core.Snapshot{State: string(StateOff), Flows: map[string]int64{}})
	return s
}

// Start launches the event loop. It fails only if called with a nil ctx.
func (s *Supervisor) Start(ctx context.Context) error {
	s.startOnce.Do(func() {
		if ctx == nil {
			s.startErr = fmt.Errorf("nil context")
			return
		}
		s.ctx, s.cancel = context.WithCancel(ctx)
		s.wg.Add(1)
		go s.run()
		s.log.Printf("supervisor: started (state=%s)", StateOff)
	})
	return s.startErr
}

// Close stops the loop, cancels in-flight probes, stops the pipeline and
// disarms timers. Idempotent.
func (s *Supervisor) Close() error {
	s.closeOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		done := make(chan struct{})
		go func() { s.wg.Wait(); close(done) }()
		<-done
	})
	return nil
}

// Snapshot returns the authoritative status (core.StatusSource).
func (s *Supervisor) Snapshot() core.Snapshot {
	if p := s.snap.Load(); p != nil {
		return *p
	}
	return core.Snapshot{State: string(StateOff), Flows: map[string]int64{}}
}

// DroppedEvents reports events discarded because the queue was full.
func (s *Supervisor) DroppedEvents() uint64 { return s.dropped.Load() }

// On turns the supervisor on (RPC "on").
func (s *Supervisor) On() error { return s.send(event{kind: evCmdOn}) }

// Off turns it off and stops the pipeline (RPC "off").
func (s *Supervisor) Off() error { return s.send(event{kind: evCmdOff}) }

// ForceProbe re-classifies now (RPC "probe").
func (s *Supervisor) ForceProbe() error { return s.send(event{kind: evCmdProbe}) }

// Reload swaps the config; a running pipeline is restarted with it.
func (s *Supervisor) Reload(cfg *config.Config) error {
	if cfg == nil {
		return fmt.Errorf("nil config")
	}
	return s.send(event{kind: evReload, cfg: cfg})
}

// Notify implements core.EventSink: capture/prober push lifecycle events.
func (s *Supervisor) Notify(ev core.Event, note string) {
	switch ev {
	case core.EventNetChange:
		s.trySend(event{kind: evNetChange, note: note})
	case core.EventResume:
		s.trySend(event{kind: evResume, note: note})
	case core.EventDegradation:
		s.trySend(event{kind: evDegradation, note: note})
	case core.EventProbeDone:
		// External probe-done notifications carry no verdict; the real
		// result flows through the Prober interface. Treat optimistically:
		// recorded, counted as a successful classification.
		s.trySend(event{kind: evProbeDone, note: note,
			outcome: ProbeOutcome{OK: true, DesyncAlive: true, TunnelOK: true, Note: note}})
	}
}

func (s *Supervisor) send(ev event) error {
	if s.ctx == nil || s.ctx.Err() != nil {
		return fmt.Errorf("supervisor not running")
	}
	s.trySend(ev)
	return nil
}

func (s *Supervisor) trySend(ev event) {
	select {
	case s.events <- ev:
	default:
		s.dropped.Add(1)
		s.log.Printf("supervisor: event queue full, dropped %v", ev.kind)
	}
}

// jitter randomizes a base delay by ±Hysteresis.Jitter (5→10→30 s "с
// джиттером", §8).
func (s *Supervisor) jitter(d time.Duration) time.Duration {
	if d <= 0 || s.hyst.Jitter <= 0 {
		return d
	}
	var f float64
	if s.deps.Rand != nil {
		f = s.deps.Rand.Float64()
	} else {
		f = rand.Float64() // math/rand/v2 global is concurrency-safe
	}
	scale := 1 + s.hyst.Jitter*(2*f-1)
	return time.Duration(float64(d) * scale)
}

func (s *Supervisor) logf(format string, v ...any) {
	s.log.Printf("supervisor: "+format, v...)
}

// run is the single-owner event loop of the machine state.
func (s *Supervisor) run() {
	defer s.wg.Done()

	m := machine{state: StateOff, enteredAt: s.now()}
	cfg := s.deps.Config
	var (
		pipeRunning bool
		probeCancel context.CancelFunc
		timer       *time.Timer
		lastOC      ProbeOutcome
		lastOCAt    time.Time
	)

	// Tunnel health watch (§6): poll Tunnel.Healthy() and convert a 3×30 s
	// failure streak into the existing degradation event. The HOLD itself
	// lives in the tunnel (it drops new flows with a counter while
	// unhealthy); the machine reacts through its normal ACTIVE*→DEGRADED
	// path — the transition table is untouched.
	var tunnelTick <-chan time.Time
	tunnelFails := 0
	tunnelHeld := false
	if s.deps.TunnelHealth != nil {
		interval := s.deps.TunnelCheckInterval
		if interval <= 0 {
			interval = DefaultTunnelCheckInterval
		}
		tk := time.NewTicker(interval)
		defer tk.Stop()
		tunnelTick = tk.C
	}
	checkTunnel := func() {
		healthy := s.deps.TunnelHealth()
		if healthy {
			if tunnelHeld {
				tunnelHeld = false
				s.logf("tunnel healthy again; TG flows resume through the tunnel")
				s.evlog.Append("tunnel healthy again; TG flows resume through the tunnel")
			}
			tunnelFails = 0
			return
		}
		tunnelFails++
		if tunnelFails < TunnelCheckFails {
			return
		}
		if !tunnelHeld {
			tunnelHeld = true
			note := fmt.Sprintf("tunnel unhealthy %d consecutive checks: TG flows held (dropped, not escalated to direct)", tunnelFails)
			s.logf("%s", note)
			s.evlog.Append(note)
			// Reuse the §8 degradation path: ACTIVE* → DEGRADED with a
			// probe scheduled; SNI-DESYNC rules are unaffected.
			s.trySend(event{kind: evDegradation, note: note})
		}
	}

	store := func() {
		profile := cfg.Profile
		if lastOC.ProfileID != "" {
			profile = lastOC.ProfileID
		}
		s.snap.Store(&core.Snapshot{
			State:         string(m.state),
			Since:         m.enteredAt,
			ProfileID:     profile,
			TunnelHealthy: lastOC.OK && lastOC.TunnelOK,
			Flows:         map[string]int64{},
			Counters: core.Counters{
				LastProbeAt:   lastOCAt,
				LastProbeNote: lastOC.Note,
			},
		})
	}

	var exec func(mm *machine, acts []action, depth int)
	exec = func(mm *machine, acts []action, depth int) {
		for _, a := range acts {
			switch a.kind {
			case actStartPipeline:
				if !pipeRunning && s.deps.Pipeline != nil {
					if err := s.deps.Pipeline.Start(cfg); err != nil {
						s.logf("pipeline start failed: %v", err)
						s.evlog.Append("pipeline start failed: " + err.Error())
						if depth < 2 {
							var inner []action
							*mm, inner, _ = step(*mm, event{kind: evDegradation, note: "pipeline start failed"}, s.now(), s.hyst)
							exec(mm, inner, depth+1)
						}
						continue
					}
					pipeRunning = true
					s.logf("pipeline started (profile=%s)", cfg.Profile)
					s.evlog.Append("pipeline started")
				}
			case actStopPipeline:
				if pipeRunning && s.deps.Pipeline != nil {
					pipeRunning = false
					if err := s.deps.Pipeline.Stop(); err != nil {
						s.logf("pipeline stop failed: %v", err)
					} else {
						s.logf("pipeline stopped")
						s.evlog.Append("pipeline stopped")
					}
				}
			case actStartProbe:
				if s.deps.Prober == nil {
					break
				}
				if probeCancel != nil {
					probeCancel()
				}
				gen := s.probeGen.Add(1)
				pctx, pcancel := context.WithCancel(s.ctx)
				probeCancel = pcancel
				s.wg.Add(1)
				go func(gen int64, pctx context.Context, pcancel context.CancelFunc) {
					defer s.wg.Done()
					defer pcancel()
					res, err := s.deps.Prober.Run(pctx)
					oc := ProbeOutcome{ProfileID: res.ProfileID, Note: res.Note}
					if err != nil {
						oc.Note = fmt.Sprintf("probe error: %v", err)
						if res.Note != "" {
							oc.Note += " (" + res.Note + ")"
						}
					} else {
						oc.OK = true
						oc.DesyncAlive = res.DesyncAlive
						oc.TunnelOK = res.TunnelOK
					}
					if s.probeGen.Load() != gen {
						return // superseded by a newer probe
					}
					s.trySend(event{kind: evProbeDone, outcome: oc, note: oc.Note})
				}(gen, pctx, pcancel)
			case actScheduleProbe:
				if timer != nil {
					timer.Stop()
				}
				d := s.jitter(a.delay)
				timer = time.AfterFunc(d, func() {
					s.trySend(event{kind: evProbeDue})
				})
			}
		}
	}

	store()
	for {
		select {
		case <-s.ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			if probeCancel != nil {
				probeCancel()
			}
			if pipeRunning && s.deps.Pipeline != nil {
				pipeRunning = false
				_ = s.deps.Pipeline.Stop()
			}
			s.logf("stopped (state=%s)", m.state)
			s.evlog.Append("supervisor stopped")
			return

		case <-tunnelTick:
			checkTunnel()

		case ev := <-s.events:
			if ev.kind == evReload && ev.cfg != nil {
				old := cfg.Profile
				cfg = ev.cfg
				if pipeRunning && s.deps.Pipeline != nil {
					_ = s.deps.Pipeline.Stop()
					if err := s.deps.Pipeline.Start(cfg); err != nil {
						s.logf("pipeline restart after reload failed: %v", err)
					}
				}
				s.logf("config reloaded (%s -> %s)", old, cfg.Profile)
				s.evlog.Append("config reloaded (profile " + cfg.Profile + ")")
				store()
				continue
			}

			prev := m.state
			var acts []action
			m, acts, _ = step(m, ev, s.now(), s.hyst)
			if ev.kind == evProbeDone {
				lastOC = ev.outcome
				lastOCAt = s.now()
			}
			exec(&m, acts, 0)
			if m.state != prev {
				note := ev.note
				if note == "" {
					note = ev.kind.String()
				}
				s.logf("%s -> %s (%s)", prev, m.state, note)
				s.evlog.Append(fmt.Sprintf("state %s -> %s (%s)", prev, m.state, note))
			}
			store()
		}
	}
}

// Compile-time interface checks.
var (
	_ core.StatusSource = (*Supervisor)(nil)
	_ core.EventSink    = (*Supervisor)(nil)
)
