package supervisor

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

// fresh returns a machine parked in state s with clean hysteresis state.
func fresh(s State) machine {
	return machine{state: s, enteredAt: t0}
}

func hasAction(acts []action, k actionKind) bool {
	for _, a := range acts {
		if a.kind == k {
			return true
		}
	}
	return false
}

func actionDelay(acts []action, k actionKind) time.Duration {
	for _, a := range acts {
		if a.kind == k {
			return a.delay
		}
	}
	return -1
}

// TestTransitionTable walks every external event through every state and
// asserts the resulting state (§8 full transition table).
func TestTransitionTable(t *testing.T) {
	h := DefaultHysteresis()
	now := t0.Add(time.Hour)

	events := []struct {
		name string
		ev   event
	}{
		{"cmdOn", event{kind: evCmdOn}},
		{"cmdOff", event{kind: evCmdOff}},
		{"cmdProbe", event{kind: evCmdProbe}},
		{"netChange", event{kind: evNetChange, note: "nic"}},
		{"resume", event{kind: evResume, note: "wake"}},
		{"degradation", event{kind: evDegradation, note: "fail-ratio"}},
		{"probeOK_desync", event{kind: evProbeDone, outcome: ProbeOutcome{OK: true, DesyncAlive: true, TunnelOK: true}}},
		{"probeOK_nodesync", event{kind: evProbeDone, outcome: ProbeOutcome{OK: true, DesyncAlive: false, TunnelOK: true}}},
		{"probeFail", event{kind: evProbeDone, outcome: ProbeOutcome{OK: false, Note: "timeout"}}},
		{"probeDue", event{kind: evProbeDue}}, // with pendingProbe=true where relevant
	}

	// want[state][event] = expected next state.
	want := map[State]map[string]State{
		StateOff: {
			"cmdOn": StateProbing, "cmdOff": StateOff, "cmdProbe": StateOff,
			"netChange": StateOff, "resume": StateOff, "degradation": StateOff,
			"probeOK_desync": StateOff, "probeOK_nodesync": StateOff,
			"probeFail": StateOff, "probeDue": StateOff,
		},
		StateProbing: {
			"cmdOn": StateProbing, "cmdOff": StateOff, "cmdProbe": StateProbing,
			"netChange": StateProbing, "resume": StateProbing, "degradation": StateProbing,
			"probeOK_desync": StateActive, "probeOK_nodesync": StateActiveTunnelOnly,
			"probeFail": StateProbing, "probeDue": StateProbing,
		},
		StateActive: {
			"cmdOn": StateActive, "cmdOff": StateOff, "cmdProbe": StateProbing,
			"netChange": StateDegraded, "resume": StateDegraded, "degradation": StateDegraded,
			"probeOK_desync": StateActive, "probeOK_nodesync": StateActiveTunnelOnly,
			"probeFail": StateActive, "probeDue": StateActive,
		},
		StateActiveTunnelOnly: {
			"cmdOn": StateActiveTunnelOnly, "cmdOff": StateOff, "cmdProbe": StateProbing,
			"netChange": StateDegraded, "resume": StateDegraded, "degradation": StateDegraded,
			"probeOK_desync": StateActive, "probeOK_nodesync": StateActiveTunnelOnly,
			"probeFail": StateActiveTunnelOnly, "probeDue": StateActiveTunnelOnly,
		},
		StateDegraded: {
			"cmdOn": StateProbing, "cmdOff": StateOff, "cmdProbe": StateProbing,
			"netChange": StateDegraded, "resume": StateDegraded, "degradation": StateDegraded,
			"probeOK_desync": StateActive, "probeOK_nodesync": StateActiveTunnelOnly,
			"probeFail": StateDegraded, "probeDue": StateProbing,
		},
	}

	for _, st := range []State{StateOff, StateProbing, StateActive, StateActiveTunnelOnly, StateDegraded} {
		for _, e := range events {
			m := fresh(st)
			if e.name == "probeDue" {
				m.pendingProbe = true // probeDue only fires with a timer armed
			}
			got, _, _ := step(m, e.ev, now, h)
			if got.state != want[st][e.name] {
				t.Errorf("%s + %s -> %s, want %s", st, e.name, got.state, want[st][e.name])
			}
		}
	}
}

// TestTransitionTableActions spot-checks the side effects of key cells.
func TestTransitionTableActions(t *testing.T) {
	h := DefaultHysteresis()
	now := t0.Add(time.Hour)

	cases := []struct {
		name  string
		state State
		ev    event
		check func(t *testing.T, m machine, acts []action)
	}{
		{"OFF+cmdOn arms immediate probe", StateOff, event{kind: evCmdOn},
			func(t *testing.T, m machine, acts []action) {
				if !m.pendingProbe || !hasAction(acts, actScheduleProbe) || actionDelay(acts, actScheduleProbe) != 0 {
					t.Errorf("want pendingProbe + scheduleProbe(0), got pending=%v acts=%v", m.pendingProbe, acts)
				}
			}},
		{"PROBING+cmdOff stops pipeline", StateProbing, event{kind: evCmdOff},
			func(t *testing.T, m machine, acts []action) {
				if !hasAction(acts, actStopPipeline) {
					t.Errorf("want stopPipeline, got %v", acts)
				}
			}},
		{"PROBING+probeOK starts pipeline", StateProbing,
			event{kind: evProbeDone, outcome: ProbeOutcome{OK: true, DesyncAlive: true}},
			func(t *testing.T, m machine, acts []action) {
				if !hasAction(acts, actStartPipeline) {
					t.Errorf("want startPipeline, got %v", acts)
				}
			}},
		{"PROBING+probeFail retries at first backoff step", StateProbing,
			event{kind: evProbeDone, outcome: ProbeOutcome{OK: false}},
			func(t *testing.T, m machine, acts []action) {
				if d := actionDelay(acts, actScheduleProbe); d != 5*time.Second {
					t.Errorf("want scheduleProbe 5s, got %v (%v)", d, acts)
				}
				if !m.pendingProbe {
					t.Error("want pendingProbe set")
				}
			}},
		{"ACTIVE+netChange degrades with 5s reprobe", StateActive, event{kind: evNetChange},
			func(t *testing.T, m machine, acts []action) {
				if d := actionDelay(acts, actScheduleProbe); d != 5*time.Second {
					t.Errorf("want scheduleProbe 5s, got %v", d)
				}
				if !m.lastFailAt.Equal(now) {
					t.Error("want stability gate reset (lastFailAt=now)")
				}
			}},
		{"DEGRADED+probeDue re-probes in recovery mode", StateDegraded, event{kind: evProbeDue},
			func(t *testing.T, m machine, acts []action) {
				if m.state != StateProbing || !m.recovering || !hasAction(acts, actStartProbe) {
					t.Errorf("want PROBING/recovering/startProbe, got %s rec=%v %v", m.state, m.recovering, acts)
				}
			}},
		{"DEGRADED+cmdOff stops pipeline", StateDegraded, event{kind: evCmdOff},
			func(t *testing.T, m machine, acts []action) {
				if !hasAction(acts, actStopPipeline) {
					t.Errorf("want stopPipeline, got %v", acts)
				}
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := fresh(c.state)
			if c.ev.kind == evProbeDue {
				m.pendingProbe = true
			}
			got, acts, _ := step(m, c.ev, now, h)
			c.check(t, got, acts)
		})
	}
}

// TestEscalationAfterThreeFails: 2 fails keep ACTIVE, the 3rd within the
// window escalates to DEGRADED.
func TestEscalationAfterThreeFails(t *testing.T) {
	h := DefaultHysteresis()
	m := fresh(StateActive)

	fail := event{kind: evProbeDone, outcome: ProbeOutcome{OK: false}}
	for i, at := range []time.Duration{0, 10 * time.Second, 20 * time.Second} {
		var changed bool
		m, _, changed = step(m, fail, t0.Add(at), h)
		want := StateActive
		if i == 2 {
			want = StateDegraded
		}
		if m.state != want {
			t.Fatalf("fail #%d: state=%s want %s", i+1, m.state, want)
		}
		if i < 2 && changed {
			t.Fatalf("fail #%d: premature transition", i+1)
		}
	}
}

// TestEscalationWindowPrunes: fails spaced further apart than 60 s never
// accumulate to 3 inside the window.
func TestEscalationWindowPrunes(t *testing.T) {
	h := DefaultHysteresis()
	m := fresh(StateActive)
	fail := event{kind: evProbeDone, outcome: ProbeOutcome{OK: false}}

	for _, at := range []time.Duration{0, 61 * time.Second, 122 * time.Second, 130 * time.Second} {
		m, _, _ = step(m, fail, t0.Add(at), h)
	}
	if m.state != StateActive {
		t.Fatalf("state=%s, want ACTIVE (fails pruned by 60s window)", m.state)
	}
	// One more fail 1 s later: 3 inside the window (122+61>130, so 122/130/131) → escalate.
	m, _, _ = step(m, fail, t0.Add(131*time.Second), h)
	if m.state != StateDegraded {
		t.Fatalf("state=%s after 3-in-window fails, want DEGRADED", m.state)
	}
}

// TestPrematureDeescalationBlocked: a green probe inside the 300 s
// stability gate does NOT promote DEGRADED back to ACTIVE.
func TestPrematureDeescalationBlocked(t *testing.T) {
	h := DefaultHysteresis()
	m := fresh(StateActive)

	// Escalate at t0 with the 3rd fail.
	fail := event{kind: evProbeDone, outcome: ProbeOutcome{OK: false}}
	for _, at := range []time.Duration{0, time.Second, 2 * time.Second} {
		m, _, _ = step(m, fail, t0.Add(at), h)
	}
	if m.state != StateDegraded {
		t.Fatalf("setup: state=%s, want DEGRADED", m.state)
	}
	m.pendingProbe = true

	// Backoff fires → PROBING in recovery mode.
	m, _, _ = step(m, event{kind: evProbeDue}, t0.Add(10*time.Second), h)
	if m.state != StateProbing || !m.recovering {
		t.Fatalf("want PROBING/recovering, got %s rec=%v", m.state, m.recovering)
	}

	// Green probe at lastFail+10s: blocked, back to DEGRADED.
	ok := event{kind: evProbeDone, outcome: ProbeOutcome{OK: true, DesyncAlive: true}}
	m, _, _ = step(m, ok, t0.Add(11*time.Second), h)
	if m.state != StateDegraded {
		t.Fatalf("premature de-escalation not blocked: state=%s at lastFail+11s", m.state)
	}

	// Retry at +300s−ε still blocked (299s < 300s).
	m.pendingProbe = true
	m, _, _ = step(m, event{kind: evProbeDue}, t0.Add(299*time.Second), h)
	m, _, _ = step(m, ok, t0.Add(299*time.Second+500*time.Millisecond), h)
	if m.state != StateDegraded {
		t.Fatalf("de-escalation before 300s stable: state=%s", m.state)
	}

	// At lastFail+300s the gate opens.
	m.pendingProbe = true
	m, _, _ = step(m, event{kind: evProbeDue}, t0.Add(305*time.Second), h)
	m, acts, _ := step(m, ok, t0.Add(306*time.Second), h)
	if m.state != StateActive || !hasAction(acts, actStartPipeline) {
		t.Fatalf("want ACTIVE + startPipeline after stable 300s, got %s %v", m.state, acts)
	}
}

// TestDegradationEventEscalatesImmediately: the passive detector event
// carries its own threshold, so ACTIVE* escalates on the first event.
func TestDegradationEventEscalatesImmediately(t *testing.T) {
	h := DefaultHysteresis()
	for _, st := range []State{StateActive, StateActiveTunnelOnly} {
		m, _, _ := step(fresh(st), event{kind: evDegradation, note: "fail-ratio 0.6"}, t0, h)
		if m.state != StateDegraded {
			t.Fatalf("%s + degradation -> %s, want DEGRADED", st, m.state)
		}
	}
}

// TestBackoffSequence: consecutive fails walk 5→10→30→30 s.
func TestBackoffSequence(t *testing.T) {
	h := DefaultHysteresis()
	m := fresh(StateProbing)
	fail := event{kind: evProbeDone, outcome: ProbeOutcome{OK: false}}

	wantDelays := []time.Duration{5 * time.Second, 10 * time.Second, 30 * time.Second, 30 * time.Second}
	at := time.Duration(0)
	for i, want := range wantDelays {
		at += time.Second
		var acts []action
		m, acts, _ = step(m, fail, t0.Add(at), h)
		if d := actionDelay(acts, actScheduleProbe); d != want {
			t.Fatalf("retry #%d delay=%v, want %v", i+1, d, want)
		}
	}
}

// TestRecoveryGateNotAppliedOnFreshStart: entering ACTIVE from a clean
// PROBING (no prior fails) is not delayed by the 300 s gate.
func TestRecoveryGateNotAppliedOnFreshStart(t *testing.T) {
	h := DefaultHysteresis()
	m := fresh(StateProbing)
	m, acts, _ := step(m, event{kind: evProbeDone, outcome: ProbeOutcome{OK: true, DesyncAlive: true}}, t0, h)
	if m.state != StateActive || !hasAction(acts, actStartPipeline) {
		t.Fatalf("want immediate ACTIVE, got %s %v", m.state, acts)
	}
}

// TestDesyncDeathAndRecovery: probe verdicts steer ACTIVE ↔
// ACTIVE_TUNNEL_ONLY.
func TestDesyncDeathAndRecovery(t *testing.T) {
	h := DefaultHysteresis()
	m := fresh(StateProbing)

	m, _, _ = step(m, event{kind: evProbeDone, outcome: ProbeOutcome{OK: true, DesyncAlive: false}}, t0, h)
	if m.state != StateActiveTunnelOnly {
		t.Fatalf("want ACTIVE_TUNNEL_ONLY, got %s", m.state)
	}
	// Forced probe → PROBING → desync alive again → ACTIVE.
	m, _, _ = step(m, event{kind: evCmdProbe}, t0.Add(time.Second), h)
	m, _, _ = step(m, event{kind: evProbeDone, outcome: ProbeOutcome{OK: true, DesyncAlive: true}}, t0.Add(2*time.Second), h)
	if m.state != StateActive {
		t.Fatalf("want ACTIVE after desync recovery, got %s", m.state)
	}
}
