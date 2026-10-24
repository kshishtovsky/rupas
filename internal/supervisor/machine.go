// Package supervisor implements the Rupas lifecycle state machine
// (SYSTEM_DESIGN §8): OFF → PROBING → ACTIVE / ACTIVE_TUNNEL_ONLY, with
// DEGRADED as the recovery waiting room, hysteresis on escalation
// (3 fails / 60 s) and de-escalation (300 s stable), and probe retries
// with 5→10→30 s backoff plus jitter.
package supervisor

import (
	"time"

	"github.com/rupas/rupas/internal/config"
)

// State is a supervisor state-machine state (§8).
type State string

const (
	StateOff              State = "OFF"
	StateProbing          State = "PROBING"
	StateActive           State = "ACTIVE"             // DESYNC + TUNNEL both usable
	StateActiveTunnelOnly State = "ACTIVE_TUNNEL_ONLY" // desync dead, tunnel carries matched flows
	StateDegraded         State = "DEGRADED"
)

// Hysteresis tunes the §8 transition rules. Zero fields fall back to the
// documented defaults (3 fails / 60 s escalation, 300 s stable
// de-escalation, 5→10→30 s backoff, ±20 % jitter).
type Hysteresis struct {
	// EscalateFails is the number of fails within EscalateWindow that
	// escalates ACTIVE* to DEGRADED.
	EscalateFails int
	// EscalateWindow is the sliding window for fail counting.
	EscalateWindow time.Duration
	// DeescalateStable is how long the system must go without a fail
	// before DEGRADED may promote back to an ACTIVE* state.
	DeescalateStable time.Duration
	// BackoffSteps are the probe retry delays; the last one repeats.
	BackoffSteps []time.Duration
	// Jitter is the relative randomization of each backoff delay
	// (0.2 → delay ∈ [0.8×d, 1.2×d]).
	Jitter float64
}

// DefaultHysteresis returns the §8 defaults.
func DefaultHysteresis() Hysteresis {
	return Hysteresis{
		EscalateFails:    3,
		EscalateWindow:   60 * time.Second,
		DeescalateStable: 300 * time.Second,
		BackoffSteps:     []time.Duration{5 * time.Second, 10 * time.Second, 30 * time.Second},
		Jitter:           0.2,
	}
}

func (h Hysteresis) withDefaults() Hysteresis {
	d := DefaultHysteresis()
	if h.EscalateFails <= 0 {
		h.EscalateFails = d.EscalateFails
	}
	if h.EscalateWindow <= 0 {
		h.EscalateWindow = d.EscalateWindow
	}
	if h.DeescalateStable <= 0 {
		h.DeescalateStable = d.DeescalateStable
	}
	if len(h.BackoffSteps) == 0 {
		h.BackoffSteps = d.BackoffSteps
	}
	if h.Jitter < 0 {
		h.Jitter = 0
	}
	return h
}

// backoff returns the step delay for retry number idx (0-based), capped at
// the last step.
func (h Hysteresis) backoff(idx int) time.Duration {
	if len(h.BackoffSteps) == 0 {
		return 0
	}
	if idx < 0 {
		idx = 0
	}
	if idx >= len(h.BackoffSteps) {
		idx = len(h.BackoffSteps) - 1
	}
	return h.BackoffSteps[idx]
}

// eventKind is the internal event set: mapped core.Event values plus
// supervisor-internal ones.
type eventKind uint8

const (
	evCmdOn       eventKind = iota // RPC "on"
	evCmdOff                       // RPC "off"
	evCmdProbe                     // RPC "probe" (force re-classification)
	evNetChange                    // core.EventNetChange
	evResume                       // core.EventResume
	evDegradation                  // core.EventDegradation (passive detector tripped)
	evProbeDone                    // core.EventProbeDone / internal probe completion
	evProbeDue                     // internal: backoff/initial probe timer fired
	evReload                       // internal: config reload (intercepted by the loop)
)

func (k eventKind) String() string {
	switch k {
	case evCmdOn:
		return "cmdOn"
	case evCmdOff:
		return "cmdOff"
	case evCmdProbe:
		return "cmdProbe"
	case evNetChange:
		return "netChange"
	case evResume:
		return "resume"
	case evDegradation:
		return "degradation"
	case evProbeDone:
		return "probeDone"
	case evProbeDue:
		return "probeDue"
	case evReload:
		return "reload"
	}
	return "unknown"
}

// ProbeOutcome is the normalized verdict of one probe cycle.
type ProbeOutcome struct {
	OK          bool // classification completed successfully
	DesyncAlive bool // desync strategies still bypass the TSPU
	TunnelOK    bool // tunnel health marker answered
	ProfileID   string
	Note        string
}

// event is what drives the machine. cfg is only used by evReload, which the
// supervisor loop intercepts before step(); the machine itself never reads it.
type event struct {
	kind    eventKind
	note    string
	outcome ProbeOutcome
	cfg     *config.Config
}

type actionKind uint8

const (
	actNone actionKind = iota
	// actStartPipeline asks the runtime to ensure the pipeline is running
	// (idempotent at the runtime level).
	actStartPipeline
	// actStopPipeline asks the runtime to stop the pipeline if running.
	actStopPipeline
	// actStartProbe launches a probe cycle now.
	actStartProbe
	// actScheduleProbe arms the one-shot probe timer; delay is the base
	// delay before jitter.
	actScheduleProbe
)

func (a actionKind) String() string {
	switch a {
	case actStartPipeline:
		return "startPipeline"
	case actStopPipeline:
		return "stopPipeline"
	case actStartProbe:
		return "startProbe"
	case actScheduleProbe:
		return "scheduleProbe"
	}
	return "none"
}

type action struct {
	kind  actionKind
	delay time.Duration // base delay for actScheduleProbe
}

// machine is the pure state machine: no goroutines, no clocks, no I/O.
// All times are injected, which makes the whole transition table
// unit-testable. Owned exclusively by the supervisor loop.
type machine struct {
	state State

	// enteredAt is when the current state was entered (Snapshot.Since).
	enteredAt time.Time

	// fails are the recent fail timestamps inside Hysteresis.EscalateWindow.
	fails []time.Time
	// lastFailAt is the last destabilizer (fail or net change); the
	// 300 s de-escalation gate is measured from here.
	lastFailAt time.Time

	// backoffIdx is the next retry index into Hysteresis.BackoffSteps.
	backoffIdx int

	// probeInFlight is true while a Prober.Run cycle is running.
	probeInFlight bool
	// pendingProbe is true while a probe timer is armed.
	pendingProbe bool
	// recovering marks PROBING sessions entered from DEGRADED: promotion
	// back to ACTIVE* is gated by DeescalateStable.
	recovering bool
}

// to transitions to a new state, resetting per-state scratch flags.
func (m machine) to(s State, now time.Time) machine {
	m.state = s
	m.enteredAt = now
	m.probeInFlight = false
	m.pendingProbe = false
	m.recovering = false
	return m
}

// recordFail registers a fail at now, prunes the escalation window and
// stamps lastFailAt.
func (m *machine) recordFail(now time.Time, h Hysteresis) {
	m.fails = append(m.fails, now)
	m.lastFailAt = now
	cut := now.Add(-h.EscalateWindow)
	kept := m.fails[:0]
	for _, t := range m.fails {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	m.fails = kept
}

func (m *machine) escalated(h Hysteresis) bool {
	return len(m.fails) >= h.EscalateFails
}

// step applies one event to the machine at time now and returns the next
// machine, the actions the runtime must execute and whether the state
// changed. It is pure: same (m, ev, now, h) always yields the same result.
//
// Deviations from the §8 sketch, both deliberate:
//   - OFF never leaves OFF except on cmdOn/cmdProbe: with the daemon off
//     there is nothing to degrade, network notes are just recorded;
//   - NetChange/Resume while PROBING restart the probe instead of routing
//     through DEGRADED (classification is already in flight).
func step(m machine, ev event, now time.Time, h Hysteresis) (machine, []action, bool) {
	switch ev.kind {
	case evCmdOn:
		switch m.state {
		case StateOff:
			m2 := m.to(StateProbing, now)
			m2.pendingProbe = true
			return m2, []action{{kind: actScheduleProbe}}, true // delay 0: probe immediately
		case StateDegraded:
			m2 := m.to(StateProbing, now)
			m2.recovering = true
			m2.probeInFlight = true
			return m2, []action{{kind: actStartProbe}}, true
		default: // PROBING / ACTIVE / ACTIVE_TUNNEL_ONLY: already on
			return m, nil, false
		}

	case evCmdOff:
		if m.state == StateOff {
			return m, nil, false
		}
		m2 := m.to(StateOff, now)
		return m2, []action{{kind: actStopPipeline}}, true

	case evCmdProbe:
		switch m.state {
		case StateOff:
			m.probeInFlight = true // diagnostic probe: result recorded, state kept
			return m, []action{{kind: actStartProbe}}, false
		case StateDegraded:
			m2 := m.to(StateProbing, now)
			m2.recovering = true
			m2.probeInFlight = true
			return m2, []action{{kind: actStartProbe}}, true
		case StateActive, StateActiveTunnelOnly:
			m2 := m.to(StateProbing, now) // pipeline keeps running while re-classifying
			m2.probeInFlight = true
			return m2, []action{{kind: actStartProbe}}, true
		default: // PROBING: restart the in-flight probe
			m.probeInFlight = true
			return m, []action{{kind: actStartProbe}}, false
		}

	case evNetChange, evResume:
		destabilize := func(mm machine) machine {
			mm.lastFailAt = now // a fresh network breaks the stability gate
			mm.backoffIdx = 0
			mm.pendingProbe = true
			return mm
		}
		switch m.state {
		case StateOff:
			return m, nil, false
		case StateProbing:
			m.probeInFlight = true // restart classification on the new network
			return m, []action{{kind: actStartProbe}}, false
		case StateActive, StateActiveTunnelOnly:
			m2 := destabilize(m.to(StateDegraded, now))
			return m2, []action{{kind: actScheduleProbe, delay: h.backoff(0)}}, true
		case StateDegraded:
			m2 := destabilize(m)
			return m2, []action{{kind: actScheduleProbe, delay: h.backoff(0)}}, false
		}

	case evDegradation:
		// The passive detector (§7.3) fires only after its own threshold,
		// so this event escalates immediately from ACTIVE*.
		switch m.state {
		case StateOff:
			return m, nil, false
		case StateProbing:
			m.recordFail(now, h)
			m.probeInFlight = true
			if m.escalated(h) {
				m2 := m.to(StateDegraded, now)
				m2.pendingProbe = true
				return m2, []action{{kind: actScheduleProbe, delay: h.backoff(0)}}, true
			}
			return m, []action{{kind: actStartProbe}}, false
		case StateActive, StateActiveTunnelOnly:
			m2 := m.to(StateDegraded, now)
			m2.recordFail(now, h)
			m2.backoffIdx = 0
			m2.pendingProbe = true
			return m2, []action{{kind: actScheduleProbe, delay: h.backoff(0)}}, true
		case StateDegraded:
			m.recordFail(now, h)
			m.backoffIdx = 0
			m.pendingProbe = true
			return m, []action{{kind: actScheduleProbe, delay: h.backoff(0)}}, false
		}

	case evProbeDue:
		if !m.pendingProbe || m.probeInFlight {
			return m, nil, false
		}
		switch m.state {
		case StateDegraded:
			m2 := m.to(StateProbing, now)
			m2.recovering = true
			m2.probeInFlight = true
			return m2, []action{{kind: actStartProbe}}, true
		case StateProbing:
			m.pendingProbe = false
			m.probeInFlight = true
			return m, []action{{kind: actStartProbe}}, false
		}
		return m, nil, false

	case evProbeDone:
		oc := ev.outcome
		m.probeInFlight = false
		switch m.state {
		case StateOff:
			// Diagnostic probe result: recorded by the runtime, no transition.
			return m, nil, false

		case StateProbing:
			if !oc.OK {
				m.recordFail(now, h)
				delay := h.backoff(m.backoffIdx)
				m.backoffIdx++
				m.pendingProbe = true
				if m.escalated(h) {
					m2 := m.to(StateDegraded, now)
					m2.pendingProbe = true
					return m2, []action{{kind: actScheduleProbe, delay: delay}}, true
				}
				return m, []action{{kind: actScheduleProbe, delay: delay}}, false
			}
			if m.recovering && now.Sub(m.lastFailAt) < h.DeescalateStable {
				// Probe is green but the 300 s stability gate is not
				// satisfied yet: premature de-escalation is blocked.
				m2 := m.to(StateDegraded, now)
				m2.pendingProbe = true
				m2.backoffIdx = m.backoffIdx
				delay := h.backoff(m2.backoffIdx)
				m2.backoffIdx++
				return m2, []action{{kind: actScheduleProbe, delay: delay}}, true
			}
			m.recovering = false
			m.fails = nil
			m.backoffIdx = 0
			st := StateActive
			if !oc.DesyncAlive {
				st = StateActiveTunnelOnly
			}
			return m.to(st, now), []action{{kind: actStartPipeline}}, true

		case StateActive, StateActiveTunnelOnly:
			if !oc.OK {
				m.recordFail(now, h)
				if m.escalated(h) {
					m2 := m.to(StateDegraded, now)
					m2.backoffIdx = 0
					m2.pendingProbe = true
					return m2, []action{{kind: actScheduleProbe, delay: h.backoff(0)}}, true
				}
				return m, nil, false
			}
			m.fails = nil
			m.backoffIdx = 0
			switch {
			case !oc.DesyncAlive && m.state == StateActive:
				return m.to(StateActiveTunnelOnly, now), nil, true // desync died
			case oc.DesyncAlive && m.state == StateActiveTunnelOnly:
				return m.to(StateActive, now), nil, true // desync recovered
			}
			return m, nil, false

		case StateDegraded:
			// Normally reached only by stale probe results; forced probes
			// go through PROBING. Still handle it coherently.
			if oc.OK && now.Sub(m.lastFailAt) >= h.DeescalateStable {
				st := StateActive
				if !oc.DesyncAlive {
					st = StateActiveTunnelOnly
				}
				m2 := m.to(st, now)
				m2.fails = nil
				m2.backoffIdx = 0
				return m2, []action{{kind: actStartPipeline}}, true
			}
			if !oc.OK {
				m.recordFail(now, h)
			}
			m.pendingProbe = true
			delay := h.backoff(m.backoffIdx)
			m.backoffIdx++
			return m, []action{{kind: actScheduleProbe, delay: delay}}, false
		}
	}
	return m, nil, false
}
