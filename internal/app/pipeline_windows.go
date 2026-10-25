//go:build windows

package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/rupas/rupas/internal/capture"
	"github.com/rupas/rupas/internal/config"
	"github.com/rupas/rupas/internal/desync"
	"github.com/rupas/rupas/internal/rules"
	"github.com/rupas/rupas/internal/supervisor"
	"github.com/rupas/rupas/internal/tunnel"
)

// Tunnel branch modes reported by pipelineStats.TunnelMode and rendered by
// `rupasctl status` (docs/SYSTEM_DESIGN §3.3, §6):
const (
	// tunnelModeOff: -tunnel=off — TUNNEL rules demoted to DIRECT, no NAT.
	tunnelModeOff = "off"
	// tunnelModeEscalated: tunnel requested but unusable (endpoint empty
	// or tunnel start failed). TUNNEL rules are escalated: SNI rules →
	// DESYNC fallback, CIDR/port rules → DIRECT — logged and counted, so
	// flows are never silently black-holed at a dead loopback port.
	tunnelModeEscalated = "escalated"
	// tunnelModeLive: NAT → loopback tproxy → sing-box VLESS+Reality.
	tunnelModeLive = "tunnel"
)

// pipelineDeps carries the immutable construction parameters.
type pipelineDeps struct {
	tpl        []byte
	tunnel     bool
	tproxyPort uint16
	tunnelOpts tunnelRunOpts
	log        *log.Logger
	// engineHook runs after capture.New on every start segment, before
	// Run (tests inject fake transports there). Nil in production.
	engineHook func(*capture.Engine)
}

// capturePipeline implements supervisor.Pipeline (and the wider
// pipelineControl seam) over capture.Engine plus the real tunnel core
// (internal/tunnel, §3.3 + §6):
//
//   - Start compiles the rules, brings the tunnel up (sing-box VLESS+
//     Reality tproxy on the loopback NAT port — started BEFORE the engine
//     so redirected packets never hit a dead port) and launches a fresh
//     engine in a goroutine whose Run error is drained by Stop.
//     capture.Engine.Run is once-only, so every start segment gets its own
//     engine and its own tunnel — this is also what a hot desync profile
//     update rides on (see the package comment).
//   - Without a usable endpoint the tunnel branch escalates honestly
//     (see tunnelModeEscalated) instead of failing the whole pipeline.
//   - Stop is graceful: the engine unblocks pending receives, the driver
//     re-injects still-queued packets when the handle closes, the tunnel
//     relays drain and the sing-box engine closes.
//   - SuspendForProbe/ResumeFromProbe bracket probe cycles (see
//     ProbeRunner.Run).
type capturePipeline struct {
	log        *log.Logger
	tpl        []byte
	tunnel     bool
	tproxyPort uint16
	tunnelOpts tunnelRunOpts
	engineHook func(*capture.Engine)
	provider   *natProvider

	mu         sync.Mutex
	lastCfg    *config.Config
	override   *config.DesyncParams
	engine     *capture.Engine
	runErr     chan error
	tun        tunnel.Tunnel
	tunnelMode string
	escaped    int // TUNNEL rules rewritten by the escalation fallback
	running    bool
	gen        uint64
	onRunErr   func(note string)
}

var (
	_ supervisor.Pipeline = (*capturePipeline)(nil)
	_ pipelineControl     = (*capturePipeline)(nil)
)

func newPipeline(d pipelineDeps) pipelineControl {
	port := d.tproxyPort
	if port == 0 {
		port = DefaultTProxyPort
	}
	if d.log == nil {
		d.log = log.Default()
	}
	return &capturePipeline{
		log:        d.log,
		tpl:        d.tpl,
		tunnel:     d.tunnel,
		tproxyPort: port,
		tunnelOpts: d.tunnelOpts,
		engineHook: d.engineHook,
		provider:   &natProvider{},
	}
}

func (p *capturePipeline) SetDegradationSink(f func(note string)) {
	p.mu.Lock()
	p.onRunErr = f
	p.mu.Unlock()
}

// Start launches interception for cfg. Called by the supervisor event
// loop (on / reload) — an implicit restart when already running.
func (p *capturePipeline) Start(cfg *config.Config) error {
	if cfg == nil {
		return errors.New("app: pipeline: nil config")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gen++
	// A REPLACED config wins over a stale probed profile — but the very
	// first Start (lastCfg still nil) must keep the profile the initial
	// probe just calibrated.
	if p.lastCfg != nil && cfg != p.lastCfg {
		p.override = nil
	}
	p.lastCfg = cfg
	return p.startLocked(cfg)
}

// Stop shuts the pipeline down; idempotent.
func (p *capturePipeline) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gen++
	p.stopLocked()
	return nil
}

// SuspendForProbe stops interception without invalidating probe tokens:
// the generation counter is only bumped by external Start/Stop.
func (p *capturePipeline) SuspendForProbe() suspendToken {
	p.mu.Lock()
	defer p.mu.Unlock()
	t := suspendToken{gen: p.gen, wasRunning: p.running}
	if p.running {
		p.stopLocked()
	}
	return t
}

// ResumeFromProbe applies the probed profile (if any) and restarts the
// engine, unless an external Start/Stop superseded the token — in that
// case the override is kept and simply rides the next external Start.
func (p *capturePipeline) ResumeFromProbe(t suspendToken, next *config.DesyncParams) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if next != nil {
		if err := validateDesync(*next, p.tpl); err != nil {
			p.log.Printf("app: probed profile rejected, keeping the previous one: %v", err)
		} else {
			p.override = next
		}
	}
	if t.gen != p.gen {
		p.log.Printf("app: probe resume superseded by an external pipeline start/stop; profile applies on next start")
		return
	}
	if t.wasRunning && !p.running && p.lastCfg != nil {
		if err := p.startLocked(p.lastCfg); err != nil {
			p.log.Printf("app: pipeline resume failed: %v", err)
			if p.onRunErr != nil {
				p.onRunErr("pipeline resume failed: " + err.Error())
			}
		}
	}
}

// TunnelHealth reports the live tunnel branch: assembled=false means no
// live tunnel (mode off/escalated — nothing for the supervisor watch to
// degrade on), healthy mirrors tunnel.Healthy() (§6 marker).
func (p *capturePipeline) TunnelHealth() (assembled, healthy bool) {
	p.mu.Lock()
	tun := p.tun
	p.mu.Unlock()
	if tun == nil {
		return false, false
	}
	return true, tun.Healthy()
}

func (p *capturePipeline) Stats() pipelineStats {
	p.mu.Lock()
	eng, tun, running, cfg, override, mode, escaped :=
		p.engine, p.tun, p.running, p.lastCfg, p.override, p.tunnelMode, p.escaped
	p.mu.Unlock()
	st := pipelineStats{Running: running, TunnelMode: mode, TunnelEscalated: escaped}
	if eng != nil {
		st.Counters = eng.Counters()
		st.ActiveFlows = int64(eng.Flows().Len())
	}
	if tun != nil {
		ts := tun.Stats()
		st.Tunnel = &ts
	}
	switch {
	case override != nil:
		st.Desync = *override
	case cfg != nil:
		st.Desync = cfg.Desync
	}
	return st
}

// startLocked creates a fresh engine (and tunnel, when applicable) and
// launches it. Caller holds mu.
func (p *capturePipeline) startLocked(cfg *config.Config) error {
	if p.running {
		p.stopLocked()
	}
	eff := effectiveDesync(cfg.Desync, p.override)

	effCfg := *cfg
	var (
		port  uint16
		tg    []string
		tun   tunnel.Tunnel
		mode  = tunnelModeOff
		escal int
	)
	switch {
	case !p.tunnel:
		// Tunnel branch off: TUNNEL rules would NAT flows to a dead
		// loopback port, so demote them to DIRECT and don't widen the
		// capture filter with the TG CIDRs at all.
		effCfg.Rules = demoteTunnelRules(cfg.Rules)
	case !tunnelEndpointConfigured(cfg):
		// Tunnel requested but no endpoint in the config: escalate
		// honestly (documented behavior) — SNI rules get the DESYNC
		// fallback, CIDR/port rules go DIRECT, with a log line and a
		// counter. The tunnel section of `rupasctl status` shows mode
		// "escalated" until an endpoint is attached.
		escal = escalateTunnelRules(&effCfg, cfg, p.log)
		mode = tunnelModeEscalated
	default:
		// Real tunnel branch: bring the tproxy listeners up FIRST so the
		// NAT rewrite never targets a dead port.
		tun = newTunnel(cfg, p.tproxyPort, p.provider, p.log, p.tunnelOpts)
		if err := tun.Start(context.Background()); err != nil {
			p.log.Printf("app: tunnel start failed: %v; escalating TUNNEL rules (sni→desync, cidr/port→direct)", err)
			escal = escalateTunnelRules(&effCfg, cfg, p.log)
			mode = tunnelModeEscalated
			tun = nil
		} else {
			port = p.tproxyPort
			tg = tunnelCIDRs(cfg.Rules)
			effCfg.Rules = cfg.Rules
			mode = tunnelModeLive
		}
	}

	tbl, err := rules.Compile(&effCfg)
	if err != nil {
		if tun != nil {
			tun.Stop()
		}
		return fmt.Errorf("app: rules: %w", err)
	}
	if _, err := desync.New(eff, p.tpl); err != nil {
		if tun != nil {
			tun.Stop()
		}
		return fmt.Errorf("app: %w", err)
	}
	eng, err := capture.New(capture.Options{
		Rules:        tbl,
		Desync:       eff,
		FakeTemplate: p.tpl,
		TProxyPort:   port,
		TGCIDRs:      tg,
	})
	if err != nil {
		if tun != nil {
			tun.Stop()
		}
		return fmt.Errorf("app: %w", err)
	}
	p.provider.eng.Store(eng)
	if p.engineHook != nil {
		p.engineHook(eng)
	}
	runErr := make(chan error, 1)
	go func() {
		err := eng.Run(context.Background()) // stopped via eng.Stop()
		runErr <- err
		if err == nil {
			return
		}
		p.mu.Lock()
		current := p.running && p.engine == eng
		if current {
			p.running = false
			p.engine = nil
			p.runErr = nil
		}
		p.mu.Unlock()
		if current && p.onRunErr != nil {
			p.onRunErr("capture run failed: " + err.Error())
		}
	}()
	p.engine, p.runErr, p.tun, p.tunnelMode, p.escaped, p.running = eng, runErr, tun, mode, escal, true
	return nil
}

// stopLocked drains the engine and the tunnel. Caller holds mu.
func (p *capturePipeline) stopLocked() {
	if !p.running {
		return
	}
	eng, runErr, tun := p.engine, p.runErr, p.tun
	p.engine, p.runErr, p.tun, p.running = nil, nil, nil, false
	p.provider.eng.Store(nil)
	eng.Stop() // graceful drain; closes the WinDivert handles it owns
	if runErr != nil {
		select {
		case err := <-runErr:
			if err != nil {
				p.log.Printf("app: capture run ended: %v", err)
			}
		case <-time.After(2 * time.Second):
		}
	}
	if tun != nil {
		if err := tun.Stop(); err != nil {
			p.log.Printf("app: tunnel stop: %v", err)
		}
	}
}
