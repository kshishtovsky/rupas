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
)

// pipelineDeps carries the immutable construction parameters.
type pipelineDeps struct {
	tpl        []byte
	tunnel     bool
	tproxyPort uint16
	log        *log.Logger
}

// capturePipeline implements supervisor.Pipeline (and the wider
// pipelineControl seam) over capture.Engine:
//
//   - Start compiles the rules, starts the tproxy stub (tunnel branch)
//     and launches a fresh engine in a goroutine whose Run error is
//     drained by Stop. capture.Engine.Run is once-only, so every start
//     segment gets its own engine — this is also what a hot desync
//     profile update rides on (see the package comment).
//   - Stop is graceful: the engine unblocks pending receives, the driver
//     re-injects still-queued packets when the handle closes.
//   - SuspendForProbe/ResumeFromProbe bracket probe cycles (see
//     ProbeRunner.Run).
type capturePipeline struct {
	log        *log.Logger
	tpl        []byte
	tunnel     bool
	tproxyPort uint16

	mu       sync.Mutex
	lastCfg  *config.Config
	override *config.DesyncParams
	engine   *capture.Engine
	runErr   chan error
	stub     *TProxyStub
	running  bool
	gen      uint64
	onRunErr func(note string)
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

func (p *capturePipeline) Stats() pipelineStats {
	p.mu.Lock()
	eng, stub, running, cfg, override := p.engine, p.stub, p.running, p.lastCfg, p.override
	p.mu.Unlock()
	st := pipelineStats{Running: running}
	if eng != nil {
		st.Counters = eng.Counters()
		st.ActiveFlows = int64(eng.Flows().Len())
	}
	if stub != nil {
		st.TProxyConns = stub.Conns()
		st.TProxyDgrams = stub.Dgrams()
	}
	switch {
	case override != nil:
		st.Desync = *override
	case cfg != nil:
		st.Desync = cfg.Desync
	}
	return st
}

// startLocked creates a fresh engine and launches it. Caller holds mu.
func (p *capturePipeline) startLocked(cfg *config.Config) error {
	if p.running {
		p.stopLocked()
	}
	eff := effectiveDesync(cfg.Desync, p.override)

	effCfg := *cfg
	var (
		port uint16
		tg   []string
		stub *TProxyStub
	)
	if p.tunnel {
		effCfg.Rules = cfg.Rules
		port = p.tproxyPort
		tg = tunnelCIDRs(cfg.Rules)
		s, err := StartTProxyStub(port, p.log)
		if err != nil {
			return fmt.Errorf("app: %w", err)
		}
		stub = s
	} else {
		// Tunnel branch off: TUNNEL rules would NAT flows to a dead
		// loopback port, so demote them to DIRECT and don't widen the
		// capture filter with the TG CIDRs at all.
		effCfg.Rules = demoteTunnelRules(cfg.Rules)
	}

	tbl, err := rules.Compile(&effCfg)
	if err != nil {
		if stub != nil {
			stub.Stop()
		}
		return fmt.Errorf("app: rules: %w", err)
	}
	if _, err := desync.New(eff, p.tpl); err != nil {
		if stub != nil {
			stub.Stop()
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
		if stub != nil {
			stub.Stop()
		}
		return fmt.Errorf("app: %w", err)
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
	p.engine, p.runErr, p.stub, p.running = eng, runErr, stub, true
	return nil
}

// stopLocked drains the engine and the tproxy stub. Caller holds mu.
func (p *capturePipeline) stopLocked() {
	if !p.running {
		return
	}
	eng, runErr, stub := p.engine, p.runErr, p.stub
	p.engine, p.runErr, p.stub, p.running = nil, nil, nil, false
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
	if stub != nil {
		stub.Stop()
	}
}
