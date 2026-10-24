// Package app assembles the Rupas runtime (wave 3 integration): it owns
// the configuration lifecycle, the capture pipeline (supervisor.Pipeline
// over capture.Engine), the probe engine (supervisor.Prober over
// prober.Classifier + CalibrateTTL with a WinDivert-backed FakeInjector)
// and the supervisor state machine. cmd/rupasd only parses flags, builds
// an App and serves the RPC pipe.
//
// Hot profile updates: capture.Engine compiles its desync.Engine once in
// New and its hot path is single-threaded by design (SYSTEM_DESIGN §3.2),
// so capture deliberately exposes no desync setter. Applying a freshly
// calibrated profile therefore RESTARTS the pipeline (Stop → New → Run):
// sub-second, queued packets are re-injected by the driver when the old
// handle closes, and live flows are re-classified conservatively on their
// next data segment. This trade-off is documented here instead of carving
// an atomic swap into the capture hot path.
package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/rupas/rupas/internal/config"
	"github.com/rupas/rupas/internal/core"
	"github.com/rupas/rupas/internal/desync"
	"github.com/rupas/rupas/internal/rules"
	"github.com/rupas/rupas/internal/supervisor"
)

// Options tunes App construction. The zero value is usable: the tunnel
// branch is disabled and the fake template is autodiscovered.
type Options struct {
	// FakeTemplatePath explicitly points at the fake ClientHello binary.
	// Empty autodiscovers build/desync/<cfg.Desync.FakeTemplate>, then
	// build/desync/fake-chrome.bin (walking up from the working directory).
	FakeTemplatePath string
	// Tunnel enables the tunnel branch: TUNNEL-verdict flows (TG CIDRs,
	// UDP relay, ECH) are NAT-redirected to a loopback tproxy that, until
	// the sing-box core lands in wave 4, is a stub logger which counts
	// and closes the flow. With Tunnel=false the TUNNEL rules are demoted
	// to DIRECT and the NAT branch stays off entirely.
	Tunnel bool
	// TProxyPort is the loopback NAT/tproxy port (0 = DefaultTProxyPort).
	TProxyPort uint16
	// NoCalibration skips the TTL binary search during probe cycles
	// (tests use it to keep probe cycles short).
	NoCalibration bool
	// ProbeAttempts overrides classification attempts per target
	// (0 = prober default 3).
	ProbeAttempts int
}

// App is the assembled Rupas runtime.
type App struct {
	opts     Options
	log      *log.Logger
	tpl      []byte
	cfg      atomic.Pointer[config.Config]
	pipeline pipelineControl
	prober   *ProbeRunner
	evlog    *supervisor.EventLog
	sup      *supervisor.Supervisor
}

// New validates the configuration, loads the fake ClientHello template
// and wires the pipeline, the prober and the supervisor. It touches no
// driver handles: the capture engine is created per start segment inside
// the pipeline (capture.Engine.Run is once-only).
func New(cfg *config.Config, logger *log.Logger, opts Options) (*App, error) {
	if cfg == nil {
		return nil, errors.New("app: nil config")
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("app: %w", err)
	}
	if _, err := rules.Compile(cfg); err != nil {
		return nil, fmt.Errorf("app: %w", err)
	}
	if logger == nil {
		logger = log.New(os.Stderr, "rupas ", log.LstdFlags|log.Lmicroseconds)
	}
	tpl, src, err := loadFakeTemplate(opts.FakeTemplatePath, cfg)
	if err != nil {
		return nil, err
	}
	logger.Printf("app: fake template %s (%d bytes)", src, len(tpl))

	a := &App{opts: opts, log: logger, tpl: tpl}
	a.cfg.Store(cfg)
	a.pipeline = newPipeline(pipelineDeps{
		tpl:        tpl,
		tunnel:     opts.Tunnel,
		tproxyPort: opts.TProxyPort,
		log:        logger,
	})
	a.prober = newProbeRunner(probeDeps{
		log:           logger,
		tpl:           tpl,
		pipeline:      a.pipeline,
		cfg:           a.Config,
		attempts:      opts.ProbeAttempts,
		inj:           newFakeInjector(tpl, logger),
		noCalibration: opts.NoCalibration,
	})
	a.evlog = supervisor.NewEventLog(100)
	a.sup = supervisor.New(supervisor.Deps{
		Pipeline: a.pipeline,
		Prober:   a.prober,
		Config:   cfg,
		Logger:   logger,
		EventLog: a.evlog,
	})
	// A dead capture engine escalates the supervisor (§8 degradation).
	a.pipeline.SetDegradationSink(func(note string) {
		a.sup.Notify(core.EventDegradation, note)
	})
	return a, nil
}

// Supervisor returns the state machine (On/Off/ForceProbe/Reload/Close).
func (a *App) Supervisor() *supervisor.Supervisor { return a.sup }

// EventLog returns the lifecycle event log streamed by the "logs" command.
func (a *App) EventLog() *supervisor.EventLog { return a.evlog }

// Config returns the current configuration.
func (a *App) Config() *config.Config { return a.cfg.Load() }

// SetConfig validates and installs a new configuration (RPC "reload").
func (a *App) SetConfig(cfg *config.Config) error {
	if cfg == nil {
		return errors.New("app: nil config")
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("app: %w", err)
	}
	a.cfg.Store(cfg)
	return nil
}

// Start launches the supervisor event loop.
func (a *App) Start(ctx context.Context) error { return a.sup.Start(ctx) }

// Close stops the supervisor, cancels in-flight probes and stops the
// capture pipeline (WinDivert handles are closed even on failure paths).
// Idempotent.
func (a *App) Close() error { return a.sup.Close() }

// Stats returns live pipeline state (engine counters, flow count, tproxy
// stub counters, effective desync profile).
func (a *App) Stats() pipelineStats { return a.pipeline.Stats() }

// LastCalibration returns the last TTL-calibration outcome, or nil before
// the first probe cycle. Found=false means every candidate target was
// proven window-less (the split fallback is armed).
func (a *App) LastCalibration() *calInfo { return a.prober.LastCalibration() }

// Snapshot merges the authoritative supervisor snapshot with the live
// capture counters, so `rupasctl status` reports real numbers while the
// pipeline runs. The probe bookkeeping (LastProbeAt/Note) stays owned by
// the supervisor.
func (a *App) Snapshot() core.Snapshot {
	s := a.sup.Snapshot()
	st := a.pipeline.Stats()
	c := st.Counters
	if c.PacketsTotal > 0 || c.HandshakeOK > 0 {
		s.Counters.PacketsTotal = c.PacketsTotal
		s.Counters.PacketsPass = c.PacketsPass
		s.Counters.PacketsDesync = c.PacketsDesync
		s.Counters.PacketsRedir = c.PacketsRedir
		s.Counters.PacketsDrop = c.PacketsDrop
		s.Counters.HandshakeOK = c.HandshakeOK
		s.Counters.HandshakeFail = c.HandshakeFail
		s.Counters.TunnelRx = c.TunnelRx
		s.Counters.TunnelTx = c.TunnelTx
	}
	flows := map[string]int64{}
	if st.ActiveFlows > 0 {
		flows["active"] = st.ActiveFlows
	}
	if st.TProxyConns > 0 {
		flows["tproxy_conns"] = st.TProxyConns
	}
	if st.TProxyDgrams > 0 {
		flows["tproxy_dgrams"] = st.TProxyDgrams
	}
	if len(flows) > 0 {
		s.Flows = flows
	}
	return s
}

// ---------------------------------------------------------------------------
// Pipeline seam (portable contract; Windows implements it over capture)
// ---------------------------------------------------------------------------

// pipelineStats is the live pipeline state surfaced to App.Snapshot/Stats.
type pipelineStats struct {
	Running      bool
	Counters     core.Counters
	ActiveFlows  int64
	TProxyConns  int64
	TProxyDgrams int64
	Desync       config.DesyncParams
}

// pipelineControl is what App needs from the capture side. On Windows it
// is implemented by capturePipeline (capture.Engine lifecycle + tproxy
// stub); other platforms get an explicit "unsupported" stub.
type pipelineControl interface {
	// Start launches interception for cfg (supervisor.Pipeline.Start).
	Start(cfg *config.Config) error
	// Stop shuts interception down (supervisor.Pipeline.Stop).
	Stop() error
	// SuspendForProbe stops interception for the duration of a probe
	// cycle: classification and TTL calibration must observe the raw
	// path, not the engine's own desync.
	SuspendForProbe() suspendToken
	// ResumeFromProbe restarts interception with an optionally updated
	// desync profile, unless an external Start/Stop superseded the token.
	ResumeFromProbe(t suspendToken, next *config.DesyncParams)
	Stats() pipelineStats
	SetDegradationSink(f func(note string))
}

// suspendToken guards ResumeFromProbe against interleaved external
// lifecycle operations (supervisor on/off/reload).
type suspendToken struct {
	gen        uint64
	wasRunning bool
}

// ---------------------------------------------------------------------------
// Helpers shared by the pipeline and the prober
// ---------------------------------------------------------------------------

// validateDesync checks a (possibly probed) profile against the real
// desync engine constraints.
func validateDesync(p config.DesyncParams, tpl []byte) error {
	if p.Strategy == "" {
		return errors.New("app: empty desync strategy")
	}
	if _, err := desync.New(p, tpl); err != nil {
		return err
	}
	return nil
}

// effectiveDesync picks the probed override when present; a config with
// no DESYNC rule carries no desync section, but capture.New always
// compiles one, so fall back to the built-in default profile.
func effectiveDesync(base config.DesyncParams, override *config.DesyncParams) config.DesyncParams {
	if override != nil {
		return *override
	}
	if base.Strategy == "" {
		return config.Default().Desync
	}
	return base
}

// demoteTunnelRules rewrites TUNNEL rules to DIRECT (used when the tunnel
// branch is off: without a tproxy the NAT rewrite would black-hole the
// flow at 127.0.0.1:<dead port>).
func demoteTunnelRules(rules []config.Rule) []config.Rule {
	out := make([]config.Rule, len(rules))
	for i, r := range rules {
		if r.Action == config.ActionTunnel {
			r.Action = config.ActionDirect
		}
		out[i] = r
	}
	return out
}

// tunnelCIDRs lists the CIDR matchers of TUNNEL rules (widens the capture
// filter for the NAT branch, SYSTEM_DESIGN §3.1).
func tunnelCIDRs(rules []config.Rule) []string {
	var out []string
	for _, r := range rules {
		if r.Action == config.ActionTunnel && r.CIDR != "" {
			out = append(out, r.CIDR)
		}
	}
	return out
}

// firstIP returns the network address of a CIDR as a probe target.
func firstIP(cidr string) string {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}
	return ip.String()
}

// hostOf strips a "*." wildcard prefix from an SNI rule matcher.
func hostOf(sni string) string { return strings.TrimPrefix(sni, "*.") }

// loadFakeTemplate resolves the fake ClientHello template. An explicit
// path must load; otherwise a fixed candidate list (walking up from the
// working directory so package-relative test runs find the repo layout)
// is tried in order.
func loadFakeTemplate(explicit string, cfg *config.Config) ([]byte, string, error) {
	candidates := []string{}
	if explicit != "" {
		candidates = append(candidates, explicit)
	} else {
		if name := cfg.Desync.FakeTemplate; name != "" {
			candidates = append(candidates,
				filepath.Join("build", "desync", name),
				name,
			)
		}
		candidates = append(candidates,
			filepath.Join("build", "desync", "fake-chrome.bin"),
			"fake-chrome.bin",
			filepath.Join("..", "build", "desync", "fake-chrome.bin"),
			filepath.Join("..", "..", "build", "desync", "fake-chrome.bin"),
			filepath.Join("..", "..", "..", "build", "desync", "fake-chrome.bin"),
		)
	}
	var firstErr error
	for _, c := range candidates {
		tpl, err := desync.LoadTemplate(c)
		if err == nil {
			return tpl, c, nil
		}
		if firstErr == nil {
			firstErr = err
		}
		if explicit != "" {
			break
		}
	}
	if firstErr == nil {
		firstErr = errors.New("no fake template candidate found")
	}
	return nil, "", fmt.Errorf("app: fake template: %w", firstErr)
}
