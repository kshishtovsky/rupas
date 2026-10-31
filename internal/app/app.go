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
	"time"

	"github.com/kshishtovsky/rupas/internal/config"
	"github.com/kshishtovsky/rupas/internal/core"
	"github.com/kshishtovsky/rupas/internal/desync"
	"github.com/kshishtovsky/rupas/internal/rules"
	"github.com/kshishtovsky/rupas/internal/supervisor"
	"github.com/kshishtovsky/rupas/internal/tunnel"
)

// Options tunes App construction. The zero value is usable: the tunnel
// branch is disabled and the fake template is autodiscovered.
type Options struct {
	// FakeTemplatePath explicitly points at the fake ClientHello binary.
	// Empty autodiscovers build/desync/<cfg.Desync.FakeTemplate>, then
	// build/desync/fake-chrome.bin (walking up from the working directory).
	FakeTemplatePath string
	// Tunnel enables the tunnel branch: TUNNEL-verdict flows (TG CIDRs,
	// UDP relay, ECH) are NAT-redirected to the loopback tproxy and
	// relayed through the sing-box VLESS+Reality core (internal/tunnel).
	// With Tunnel=true but NO endpoint in the config the TUNNEL rules are
	// escalated honestly instead: SNI rules → DESYNC fallback, CIDR/port
	// rules → DIRECT (logged + counted; see tunnelModeEscalated).
	// With Tunnel=false the TUNNEL rules are demoted to DIRECT and the
	// NAT branch stays off entirely.
	Tunnel bool
	// TProxyPort is the loopback NAT/tproxy port (0 = DefaultTProxyPort).
	TProxyPort uint16
	// TunnelMarkerURL overrides the tunnel health-marker endpoint (§6).
	// Empty → tunnel.DefaultMarkerURL.
	TunnelMarkerURL string
	// TunnelHealthInterval overrides the marker probe period (0 → 30 s,
	// §6). Tests shrink it.
	TunnelHealthInterval time.Duration
	// TunnelDialTimeout bounds one tunnel relay dial (0 → 20 s) so a dead
	// endpoint closes redirected flows promptly.
	TunnelDialTimeout time.Duration
	// NoCalibration skips the TTL binary search during probe cycles
	// (tests use it to keep probe cycles short).
	NoCalibration bool
	// ProbeAttempts overrides classification attempts per target
	// (0 = prober default 3).
	ProbeAttempts int
	// ChLog turns on the per-ClientHello decision diagnostics (wave 7):
	// ONE log line per inspected ClientHello ("CH sni=… ech=… dst=…
	// verdict=…") — TSPU-shape diagnostics. Off by default: the capture
	// hot path pays nothing (nil formatter = silent).
	ChLog bool
	// ProfilePath overrides the persisted probe profile location (§4.3
	// fast start). Empty → %ProgramData%/rupas/profile.json. Tests point
	// it at a temp dir.
	ProfilePath string
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
		tunnelOpts: tunnelRunOpts{
			markerURL:      opts.TunnelMarkerURL,
			healthInterval: opts.TunnelHealthInterval,
			dialTimeout:    opts.TunnelDialTimeout,
		},
		chLog: opts.ChLog,
		log:   logger,
	})
	a.prober = newProbeRunner(probeDeps{
		log:           logger,
		tpl:           tpl,
		pipeline:      a.pipeline,
		cfg:           a.Config,
		attempts:      opts.ProbeAttempts,
		inj:           newFakeInjector(tpl, logger),
		noCalibration: opts.NoCalibration,
		profilePath:   opts.ProfilePath,
	})
	a.evlog = supervisor.NewEventLog(100)
	a.sup = supervisor.New(supervisor.Deps{
		Pipeline:  a.pipeline,
		Prober:    a.prober,
		Config:    cfg,
		Logger:    logger,
		EventLog:  a.evlog,
		FastStart: a.prober,
		// Tunnel health watch (§6): the tunnel's own marker loop flips
		// Healthy() after 3×30 s failures; the supervisor turns a
		// persistent failure into its existing degradation path. An
		// unassembled tunnel (off/escalated) reports healthy so it never
		// degrades the machine.
		TunnelHealth: func() bool {
			assembled, healthy := a.pipeline.TunnelHealth()
			return !assembled || healthy
		},
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

// Stats returns live pipeline state (engine counters, flow count, tunnel
// branch status, effective desync profile).
func (a *App) Stats() pipelineStats { return a.pipeline.Stats() }

// LastCalibration returns the last TTL-calibration outcome, or nil before
// the first probe cycle. Found=false means every candidate target was
// proven window-less (the split fallback is armed).
func (a *App) LastCalibration() *calInfo { return a.prober.LastCalibration() }

// Snapshot merges the authoritative supervisor snapshot with the live
// capture counters and the tunnel-branch section, so `rupasctl status`
// reports real numbers while the pipeline runs. The probe bookkeeping
// (LastProbeAt/Note) stays owned by the supervisor.
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
	if len(flows) > 0 {
		s.Flows = flows
	}
	// Tunnel section (§3.3/§6): mode, health, bytes, flows, drops. When a
	// live tunnel exists its marker health is authoritative (more recent
	// than the last probe outcome).
	s.Tunnel = &core.TunnelStatus{
		Mode:           st.TunnelMode,
		EscalatedRules: st.TunnelEscalated,
	}
	if st.Tunnel != nil {
		s.Tunnel.Healthy = st.Tunnel.Healthy
		s.Tunnel.Held = st.Tunnel.Held
		s.Tunnel.RxBytes = st.Tunnel.RxBytes
		s.Tunnel.TxBytes = st.Tunnel.TxBytes
		s.Tunnel.TCPFlows = st.Tunnel.TCPFlows
		s.Tunnel.TCPConns = st.Tunnel.TCPConns
		s.Tunnel.UDPSessions = st.Tunnel.UDPSessions
		s.Tunnel.UDPDgrams = st.Tunnel.UDPDgrams
		s.Tunnel.UDPHealthy = st.Tunnel.UDPHealthy
		s.Tunnel.UDPFallback = st.Tunnel.UDPFallback
		s.Tunnel.Dropped = st.Tunnel.Dropped
		s.TunnelHealthy = st.Tunnel.Healthy
	}
	return s
}

// ---------------------------------------------------------------------------
// Pipeline seam (portable contract; Windows implements it over capture)
// ---------------------------------------------------------------------------

// pipelineStats is the live pipeline state surfaced to App.Snapshot/Stats.
type pipelineStats struct {
	Running     bool
	Counters    core.Counters
	ActiveFlows int64
	Desync      config.DesyncParams
	// TunnelMode is how TUNNEL-rule flows are served right now:
	// "tunnel" (live relay) | "escalated" (no endpoint: sni→desync,
	// cidr/port→direct, counted) | "off" (-tunnel=off). Empty before the
	// first start.
	TunnelMode string
	// TunnelEscalated is the number of TUNNEL rules rewritten by the
	// escalation fallback (0 unless TunnelMode == "escalated").
	TunnelEscalated int
	// Tunnel is the live tunnel-core status (nil unless TunnelMode ==
	// "tunnel").
	Tunnel *tunnel.Stats
}

// pipelineControl is what App needs from the capture side. On Windows it
// is implemented by capturePipeline (capture.Engine + tunnel lifecycle);
// other platforms get an explicit "unsupported" stub.
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
	// TunnelHealth reports the live tunnel branch: assembled=false means
	// no live tunnel (mode off/escalated), healthy mirrors
	// tunnel.Healthy() (§6 marker). Non-Windows reports false, false.
	TunnelHealth() (assembled, healthy bool)
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

// tunnelRunOpts are the app-level tunnel overrides carried through
// Options (production keeps the zero values: default marker, §6 30 s
// health interval, 20 s dial bound).
type tunnelRunOpts struct {
	markerURL      string
	healthInterval time.Duration
	dialTimeout    time.Duration
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

// escalateTunnelRules rewrites TUNNEL rules for the no-endpoint fallback
// (documented behavior of -tunnel=on with an empty config tunnel
// section): SNI-matched rules degrade to the DESYNC fallback (the SNI
// branch can still bypass the TSPU), CIDR/port/default rules go DIRECT —
// honest in both directions: an IP-blackholed CIDR will not pass DIRECT,
// but the flow is no longer silently black-holed at a dead loopback port
// either, and the rewrite is logged and counted (pipelineStats.
// TunnelEscalated / status "escalated"). A config without a usable
// desync section escalates everything to DIRECT. It mutates effCfg.Rules
// and returns the number of rewritten rules.
func escalateTunnelRules(effCfg *config.Config, base *config.Config, log *log.Logger) int {
	desyncReady := base.Desync.Strategy != ""
	ns, no := 0, 0 // sni→desync, cidr/port/default→direct
	out := make([]config.Rule, len(base.Rules))
	for i, r := range base.Rules {
		if r.Action == config.ActionTunnel {
			if r.SNI != "" && desyncReady {
				r.Action = config.ActionDesync
				ns++
			} else {
				r.Action = config.ActionDirect
				no++
			}
		}
		out[i] = r
	}
	effCfg.Rules = out
	n := ns + no
	if n > 0 {
		log.Printf("app: tunnel endpoint not configured: %d TUNNEL rule(s) escalated (sni→desync: %d, cidr/port→direct: %d); honest fallback, flows are not black-holed",
			n, ns, no)
	}
	return n
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
				// Portable-zip layout: templates sit in <exe dir>\desync.
				filepath.Join("desync", name),
				name,
			)
		}
		candidates = append(candidates,
			filepath.Join("build", "desync", "fake-chrome.bin"),
			filepath.Join("desync", "fake-chrome.bin"),
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
