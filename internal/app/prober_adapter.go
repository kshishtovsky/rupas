package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rupas/rupas/internal/config"
	"github.com/rupas/rupas/internal/prober"
	"github.com/rupas/rupas/internal/supervisor"
)

const (
	// DefaultCalibrationBudget bounds the whole calibration phase (scan +
	// binary search) across all candidate targets.
	DefaultCalibrationBudget = 240 * time.Second
	// perIPCaliBudget bounds the rigorous CalibrateTTL run on one target.
	perIPCaliBudget = 90 * time.Second
	// calibrationDelay paces the 3 repeats within one TTL point.
	calibrationDelay = 150 * time.Millisecond
	// maxCalTargets caps how many candidate ip/sni pairs calibration
	// tries before declaring the fake strategy dead. Candidates are
	// interleaved across the desync-rule targets so one hard target
	// (e.g. a Google frontend where every TTL is filtered) cannot
	// exhaust the budget before other paths are tried.
	maxCalTargets = 6
)

// defaultScanTTLs is the ascending single-attempt ladder used to find a
// working TTL before the rigorous binary search. Lab + live data: the
// fake must reach the TSPU but die before the server (the TSPU window is
// bounded from above on Google front-ends: TTL 8 worked where 16/32 were
// blackholed), so CalibrateTTL's monotone-to-Hi assumption cannot be
// seeded with Hi=32 directly — we first locate any passing TTL and seed
// the binary search just there.
var defaultScanTTLs = []int{4, 6, 8, 10, 12, 14, 16, 20, 24, 28, 32}

// calInfo is the outcome of the last TTL calibration (diagnostics/e2e).
type calInfo struct {
	IP        string
	SNI       string
	Star      int // minimal working TTL (t*)
	Effective int // Star+Margin, what the engine programs
	Found     bool
	At        time.Time
}

// calTarget is one ip/sni calibration candidate.
type calTarget struct{ ip, sni string }

// probeDeps carries the ProbeRunner wiring.
type probeDeps struct {
	log      *log.Logger
	tpl      []byte
	pipeline pipelineControl
	cfg      func() *config.Config
	// transport overrides TCP establishment (tests); nil → RealTransport.
	transport prober.Transport
	// inj is the capture-backed fake injector; nil (non-Windows) skips
	// calibration. Production never passes prober.UnwiredInjector here.
	inj prober.FakeInjector
	// attempts overrides classification attempts per target (0 → 3).
	attempts int
	// handshakeTimeout / attemptDelay override classifier pacing (tests).
	handshakeTimeout time.Duration
	attemptDelay     time.Duration
	// noCalibration skips the TTL search (tests keep cycles short).
	noCalibration bool
	// calBudget overrides DefaultCalibrationBudget when positive.
	calBudget time.Duration
	// scanTTLs overrides the scan ladder (tests).
	scanTTLs []int
	// resolveIP overrides DNS resolution (tests); nil → the system
	// resolver. *net.Resolver satisfies the signature.
	resolveIP func(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// lookupIP resolves host through the seam (system resolver by default).
func (p *ProbeRunner) lookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	if p.resolveIP != nil {
		return p.resolveIP(ctx, "ip4", host)
	}
	return net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
}

// ProbeRunner implements supervisor.Prober: classify the configured
// targets, calibrate the fake TTL on blocked SNIs and hand the resulting
// desync profile to the pipeline (which restarts the engine with it).
type ProbeRunner struct {
	probeDeps
	classifier *prober.Classifier
	lastCal    atomic.Pointer[calInfo]
}

var _ supervisor.Prober = (*ProbeRunner)(nil)

func newProbeRunner(d probeDeps) *ProbeRunner {
	t := d.transport
	if t == nil {
		t = &prober.RealTransport{}
	}
	c := prober.NewClassifier(t)
	if d.attempts > 0 {
		c.Attempts = d.attempts
	}
	if d.handshakeTimeout > 0 {
		c.HandshakeTimeout = d.handshakeTimeout
	}
	if d.attemptDelay > 0 {
		c.AttemptDelay = d.attemptDelay
	}
	return &ProbeRunner{probeDeps: d, classifier: c}
}

// LastCalibration returns the outcome of the last calibration attempt
// (nil before the first probe cycle).
func (p *ProbeRunner) LastCalibration() *calInfo { return p.lastCal.Load() }

// Run executes one probe cycle. The capture pipeline is suspended for the
// whole cycle: the engine would otherwise desync its own probe traffic
// and a broken TSPU bypass would classify as healthy. Classification
// (ProbeIP/ProbeSNI per §7.1) runs against targets derived from the
// current config rules; a successful (or definitively window-less)
// calibration produces a new desync profile that ResumeFromProbe applies.
func (p *ProbeRunner) Run(ctx context.Context) (supervisor.ProfileResult, error) {
	cfg := p.cfg()
	if cfg == nil {
		return supervisor.ProfileResult{}, errors.New("app: prober: no configuration")
	}
	tok := p.pipeline.SuspendForProbe()
	var next *config.DesyncParams
	defer func() { p.pipeline.ResumeFromProbe(tok, next) }()

	var sb strings.Builder
	targets, cals, notes := p.buildTargets(ctx, cfg)
	for _, n := range notes {
		sb.WriteString("; ")
		sb.WriteString(n)
	}
	if len(targets.SNI) == 0 && len(targets.IP) == 0 && len(targets.UDP) == 0 {
		// Nothing probeable (e.g. default-rule-only config, or DNS is
		// down): keep the configured profile instead of failing — the
		// engine must still be able to come up offline.
		return supervisor.ProfileResult{
			ProfileID:   cfg.Profile,
			DesyncAlive: true,
			TunnelOK:    false,
			Note:        "no probeable targets in the config; keeping the configured profile (tunnel n/a until wave 4)",
		}, nil
	}

	res := p.classifier.Classify(ctx, targets)
	if len(res.SNIBlocked) > 0 {
		fmt.Fprintf(&sb, "; sni blocked: %s", strings.Join(res.SNIBlocked, ","))
	}
	if len(res.IPBlackhole) > 0 {
		fmt.Fprintf(&sb, "; ip blackhole: %s", strings.Join(res.IPBlackhole, ","))
	}

	var (
		calRes     prober.Calibration
		calTgt     *calTarget
		calibrated bool
	)
	switch {
	case p.noCalibration:
		sb.WriteString("; ttl calibration disabled by option")
	case p.inj == nil:
		sb.WriteString("; ttl calibration unavailable on this platform")
	case len(cals) == 0:
		sb.WriteString("; no desync-rule SNI target to calibrate on")
	case ctx.Err() != nil:
		// skip: the cycle is being canceled
	default:
		var calNotes []string
		calRes, calTgt, calibrated, calNotes = p.calibrate(ctx, cals)
		for _, n := range calNotes {
			sb.WriteString("; ")
			sb.WriteString(n)
		}
	}

	if calibrated {
		// Program t* and let the engine add the margin exactly once
		// (desync.New computes InjectFake.TTL = TTL + TTLMargin).
		params := res.ToDesyncParams()
		params.Strategy = prober.StrategyFake
		params.TTL = calRes.Star
		params.TTLMargin = calRes.Margin
		if cfg.Desync.Repeats > 0 {
			params.Repeats = cfg.Desync.Repeats
		}
		if err := validateDesync(params, p.tpl); err != nil {
			fmt.Fprintf(&sb, "; probed profile rejected: %v", err)
		} else {
			next = &params
		}
		p.lastCal.Store(&calInfo{
			IP:        calTgt.ip,
			SNI:       calTgt.sni,
			Star:      calRes.Star,
			Effective: calRes.Effective,
			Found:     true,
			At:        time.Now(),
		})
	} else {
		// Definitive: fakes cannot help any candidate target → the
		// split-based fallback (§7.2). SplitOffset 2 keeps the strategy
		// non-degenerate (capture's sendSplit ignores offsets < 1).
		params := res.ToDesyncParams()
		params.Strategy = prober.StrategyFakeSplit
		if params.TTL < 1 {
			params.TTL = cfg.Desync.TTL
			if params.TTL < 1 {
				params.TTL = 13
			}
		}
		if params.SplitOffset < 1 {
			params.SplitOffset = 2
		}
		if cfg.Desync.Repeats > 0 {
			params.Repeats = cfg.Desync.Repeats
		}
		if err := validateDesync(params, p.tpl); err == nil {
			next = &params
		}
		p.lastCal.Store(&calInfo{Found: false, At: time.Now()})
	}

	return supervisor.ProfileResult{
		ProfileID:   cfg.Profile,
		DesyncAlive: true,  // v3: fake or fake_split always armed; a dead-desync verdict needs tunnel-side evidence (wave 4)
		TunnelOK:    false, // no tunnel core until wave 4 — reported honestly
		Note:        strings.TrimPrefix(sb.String(), "; "),
	}, nil
}

// calibrate finds a working fake-TTL window across the candidate
// targets. Per candidate: (1) an ascending single-attempt scan locates
// any passing TTL (the live TSPU window is bounded from above, so a
// plain CalibrateTTL seeded with Hi=32 reports "no window" on paths
// where low TTLs work); (2) the rigorous CalibrateTTL binary search
// seeded with that Hi pins the minimal t*.
func (p *ProbeRunner) calibrate(ctx context.Context, cals []calTarget) (prober.Calibration, *calTarget, bool, []string) {
	var notes []string
	budget := p.calBudget
	if budget <= 0 {
		budget = DefaultCalibrationBudget
	}
	cctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	ladder := p.scanTTLs
	if len(ladder) == 0 {
		ladder = defaultScanTTLs
	}
	for _, c := range cals {
		if cctx.Err() != nil {
			notes = append(notes, "calibration budget spent")
			break
		}
		hi := 0
		for _, t := range ladder {
			if cctx.Err() != nil {
				break
			}
			ok, _ := p.inj.InjectAndHandshake(c.ip, c.sni, uint8(t))
			if ok {
				hi = t
				break
			}
		}
		if hi == 0 {
			notes = append(notes, fmt.Sprintf("no passing fake ttl on %s (%s)", c.ip, c.sni))
			continue
		}
		notes = append(notes, fmt.Sprintf("ttl %d passes on %s", hi, c.ip))
		perIP, pcancel := context.WithTimeout(cctx, perIPCaliBudget)
		opt := prober.DefaultTTLOptions()
		opt.Hi = hi
		opt.Delay = calibrationDelay
		cal, err := prober.CalibrateTTL(perIP, p.inj, c.ip, c.sni, opt)
		pcancel()
		if err == nil {
			notes = append(notes, fmt.Sprintf("t*=%d on %s (%d probes)", cal.Star, c.ip, cal.Probes))
			return cal, &c, true, notes
		}
		notes = append(notes, fmt.Sprintf("search on %s failed: %v", c.ip, err))
	}
	return prober.Calibration{}, nil, false, notes
}

// buildTargets derives the probe matrix (§7.1) from the config rules:
// DESYNC SNI rules become SNI classification targets (first resolved IP)
// and contribute all their resolved IPs as calibration candidates;
// TUNNEL CIDR rules become IP reachability targets.
func (p *ProbeRunner) buildTargets(ctx context.Context, cfg *config.Config) (prober.Targets, []calTarget, []string) {
	var (
		targets   prober.Targets
		notes     []string
		perTarget [][]calTarget
	)
	for _, r := range cfg.Rules {
		switch {
		case r.SNI != "" && r.Action == config.ActionDesync:
			host := hostOf(r.SNI)
			ips, err := p.lookupIP(ctx, host)
			if err != nil || len(ips) == 0 {
				notes = append(notes, fmt.Sprintf("resolve %s failed", host))
				continue
			}
			targets.SNI = append(targets.SNI, prober.SNITarget{IP: ips[0].String(), SNI: host})
			// TTL windows are per-path (live-verified): collect every
			// resolved address of the desync targets; the interleave
			// below spreads candidates across targets.
			var cands []calTarget
			for _, ip := range ips {
				cands = append(cands, calTarget{ip: ip.String(), sni: host})
			}
			perTarget = append(perTarget, cands)
		case r.CIDR != "" && r.Action == config.ActionTunnel:
			if ip := firstIP(r.CIDR); ip != "" {
				targets.IP = append(targets.IP, prober.IPTarget{IP: ip, Port: 443})
			}
		}
	}
	var cals []calTarget
	for round := 0; len(cals) < maxCalTargets; round++ {
		added := false
		for _, cands := range perTarget {
			if round < len(cands) && len(cals) < maxCalTargets {
				cals = append(cals, cands[round])
				added = true
			}
		}
		if !added {
			break
		}
	}
	return targets, cals, notes
}
