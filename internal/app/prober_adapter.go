package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kshishtovsky/rupas/internal/config"
	"github.com/kshishtovsky/rupas/internal/prober"
	"github.com/kshishtovsky/rupas/internal/supervisor"
)

const (
	// DefaultCalibrationBudget bounds the whole calibration phase (scan +
	// binary search) across all candidate targets.
	DefaultCalibrationBudget = 240 * time.Second
	// perIPCaliBudget bounds the rigorous CalibrateTTL run on one target.
	perIPCaliBudget = 90 * time.Second
	// ladderFailDecay is the cooldown after a failed ladder rung (see
	// defaultScanTTLs): lets the TSPU per-host escalation decay so the
	// next rung is not judged on poisoned state.
	ladderFailDecay = 8 * time.Second
	// calibrationDelay paces the repeats within one TTL point. Wave 4A
	// live finding: back-to-back TLS flows to a blocked SNI trip the
	// TSPU's per-host escalation for tens of seconds (a freshly succeeded
	// window check can still poison the point evaluation that follows),
	// so repeats are spaced by seconds, not milliseconds.
	calibrationDelay = 4 * time.Second
	// maxCalTargets caps how many candidate ip/sni pairs calibration
	// tries before declaring the fake strategy dead. Candidates are
	// interleaved across the desync-rule targets so one hard target
	// (e.g. a Google frontend where every TTL is filtered) cannot
	// exhaust the budget before other paths are tried.
	maxCalTargets = 6
)

// defaultScanTTLs is the single-attempt ladder used to find a working TTL
// before the rigorous binary search. Lab + live data: the fake must reach
// the TSPU but die before the server (the TSPU window is bounded from
// above on Google front-ends: TTL 8 worked where 16/32 were blackholed),
// so CalibrateTTL's monotone-to-Hi assumption cannot be seeded with Hi=32
// directly — we first locate any passing TTL and seed the binary search
// just there. Wave-4A live finding (2026-10-25): the TSPU escalates a
// host that attempts blocked SNIs back-to-back (uTLS flows stay throttled
// for tens of seconds), so the ladder starts at the profile's calibrated
// window (12..14) and each failed rung waits for the escalation to decay
// — the old 4,6,8,… order burned five doomed attempts (~30 s of blackhole
// timeouts) before reaching the window and heated the channel for the
// rigorous search that followed.
var defaultScanTTLs = []int{12, 14, 10, 16, 8, 20, 6, 24, 4, 28, 32}

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
	// calDelay overrides the per-point pacing (tests; 0 → calibrationDelay,
	// the 4 s anti-escalation pacing from the wave-4A live findings).
	calDelay time.Duration
	// ladderDecay overrides the failed-rung decay (tests; 0 →
	// ladderFailDecay, the 8 s escalation decay).
	ladderDecay time.Duration
	// resolveIP overrides DNS resolution (tests); nil → the system
	// resolver. *net.Resolver satisfies the signature.
	resolveIP func(ctx context.Context, network, host string) ([]netip.Addr, error)
	// profilePath is where the calibrated probe profile persists
	// (§4.3 fast start). Empty → prober.DefaultProfilePath.
	profilePath string
	// profileMaxAge overrides prober.DefaultProfileMaxAge (72 h) when
	// positive (tests shrink it).
	profileMaxAge time.Duration
	// bindIP forces the probe source address (tests); nil → autodetect
	// the physical NIC (bind.go).
	bindIP net.IP
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
// It also implements supervisor.FastStarter/RevalidatingProber (§4.3
// fast start): the calibrated profile persists to disk and a fresh one
// short-circuits the 3–5 min PROBING into an immediate ACTIVE plus one
// background control probe.
type ProbeRunner struct {
	probeDeps
	classifier *prober.Classifier
	lastCal    atomic.Pointer[calInfo]
	// saved is the persisted profile (nil until loaded from disk and
	// after a failed/absent load).
	saved      atomic.Pointer[prober.PersistedProfile]
	profPath   string
	profMaxAge time.Duration
}

var (
	_ supervisor.Prober             = (*ProbeRunner)(nil)
	_ supervisor.FastStarter        = (*ProbeRunner)(nil)
	_ supervisor.RevalidatingProber = (*ProbeRunner)(nil)
)

func newProbeRunner(d probeDeps) *ProbeRunner {
	var bind net.IP
	t := d.transport
	if t == nil {
		// Production default: bind probes to the physical NIC so the
		// classification measures the ISP path even when a TUN client
		// (Happ) owns the default route — otherwise the classifier
		// blackholes its own probes and reports false "sni blocked".
		ip, name, err := prober.ProbeBindIP()
		if err != nil {
			if d.log != nil {
				d.log.Printf("app: prober: %v; probes follow the default route", err)
			}
			t = &prober.RealTransport{}
		} else {
			bind = ip
			t = &prober.PhysicalTransport{LocalIP: ip, IfaceName: name}
			if d.log != nil {
				d.log.Printf("app: prober: probes bound to %s (%s)", name, ip)
			}
		}
	}
	if d.bindIP != nil {
		bind = d.bindIP
	}
	c := prober.NewClassifier(t)
	c.LocalIP = bind
	if d.attempts > 0 {
		c.Attempts = d.attempts
	}
	if d.handshakeTimeout > 0 {
		c.HandshakeTimeout = d.handshakeTimeout
	}
	if d.attemptDelay > 0 {
		c.AttemptDelay = d.attemptDelay
	}
	r := &ProbeRunner{probeDeps: d, classifier: c}
	r.profPath = d.profilePath
	if r.profPath == "" {
		r.profPath = prober.DefaultProfilePath()
	}
	r.profMaxAge = d.profileMaxAge
	if r.profMaxAge <= 0 {
		r.profMaxAge = prober.DefaultProfileMaxAge
	}
	r.loadPersisted()
	return r
}

// loadPersisted reads the profile file. Missing/corrupt/stale files are
// non-fatal: they just select the classic full-calibration start.
func (p *ProbeRunner) loadPersisted() {
	prof, err := prober.LoadProfile(p.profPath)
	switch {
	case err != nil:
		if !errors.Is(err, os.ErrNotExist) {
			p.log.Printf("app: prober: persisted profile unusable (%v); full calibration on start", err)
		}
		return
	case !prof.Usable():
		p.log.Printf("app: prober: persisted profile has no TTL window; full calibration on start")
	case !prof.Fresh(p.profMaxAge, time.Now()):
		p.log.Printf("app: prober: persisted profile is stale (calibrated %s, max age %s); full calibration on start",
			prof.CalibratedAt.Format(time.RFC3339), p.profMaxAge)
	default:
		p.saved.Store(prof)
		p.log.Printf("app: prober: persisted profile loaded (t*=%d+%d on %s/%s, calibrated %s)",
			prof.TTLStar, prof.TTLMargin, prof.CalIP, prof.CalSNI, prof.CalibratedAt.Format(time.RFC3339))
	}
}

// QuickStart implements supervisor.FastStarter: a fresh, usable,
// engine-valid persisted profile turns into an immediate desync
// configuration; anything else returns nil and keeps the classic path.
func (p *ProbeRunner) QuickStart() *supervisor.FastStart {
	prof := p.saved.Load()
	if !prof.Usable() || !prof.Fresh(p.profMaxAge, time.Now()) {
		return nil
	}
	cfg := p.cfg()
	if cfg == nil {
		return nil
	}
	params := prof.DesyncParams()
	if cfg.Desync.Repeats > 0 {
		params.Repeats = cfg.Desync.Repeats
	}
	if err := validateDesync(params, p.tpl); err != nil {
		p.log.Printf("app: prober: persisted profile rejected by the desync engine (%v); full calibration on start", err)
		return nil
	}
	return &supervisor.FastStart{
		Desync:    params,
		ProfileID: cfg.Profile,
		Note: fmt.Sprintf("persisted profile applied without probing (t*=%d+%d on %s/%s, calibrated %s)",
			prof.TTLStar, prof.TTLMargin, prof.CalIP, prof.CalSNI,
			prof.CalibratedAt.Format(time.RFC3339)),
	}
}

// revalidateDelay paces the background control probe (§7.3: the retry
// after a lost control probe must respect the anti-escalation pacing).
// A var only so tests can shrink it; production never mutates it.
var revalidateDelay = 4 * time.Second

// Revalidate implements supervisor.RevalidatingProber (§7.3): one control
// probe on the saved t* against the saved calibration target — no TTL
// ladder, paced like the calibration repeats. Success refreshes the
// profile timestamp; failure keeps the file untouched and reports a dead
// profile (the supervisor then schedules the full recalibration).
func (p *ProbeRunner) Revalidate(ctx context.Context) (supervisor.ProfileResult, error) {
	prof := p.saved.Load()
	if !prof.Usable() || prof.CalIP == "" || prof.CalSNI == "" {
		return supervisor.ProfileResult{}, errors.New("app: prober: no persisted profile to revalidate")
	}
	if p.inj == nil {
		return supervisor.ProfileResult{}, errors.New("app: prober: fake injection unavailable for revalidation")
	}
	cfg := p.cfg()
	if cfg == nil {
		return supervisor.ProfileResult{}, errors.New("app: prober: no configuration")
	}
	// Capture tunnel health before suspending (same reasoning as Run).
	tunAssembled, tunHealthy := p.pipeline.TunnelHealth()
	tok := p.pipeline.SuspendForProbe()
	// Re-apply the persisted parameters on resume so the restarted
	// engine keeps exactly what the fast start programmed.
	next := prof.DesyncParams()
	if cfg.Desync.Repeats > 0 {
		next.Repeats = cfg.Desync.Repeats
	}
	defer func() { p.pipeline.ResumeFromProbe(tok, &next) }()

	// Control probe at the saved t* (the engine adds the margin on top).
	ok := false
	for attempt := 0; attempt < 2 && ctx.Err() == nil; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(revalidateDelay):
			}
		}
		if good, err := p.inj.InjectAndHandshake(prof.CalIP, prof.CalSNI, uint8(prof.TTLStar)); err == nil && good {
			ok = true
			break
		}
	}
	if ctx.Err() != nil {
		return supervisor.ProfileResult{}, ctx.Err()
	}
	if !ok {
		return supervisor.ProfileResult{
			ProfileID:   cfg.Profile,
			DesyncAlive: false,
			TunnelOK:    tunAssembled && tunHealthy,
			Note: fmt.Sprintf("control probe failed on saved t*=%d (%s/%s); full recalibration scheduled",
				prof.TTLStar, prof.CalIP, prof.CalSNI),
		}, nil
	}
	// Confirmed: refresh the freshness anchor so a continuously healthy
	// line never goes stale.
	prof.CalibratedAt = time.Now().UTC()
	if err := prober.SaveProfile(p.profPath, prof); err != nil {
		p.log.Printf("app: prober: profile refresh failed: %v", err)
	} else {
		p.saved.Store(prof)
	}
	return supervisor.ProfileResult{
		ProfileID:   cfg.Profile,
		DesyncAlive: true,
		TunnelOK:    tunAssembled && tunHealthy,
		Note: fmt.Sprintf("profile revalidated ok (t*=%d on %s/%s)",
			prof.TTLStar, prof.CalIP, prof.CalSNI),
	}, nil
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
	// Capture the live tunnel health BEFORE suspending the pipeline: the
	// suspend stops the tunnel, so polling during the cycle would always
	// report false. assembled=false (no endpoint / tunnel off) reports
	// TunnelOK=false honestly.
	tunAssembled, tunHealthy := p.pipeline.TunnelHealth()
	tok := p.pipeline.SuspendForProbe()
	var next *config.DesyncParams
	defer func() { p.pipeline.ResumeFromProbe(tok, next) }()

	var sb strings.Builder
	targets, cals, notes := p.buildTargets(ctx, cfg)
	var sniHosts []string
	for _, st := range targets.SNI {
		sniHosts = append(sniHosts, st.SNI)
	}
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
			TunnelOK:    tunAssembled && tunHealthy,
			Note:        "no probeable targets in the config; keeping the configured profile",
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
		// §4.3: persist the profile so the next start skips the full
		// calibration (fast start + §7.3 background revalidation).
		prof := &prober.PersistedProfile{
			SchemaVersion: prober.ProfileSchemaVersion,
			SNIBlackhole:  res.SNIBlocked,
			IPBlackhole:   res.IPBlackhole,
			TTLStar:       calRes.Star,
			TTLMargin:     calRes.Margin,
			Strategy:      prober.StrategyFake,
			CalIP:         calTgt.ip,
			CalSNI:        calTgt.sni,
			Targets:       sniHosts,
			CalibratedAt:  time.Now().UTC(),
		}
		if err := prober.SaveProfile(p.profPath, prof); err != nil {
			fmt.Fprintf(&sb, "; profile save failed: %v", err)
			p.log.Printf("app: prober: profile save failed: %v", err)
		} else {
			p.saved.Store(prof)
			fmt.Fprintf(&sb, "; profile saved (t*=%d+%d on %s/%s)", prof.TTLStar, prof.TTLMargin, prof.CalIP, prof.CalSNI)
		}
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
		DesyncAlive: true,                       // v3: fake or fake_split always armed; a dead-desync verdict needs tunnel-side evidence
		TunnelOK:    tunAssembled && tunHealthy, // live §6 marker health, captured before the suspend
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

	decay := p.ladderDecay
	if decay <= 0 {
		decay = ladderFailDecay
	}
	ladder := p.scanTTLs
	if len(ladder) == 0 {
		ladder = defaultScanTTLs
	}
	// §4.3: with a persisted profile on disk, seed the ladder around the
	// last known-good t* (±1) instead of walking the generic order — the
	// window rarely moves between calibrations.
	if seed := p.saved.Load(); seed != nil && seed.TTLStar > 1 {
		ladder = seededScanTTLs(seed.TTLStar, ladder)
		notes = append(notes, fmt.Sprintf("ladder seeded from persisted t*=%d", seed.TTLStar))
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
			// A failed rung means six seconds of blackholed flow; the
			// TSPU's per-host escalation needs several seconds to decay
			// before the next rung is judged fairly (wave 4A).
			select {
			case <-cctx.Done():
			case <-time.After(decay):
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
		opt.Delay = p.calDelay
		if opt.Delay <= 0 {
			opt.Delay = calibrationDelay
		}
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

// seededScanTTLs puts the last known-good t* and its neighbours at the
// front of the ladder, keeping the remaining default rungs as fallback
// (deduped, clamped to the fake TTL safety range 1..32).
func seededScanTTLs(star int, fallback []int) []int {
	out := make([]int, 0, len(fallback)+3)
	seen := map[int]bool{}
	add := func(t int) {
		if t < 1 || t > 32 || seen[t] {
			return
		}
		seen[t] = true
		out = append(out, t)
	}
	add(star + 1)
	add(star)
	if star > 1 {
		add(star - 1)
	}
	for _, t := range fallback {
		add(t)
	}
	return out
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
