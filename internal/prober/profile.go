package prober

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kshishtovsky/rupas/internal/config"
)

// Strategy names produced by the prober (subset of
// config.DesyncStrategies()).
const (
	// StrategyFake is the primary strategy once a TTL window is
	// calibrated (lab-confirmed: fake TTL=13 opens YouTube).
	StrategyFake = "fake"
	// StrategyFakeSplit is the fallback when no TTL window exists
	// (§7.2: "если t* не найден → стратегия split/disorder").
	StrategyFakeSplit = "fake_split"
)

// Profile defaults matching the design profile (SYSTEM_DESIGN §4.3).
const (
	// DefaultFakeTemplate is the uTLS-generated browser-like fake CH
	// template id (chrome-124-pq.bin in the design profile).
	DefaultFakeTemplate = "chrome-124-pq"
	// DefaultRepeats is the fake count per desync attempt (§4.3: 6).
	DefaultRepeats = 6
)

// UDPEndpoint identifies one probed UDP destination (ip:port pair).
type UDPEndpoint struct {
	IP   string `json:"ip" yaml:"ip"`
	Port uint16 `json:"port" yaml:"port"`
}

// Result is the aggregated probe outcome: the classification half of a
// provider profile (SYSTEM_DESIGN §4.3 "evidence"), with the calibrated
// desync parameters attached.
type Result struct {
	// SNIBlocked lists server names classified as SNIDrop or RSTInject
	// (SNI-triggered blocking; desync or tunnel candidates).
	SNIBlocked []string `json:"sni_blackhole,omitempty"`
	// IPBlackhole lists IPs whose SYNs never got a response (tunnel-only
	// destinations, e.g. Telegram DCs).
	IPBlackhole []string `json:"ip_blackhole,omitempty"`
	// UDPDead lists ip:port pairs with no UDP response (media ports that
	// must go through the tunnel).
	UDPDead []UDPEndpoint `json:"udp_dead,omitempty"`
	// TTL is the effective fake TTL (calibrated t* + margin); 0 when no
	// window was found or calibration was not run.
	TTL int `json:"ttl,omitempty"`
	// TTLMargin is the safety margin applied to t*.
	TTLMargin int `json:"ttl_margin,omitempty"`
	// Strategy is the recommended desync strategy ("fake" with a
	// calibrated TTL, "fake_split" without a window).
	Strategy string `json:"strategy,omitempty"`
	// CheckedAt is the UTC completion time of the probe run.
	CheckedAt time.Time `json:"checked_at"`
}

// SNITarget is one SNI-classification probe destination.
type SNITarget struct {
	IP  string
	SNI string
}

// IPTarget is one IP-reachability probe destination.
type IPTarget struct {
	IP   string
	Port uint16
}

// Targets is the probe matrix (§7.1): SNI targets, IP targets and the
// UDP port matrix, all probed concurrently.
type Targets struct {
	SNI []SNITarget
	IP  []IPTarget
	UDP []UDPEndpoint
}

// MaxParallelProbes bounds concurrency of one classification run.
const MaxParallelProbes = 8

// Classify probes all targets concurrently (bounded by MaxParallelProbes)
// and aggregates the verdicts into a Result. TTL calibration is separate
// (CalibrateTTL); attach it with ApplyCalibration.
func (c *Classifier) Classify(ctx context.Context, t Targets) *Result {
	res := &Result{CheckedAt: time.Now().UTC()}
	sniV := make([]SNIVerdict, len(t.SNI))
	ipV := make([]IPVerdict, len(t.IP))
	udpV := make([]bool, len(t.UDP))

	jobs := make([]func(), 0, len(t.SNI)+len(t.IP)+len(t.UDP))
	for i := range t.SNI {
		jobs = append(jobs, func() {
			if ctx.Err() != nil {
				sniV[i] = SNIUnknown
				return
			}
			sniV[i] = c.ProbeSNI(t.SNI[i].IP, t.SNI[i].SNI)
		})
	}
	for i := range t.IP {
		jobs = append(jobs, func() {
			if ctx.Err() != nil {
				ipV[i] = IPUnknown
				return
			}
			ipV[i] = c.ProbeIP(t.IP[i].IP, t.IP[i].Port)
		})
	}
	for i := range t.UDP {
		jobs = append(jobs, func() {
			if ctx.Err() != nil {
				udpV[i] = false
				return
			}
			udpV[i] = c.ProbeUDP(t.UDP[i].IP, t.UDP[i].Port)
		})
	}
	runParallel(MaxParallelProbes, jobs...)

	for i := range t.SNI {
		if sniV[i] == SNIDrop || sniV[i] == SNIRSTInject {
			res.SNIBlocked = append(res.SNIBlocked, t.SNI[i].SNI)
		}
	}
	for i := range t.IP {
		if ipV[i] == IPSynDrop {
			res.IPBlackhole = append(res.IPBlackhole, t.IP[i].IP)
		}
	}
	for i := range t.UDP {
		if !udpV[i] {
			res.UDPDead = append(res.UDPDead, t.UDP[i])
		}
	}
	return res
}

// ApplyCalibration attaches a TTL calibration result and selects the
// default strategy for it.
func (r *Result) ApplyCalibration(cal Calibration) {
	r.TTL = cal.Star // raw t*: the engine adds TTLMargin exactly once
	r.TTLMargin = cal.Margin
	if r.Strategy == "" && cal.Star > 0 {
		r.Strategy = StrategyFake
	}
}

// ToDesyncParams converts the probe result into the runtime desync
// profile. Without a calibrated TTL window the strategy falls back to
// fake_split (§7.2); tunnel fallback for dead SNI rules is the
// supervisor's policy, not the prober's.
func (r *Result) ToDesyncParams() config.DesyncParams {
	// A margin of exactly 0 is a REAL value, not "unset": the calibration
	// clamps the total to the ladder ceiling (CalibrateTTL), so substituting
	// the default here would push the fake past Hi and kill the desync.
	margin := r.TTLMargin
	if margin < 0 {
		margin = 0
	}
	p := config.DesyncParams{
		Strategy:     r.Strategy,
		FakeTemplate: DefaultFakeTemplate,
		TTL:          r.TTL,
		TTLMargin:    margin,
		Repeats:      DefaultRepeats,
	}
	if r.TTL > 0 {
		if p.Strategy == "" {
			p.Strategy = StrategyFake
		}
		return p
	}
	// No TTL window (or calibration not run): the fake cannot die before
	// the TSPU, so recommend a split-based strategy. TTL stays 0 as the
	// "uncalibrated" signal.
	if p.Strategy == "" || p.Strategy == StrategyFake {
		p.Strategy = StrategyFakeSplit
	}
	return p
}

// ---------------------------------------------------------------------------
// Persisted profile (SYSTEM_DESIGN §4.3/§7.3 fast start)
// ---------------------------------------------------------------------------

// ProfileSchemaVersion is the on-disk profile schema version. LoadProfile
// rejects files with a different version: a stale schema must never be
// silently applied as a fresh calibration.
const ProfileSchemaVersion = 1

// DefaultProfileMaxAge is how long a persisted profile stays fresh
// (owner requirement: fast start from a profile younger than ~72 h).
const DefaultProfileMaxAge = 72 * time.Hour

// PersistedProfile is the calibrated provider profile saved to disk after
// a successful PROBING→ACTIVE cycle and loaded on the next start to skip
// the full 3–5 min calibration (SYSTEM_DESIGN §4.3).
type PersistedProfile struct {
	// SchemaVersion guards on-disk compatibility (ProfileSchemaVersion).
	SchemaVersion int `json:"schema_version"`
	// Classification evidence from the last full probe run.
	SNIBlackhole []string      `json:"sni_blackhole,omitempty"`
	IPBlackhole  []string      `json:"ip_blackhole,omitempty"`
	UDPDead      []UDPEndpoint `json:"udp_dead,omitempty"`
	// TTLStar is the minimal calibrated fake TTL (t*); the runtime
	// desync engine programs TTL = t* + TTLMargin itself, so TTLMargin
	// is stored separately (design profile: +2).
	TTLStar   int `json:"ttl_star"`
	TTLMargin int `json:"ttl_margin,omitempty"`
	// Strategy is the desync strategy the profile was calibrated for.
	Strategy string `json:"strategy,omitempty"`
	// CalIP/CalSNI identify the target the TTL window was calibrated on
	// (the background revalidation control probe re-runs exactly this
	// pair at t*).
	CalIP  string `json:"calibrated_ip,omitempty"`
	CalSNI string `json:"calibrated_sni,omitempty"`
	// Targets lists the SNI hosts the classification covered.
	Targets []string `json:"targets,omitempty"`
	// CalibratedAt is the UTC completion time of the calibration (the
	// freshness anchor; refreshed by every confirmed revalidation).
	CalibratedAt time.Time `json:"calibrated_at"`
}

// DefaultProfilePath returns %ProgramData%/rupas/profile.json.
func DefaultProfilePath() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = "."
	}
	return filepath.Join(base, "rupas", "profile.json")
}

// SaveProfile atomically writes the profile (temp file + rename in the
// target directory) and fills in the schema version / timestamp defaults.
func SaveProfile(path string, p *PersistedProfile) error {
	if p == nil {
		return errors.New("prober: nil profile")
	}
	if p.SchemaVersion == 0 {
		p.SchemaVersion = ProfileSchemaVersion
	}
	if p.CalibratedAt.IsZero() {
		p.CalibratedAt = time.Now().UTC()
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("prober: marshal profile: %w", err)
	}
	b = append(b, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("prober: profile dir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return fmt.Errorf("prober: write profile: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("prober: rename profile: %w", err)
	}
	return nil
}

// LoadProfile reads a persisted profile. Missing, corrupt and
// wrong-schema files are errors — the caller must treat them as "no
// profile" and fall back to the full calibration path.
func LoadProfile(path string) (*PersistedProfile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("prober: read profile: %w", err)
	}
	var p PersistedProfile
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("prober: parse profile %s: %w", path, err)
	}
	if p.SchemaVersion != ProfileSchemaVersion {
		return nil, fmt.Errorf("prober: profile %s: schema version %d, want %d", path, p.SchemaVersion, ProfileSchemaVersion)
	}
	if p.TTLStar < 0 || p.TTLStar > 255 {
		return nil, fmt.Errorf("prober: profile %s: ttl_star %d out of range", path, p.TTLStar)
	}
	return &p, nil
}

// Fresh reports whether the profile is young enough for a fast start.
// A zero CalibratedAt is never fresh.
func (p *PersistedProfile) Fresh(maxAge time.Duration, now time.Time) bool {
	if p == nil || p.CalibratedAt.IsZero() {
		return false
	}
	age := now.Sub(p.CalibratedAt)
	return age >= 0 && age < maxAge
}

// Usable reports whether the profile carries a calibrated TTL window
// (the precondition for the fake strategy and thus for a fast start).
func (p *PersistedProfile) Usable() bool {
	return p != nil && p.TTLStar > 0
}

// DesyncParams maps the persisted profile onto the runtime desync
// parameters. TTL carries the raw t*: the engine adds TTLMargin exactly
// once (desync.New computes InjectFake.TTL = TTL + TTLMargin).
//
// A saved margin of 0 is authoritative: CalibrateTTL clamps t*+margin to
// the ladder ceiling, and the ceiling rung is a passing TTL by itself
// (live 2026-10-27: t*=10 on a ceiling of 10 worked, 10+2 was a blackhole).
// Substituting the default here would undo the clamp on every restart.
func (p *PersistedProfile) DesyncParams() config.DesyncParams {
	margin := p.TTLMargin
	if margin < 0 {
		margin = 0
	}
	st := p.Strategy
	if st == "" {
		st = StrategyFake
	}
	repeats := DefaultRepeats
	return config.DesyncParams{
		Strategy:     st,
		FakeTemplate: DefaultFakeTemplate,
		TTL:          p.TTLStar,
		TTLMargin:    margin,
		Repeats:      repeats,
	}
}
