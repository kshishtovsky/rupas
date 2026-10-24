package prober

import (
	"context"
	"time"

	"github.com/rupas/rupas/internal/config"
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
	r.TTL = cal.Effective
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
	margin := r.TTLMargin
	if margin <= 0 {
		margin = DefaultTTLMargin
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
