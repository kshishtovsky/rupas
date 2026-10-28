package prober

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// FakeInjector is the capture-side half of TTL calibration: it sends a
// fake ClientHello (browser-like template from the desync engine) with a
// limited TTL on a fresh flow and then attempts the real TLS handshake
// on that same flow. ok reports whether the handshake completed.
//
// The whole calibration algorithm lives above this interface
// (CalibrateTTL) so it is fully testable against deterministic mocks
// (lab window: success(t) = t >= 12, monotone).
type FakeInjector interface {
	InjectAndHandshake(ip, sni string, fakeTTL uint8) (ok bool, err error)
}

// ErrNotWired reports that fake injection is not wired to the capture
// layer yet; calibration cannot run until the WinDivert integration
// lands (SYSTEM_DESIGN §3.2).
var ErrNotWired = errors.New("prober: fake injection is not wired to the capture layer yet")

// ErrNoTTLWindow reports that even the maximum probed TTL lets the
// handshake pass nowhere — the fake never dies before the TSPU, so the
// fake strategy is unusable and the caller must fall back to
// split/disorder strategies or TUNNEL (§7.2).
var ErrNoTTLWindow = errors.New("prober: no TTL window: fake never dies before the TSPU")

// errTTLBudget is the internal signal that the iteration budget is spent.
var errTTLBudget = errors.New("prober: TTL calibration iteration budget exhausted")

// TTL calibration bounds (SYSTEM_DESIGN §7.2 and §5 safety limits).
const (
	// DefaultTTLLo/DefaultTTLHi bracket the binary search; fakes are
	// capped at TTL 32 by the desync safety rules.
	DefaultTTLLo = 1
	DefaultTTLHi = 32
	// DefaultTTLMargin is added to the calibrated minimum for robustness
	// against route fluctuations (design profile: ttl_margin +2).
	DefaultTTLMargin = 2
	// DefaultTTLRepeats is the 3/3-success criterion per TTL point.
	DefaultTTLRepeats = 3
	// DefaultTTLIterations is the budget: ≤ 10 point evaluations × 3
	// repeats × ~0.3 s ≈ 9–15 s total (§7.2).
	DefaultTTLIterations = 10
)

// UnwiredInjector is the placeholder production FakeInjector until the
// capture layer integration lands; every call fails with ErrNotWired.
type UnwiredInjector struct{}

// InjectAndHandshake implements FakeInjector; it always reports
// ErrNotWired.
func (UnwiredInjector) InjectAndHandshake(ip, sni string, fakeTTL uint8) (bool, error) {
	return false, ErrNotWired
}

// TTLOptions parameterises CalibrateTTL. The zero value selects all
// defaults.
type TTLOptions struct {
	// Lo, Hi bound the search range (defaults 1..32).
	Lo, Hi int
	// Margin is added to the calibrated minimum (default 2).
	Margin int
	// Repeats is the per-point success criterion: Repeats/Repeats
	// handshakes must complete (default 3, "ok 3/3").
	Repeats int
	// MaxIterations caps the number of evaluated TTL points
	// (default 10, §7.2 budget).
	MaxIterations int
	// Delay paces inject attempts within one point evaluation (no delay
	// by default; production sets it from the probe budget).
	Delay time.Duration
}

// DefaultTTLOptions returns the lab-derived defaults.
func DefaultTTLOptions() TTLOptions {
	return TTLOptions{
		Lo:            DefaultTTLLo,
		Hi:            DefaultTTLHi,
		Margin:        DefaultTTLMargin,
		Repeats:       DefaultTTLRepeats,
		MaxIterations: DefaultTTLIterations,
	}
}

// Calibration is the outcome of a TTL binary search.
type Calibration struct {
	// Star is the minimal TTL t* whose criterion (3/3 handshakes ok with
	// fake TTL=t) held. Always a value that passed the criterion.
	Star int
	// Effective is Star+Margin clamped to Hi: the value to program into
	// InjectFake packets.
	Effective int
	// Margin is the applied safety margin.
	Margin int
	// Iterations counts evaluated TTL points (≤ MaxIterations).
	Iterations int
	// Probes counts individual inject+handshake attempts.
	Probes int
	// Verified reports that minimality was confirmed: success(Star-1)
	// failed or Star equals the search floor.
	Verified bool
}

// CalibrateTTL binary-searches the minimal fake TTL t* for which the
// real handshake still completes when a fake ClientHello with TTL=t is
// injected first (§7.2). success(t) is assumed monotone non-decreasing
// (lab-confirmed window [12,∞)); the algorithm additionally verifies
// minimality and re-searches below Star when the verification contradicts
// monotonicity, all within the iteration budget.
//
// Algorithm:
//
//  1. window check: ok(Hi) must hold — otherwise ErrNoTTLWindow;
//  2. binary search of minimal t* in [Lo,Hi] with criterion ok 3/3;
//  3. verify ok(Star-1) fails; on contradiction (noise) continue the
//     search in [Lo,Star-1];
//  4. Effective = min(Star+Margin, Hi).
//
// A FakeInjector returning ErrNotWired aborts immediately with that
// error. Other injector errors count as failed attempts of that point.
func CalibrateTTL(ctx context.Context, inj FakeInjector, ip, sni string, opt TTLOptions) (Calibration, error) {
	if inj == nil {
		return Calibration{}, errors.New("prober: nil FakeInjector")
	}
	if opt.Lo <= 0 {
		opt.Lo = DefaultTTLLo
	}
	if opt.Hi <= opt.Lo {
		return Calibration{}, fmt.Errorf("prober: TTLOptions Hi(%d) must be > Lo(%d)", opt.Hi, opt.Lo)
	}
	if opt.Margin < 0 {
		opt.Margin = 0
	}
	if opt.Repeats < 1 {
		opt.Repeats = DefaultTTLRepeats
	}
	if opt.MaxIterations < 1 {
		opt.MaxIterations = DefaultTTLIterations
	}

	cal := Calibration{Margin: opt.Margin}
	budget := opt.MaxIterations

	// ok3 evaluates one TTL point against the Repeats/Repeats criterion.
	ok3 := func(t int) (bool, error) {
		if budget <= 0 {
			return false, errTTLBudget
		}
		budget--
		cal.Iterations++
		for i := 0; i < opt.Repeats; i++ {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			if i > 0 && opt.Delay > 0 {
				time.Sleep(opt.Delay)
			}
			ok, err := inj.InjectAndHandshake(ip, sni, uint8(t))
			cal.Probes++
			if err != nil {
				if errors.Is(err, ErrNotWired) {
					return false, err
				}
				ok = false // transient probe error counts as failure
			}
			if !ok {
				return false, nil
			}
		}
		return true, nil
	}

	// Step 1: the lab window is [t*,∞) — the highest allowed TTL must
	// work, else fakes cannot help this path at all.
	win, err := ok3(opt.Hi)
	if err != nil {
		return cal, err
	}
	if !win {
		return cal, ErrNoTTLWindow
	}

	// Step 2-3: binary search with minimality verification. Invariant:
	// ok3(star) == true.
	lo, hi := opt.Lo, opt.Hi
	star := hi
	verified := false
search:
	for {
		for lo < hi {
			mid := lo + (hi-lo)/2
			ok, err := ok3(mid)
			if err != nil {
				if errors.Is(err, errTTLBudget) {
					break search // keep the best known working star
				}
				return cal, err
			}
			if ok {
				hi, star = mid, mid
			} else {
				lo = mid + 1
			}
		}
		// Converged: lo == hi and star is the minimal candidate found.
		if star == opt.Lo {
			verified = true // search floor: nothing below to verify
			break
		}
		if budget <= 0 {
			break // star works but minimality unverified
		}
		prev, err := ok3(star - 1)
		if err != nil {
			if errors.Is(err, errTTLBudget) {
				break
			}
			return cal, err
		}
		if !prev {
			verified = true // minimal confirmed
			break
		}
		// Monotonicity violated on the low side: a smaller working TTL
		// exists — resume the search below it with the remaining budget.
		hi = star - 1
		star = hi // ok3(star-1) just returned true
		lo = opt.Lo
	}

	cal.Star = star
	cal.Verified = verified
	cal.Effective = star + opt.Margin
	if cal.Effective > opt.Hi {
		cal.Effective = opt.Hi
	}
	// The clamp must reach the margin too: callers persist Margin and the
	// engine programs Star+Margin, so a stale margin overshoots Hi.
	cal.Margin = cal.Effective - cal.Star
	return cal, nil
}
