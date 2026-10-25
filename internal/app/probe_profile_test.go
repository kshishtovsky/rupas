package app

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rupas/rupas/internal/config"
	"github.com/rupas/rupas/internal/prober"
)

// thresholdInjector reports success only at/above the threshold TTL
// (the lab window shape: success(t) = t >= t*).
type thresholdInjector struct{ threshold uint8 }

func (f *thresholdInjector) InjectAndHandshake(_ string, _ string, ttl uint8) (bool, error) {
	return ttl >= f.threshold, nil
}

func probeConfig() *config.Config {
	cfg := &config.Config{
		Profile: "unit",
		Rules:   []config.Rule{{SNI: "www.youtube.com", Action: config.ActionDesync}},
		Desync:  config.DesyncParams{Strategy: "fake", TTL: 13, TTLMargin: 2, Repeats: 6},
	}
	if err := cfg.Validate(); err != nil {
		panic(err)
	}
	return cfg
}

func profileProbeDeps(dir string, inj prober.FakeInjector) probeDeps {
	return probeDeps{
		log: discardLogger(), tpl: validTpl(), pipeline: &mockPipeline{},
		cfg:       func() *config.Config { return probeConfig() },
		transport: &refuseTransport{},
		inj:       inj,
		resolveIP: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
		},
		scanTTLs:      []int{13},
		calDelay:      time.Millisecond,
		ladderDecay:   time.Millisecond,
		profilePath:   filepath.Join(dir, "profile.json"),
		profileMaxAge: time.Hour,
	}
}

func TestProbeRunnerSavesProfileAfterCalibration(t *testing.T) {
	dir := t.TempDir()
	pr := newProbeRunner(profileProbeDeps(dir, &thresholdInjector{threshold: 13}))

	res, err := pr.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Note, "profile saved") {
		t.Fatalf("note = %q, want the save confirmation", res.Note)
	}
	prof, err := prober.LoadProfile(filepath.Join(dir, "profile.json"))
	if err != nil {
		t.Fatalf("profile not saved on disk: %v", err)
	}
	if prof.TTLStar != 13 || prof.TTLMargin != 2 || prof.Strategy != prober.StrategyFake {
		t.Fatalf("saved profile = %+v", prof)
	}
	if prof.CalIP != "192.0.2.10" || prof.CalSNI != "www.youtube.com" {
		t.Fatalf("calibration target = %s/%s", prof.CalIP, prof.CalSNI)
	}
	if len(prof.Targets) != 1 || prof.Targets[0] != "www.youtube.com" {
		t.Fatalf("targets = %v", prof.Targets)
	}

	// The freshly saved profile must qualify for a fast start.
	fs := pr.QuickStart()
	if fs == nil {
		t.Fatal("QuickStart = nil, want the persisted profile")
	}
	if fs.Desync.TTL != 13 || fs.Desync.TTLMargin != 2 {
		t.Fatalf("fast-start desync = %+v", fs.Desync)
	}
}

func TestProbeRunnerReloadsProfileAndRevalidates(t *testing.T) {
	dir := t.TempDir()
	// First cycle calibrates and saves.
	pr := newProbeRunner(profileProbeDeps(dir, &thresholdInjector{threshold: 13}))
	if _, err := pr.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	// A new runner over the same file starts from the persisted profile.
	pr2 := newProbeRunner(profileProbeDeps(dir, &thresholdInjector{threshold: 13}))
	if pr2.QuickStart() == nil {
		t.Fatal("persisted profile not loaded for a fast start")
	}
	res, err := pr2.Revalidate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.DesyncAlive || !strings.Contains(res.Note, "revalidated ok") {
		t.Fatalf("revalidation result = %+v", res)
	}
	if mp := pr2.pipeline.(*mockPipeline); mp.suspends != 1 || mp.resumes != 1 {
		t.Fatalf("suspend=%d resume=%d, want 1/1", mp.suspends, mp.resumes)
	}

	// A dead control probe keeps the file but reports the dead profile;
	// the supervisor then schedules the full recalibration.
	oldDelay := revalidateDelay
	revalidateDelay = time.Millisecond
	t.Cleanup(func() { revalidateDelay = oldDelay })
	pr3 := newProbeRunner(profileProbeDeps(dir, &thresholdInjector{threshold: 13}))
	inj := &failingInjector{}
	pr3.inj = inj
	res, err = pr3.Revalidate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.DesyncAlive {
		t.Fatalf("failed control probe must report a dead profile: %+v", res)
	}
	if !strings.Contains(res.Note, "control probe failed") {
		t.Fatalf("note = %q", res.Note)
	}
	// The profile file must be untouched by a failed revalidation.
	prof, err := prober.LoadProfile(filepath.Join(dir, "profile.json"))
	if err != nil || !prof.Usable() {
		t.Fatalf("failed revalidation must keep the saved profile: %v %+v", err, prof)
	}
}

func TestQuickStartNilWithoutProfile(t *testing.T) {
	dir := t.TempDir()
	pr := newProbeRunner(profileProbeDeps(dir, &thresholdInjector{threshold: 13}))
	if fs := pr.QuickStart(); fs != nil {
		t.Fatalf("QuickStart with no file = %+v, want nil", fs)
	}

	// Corrupt file.
	path := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(path, []byte("}{"), 0o644); err != nil {
		t.Fatal(err)
	}
	pr = newProbeRunner(profileProbeDeps(dir, &thresholdInjector{threshold: 13}))
	if fs := pr.QuickStart(); fs != nil {
		t.Fatalf("QuickStart with a corrupt file = %+v, want nil", fs)
	}

	// Stale file.
	prof := &prober.PersistedProfile{
		SchemaVersion: prober.ProfileSchemaVersion,
		TTLStar:       12,
		CalIP:         "192.0.2.10",
		CalSNI:        "www.youtube.com",
		CalibratedAt:  time.Now().Add(-2 * time.Hour),
	}
	if err := prober.SaveProfile(path, prof); err != nil {
		t.Fatal(err)
	}
	pr = newProbeRunner(profileProbeDeps(dir, &thresholdInjector{threshold: 13}))
	if fs := pr.QuickStart(); fs != nil {
		t.Fatalf("QuickStart with a stale profile = %+v, want nil", fs)
	}

	// But the last known t* still seeds the calibration ladder (§4.3).
	inj := &seqRecorder{}
	pr.inj = inj
	if _, err := pr.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(inj.ttls) == 0 || inj.ttls[0] != 13 { // t*+1 first
		t.Fatalf("ladder not seeded from the stale t*: %v", inj.ttls)
	}
}

// seqRecorder records the TTLs the ladder tried.
type seqRecorder struct {
	ttls   []uint8
	called int
}

func (s *seqRecorder) InjectAndHandshake(_ string, _ string, ttl uint8) (bool, error) {
	s.called++
	s.ttls = append(s.ttls, ttl)
	return ttl >= 13, nil
}
