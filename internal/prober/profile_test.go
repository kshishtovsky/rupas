package prober

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func testProfile() *PersistedProfile {
	return &PersistedProfile{
		SchemaVersion: ProfileSchemaVersion,
		SNIBlackhole:  []string{"www.youtube.com", "discord.com"},
		IPBlackhole:   []string{"149.154.160.0"},
		UDPDead:       []UDPEndpoint{{IP: "149.154.167.51", Port: 443}},
		TTLStar:       12,
		TTLMargin:     2,
		Strategy:      StrategyFake,
		CalIP:         "142.251.154.4",
		CalSNI:        "www.youtube.com",
		Targets:       []string{"www.youtube.com", "discord.com"},
		CalibratedAt:  time.Date(2026, 10, 25, 23, 0, 0, 0, time.UTC),
	}
}

func TestSaveLoadProfileRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "profile.json") // SaveProfile must mkdir
	in := testProfile()
	if err := SaveProfile(path, in); err != nil {
		t.Fatal(err)
	}
	out, err := LoadProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("roundtrip mismatch:\n in=%+v\nout=%+v", in, out)
	}
}

func TestLoadProfileMissing(t *testing.T) {
	if _, err := LoadProfile(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("missing file must be an error")
	}
}

func TestLoadProfileCorrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProfile(path); err == nil {
		t.Fatal("corrupt file must be an error")
	}
}

func TestLoadProfileWrongSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.json")
	b, _ := json.Marshal(map[string]any{"schema_version": 99, "ttl_star": 12})
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProfile(path); err == nil {
		t.Fatal("wrong schema version must be rejected")
	}
}

func TestProfileFresh(t *testing.T) {
	now := time.Now()
	p := &PersistedProfile{CalibratedAt: now.Add(-time.Hour)}
	if !p.Fresh(72*time.Hour, now) {
		t.Fatal("1h-old profile must be fresh")
	}
	p.CalibratedAt = now.Add(-73 * time.Hour)
	if p.Fresh(72*time.Hour, now) {
		t.Fatal("73h-old profile must be stale")
	}
	// Future timestamps (clock skew) are treated as stale, not fresh.
	p.CalibratedAt = now.Add(time.Hour)
	if p.Fresh(72*time.Hour, now) {
		t.Fatal("future CalibratedAt must not be fresh")
	}
	var zero *PersistedProfile
	if zero.Fresh(72*time.Hour, now) {
		t.Fatal("nil profile must not be fresh")
	}
	if (&PersistedProfile{}).Fresh(72*time.Hour, now) {
		t.Fatal("zero CalibratedAt must not be fresh")
	}
}

func TestProfileDesyncParams(t *testing.T) {
	p := testProfile()
	got := p.DesyncParams()
	if got.Strategy != StrategyFake || got.TTL != 12 || got.TTLMargin != 2 {
		t.Fatalf("params = %+v", got)
	}
	if got.FakeTemplate != DefaultFakeTemplate || got.Repeats != DefaultRepeats {
		t.Fatalf("params = %+v", got)
	}
	// Zero margin/strategy fall back to the documented defaults.
	p.TTLMargin = 0
	p.Strategy = ""
	got = p.DesyncParams()
	if got.TTLMargin != DefaultTTLMargin || got.Strategy != StrategyFake {
		t.Fatalf("defaults not applied: %+v", got)
	}
}

func TestSaveProfileFillsDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.json")
	in := &PersistedProfile{TTLStar: 13}
	if err := SaveProfile(path, in); err != nil {
		t.Fatal(err)
	}
	if in.SchemaVersion != ProfileSchemaVersion || in.CalibratedAt.IsZero() {
		t.Fatalf("defaults not filled: %+v", in)
	}
	out, err := LoadProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if out.TTLStar != 13 {
		t.Fatalf("ttl_star = %d", out.TTLStar)
	}
}
