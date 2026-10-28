package desync

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/kshishtovsky/rupas/internal/config"
)

// validTmpl — минимальный валидный fake-CH payload (TLS handshake record).
var validTmpl = append([]byte{0x16, 0x03, 0x01, 0x00, 0x02, 0x01}, bytes.Repeat([]byte{0xaa}, 58)...)

func baseParams(strategy string) config.DesyncParams {
	return config.DesyncParams{
		Strategy:    strategy,
		TTL:         8,
		TTLMargin:   2,
		Repeats:     4,
		SplitOffset: 3,
	}
}

func TestNewStrategyTable(t *testing.T) {
	// TTL 8 + margin 2 = 10; Repeats 4; SplitOffset 3.
	inject := InjectFake{TTL: 10, Count: 4}
	split := SplitAt{Offset: 3}
	cases := []struct {
		strategy string
		want     []Op
	}{
		{"fake", []Op{inject}},
		{"fake,split", []Op{inject, split}},
		{"fake_split", []Op{inject, split}}, // alias из config.DesyncStrategies()
		{"multisplit", []Op{inject, split}},
		{"split", []Op{split}},
		{"disorder", []Op{split}}, // v1: аппроксимация split
		{"disorder2", []Op{split}},
	}
	for _, tc := range cases {
		t.Run(tc.strategy, func(t *testing.T) {
			e, err := New(baseParams(tc.strategy), validTmpl)
			if err != nil {
				t.Fatalf("New(%q): unexpected error: %v", tc.strategy, err)
			}
			got := e.Actions([]byte("www.youtube.com"))
			if !reflect.DeepEqual(tc.want, got) {
				t.Fatalf("Actions(%q) = %#v, want %#v", tc.strategy, got, tc.want)
			}
			if len(got) == 0 {
				t.Fatal("Actions returned no ops")
			}
		})
	}
}

func TestNewValidation(t *testing.T) {
	cases := []struct {
		name     string
		strategy string
		mutate   func(*config.DesyncParams)
		tmpl     []byte
	}{
		{"unknown strategy", "bogus", nil, validTmpl},
		{"empty strategy", "", nil, validTmpl},
		{"unknown strategy composite", "fake,bogus", nil, validTmpl},
		{"ttl zero", "fake", func(p *config.DesyncParams) { p.TTL = 0 }, validTmpl},
		{"ttl negative", "fake", func(p *config.DesyncParams) { p.TTL = -1 }, validTmpl},
		{"ttl 33", "fake", func(p *config.DesyncParams) { p.TTL = 33 }, validTmpl},
		{"ttl 33 on split", "split", func(p *config.DesyncParams) { p.TTL = 33 }, validTmpl},
		{"repeats zero", "fake", func(p *config.DesyncParams) { p.Repeats = 0 }, validTmpl},
		{"repeats 17", "fake", func(p *config.DesyncParams) { p.Repeats = 17 }, validTmpl},
		{"repeats 17 on composite", "fake,split", func(p *config.DesyncParams) { p.Repeats = 17 }, validTmpl},
		{"negative ttl_margin", "fake", func(p *config.DesyncParams) { p.TTLMargin = -1 }, validTmpl},
		{"ttl+margin overflows uint8", "fake", func(p *config.DesyncParams) { p.TTL = 32; p.TTLMargin = 224 }, validTmpl},
		{"negative split_offset", "split", func(p *config.DesyncParams) { p.SplitOffset = -1 }, validTmpl},
		{"negative split_offset composite", "multisplit", func(p *config.DesyncParams) { p.SplitOffset = -5 }, validTmpl},
		{"negative split_offset disorder", "disorder2", func(p *config.DesyncParams) { p.SplitOffset = -2 }, validTmpl},
		{"nil template", "fake", nil, nil},
		{"empty template", "fake", nil, []byte{}},
		{"empty template composite", "fake,split", nil, []byte{}},
		{"1-byte template", "fake", nil, []byte{0x16}},
		{"wrong record type", "fake", nil, append([]byte{0x17, 0x03, 0x03}, validTmpl[3:]...)},
		{"wrong version major", "fake", nil, append([]byte{0x16, 0x02, 0x01}, validTmpl[3:]...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := baseParams(tc.strategy)
			if tc.mutate != nil {
				tc.mutate(&p)
			}
			if _, err := New(p, tc.tmpl); err == nil {
				t.Errorf("New accepted invalid profile: %+v (case %q)", p, tc.name)
			}
		})
	}
}

func TestNewBoundaryValues(t *testing.T) {
	cases := []config.DesyncParams{
		{Strategy: "fake", TTL: 1, TTLMargin: 0, Repeats: 1},
		{Strategy: "fake", TTL: 32, TTLMargin: 0, Repeats: 16},
		{Strategy: "split", TTL: 1, TTLMargin: 3, Repeats: 1, SplitOffset: 0},
	}
	for i, p := range cases {
		if _, err := New(p, validTmpl); err != nil {
			t.Errorf("case %d: New(%+v): %v", i, p, err)
		}
	}
}

func TestActionsZeroAllocs(t *testing.T) {
	sni := []byte("www.youtube.com")
	for _, strategy := range []string{"fake", "fake,split", "multisplit", "split", "disorder", "disorder2"} {
		t.Run(strategy, func(t *testing.T) {
			e, err := New(baseParams(strategy), validTmpl)
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 3; i++ { // прогрев
				e.Actions(sni)
			}
			allocs := testing.AllocsPerRun(100, func() {
				_ = e.Actions(sni)
			})
			if allocs != 0 {
				t.Fatalf("Actions allocs per run = %v, want 0", allocs)
			}
			// Ёмкость внутреннего слайса стабильна между вызовами и не
			// превышает max(число_операций, max(1, Repeats)) = 4 здесь.
			capBefore := cap(e.ops)
			for i := 0; i < 100; i++ {
				e.Actions(sni)
			}
			if cap(e.ops) != capBefore {
				t.Fatalf("ops cap grew between calls: %d -> %d", capBefore, cap(e.ops))
			}
			if capBefore > 4 {
				t.Fatalf("ops cap %d exceeds max(1, Repeats)=4", capBefore)
			}
		})
	}
}

func TestTemplateSameSlice(t *testing.T) {
	e, err := New(baseParams("fake"), validTmpl)
	if err != nil {
		t.Fatal(err)
	}
	a := e.Template()
	b := e.Template()
	if len(a) != len(validTmpl) {
		t.Fatalf("Template() len = %d, want %d", len(a), len(validTmpl))
	}
	if &a[0] != &b[0] {
		t.Fatal("Template() returns different backing arrays on successive calls")
	}
	if &a[0] != &validTmpl[0] {
		t.Fatal("Template() must return the same slice passed to New (no copy)")
	}
}

func TestLoadTemplate(t *testing.T) {
	dir := t.TempDir()

	good := append([]byte{0x16, 0x03, 0x03}, bytes.Repeat([]byte{0x42}, 32)...)
	goodPath := filepath.Join(dir, "fake.bin")
	if err := os.WriteFile(goodPath, good, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadTemplate(goodPath)
	if err != nil {
		t.Fatalf("LoadTemplate(good): %v", err)
	}
	if !bytes.Equal(got, good) {
		t.Fatal("LoadTemplate changed payload")
	}

	bad := append([]byte{0x47, 0x45, 0x54}, bytes.Repeat([]byte{0x20}, 8)...) // HTTP
	badPath := filepath.Join(dir, "bad.bin")
	if err := os.WriteFile(badPath, bad, 0o644); err != nil {
		t.Fatal(err)
	}
	emptyPath := filepath.Join(dir, "empty.bin")
	if err := os.WriteFile(emptyPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		filepath.Join(dir, "missing.bin"),
		badPath,
		emptyPath,
	} {
		if _, err := LoadTemplate(p); err == nil {
			t.Errorf("LoadTemplate(%q) accepted invalid file", p)
		}
	}

	// Репозитарный шаблон из build/desync — uTLS chrome ClientHello.
	repo, err := LoadTemplate("../../build/desync/fake-chrome.bin")
	if err != nil {
		t.Fatalf("LoadTemplate(repo fake-chrome.bin): %v", err)
	}
	if len(repo) == 0 || repo[0] != 0x16 || repo[1] != 0x03 {
		t.Fatalf("repo template has bad TLS prefix: % x", repo[:min(2, len(repo))])
	}
	if _, err := New(baseParams("fake,split"), repo); err != nil {
		t.Fatalf("New with repo template: %v", err)
	}
}

func BenchmarkActions(b *testing.B) {
	sni := []byte("www.youtube.com")
	for _, strategy := range []string{"fake", "fake,split", "multisplit", "split", "disorder"} {
		b.Run(strategy, func(b *testing.B) {
			e, err := New(baseParams(strategy), validTmpl)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			var sink []Op
			for i := 0; i < b.N; i++ {
				sink = e.Actions(sni)
			}
			if len(sink) == 0 {
				b.Fatal("empty actions")
			}
		})
	}
}
