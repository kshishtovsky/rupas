package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rupas/rupas/internal/config"
	"github.com/rupas/rupas/internal/prober"
	"github.com/rupas/rupas/internal/supervisor"
)

// validTpl is a minimal TLS-handshake-record template (0x16 0x03 …).
func validTpl() []byte { return []byte{0x16, 0x03, 0x01, 0x00, 0x10} }

func discardLogger() *log.Logger { return log.New(io.Discard, "", 0) }

// mockPipeline records lifecycle calls (portable seam for prober tests).
type mockPipeline struct {
	starts     int
	stops      int
	suspends   int
	resumes    int
	running    bool
	lastStart  *config.Config
	lastResume *config.DesyncParams
	resumeTok  suspendToken
	superseded bool
}

func (m *mockPipeline) Start(cfg *config.Config) error {
	m.starts++
	m.lastStart = cfg
	m.running = true
	return nil
}
func (m *mockPipeline) Stop() error {
	m.stops++
	m.running = false
	return nil
}
func (m *mockPipeline) SuspendForProbe() suspendToken {
	m.suspends++
	if m.superseded {
		// simulate an external Start/Stop landing after the suspend
		m.running = m.running && false
		return suspendToken{gen: 41, wasRunning: true}
	}
	return suspendToken{gen: 7, wasRunning: m.running}
}
func (m *mockPipeline) ResumeFromProbe(t suspendToken, next *config.DesyncParams) {
	m.resumes++
	m.resumeTok = t
	m.lastResume = next
}
func (m *mockPipeline) Stats() pipelineStats            { return pipelineStats{Running: m.running} }
func (m *mockPipeline) SetDegradationSink(func(string)) {}

// refuseTransport fails every dial instantly (no network in unit tests).
type refuseTransport struct{}

func (refuseTransport) Dial(string, uint16) (prober.Conn, error) {
	return nil, errors.New("refused (unit test)")
}

// stallTransport connects but never answers: the handshake stalls until
// the (short, test-configured) deadline — the SNI blackhole signature.
type stallTransport struct{}

func (stallTransport) Dial(string, uint16) (prober.Conn, error) {
	a, b := net.Pipe()
	go func() { // drain nothing: writer blocks until deadline
		<-time.After(5 * time.Second)
		a.Close()
		b.Close()
	}()
	return b, nil
}

// failingInjector reports every inject attempt as a failed handshake.
type failingInjector struct{ calls int }

func (f *failingInjector) InjectAndHandshake(string, string, uint8) (bool, error) {
	f.calls++
	return false, nil
}

func TestDemoteTunnelRules(t *testing.T) {
	in := []config.Rule{
		{SNI: "www.youtube.com", Action: config.ActionDesync},
		{CIDR: "149.154.160.0/20", Action: config.ActionTunnel},
		{Ports: "50000-65535", Action: config.ActionTunnel},
		{Action: config.ActionDirect},
	}
	out := demoteTunnelRules(in)
	want := []config.Action{config.ActionDesync, config.ActionDirect, config.ActionDirect, config.ActionDirect}
	for i, a := range want {
		if out[i].Action != a {
			t.Fatalf("rule %d action = %v, want %v", i, out[i].Action, a)
		}
	}
	if in[1].Action != config.ActionTunnel {
		t.Fatal("demoteTunnelRules mutated the input slice")
	}
}

func TestTunnelCIDRsAndFirstIPAndHostOf(t *testing.T) {
	rules := []config.Rule{
		{CIDR: "149.154.160.0/20", Action: config.ActionTunnel},
		{CIDR: "91.108.0.0/16", Action: config.ActionDesync}, // wrong action: ignored
		{SNI: "x", Action: config.ActionTunnel},              // not a CIDR rule
	}
	got := tunnelCIDRs(rules)
	if len(got) != 1 || got[0] != "149.154.160.0/20" {
		t.Fatalf("tunnelCIDRs = %v", got)
	}
	if ip := firstIP("149.154.160.0/20"); ip != "149.154.160.0" {
		t.Fatalf("firstIP = %q", ip)
	}
	if ip := firstIP("95.161.76.100/32"); ip != "95.161.76.100" {
		t.Fatalf("firstIP/32 = %q", ip)
	}
	if h := hostOf("*.googlevideo.com"); h != "googlevideo.com" {
		t.Fatalf("hostOf wildcard = %q", h)
	}
	if h := hostOf("discord.com"); h != "discord.com" {
		t.Fatalf("hostOf plain = %q", h)
	}
}

func TestEffectiveDesync(t *testing.T) {
	base := config.DesyncParams{Strategy: "fake", TTL: 13, TTLMargin: 2, Repeats: 6}
	over := config.DesyncParams{Strategy: "fake", TTL: 17, TTLMargin: 1, Repeats: 4}
	if got := effectiveDesync(base, &over); got.TTL != 17 || got.Repeats != 4 {
		t.Fatalf("override not applied: %+v", got)
	}
	if got := effectiveDesync(config.DesyncParams{}, nil); got.Strategy != "fake" || got.TTL != 13 {
		t.Fatalf("empty base not defaulted: %+v", got)
	}
	if got := effectiveDesync(base, nil); got.TTL != 13 {
		t.Fatalf("base not kept: %+v", got)
	}
}

func TestTProxyStubCounts(t *testing.T) {
	stub, err := StartTProxyStub(0, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	tcp := fmt.Sprintf("127.0.0.1:%d", stub.TCPPort())
	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", tcp)
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	uc, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", stub.UDPPort()))
	if err != nil {
		t.Fatal(err)
	}
	uc.Write([]byte("x"))
	uc.Write([]byte("y"))
	uc.Close()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if stub.Conns() >= 3 && stub.Dgrams() >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if stub.Conns() != 3 {
		t.Fatalf("conns = %d, want 3", stub.Conns())
	}
	if stub.Dgrams() < 2 {
		t.Fatalf("dgrams = %d, want >= 2", stub.Dgrams())
	}
	stub.Stop()
	stub.Stop() // idempotent
	if c, err := net.Dial("tcp", tcp); err == nil {
		c.Close()
		t.Fatal("tcp listener alive after Stop")
	}
}

func TestProbeRunnerNoTargets(t *testing.T) {
	cfg := &config.Config{Profile: "unit", Rules: []config.Rule{{Action: config.ActionDirect}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	mp := &mockPipeline{}
	pr := newProbeRunner(probeDeps{
		log: discardLogger(), tpl: validTpl(), pipeline: mp,
		cfg:       func() *config.Config { return cfg },
		transport: &refuseTransport{}, inj: nil,
	})
	res, err := pr.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.DesyncAlive || res.ProfileID != "unit" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.TunnelOK {
		t.Fatal("TunnelOK must be false until wave 4")
	}
	if !strings.Contains(res.Note, "no probeable targets") {
		t.Fatalf("note = %q", res.Note)
	}
	if mp.suspends != 1 || mp.resumes != 1 {
		t.Fatalf("suspend=%d resume=%d, want 1/1", mp.suspends, mp.resumes)
	}
	if mp.lastResume != nil {
		t.Fatal("no calibration ran; profile must be unchanged")
	}
}

func TestProbeRunnerNoTTLWindowFallsBackToSplit(t *testing.T) {
	cfg := &config.Config{
		Profile: "unit",
		Rules:   []config.Rule{{SNI: "www.youtube.com", Action: config.ActionDesync}},
		// A complete desync section is required when a DESYNC rule exists.
		Desync: config.DesyncParams{Strategy: "fake", TTL: 13, TTLMargin: 2, Repeats: 6},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	mp := &mockPipeline{}
	inj := &failingInjector{}
	pr := newProbeRunner(probeDeps{
		log: discardLogger(), tpl: validTpl(), pipeline: mp,
		cfg:       func() *config.Config { return cfg },
		transport: &stallTransport{},
		inj:       inj,
		resolveIP: func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
		},
		handshakeTimeout: 150 * time.Millisecond,
		attemptDelay:     10 * time.Millisecond,
	})
	res, err := pr.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.DesyncAlive {
		t.Fatalf("desync must stay alive with the split fallback: %+v", res)
	}
	if !strings.Contains(res.Note, "no passing fake ttl") {
		t.Fatalf("note = %q", res.Note)
	}
	if !strings.Contains(res.Note, "sni blocked") {
		t.Fatalf("classification missed the blocked SNI: %q", res.Note)
	}
	if inj.calls == 0 {
		t.Fatal("calibration never invoked the injector")
	}
	if mp.lastResume == nil {
		t.Fatal("fallback profile not handed to the pipeline")
	}
	got := mp.lastResume
	if got.Strategy != "fake_split" {
		t.Fatalf("strategy = %q, want fake_split", got.Strategy)
	}
	if got.TTL < 1 {
		t.Fatalf("split profile needs a structurally valid TTL: %+v", got)
	}
	if err := validateDesync(*got, validTpl()); err != nil {
		t.Fatalf("fallback profile invalid: %v", err)
	}
}

func TestProbeRunnerSupersededTokenKeepsProfileForNextStart(t *testing.T) {
	// The mock returns a token whose generation never matches the
	// "external" one; ResumeFromProbe on the real pipeline would then
	// only store the override. Here we assert the runner always pairs
	// suspend with resume, even when the probe is canceled mid-cycle.
	cfg := config.Default()
	mp := &mockPipeline{superseded: true, running: true}
	pr := newProbeRunner(probeDeps{
		log: discardLogger(), tpl: validTpl(), pipeline: mp,
		cfg:              func() *config.Config { return cfg },
		transport:        &refuseTransport{},
		handshakeTimeout: 100 * time.Millisecond,
		attemptDelay:     10 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled before any work
	_, _ = pr.Run(ctx)
	if mp.suspends != 1 || mp.resumes != 1 {
		t.Fatalf("suspend=%d resume=%d, want 1/1 even on canceled ctx", mp.suspends, mp.resumes)
	}
}

func TestLoadFakeTemplate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tpl.bin")
	if err := os.WriteFile(path, validTpl(), 0o644); err != nil {
		t.Fatal(err)
	}
	tpl, src, err := loadFakeTemplate(path, config.Default())
	if err != nil {
		t.Fatal(err)
	}
	if src != path || len(tpl) != len(validTpl()) {
		t.Fatalf("tpl=%d src=%q", len(tpl), src)
	}

	if _, _, err := loadFakeTemplate(filepath.Join(dir, "missing.bin"), config.Default()); err == nil {
		t.Fatal("explicit missing template must fail")
	}

	// A non-record payload is rejected by the desync sanitizer.
	bad := filepath.Join(dir, "bad.bin")
	os.WriteFile(bad, []byte("nope"), 0o644)
	if _, _, err := loadFakeTemplate(bad, config.Default()); err == nil {
		t.Fatal("non-TLS template must fail")
	}
}

// TestAppNewAndSnapshotSmoke builds the whole assembly with an explicit
// template and asserts the supervisor snapshot merge is safe before the
// pipeline ever runs (counters stay zero, no fabricated flows).
func TestAppNewAndSnapshotSmoke(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tpl.bin")
	os.WriteFile(path, validTpl(), 0o644)

	a, err := New(config.Default(), discardLogger(), Options{FakeTemplatePath: path, Tunnel: false})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if err := a.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	snap := a.Snapshot()
	if snap.State != string(supervisor.StateOff) {
		t.Fatalf("state = %q, want OFF", snap.State)
	}
	if snap.Counters.PacketsTotal != 0 || len(snap.Flows) != 0 {
		t.Fatalf("fabricated live stats before any start: %+v", snap)
	}
	if err := a.SetConfig(nil); err == nil {
		t.Fatal("SetConfig(nil) must fail")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	st := a.Stats()
	if st.Running {
		t.Fatal("pipeline must not run without an explicit start")
	}
}
