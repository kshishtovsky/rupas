//go:build windows && live

package app

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kshishtovsky/rupas/internal/capture"
	"github.com/kshishtovsky/rupas/internal/config"
	"github.com/kshishtovsky/rupas/internal/core"
	"github.com/kshishtovsky/rupas/internal/prober"
	"github.com/kshishtovsky/rupas/internal/rpc"
	"github.com/kshishtovsky/rupas/internal/rules"
	"github.com/kshishtovsky/rupas/pkg/windivert"
)

// ensureDLL adds the repository's build/windivert directory to PATH so
// the lazy-loaded WinDivert.dll resolves (same trick as the pkg/windivert
// tests).
func ensureDLL() {
	if windivert.Available() {
		return
	}
	wd, err := os.Getwd()
	if err != nil {
		return
	}
	for dir, up := wd, 0; up < 4; up, dir = up+1, filepath.Dir(dir) {
		cand := filepath.Join(dir, "build", "windivert", "WinDivert.dll")
		if _, err := os.Stat(cand); err == nil {
			os.Setenv("PATH", filepath.Join(dir, "build", "windivert")+";"+os.Getenv("PATH"))
			return
		}
	}
}

// driverReady skips the test unless a WinDivert handle opens (requires
// administrator privileges and the driver service, mirroring the capture
// live tests).
func driverReady(t *testing.T) {
	t.Helper()
	ensureDLL()
	h, err := windivert.OpenWithFlags("tcp.DstPort == 1", windivert.LayerNetwork, 0,
		windivert.FlagSniff|windivert.FlagRecvOnly)
	if err == nil {
		_ = h.Close()
		return
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case 5:
			t.Skipf("WinDivert requires administrator: %v", err)
		case 2, 1058, 1062:
			t.Skipf("WinDivert driver unavailable: %v", err)
		}
	}
	t.Skipf("WinDivert open failed: %v", err)
}

// internetUp checks plain TCP reachability (not TLS — the SNI under test
// may be legitimately blackholed by the TSPU, which is the very thing
// rupasd defeats).
func internetUp(t *testing.T) bool {
	t.Helper()
	for _, addr := range []string{"1.1.1.1:443", "8.8.8.8:53"} {
		c, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err == nil {
			c.Close()
			return true
		}
	}
	return false
}

// tlsDialSNI performs the plain Go crypto/tls handshake the task
// specifies. Verification is skipped on purpose: the assertion is that
// the HANDSHAKE completes through the desync engine, whatever the local
// path does to certificates.
func tlsDialSNI(host string, timeout time.Duration) error {
	return tlsDialSNIAddr(host, host, timeout)
}

// tlsDialSNIAddr dials ip directly while presenting sni.
func tlsDialSNIAddr(ip, sni string, timeout time.Duration) error {
	d := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(ip, "443"), &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return err
	}
	return conn.Close()
}

// --- pipe helpers (rupasctl-style JSON-line protocol) ---

func pipeCmd(t *testing.T, pipe, cmd string) core.Snapshot {
	t.Helper()
	conn, err := rpc.DialPipe(pipe, 3*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", pipe, err)
	}
	defer conn.Close()
	req, _ := json.Marshal(rpc.Request{Cmd: cmd})
	if _, err := conn.Write(append(req, '\n')); err != nil {
		t.Fatalf("write %s: %v", cmd, err)
	}
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		t.Fatalf("read %s: %v", cmd, err)
	}
	var r struct {
		OK    bool          `json:"ok"`
		Data  core.Snapshot `json:"data"`
		Error string        `json:"error"`
	}
	if err := json.Unmarshal(line, &r); err != nil {
		t.Fatalf("bad response %q: %v", line, err)
	}
	if !r.OK {
		t.Fatalf("cmd %s failed: %s", cmd, r.Error)
	}
	return r.Data
}

func waitState(t *testing.T, pipe, state string, timeout time.Duration) core.Snapshot {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last core.Snapshot
	for time.Now().Before(deadline) {
		last = pipeCmd(t, pipe, "status")
		if last.State == state {
			return last
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("state = %q, want %q after %v", last.State, state, timeout)
	return last
}

// TestLiveEndToEnd drives the assembled daemon like production does:
// App + supervisor + RPC pipe, `on` through the pipe, a real crypto/tls
// handshake to www.youtube.com through the intercepting engine, live
// counters via `status`, `off`, clean shutdown. The 443 interception
// window is bounded by the deferred Close (handles close even on
// failure).
func TestLiveEndToEnd(t *testing.T) {
	driverReady(t)
	if !internetUp(t) {
		t.Skip("no internet: control TCP dials failed")
	}

	logger := log.New(os.Stderr, "e2e ", log.LstdFlags|log.Lmicroseconds)
	tpl, src, err := loadFakeTemplate("", config.Default())
	if err != nil {
		t.Skipf("fake template unavailable: %v", err)
	}
	t.Logf("template %s (%d bytes)", src, len(tpl))

	application, err := New(config.Default(), logger, Options{
		Tunnel: true,
		// Full production path: classification + live TTL calibration.
		// (The calibrated TTL replaces the lab-default profile before the
		// engine starts, so the handshake assertion holds on whatever
		// network the test host is currently behind.)
		ProbeAttempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := application.Start(ctx); err != nil {
		t.Fatal(err)
	}
	// Hard guarantee: the supervisor Close stops the pipeline and the
	// WinDivert handles close even when an assertion fails mid-test.
	defer application.Close()

	sup := application.Supervisor()
	pipe := fmt.Sprintf(`\\.\pipe\rupas-e2e-%d`, os.Getpid())
	srv := rpc.New(pipe, rpc.Deps{
		Status: application.Snapshot,
		On:     sup.On,
		Off:    sup.Off,
		Probe:  sup.ForceProbe,
		Logs:   application.EventLog().Last,
		Logger: logger,
	})
	defer srv.Close()
	srvDone := make(chan error, 1)
	go func() { srvDone <- srv.ListenAndServe(ctx) }()

	// Wait for the pipe listener.
	pipeDeadline := time.Now().Add(5 * time.Second)
	for {
		if c, err := rpc.DialPipe(pipe, 200*time.Millisecond); err == nil {
			c.Close()
			break
		}
		if time.Now().After(pipeDeadline) {
			t.Fatal("rpc pipe never came up")
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Log("sending 'on' through the pipe; probing (classify + TTL calibration) then ACTIVE")
	pipeCmd(t, pipe, "on")
	snap := waitState(t, pipe, "ACTIVE", 360*time.Second)
	t.Logf("ACTIVE (profile=%s, probe note: %s)", snap.ProfileID, snap.Counters.LastProbeNote)

	// The calibrated window is per-path; assert the engine profile was
	// actually reprogrammed from the probe outcome.
	cal := application.LastCalibration()
	if cal == nil {
		t.Fatal("no calibration outcome recorded")
	}
	st := application.Stats()
	if !cal.Found {
		// Live finding (2026-10-25): the local TSPU currently defeats
		// the fake strategy on every desync target (no TTL in 4..32
		// opens a blocked SNI; fakes themselves are proven to egress
		// and to be harmless to servers). The system response is the
		// designed §7.2 fallback — assert that, then still exercise
		// the interception path and counters below.
		t.Logf("NO TTL WINDOW on this network right now; probe note: %s", snap.Counters.LastProbeNote)
		if st.Desync.Strategy != "fake_split" || st.Desync.SplitOffset < 1 {
			t.Fatalf("split fallback not armed: %+v", st.Desync)
		}
	} else {
		t.Logf("calibrated on %s (%s): t*=%d effective=%d", cal.IP, cal.SNI, cal.Star, cal.Effective)
		if st.Desync.Strategy != "fake" || st.Desync.TTL != cal.Star {
			t.Fatalf("engine profile not reprogrammed: %+v (want fake / t*=%d)", st.Desync, cal.Star)
		}
	}

	// Dial target: the calibrated pair when a window exists, otherwise
	// the rule's own target — either way the ClientHello traverses the
	// intercepting engine and must record a DESYNC verdict.
	// (cal.SNI may be the bare registrable domain of a wildcard rule —
	// e.g. "googlevideo.com" from "*.googlevideo.com" — which the rule
	// table does NOT match; dial a rule-matching SNI or the verdict
	// never fires. Wave-4A live catch.)
	dialIP, dialSNI := cal.IP, cal.SNI
	if !strings.HasPrefix(cal.SNI, "www.") {
		for _, r := range config.Default().Rules {
			if strings.HasPrefix(r.SNI, "*.") && strings.TrimPrefix(r.SNI, "*.") == cal.SNI {
				dialSNI = "www." + cal.SNI
				break
			}
		}
	}
	if !cal.Found {
		dialIP, dialSNI = "www.youtube.com", "www.youtube.com"
	}

	// The engine opens its handles asynchronously right after the ACTIVE
	// transition; retry the handshake until the desync counter moves so a
	// slow handle-open never fails the test spuriously.
	handshakeOK := false
	var hsErr error
	var okSnap core.Snapshot
	for attempt := 1; attempt <= 3; attempt++ {
		if hsErr = tlsDialSNIAddr(dialIP, dialSNI, 10*time.Second); hsErr == nil {
			handshakeOK = true
		}
		okSnap = pipeCmd(t, pipe, "status")
		if okSnap.Counters.PacketsDesync > 0 {
			break
		}
		t.Logf("attempt %d done (handshake ok=%v); waiting for the desync verdict", attempt, handshakeOK)
		time.Sleep(500 * time.Millisecond)
	}
	if okSnap.Counters.PacketsTotal == 0 {
		t.Fatalf("engine captured no packets: %+v", okSnap)
	}
	if okSnap.Counters.PacketsDesync == 0 {
		t.Fatalf("no DESYNC verdict recorded for the ClientHello: %+v", okSnap)
	}
	if cal.Found && !handshakeOK {
		t.Fatalf("calibrated window (t*=%d on %s) did not hold through the engine: %v", cal.Star, cal.IP, hsErr)
	}
	if !cal.Found && !handshakeOK {
		t.Logf("handshake through the engine still blocked (expected: no TTL window, split fallback may not defeat this TSPU): %v", hsErr)
	}
	t.Logf("live counters via rupasctl-status: total=%d pass=%d desync=%d redir=%d hsOK=%d flows=%v handshakeOK=%v",
		okSnap.Counters.PacketsTotal, okSnap.Counters.PacketsPass, okSnap.Counters.PacketsDesync,
		okSnap.Counters.PacketsRedir, okSnap.Counters.HandshakeOK, okSnap.Flows, handshakeOK)
	if okSnap.State != "ACTIVE" {
		t.Fatalf("state drifted during interception: %s", okSnap.State)
	}

	t.Log("sending 'off'; expecting graceful pipeline stop")
	pipeCmd(t, pipe, "off")
	waitState(t, pipe, "OFF", 30*time.Second)
	stopDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(stopDeadline) {
		if !application.Stats().Running {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if application.Stats().Running {
		t.Fatal("pipeline still running after off")
	}

	// Explicit clean shutdown (defers are idempotent).
	cancel()
	if err := application.Close(); err != nil {
		t.Fatalf("application.Close: %v", err)
	}
	select {
	case err := <-srvDone:
		if err != nil {
			t.Fatalf("rpc server exited with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("rpc server did not shut down")
	}
	if application.Stats().Running {
		t.Fatal("pipeline still running after Close")
	}
	for _, ev := range application.EventLog().Last(20) {
		if strings.Contains(ev, "tunnel") || strings.Contains(ev, "pipeline") {
			t.Logf("event: %s", ev)
		}
	}
}

// TestLiveFakeInjector exercises the TTL-calibration mechanics against
// the real driver: a fake ClientHello with a tiny TTL (dies at the first
// hops) must not disturb the browser-like handshake on the same flow.
func TestLiveFakeInjector(t *testing.T) {
	driverReady(t)
	if !internetUp(t) {
		t.Skip("no internet: control TCP dials failed")
	}
	tpl, _, err := loadFakeTemplate("", config.Default())
	if err != nil {
		t.Skipf("fake template unavailable: %v", err)
	}
	inj, ok := newFakeInjector(tpl, log.New(os.Stderr, "inj ", log.LstdFlags)).(*winInjector)
	if !ok {
		t.Fatal("unexpected injector type")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", "www.cloudflare.com")
	if err != nil || len(ips) == 0 {
		t.Skipf("resolve cloudflare failed: %v", err)
	}
	ip := ips[0].String()

	// TTL=1: the fake must die at the first router. (The old TTL=4 was
	// fine while the injector's fake was malformed garbage; a well-formed
	// fake with TTL=4 can REACH nearby anycast edges like cloudflare and
	// poison the real stream — live-measured wave 4A.)
	okHS, err := inj.InjectAndHandshake(ip, "www.cloudflare.com", 1)
	if err != nil {
		t.Fatalf("inject+handshake: %v", err)
	}
	if !okHS {
		t.Fatal("handshake did not complete with fake TTL=1 (fake should die at the first hop)")
	}
	if n := inj.Injected(); n != int64(calibFakeRepeats) {
		t.Fatalf("injected = %d, want %d (calibFakeRepeats)", n, calibFakeRepeats)
	}
	t.Logf("%d fakes injected ahead of the real ClientHello; handshake completed (target %s)", calibFakeRepeats, ip)
}

// ---------------------------------------------------------------------------
// Wave 4A live gates: fake-inject parity with the winws reference
// ---------------------------------------------------------------------------

// winwsReference locates the reference winws.exe (zapret distro) used to
// prove the TTL window exists on the current channel.
const winwsReference = `E:\zapret-discord-youtube-1.10.2\zapret-discord-youtube-1.10.2\bin\winws.exe`

// runWinwsReference starts the reference winws (fake, ttl) filtered to a
// single target IP and returns a stop function. Skips the test when the
// distro binary is not on disk.
func runWinwsReference(t *testing.T, ip string, ttl int, tplPath string) func() {
	t.Helper()
	if _, err := os.Stat(winwsReference); err != nil {
		t.Skipf("winws reference binary unavailable (%v); cannot prove the channel window", err)
	}
	ipFile := filepath.Join(t.TempDir(), "ipset.txt")
	if err := os.WriteFile(ipFile, []byte(ip+"\n"), 0644); err != nil {
		t.Fatalf("ipset file: %v", err)
	}
	absTpl, err := filepath.Abs(tplPath)
	if err != nil {
		t.Fatalf("abs template path: %v", err)
	}
	args := []string{
		"--wf-tcp=443",
		"--filter-tcp=443",
		"--ipset=" + ipFile,
		"--dpi-desync=fake",
		"--dpi-desync-repeats=6",
		fmt.Sprintf("--dpi-desync-ttl=%d", ttl),
		"--dpi-desync-fake-tls=" + absTpl,
	}
	t.Logf("reference: winws %s", strings.Join(args, " "))
	cmd := exec.Command(winwsReference, args...)
	cmd.Dir = filepath.Dir(winwsReference)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start winws: %v", err)
	}
	time.Sleep(1500 * time.Millisecond)
	return func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}
}

// referencePunches proves the channel's fake-TTL window with the winws
// reference: true when winws(ttl) completes a handshake, false when the
// reference is itself blocked (channel changed), skips when the binary
// is missing.
func referencePunches(t *testing.T, ip string, ttl int, tplPath string) bool {
	t.Helper()
	stop := runWinwsReference(t, ip, ttl, tplPath)
	defer stop()
	err := tlsDialSNIAddr(ip, "www.youtube.com", 8*time.Second)
	t.Logf("reference winws ttl=%d dial: %v", ttl, err)
	return err == nil
}

// TestLiveEngineFakeParity is the wave-4A strict gate: the capture engine
// with the fixed fake mechanics (held CH, seq verbatim, synthetic rawsend
// address — see capture/ops.go doctrine) must complete a real crypto/tls
// handshake to the SNI-blackholed www.youtube.com at the calibrated TTL,
// ≥2 of 3 dials. A failure is only excused when the winws reference itself
// cannot punch through the channel anymore (honest skip, not a soft pass).
func TestLiveEngineFakeParity(t *testing.T) {
	driverReady(t)
	if !internetUp(t) {
		t.Skip("no internet: control TCP dials failed")
	}
	tpl, src, err := loadFakeTemplate("", config.Default())
	if err != nil {
		t.Skipf("fake template unavailable: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", "www.youtube.com")
	if err != nil || len(ips) == 0 {
		t.Skipf("resolve www.youtube.com failed: %v", err)
	}
	ip := ips[0].String()

	// Control: without interception the channel must be blocking this
	// SNI, otherwise the gate proves nothing.
	if err := tlsDialSNIAddr(ip, "www.youtube.com", 8*time.Second); err == nil {
		t.Skipf("channel no longer blocks www.youtube.com (dial succeeded unassisted from %s)", ip)
	}

	for _, ttl := range []int{12, 13} {
		okN, ms := engineDialCount(t, ip, tpl, ttl, 3)
		t.Logf("engine fake ttl=%d: %d/3 handshakes OK (median %.0f ms)", ttl, okN, ms)
		if okN >= 2 {
			continue // strict gate met at this TTL
		}
		if referencePunches(t, ip, 12, src) {
			t.Fatalf("engine fake ttl=%d: %d/3 handshakes OK but the winws reference punches through the same channel — fake mechanics regressed", ttl, okN)
		}
		t.Skipf("engine fake ttl=%d: %d/3 and the winws reference is blocked too — channel changed, window gone", ttl, okN)
	}
}

// engineDialCount starts a capture.Engine (fake strategy, given TTL),
// performs n dials and returns (successful handshakes, median duration ms).
func engineDialCount(t *testing.T, ip string, tpl []byte, ttl, n int) (int, float64) {
	t.Helper()
	cfg := config.Default()
	cfg.Rules = []config.Rule{
		{SNI: "www.youtube.com", Action: config.ActionDesync},
		{Action: config.ActionDirect},
	}
	cfg.Desync = config.DesyncParams{Strategy: "fake", TTL: ttl, Repeats: 6}
	tbl, err := rules.Compile(cfg)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	eng, err := capture.New(capture.Options{Rules: tbl, Desync: cfg.Desync, FakeTemplate: tpl})
	if err != nil {
		t.Fatalf("capture.New: %v", err)
	}
	go func() { _ = eng.Run(context.Background()) }()
	defer eng.Stop()
	time.Sleep(1200 * time.Millisecond)

	ok, ds, hs := 0, uint64(0), time.Duration(0)
	var durations []time.Duration
	for i := 0; i < n; i++ {
		t0 := time.Now()
		err := tlsDialSNIAddr(ip, "www.youtube.com", 10*time.Second)
		durations = append(durations, time.Since(t0))
		if err == nil {
			ok++
			hs += time.Since(t0)
		}
		t.Logf("dial %d/%d (ttl=%d): %v", i+1, n, ttl, err)
		time.Sleep(700 * time.Millisecond)
	}
	ds = uint64(eng.Counters().PacketsDesync)
	if ds == 0 {
		t.Fatalf("engine recorded no DESYNC verdict (captured=%d pass=%d)", eng.Counters().PacketsTotal, eng.Counters().PacketsPass)
	}
	sortDurations(durations)
	med := float64(durations[len(durations)/2].Microseconds()) / 1000
	return ok, med
}

func sortDurations(d []time.Duration) {
	for i := 1; i < len(d); i++ {
		for j := i; j > 0 && d[j] < d[j-1]; j-- {
			d[j], d[j-1] = d[j-1], d[j]
		}
	}
}

// TestLiveCalibrateTTLWindow proves the FakeInjector+CalibrateTTL pair
// finds the channel's real fake-TTL window (wave 4A: expect t*≈12..14,
// effective t*+margin ≤ 16). The window's existence is first proven with
// the winws reference; if the reference is blocked the channel changed and
// the test skips honestly.
func TestLiveCalibrateTTLWindow(t *testing.T) {
	driverReady(t)
	if !internetUp(t) {
		t.Skip("no internet: control TCP dials failed")
	}
	tpl, src, err := loadFakeTemplate("", config.Default())
	if err != nil {
		t.Skipf("fake template unavailable: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", "www.youtube.com")
	if err != nil || len(ips) == 0 {
		t.Skipf("resolve www.youtube.com failed: %v", err)
	}
	ip := ips[0].String()

	// Prove the window exists with the reference BEFORE judging our
	// calibration (task gate (c): a skip is legitimate only if winws
	// cannot punch through either).
	if !referencePunches(t, ip, 12, src) {
		t.Skip("winws reference ttl=12 is blocked on this channel — TTL window gone, calibration unprovable")
	}

	inj := newFakeInjector(tpl, log.New(os.Stderr, "calib ", log.LstdFlags))
	opt := prober.DefaultTTLOptions()
	// Hi=14: the live channel's upper window edge (live-measured wave 4A:
	// ok at 12..14; at 16 the fake reaches the server and can poison the
	// browser-like handshake, so 16 is not a reliable window probe).
	opt.Lo, opt.Hi, opt.Repeats, opt.MaxIterations = 10, 14, 2, 6
	cal, err := prober.CalibrateTTL(ctx, inj, ip, "www.youtube.com", opt)
	if err != nil {
		if errors.Is(err, prober.ErrNoTTLWindow) {
			t.Fatalf("no TTL window found while the winws reference punches through ttl=12 — injector mechanics regressed")
		}
		t.Fatalf("CalibrateTTL: %v (cal=%+v)", err, cal)
	}
	t.Logf("calibration: %+v", cal)
	if cal.Star < 11 || cal.Star > 15 {
		t.Fatalf("calibrated t*=%d outside the expected 12..14 window (±1 hop jitter)", cal.Star)
	}
	if eff := cal.Star + cal.Margin; eff < 12 || eff > 16 {
		t.Fatalf("effective TTL %d outside 12..16", eff)
	}
}
