//go:build windows

package guictrl

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kshishtovsky/rupas/internal/config"
	"github.com/kshishtovsky/rupas/internal/core"
	"github.com/kshishtovsky/rupas/internal/rpc"
)

// testDaemon serves the control pipe in-process and counts status polls;
// reload is the daemon's answer to "reload" (nil error = accepted).
func testDaemon(t *testing.T, reload func() error) (string, *int32) {
	t.Helper()
	var polls int32
	pipe := fmt.Sprintf(`\\.\pipe\rupas-guictrl-test-%d-%d`, os.Getpid(), rand.Int64())
	srv := rpc.New(pipe, rpc.Deps{
		Status: func() core.Snapshot {
			atomic.AddInt32(&polls, 1)
			return core.Snapshot{State: "ACTIVE", Since: time.Now()}
		},
		Reload: reload,
	})
	go func() { _ = srv.ListenAndServe(context.Background()) }()
	t.Cleanup(func() { _ = srv.Close() })

	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if f, err := rpc.DialPipe(pipe, 300*time.Millisecond); err == nil {
			f.Close()
			return pipe, &polls
		}
	}
	t.Fatalf("daemon did not come up on %s", pipe)
	return "", nil
}

// initialConfig writes a config with content a links save would destroy.
func initialConfig(t *testing.T) (path string, body []byte) {
	t.Helper()
	body = []byte("profile: owner\nrules:\n  - cidr: 10.0.0.0/8\n    action: direct\n")
	path = filepath.Join(t.TempDir(), "rupas.yaml")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, body
}

// TestWriteConfigRollsBackOnRefusal: a daemon that answers ok=false must
// leave the previous file untouched.
func TestWriteConfigRollsBackOnRefusal(t *testing.T) {
	pipe, _ := testDaemon(t, func() error { return errors.New("pipeline rejected the plan") })
	path, before := initialConfig(t)
	c, err := New(Options{Pipe: pipe, ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	err = c.writeConfig(presetConfig(true))
	if err == nil || !strings.Contains(err.Error(), "отклонил") {
		t.Fatalf("want the refusal error, got %v", err)
	}
	cur, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(cur) != string(before) {
		t.Fatalf("refused config left on disk:\n%s", cur)
	}
}

// TestWriteConfigKeepsFileWhenDaemonDown: no daemon → the validated file
// stays on disk (save contract) but the caller is told it is unconfirmed.
func TestWriteConfigKeepsFileWhenDaemonDown(t *testing.T) {
	path, _ := initialConfig(t)
	c, err := New(Options{Pipe: `\\.\pipe\rupas-guictrl-test-absent`, ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	err = c.writeConfig(presetConfig(true))
	if !errors.Is(err, ErrDaemonDown) {
		t.Fatalf("want ErrDaemonDown (file kept), got %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("saved config does not load: %v", err)
	}
	if cfg.Profile != "gui" {
		t.Fatalf("new config was not kept on disk: profile %q", cfg.Profile)
	}
}

// TestSaveLinksRejectsEmptyPlan: an empty box or only unsupported links must
// not overwrite the live config with the bare preset.
func TestSaveLinksRejectsEmptyPlan(t *testing.T) {
	path, before := initialConfig(t)
	c, err := New(Options{Pipe: `\\.\pipe\rupas-guictrl-test-absent`, ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	for _, blob := range []string{"", "trojan://pw@example.com:443#t", "vless://uuid@h:443?type=ws#w"} {
		if _, err := c.SaveLinks(blob); err == nil {
			t.Fatalf("SaveLinks(%q) must fail", blob)
		}
	}
	cur, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(cur) != string(before) {
		t.Fatalf("empty links save overwrote the config:\n%s", cur)
	}
}

// TestCheckLinks: the validation path must report warnings/errors without
// touching the live config, the backup or the daemon.
func TestCheckLinks(t *testing.T) {
	path, before := initialConfig(t)
	// No daemon on purpose: a check that dialed RPC would return ErrDaemonDown.
	c, err := New(Options{Pipe: `\\.\pipe\rupas-guictrl-test-absent`, ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	valid := "vless://0f4e1c2d-3b5a-4c6d-8e9f-aabbccddeeff@vps.example.net:443?security=reality&pbk=PBK&sid=AB&sni=camo.net&type=tcp#primary\n" +
		"hysteria2://hy2secret@vps.example.net:53552?sni=camo.net#voice\n" +
		"trojan://pass@trojan.example.net:443?security=tls&sni=t.net#ignored\n"
	warnings, err := c.CheckLinks(valid)
	if err != nil {
		t.Fatalf("valid blob: %v", err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "trojan") {
		t.Fatalf("want the trojan warning, got %v", warnings)
	}

	if _, err := c.CheckLinks("vless://not-a-link"); err == nil || err.Error() == "" {
		t.Fatalf("broken blob: want a message, got %v", err)
	}
	warnings, err = c.CheckLinks("")
	if err != nil || len(warnings) == 0 || !strings.Contains(strings.Join(warnings, " "), "нет ссылок") {
		t.Fatalf("empty blob: want a «нет ссылок» warning, got %v / %v", warnings, err)
	}

	for _, suffix := range []string{".bak", ".tmp"} {
		if _, err := os.Stat(path + suffix); err == nil {
			t.Fatalf("CheckLinks created %s", path+suffix)
		}
	}
	cur, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(cur) != string(before) || !after.ModTime().Equal(st.ModTime()) {
		t.Fatalf("CheckLinks wrote the live config:\n%s", cur)
	}
}

// TestListProcesses: the picker must see at least itself, be sorted and
// deduplicated by name.
func TestListProcesses(t *testing.T) {
	c, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	procs, err := c.ListProcesses()
	if err != nil {
		t.Fatalf("ListProcesses: %v", err)
	}
	if len(procs) == 0 {
		t.Fatal("process list is empty")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	selfName := strings.ToLower(filepath.Base(self))
	found := false
	for i, p := range procs {
		if p.Name != strings.ToLower(p.Name) || p.Path == "" || p.PID == 0 {
			t.Errorf("row %d not normalized: %+v", i, p)
		}
		if i > 0 && procs[i-1].Name >= p.Name {
			t.Errorf("not sorted/deduplicated: %q then %q", procs[i-1].Name, p.Name)
		}
		if p.Name == selfName {
			found = true
		}
	}
	if !found {
		t.Fatalf("current process %q missing from the list", selfName)
	}
}

// TestPollerStopsAndRestarts: StopPoller must actually stop the loop, and a
// restart must run exactly one poller.
func TestPollerStopsAndRestarts(t *testing.T) {
	pipe, polls := testDaemon(t, nil)
	c, err := New(Options{Pipe: pipe, PollInterval: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	c.StartPoller(func(Snapshot) {})
	time.Sleep(150 * time.Millisecond)
	c.StopPoller()
	stopped := atomic.LoadInt32(polls)
	if stopped == 0 {
		t.Fatal("poller never polled")
	}
	time.Sleep(150 * time.Millisecond)
	if extra := atomic.LoadInt32(polls) - stopped; extra > 1 {
		t.Fatalf("poller kept running after StopPoller: %d extra status RPCs", extra)
	}

	base := atomic.LoadInt32(polls)
	c.StartPoller(func(Snapshot) {})
	time.Sleep(150 * time.Millisecond)
	restarted := atomic.LoadInt32(polls) - base
	if restarted == 0 {
		t.Fatal("poller did not restart")
	}
	// One 20 ms poller fits ~8 polls in 150 ms; two would be ~16.
	if restarted > 10 {
		t.Fatalf("restart left two pollers running: %d polls in 150ms", restarted)
	}
}
