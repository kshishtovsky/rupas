//go:build windows

package rpc

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/kshishtovsky/rupas/internal/core"
)

// testServer starts a Server on a fresh test pipe and waits until the
// listener is actually connectable.
func testServer(t *testing.T, deps Deps) *Server {
	t.Helper()
	name := fmt.Sprintf(`\\.\pipe\rupasctl-test-%d-%d`, os.Getpid(), rand.Int64())
	srv := New(name, deps)
	served := make(chan struct{})
	var serveErr error
	go func() {
		defer close(served)
		serveErr = srv.ListenAndServe(context.Background())
	}()
	t.Cleanup(func() {
		srv.Close()
		<-served
		if serveErr != nil {
			t.Logf("ListenAndServe: %v", serveErr)
		}
	})

	// Wait for the first pipe instance to be armed.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if f, err := DialPipe(name, 500*time.Millisecond); err == nil {
			f.Close()
			return srv
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("server did not come up on %s", name)
	return nil
}

type client struct {
	f  *os.File
	rd *bufio.Reader
	t  *testing.T
}

func dial(t *testing.T, name string) *client {
	t.Helper()
	f, err := DialPipe(name, 3*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", name, err)
	}
	return &client{f: f, rd: bufio.NewReader(f), t: t}
}

func (c *client) do(cmd string) Response {
	c.t.Helper()
	b, _ := json.Marshal(Request{Cmd: cmd})
	if _, err := c.f.Write(append(b, '\n')); err != nil {
		c.t.Fatalf("write %s: %v", cmd, err)
	}
	line, err := c.rd.ReadBytes('\n')
	if err != nil {
		c.t.Fatalf("read %s: %v", cmd, err)
	}
	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		c.t.Fatalf("unmarshal %q: %v", line, err)
	}
	return resp
}

func (c *client) close() { c.f.Close() }

func testDeps() (Deps, *map[string]int) {
	calls := map[string]int{}
	mu := sync.Mutex{}
	rec := func(k string) func() error {
		return func() error {
			mu.Lock()
			defer mu.Unlock()
			calls[k]++
			return nil
		}
	}
	logs := []string{"2026-10-25T12:00:00+05:00 state OFF -> PROBING (cmdOn)",
		"2026-10-25T12:00:01+05:00 state PROBING -> ACTIVE (probe ok)"}
	return Deps{
		Status: func() core.Snapshot {
			return core.Snapshot{
				State:     "ACTIVE",
				ProfileID: "isp-home-2025-10-25",
				Flows:     map[string]int64{"DIRECT": 3, "DESYNCED": 2},
			}
		},
		On:     rec("on"),
		Off:    rec("off"),
		Probe:  rec("probe"),
		Reload: rec("reload"),
		Logs:   func(n int) []string { return logs },
	}, &calls
}

// TestPipeLoopback exercises the full JSON-line protocol over a real
// named pipe: every command, error paths, pipelining and the logs stream.
func TestPipeLoopback(t *testing.T) {
	deps, callsPtr := testDeps()
	srv := testServer(t, deps)
	calls := *callsPtr

	c := dial(t, srv.pipe)
	defer c.close()

	// status returns the snapshot as data.
	resp := c.do("status")
	if !resp.OK {
		t.Fatalf("status: %+v", resp)
	}
	raw, _ := json.Marshal(resp.Data)
	var snap core.Snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatalf("snapshot decode: %v (%s)", err, raw)
	}
	if snap.State != "ACTIVE" || snap.ProfileID != "isp-home-2025-10-25" || snap.Flows["DESYNCED"] != 2 {
		t.Fatalf("snapshot roundtrip damaged: %+v", snap)
	}

	// on/off/probe/reload invoke the wired callbacks.
	for _, cmd := range []string{"on", "off", "probe", "reload"} {
		if r := c.do(cmd); !r.OK {
			t.Fatalf("%s: %+v", cmd, r)
		}
	}
	for _, cmd := range []string{"on", "off", "probe", "reload"} {
		if calls[cmd] != 1 {
			t.Fatalf("cmd %q called %d times, want 1", cmd, calls[cmd])
		}
	}

	// Unknown command and malformed JSON answer ok=false and keep the
	// connection usable (pipelined follow-up).
	if r := c.do("definitely-not-a-cmd"); r.OK || r.Error == "" {
		t.Fatalf("unknown cmd: %+v", r)
	}
	if _, err := c.f.WriteString("this is not json\n"); err != nil {
		t.Fatal(err)
	}
	line, err := c.rd.ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	var bad Response
	if json.Unmarshal(line, &bad) != nil || bad.OK {
		t.Fatalf("malformed request not rejected: %q", line)
	}
	if r := c.do("status"); !r.OK {
		t.Fatalf("connection broken after errors: %+v", r)
	}
	c.close()

	// logs streams every buffered line as its own JSON line, then closes.
	c2 := dial(t, srv.pipe)
	defer c2.close()
	b, _ := json.Marshal(Request{Cmd: "logs"})
	if _, err := c2.f.Write(append(b, '\n')); err != nil {
		t.Fatal(err)
	}
	var got []string
	for {
		line, err := c2.rd.ReadBytes('\n')
		if len(line) > 0 {
			var r Response
			if json.Unmarshal(line, &r) != nil || !r.OK {
				t.Fatalf("bad stream line %q", line)
			}
			m, _ := r.Data.(map[string]any)
			if s, ok := m["log"].(string); ok {
				got = append(got, s)
			}
		}
		if err != nil {
			break // EOF: server half-closed after the stream
		}
	}
	if len(got) != 2 || got[0] != "2026-10-25T12:00:00+05:00 state OFF -> PROBING (cmdOn)" {
		t.Fatalf("logs stream = %v", got)
	}

	// A fresh connection still works afterwards (instance pool recycled).
	c3 := dial(t, srv.pipe)
	defer c3.close()
	if r := c3.do("status"); !r.OK {
		t.Fatalf("post-stream status: %+v", r)
	}
}

// TestPipeConcurrentClients hammers the server from several connections at
// once (run with -race).
func TestPipeConcurrentClients(t *testing.T) {
	deps, _ := testDeps()
	srv := testServer(t, deps)

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := dial(t, srv.pipe)
			defer c.close()
			for j := 0; j < 25; j++ {
				if r := c.do("status"); !r.OK {
					t.Errorf("status: %+v", r)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// TestServerCloseIsIdempotent covers shutdown hygiene.
func TestServerCloseIsIdempotent(t *testing.T) {
	deps, _ := testDeps()
	srv := testServer(t, deps)
	if err := srv.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

func TestNewNormalizesPipeName(t *testing.T) {
	if New("", Deps{}).pipe != DefaultPipe {
		t.Fatal("empty name must default to DefaultPipe")
	}
	if got := New("rupasctl", Deps{}).pipe; got != `\\.\pipe\rupasctl` {
		t.Fatalf("bare name not prefixed: %q", got)
	}
	if got := New(`\\.\pipe\x`, Deps{}).pipe; got != `\\.\pipe\x` {
		t.Fatalf("full name mangled: %q", got)
	}
}

func TestSDDLParses(t *testing.T) {
	sa, sd, err := sddlSecurityAttributes(pipeSDDL)
	if err != nil {
		t.Fatalf("SDDL parse: %v", err)
	}
	if sa == nil || sd == 0 || sa.Length != uint32(unsafe.Sizeof(*sa)) || sa.SecurityDescriptor != sd {
		t.Fatalf("bad SECURITY_ATTRIBUTES: %+v sd=%x", sa, sd)
	}
	procLocalFree.Call(sd)
}

// TestPipeRejectsOversizedLine: a line past maxLineBytes is rejected from the
// bounded read buffer instead of being accumulated, and the client dropped.
func TestPipeRejectsOversizedLine(t *testing.T) {
	deps, _ := testDeps()
	srv := testServer(t, deps)
	c := dial(t, srv.pipe)
	defer c.close()

	go func() {
		// No newline: the server must stop reading at its cap, not at EOF.
		_, _ = c.f.Write(make([]byte, 2*maxLineBytes))
	}()
	_ = c.f.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := c.rd.ReadBytes('\n')
	if err != nil {
		t.Fatalf("no rejection line, got err %v (%q)", err, line)
	}
	var r Response
	if json.Unmarshal(line, &r) != nil || r.OK || r.Error != "request too large" {
		t.Fatalf("oversize answer = %q", line)
	}
}
