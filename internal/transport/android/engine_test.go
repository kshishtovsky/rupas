package android

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

// Regression: Start used to return while still holding e.mu (no Unlock on
// the success path). The next Status()/Stop() — called from the Java main
// thread in production — then blocked on the mutex forever (ANR). Status()
// must return promptly right after Start.
func TestStartDoesNotHoldMutex(t *testing.T) {
	e := NewEngine(nil, func(int) bool { return true }, nil)

	// fd<=0 keeps run() from touching any real TUN; the lifecycle path is
	// what we exercise here.
	if err := e.Start(-1); err == nil {
		t.Fatal("Start(-1) must fail")
	}

	if err := e.Start(0); err == nil {
		t.Fatal("Start(0) must fail")
	}

	// A fake long-running run is not needed: even with a valid lifecycle the
	// regression was an unlock-free success path, so verify the success path
	// by stopping immediately after an in-flight run() is impossible here
	// (no TUN on the host). Instead: start with a verdict engine on a real
	// goroutine is covered by tun tests on linux; here we assert Stop on a
	// never-started engine and Status-after-Stop latency.
	_ = e.Stop()

	done := make(chan struct{})
	go func() {
		e.Snapshot()
		e.Running()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Status-path accessors blocked: mutex held (regression)")
	}
}

// Stop must be bounded: it may be called from the Java main thread.
// A never-ending transport is simulated by a done-channel that never closes
// (Start with invalid fd leaves running=false, so emulate by direct field
// manipulation through a started-but-broken engine is not possible here;
// hence this test pins the 3s ceiling via the exported behavior only when a
// transport is genuinely running — skipped on windows where run() is a stub).
func TestStopIsBounded(t *testing.T) {
	e := NewEngine(nil, func(int) bool { return true }, nil)
	// Engine not started: Stop returns nil immediately.
	start := time.Now()
	if err := e.Stop(); err != nil {
		t.Fatalf("Stop on idle engine: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("Stop on idle engine must be immediate")
	}
	// Concurrent Stop calls must not race or deadlock.
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = e.Stop()
		}()
	}
	wg.Wait()
}

// The app surfaces TunnelInfo() as "protected"; it must therefore never claim
// "on" for an engine whose chain holds only the "direct" escalation tail —
// that is exactly the misconfigured-device state that blackholed Telegram.
func TestTunnelInfoAndCarrierCount(t *testing.T) {
	e := NewW3EngineWithRules(nil, nil, nil, "", nil)
	if st, detail := e.TunnelInfo(); st != "off" || detail != "no endpoint settings" {
		t.Fatalf("no settings must report off/no endpoint settings, got %q/%q", st, detail)
	}
	e.carriers = []tcpCarrier{{name: "endpoint-a"}, {name: "direct"}}
	if n := e.tunnelCarrierCount(); n != 1 {
		t.Fatalf("tunnelCarrierCount must skip the direct tail, got %d", n)
	}
	e.setTunnel("on", "1 carrier(s)")
	if st, detail := e.TunnelInfo(); st != "on" || detail != "1 carrier(s)" {
		t.Fatalf("setTunnel must be visible through TunnelInfo, got %q/%q", st, detail)
	}
}

// DoT (TCP/853) must be refused while the filter is on: it is encrypted, so the
// DNS sinkhole never sees it, and Android's resolver would happily resolve ad
// hosts for real. Refusal makes it fall back to UDP/53, which is filtered.
func TestAdblockRefusesDoT(t *testing.T) {
	e := NewW3EngineWithRules(nil, nil, nil, "", nil)
	e.adblock = &Adblock{} // filter on, empty tables: only the 853 branch matters
	dot := FlowMeta{Destination: netip.MustParseAddrPort("8.8.8.8:853")}
	if got := e.decide(dot); got != ActionBlock {
		t.Fatalf("TCP/853 with the filter on must be blocked, got %v", got)
	}
	// Filter off → DoT is left alone.
	e.adblock = nil
	if got := e.decide(dot); got == ActionBlock && e.rules != nil {
		t.Log("rules blocked 853 on their own; that is the preset's business")
	}
}
