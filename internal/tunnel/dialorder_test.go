package tunnel

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rupas/rupas/internal/config"
)

// stubCarrier is a tcpCarrier recording dial order.
type stubCarrier struct {
	name  string
	calls *[]string
	fail  bool
}

func (s stubCarrier) dial(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	if s.calls != nil {
		*s.calls = append(*s.calls, s.name)
	}
	if s.fail {
		return nil, io.EOF
	}
	c1, c2 := net.Pipe()
	go func() { _, _ = io.Copy(io.Discard, c2) }() //nolint:errcheck // drain
	_ = c1.Close()
	return c1, nil
}

func (s stubCarrier) dialHost(ctx context.Context, host string, port uint16) (net.Conn, error) {
	return s.dial(ctx, netip.MustParseAddrPort("127.0.0.1:1"))
}

// dialOrder must put the fallback carrier first for TCPFallbackFirstCIDR
// destinations (wave 6: TG destinations poison the primary vless endpoint)
// and keep the normal order otherwise.
func TestDialOrderFallbackFirstForTGCIDRs(t *testing.T) {
	tun := &tunnel{
		opts: Options{TCPFallbackFirstCIDRs: []netip.Prefix{
			netip.MustParsePrefix("149.154.160.0/20"),
		}},
	}
	tun.tcpPaths = []namedTCP{
		{name: "vless", c: stubCarrier{name: "vless"}},
		{name: "hy2", c: stubCarrier{name: "hy2"}},
		{name: "xhttp", c: stubCarrier{name: "xhttp"}},
	}

	got := namesOf(tun.dialOrder(netip.MustParseAddrPort("149.154.167.51:443")))
	want := []string{"hy2", "xhttp", "vless"}
	if !equalNames(got, want) {
		t.Fatalf("TG dst order = %v, want %v", got, want)
	}

	got = namesOf(tun.dialOrder(netip.MustParseAddrPort("1.1.1.1:443")))
	want = []string{"vless", "hy2", "xhttp"}
	if !equalNames(got, want) {
		t.Fatalf("non-TG dst order = %v, want %v", got, want)
	}
}

// dialOrder must deprioritize carriers in failure cooldown (fast failover
// instead of burning the dial timeout on a quarantined endpoint).
func TestDialOrderCooldownSkipsFailedPath(t *testing.T) {
	tun := &tunnel{}
	tun.tcpPaths = []namedTCP{
		{name: "vless", c: stubCarrier{name: "vless"}},
		{name: "hy2", c: stubCarrier{name: "hy2"}},
	}
	tun.markPathFailure("vless")

	got := namesOf(tun.dialOrder(netip.MustParseAddrPort("1.1.1.1:443")))
	want := []string{"hy2", "vless"}
	if !equalNames(got, want) {
		t.Fatalf("order with vless cooling = %v, want %v", got, want)
	}

	// Success clears the cooldown.
	tun.markPathSuccess("vless")
	got = namesOf(tun.dialOrder(netip.MustParseAddrPort("1.1.1.1:443")))
	want = []string{"vless", "hy2"}
	if !equalNames(got, want) {
		t.Fatalf("order after recovery = %v, want %v", got, want)
	}
}

// dialTCPFlow must mark failing paths (cooldown) and succeed via the next
// carrier, and count the flow.
func TestDialTCPFlowFailsOverAndMarks(t *testing.T) {
	var calls []string
	tun := &tunnel{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	tun.tcpPaths = []namedTCP{
		{name: "vless", c: stubCarrier{name: "vless", fail: true, calls: &calls}},
		{name: "hy2", c: stubCarrier{name: "hy2", calls: &calls}},
	}
	tun.dialTimeout = 2 * time.Second

	conn := tun.dialTCPFlow("src", netip.MustParseAddrPort("1.1.1.1:443"))
	if conn == nil {
		t.Fatal("dialTCPFlow returned nil although hy2 carrier works")
	}
	_ = conn.Close()
	if !equalNames(calls, []string{"vless", "hy2"}) {
		t.Fatalf("dial order = %v, want [vless hy2]", calls)
	}
	if _, ok := tun.pathDownUntil("vless"); !ok {
		t.Fatal("failed vless path not marked down")
	}
	if tun.tcpFlows.Load() != 1 {
		t.Fatalf("flows = %d, want 1", tun.tcpFlows.Load())
	}
}

// fbRouteTag: the TCP-fallback mixed inbound routes to a sing-box fallback
// when configured, else to the distinct hysteria2 outbound.
func TestFBRouteTag(t *testing.T) {
	vless := &config.Endpoint{Kind: config.KindVLESSTCP}
	hy2 := &config.Endpoint{Kind: config.KindHysteria2}
	xhttp := &config.Endpoint{Kind: config.KindVLESSXHTTP}

	cases := []struct {
		name   string
		plan   tunnelPlan
		udpSB  bool
		wantFB string
	}{
		{"sb fallback", tunnelPlan{tcp: vless, udp: hy2, fallback: vless}, true, fbTag},
		{"xhttp fallback + hy2", tunnelPlan{tcp: vless, udp: hy2, fallback: xhttp}, true, udpTag},
		{"no fallback + hy2", tunnelPlan{tcp: vless, udp: hy2}, true, udpTag},
		{"no fallback, no distinct udp", tunnelPlan{tcp: vless, udp: vless}, false, ""},
	}
	for _, c := range cases {
		if got := fbRouteTag(c.plan, c.udpSB); got != c.wantFB {
			t.Errorf("%s: fbRouteTag = %q, want %q", c.name, got, c.wantFB)
		}
	}
}

// countingConn must feed rx/tx bytes into the counters (wave-6 acceptance
// asserts tunnel rx > 0 on the terminator path).
func TestCountingConn(t *testing.T) {
	var rx, tx atomic.Uint64
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	cc := &countingConn{Conn: a, rx: &rx, tx: &tx}

	done := make(chan struct{})
	go func() {
		_, _ = b.Write([]byte("hello")) //nolint:errcheck // test
		close(done)
	}()
	buf := make([]byte, 5)
	if _, err := cc.Read(buf); err != nil {
		t.Fatal(err)
	}
	<-done
	if rx.Load() != 5 {
		t.Fatalf("rx = %d, want 5", rx.Load())
	}

	wdone := make(chan struct{})
	go func() {
		_, _ = io.ReadFull(b, make([]byte, 2)) //nolint:errcheck // test
		close(wdone)
	}()
	if _, err := cc.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	<-wdone
	if tx.Load() != 2 {
		t.Fatalf("tx = %d, want 2", tx.Load())
	}
}

func namesOf(chain []namedTCP) []string {
	out := make([]string, len(chain))
	for i, p := range chain {
		out[i] = p.name
	}
	return out
}

func equalNames(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestDialTCPFlowPacesVlessBurst: with a multi-path plan, rapid dials
// overflow from the paced vless carrier to the unpaced hy2 carrier instead
// of hammering the TSPU-rate-limited endpoint (wave 6).
func TestDialTCPFlowPacesVlessBurst(t *testing.T) {
	var calls []string
	tun := &tunnel{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	tun.tcpPaths = []namedTCP{
		{name: "vless", c: stubCarrier{name: "vless", calls: &calls}, paced: true},
		{name: "hy2", c: stubCarrier{name: "hy2", calls: &calls}},
	}
	tun.dialTimeout = 2 * time.Second

	for i := 0; i < 4; i++ {
		c := tun.dialTCPFlow("src", netip.MustParseAddrPort("1.1.1.1:443"))
		if c == nil {
			t.Fatalf("dial %d failed entirely", i)
		}
		_ = c.Close()
	}
	vlessN, hy2N := 0, 0
	for _, n := range calls {
		switch n {
		case "vless":
			vlessN++
		case "hy2":
			hy2N++
		}
	}
	if vlessN > pathTokenBurst {
		t.Errorf("vless dialed %d× in one burst, want ≤ %d (pacing)", vlessN, pathTokenBurst)
	}
	if hy2N == 0 {
		t.Error("burst overflow never rode the hy2 carrier")
	}

	// Single-path plans never pace: the only carrier must keep answering.
	calls = nil
	single := &tunnel{logger: tun.logger}
	single.tcpPaths = []namedTCP{{name: "vless", c: stubCarrier{name: "vless", calls: &calls}, paced: true}}
	single.dialTimeout = 2 * time.Second
	for i := 0; i < 4; i++ {
		c := single.dialTCPFlow("src", netip.MustParseAddrPort("1.1.1.1:443"))
		if c == nil {
			t.Fatalf("single-path dial %d failed (pacing must not apply)", i)
		}
		_ = c.Close()
	}
	if len(calls) != 4 {
		t.Fatalf("single-path dials = %v, want 4× vless", calls)
	}
}
