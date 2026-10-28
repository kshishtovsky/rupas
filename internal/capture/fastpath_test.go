package capture

import (
	"sync"
	"testing"

	"github.com/kshishtovsky/rupas/internal/flowtable"
	"github.com/kshishtovsky/rupas/internal/rules"
)

// hookRecorder is a fake TunnelTCP: records fed packets.
type hookRecorder struct {
	mu   sync.Mutex
	pkts []TCPPkt
}

func (h *hookRecorder) FeedTCP(p TCPPkt) {
	h.mu.Lock()
	defer h.mu.Unlock()
	p.Payload = append([]byte(nil), p.Payload...)
	h.pkts = append(h.pkts, p)
}

func (h *hookRecorder) Close() {}

func (h *hookRecorder) fed() []TCPPkt {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]TCPPkt, len(h.pkts))
	copy(out, h.pkts)
	return out
}

// newFastPathEngine builds an engine whose rules route the TG CIDR to
// TUNNEL and whose TGCIDRs enable the §4.2 fast path.
func newFastPathEngine(t *testing.T) (*Engine, *FakeTransport, *hookRecorder) {
	t.Helper()
	cfg := tunnelTestConfig()
	tbl, err := rules.Compile(cfg)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	e, err := New(Options{
		Rules:        tbl,
		Desync:       testDesyncParams("fake", 0),
		FakeTemplate: testFakeTemplate,
		TProxyPort:   testTProxyPort,
		TGCIDRs:      []string{"149.154.160.0/20"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ft := NewFakeTransport()
	loop := NewFakeTransport()
	e.InjectTransport(ft, loop)
	h := &hookRecorder{}
	e.SetTunnelTCP(h)
	return e, ft, h
}

// TestFastPathTunnelSYN: a TCP SYN toward a TUNNEL-rule CIDR is decided
// WITHOUT any ClientHello (§4.2) and, with the terminator hook installed,
// is handed to the hook (not NAT-rewritten).
func TestFastPathTunnelSYN(t *testing.T) {
	e, ft, h := newFastPathEngine(t)

	syn := buildTCP(testClientIP, testClientPort, testTGIP, 443, 9000, 0, tcpFlagSYN, nil)
	feed(t, e, syn, outboundAddr())

	fed := h.fed()
	if len(fed) != 1 {
		t.Fatalf("hook fed %d packets, want 1", len(fed))
	}
	p := fed[0]
	if p.SrcPort != testClientPort || p.DstPort != 443 || p.Seq != 9000 ||
		p.Flags != tcpFlagSYN || p.DstIP != parseIP4(testTGIP, [4]byte{}) {
		t.Fatalf("hook packet = %+v", p)
	}
	if ft.Sent() != nil && len(ft.Sent()) != 0 {
		t.Fatalf("SYN leaked to the main handle: %d packets", len(ft.Sent()))
	}
	// Flow table: TUNNEL immediately.
	f, ok := flowOf(e, testTGIP, 443)
	if !ok || f.State.Load() != flowtable.FlowTunnel {
		t.Fatalf("flow state after SYN = %v ok=%v, want FlowTunnel", f, ok)
	}
}

// TestFastPathSkipsNonCIDR: a 443 flow to a NON-CIDR destination still
// runs the ClientHello pipeline (no premature tunnel verdict).
func TestFastPathSkipsNonCIDR(t *testing.T) {
	e, ft, h := newFastPathEngine(t)

	// dst outside 149.154.160.0/20
	syn := buildTCP(testClientIP, testClientPort, "93.184.216.34", 443, 10, 0, tcpFlagSYN, nil)
	feed(t, e, syn, outboundAddr())
	ch := buildTCP(testClientIP, testClientPort, "93.184.216.34", 443, 11, 1,
		tcpFlagACK|tcpFlagPSH, buildClientHello("example.com", false))
	feed(t, e, ch, outboundAddr())

	if n := len(h.fed()); n != 0 {
		t.Fatalf("hook fed %d packets for a non-CIDR flow, want 0", n)
	}
	if len(ft.Sent()) == 0 {
		t.Fatal("non-CIDR flow never passed through")
	}
}
