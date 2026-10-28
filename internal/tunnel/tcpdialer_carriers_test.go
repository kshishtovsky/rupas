package tunnel

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"
)

// A paced primary plus a DEAD fallback must still serve every dial: pacing is
// meant to offload a burst, not to leave the machine with zero carriers
// (live 2026-10-28: hy2 refused everything, so every flow past the 2-token
// burst failed while the primary vless was healthy).
func TestTCPDialerNeverRunsOutOfCarriers(t *testing.T) {
	var calls []string
	tun := &tunnel{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	tun.tcpPaths = []namedTCP{
		{name: "vless", c: stubCarrier{name: "vless", calls: &calls}, paced: true},
		{name: "hy2", c: stubCarrier{name: "hy2", fail: true, calls: &calls}},
	}
	tun.dialTimeout = 2 * time.Second
	dial := tun.TCPDialer()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for i := 0; i < 5; i++ {
		c, err := dial(ctx, netip.MustParseAddrPort("140.82.121.3:443").String())
		if err != nil {
			t.Fatalf("dial %d failed although the primary works: %v", i, err)
		}
		_ = c.Close()
	}
	vlessN := 0
	for _, n := range calls {
		if n == "vless" {
			vlessN++
		}
	}
	if vlessN < 5 {
		t.Fatalf("vless dialed %d×, want 5 (unpaced last resort past the burst)", vlessN)
	}
}
