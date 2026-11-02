package tunnel

// Single-endpoint probe for the GUI «Проверить» button on a channel card
// (Android parity: mobile.TestProfile). One share link in, one verdict out:
// bring up a throwaway carrier for exactly that endpoint, dial the probe
// target through it, verify the TLS certificate. Nothing here touches the
// production relay — the carrier is closed before returning.

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/kshishtovsky/rupas/internal/config"
)

const (
	// Probe target: an IP literal plus its matching SNI, so the verdict is a
	// certificate-verified handshake (same target as the Android probe).
	ProbeTarget = "104.16.124.96:443"
	ProbeName   = "medium.com"

	probeDialBudget = 15 * time.Second
	probeTLSBudget  = 4 * time.Second
)

// ProbeResult is the frozen JSON contract the GUI parses.
type ProbeResult struct {
	OK    bool   `json:"ok"`
	MS    int64  `json:"ms"`
	Stage string `json:"stage"` // start | dial | tls
	Err   string `json:"err,omitempty"`
}

// ProbeEndpoint checks one endpoint end-to-end.
func ProbeEndpoint(ctx context.Context, ep config.Endpoint, logger *slog.Logger) ProbeResult {
	if logger == nil {
		logger = slog.Default()
	}
	if err := ep.Validate(); err != nil {
		return ProbeResult{Stage: "start", Err: err.Error()}
	}
	cfg := config.TunnelConfig{TCP: &ep}
	ports, err := sbPortsForPlan(cfg)
	if err != nil {
		return ProbeResult{Stage: "start", Err: err.Error()}
	}
	var closer func() error
	dial := func(dctx context.Context, dst netip.AddrPort) (net.Conn, error) {
		return nil, fmt.Errorf("probe: no carrier for %s", ep.Kind)
	}
	switch {
	case ep.SingBoxKind():
		sb, err := startSingbox(ctx, logger, boxOptions(cfg, ports), ports)
		if err != nil {
			return ProbeResult{Stage: "start", Err: err.Error()}
		}
		closer = sb.close
		p := socksPath{addr: sb.mainAddr()}
		dial = p.dial
	case ep.Kind == config.KindTMN:
		path, err := newTMNPath(ep, logger)
		if err != nil {
			return ProbeResult{Stage: "start", Err: err.Error()}
		}
		closer = path.Close
		dial = path.dial
	case ep.Kind == config.KindVLESSXHTTP:
		path, err := newXHTTPPath(ep, logger)
		if err != nil {
			return ProbeResult{Stage: "start", Err: err.Error()}
		}
		dial = path.dial
	}
	if closer != nil {
		defer closer() //nolint:errcheck // throwaway carrier
	}

	started := time.Now()
	dst := netip.MustParseAddrPort(ProbeTarget)
	dctx, cancel := context.WithTimeout(ctx, probeDialBudget)
	conn, err := dial(dctx, dst)
	cancel()
	if err != nil {
		return ProbeResult{Stage: "dial", Err: err.Error()}
	}
	defer conn.Close() //nolint:errcheck

	tctx, tcancel := context.WithTimeout(ctx, probeTLSBudget)
	defer tcancel()
	tc := tls.Client(conn, &tls.Config{ServerName: ProbeName, MinVersion: tls.VersionTLS12})
	if err := tc.HandshakeContext(tctx); err != nil {
		return ProbeResult{Stage: "tls", Err: err.Error()}
	}
	return ProbeResult{OK: true, MS: time.Since(started).Milliseconds(), Stage: "payload"}
}
