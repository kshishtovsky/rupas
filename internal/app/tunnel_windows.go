//go:build windows

package app

import (
	"log"
	"log/slog"
	"sync/atomic"

	"github.com/rupas/rupas/internal/capture"
	"github.com/rupas/rupas/internal/config"
	"github.com/rupas/rupas/internal/tunnel"
	"github.com/rupas/rupas/pkg/windivert"
)

// DefaultTProxyPort is the loopback port TUNNEL-verdict flows are
// NAT-redirected to (SYSTEM_DESIGN §3.3). It deliberately sits outside
// 443 and the [50000,65535] UDP relay range the capture filter claims.
const DefaultTProxyPort uint16 = 12713

// natProvider adapts the capture-layer NAT flow map to
// tunnel.OriginalDstProvider (§3.3): the engine instance changes with
// every pipeline start segment (capture.Engine.Run is once-only), so the
// current engine is held behind an atomic pointer and swapped by the
// pipeline. Lookup is cold-path (once per accepted tunnel flow); the
// packet hot path is untouched.
type natProvider struct {
	eng atomic.Pointer[capture.Engine]
}

// Lookup implements tunnel.OriginalDstProvider over capture.Engine.Lookup.
func (p *natProvider) Lookup(srcIP [16]byte, srcPort uint16) ([16]byte, uint16, bool) {
	if e := p.eng.Load(); e != nil {
		return e.Lookup(srcIP, srcPort)
	}
	return [16]byte{}, 0, false
}

// slogBridge routes the tunnel's structured logs into the daemon's
// *log.Logger (one line per record, the slog text format).
func slogBridge(l *log.Logger) *slog.Logger {
	return slog.New(slog.NewTextHandler(logWriter{l}, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
}

type logWriter struct{ l *log.Logger }

func (w logWriter) Write(b []byte) (int, error) {
	w.l.Print(string(b))
	return len(b), nil
}

// tunnelEndpointConfigured reports whether the config carries a usable
// tunnel plan (config.Validate enforces all-or-nothing per endpoint).
func tunnelEndpointConfigured(cfg *config.Config) bool {
	return cfg.TunnelPlan().Configured()
}

// newTunnel builds the real tunnel-core for cfg's endpoint plan (not
// started).
func newTunnel(cfg *config.Config, tproxyPort uint16, provider *natProvider, logger *log.Logger, o tunnelRunOpts) tunnel.Tunnel {
	return tunnel.NewTunnel(cfg.TunnelPlan(), tproxyPort, tunnel.Options{
		OriginalDstProvider: provider,
		MarkerURL:           o.markerURL,
		Logger:              slogBridge(logger),
		HealthInterval:      o.healthInterval,
		DialTimeout:         o.dialTimeout,
	})
}

// inboundSender adapts the engine's dedicated terminator handle to
// tunnel.PacketSender: forged packets re-enter INBOUND, not-loopback, on
// the captured packet's interface — the delivery combination the live
// matrix proved (zz_inbest_test: inbound injection delivers for flows the
// stack authorized on the outbound leg).
type inboundSender struct{ t capture.Transport }

func (s inboundSender) SendInboundTCP(pkt []byte, ifIdx, subIfIdx uint32) error {
	var addr windivert.Address
	addr.SetOutbound(false)
	addr.SetLoopback(false)
	if na := addr.Network(); na != nil {
		na.IfIdx, na.SubIfIdx = ifIdx, subIfIdx
	}
	return s.t.Send(pkt, &addr)
}

// termAdapter bridges capture.TunnelTCP (engine hook) onto the terminator.
type termAdapter struct{ tm *tunnel.Terminator }

func (a termAdapter) FeedTCP(p capture.TCPPkt) {
	a.tm.Feed(tunnel.TermPkt{
		SrcIP: p.SrcIP, DstIP: p.DstIP,
		SrcPort: p.SrcPort, DstPort: p.DstPort,
		Seq: p.Seq, Ack: p.Ack, Flags: p.Flags, Window: p.Window,
		Payload: p.Payload, IfIdx: p.IfIdx, SubIfIdx: p.SubIfIdx,
	})
}

func (a termAdapter) Close() { a.tm.Close() }
