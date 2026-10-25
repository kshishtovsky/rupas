//go:build windows

package capture

import (
	"sync/atomic"

	"github.com/rupas/rupas/internal/core"
)

// counters is the atomic twin of core.Counters for the hot path: every
// increment is a single atomic add, no locks, no allocation. Snapshot()
// renders it into the plain struct consumed by rpc/diag (cold path).
type counters struct {
	packetsTotal   atomic.Uint64
	packetsPass    atomic.Uint64
	packetsDesync  atomic.Uint64
	packetsRedir   atomic.Uint64
	packetsDrop    atomic.Uint64
	handshakeOK    atomic.Uint64
	handshakeFail  atomic.Uint64
	tunnelRx       atomic.Uint64
	tunnelTx       atomic.Uint64
	tunnelRedirect atomic.Uint64
	sendErrors     atomic.Uint64
	// sendErrBurst counts CONSECUTIVE failed re-injections (reset by
	// sendOK); it gates the receive throttle — see Engine.sendFailed.
	sendErrBurst atomic.Uint32
	// sendPauses counts the driver catch-up pauses taken.
	sendPauses atomic.Uint64
	// sendWarnAt is the unix-nano timestamp of the last throttle WARN
	// (0 = never): the WARN rate limit.
	sendWarnAt  atomic.Int64
	parseErrors atomic.Uint64
}

// countVerdict bumps the per-verdict counters for a processed packet.
func (c *counters) countVerdict(v core.Verdict) {
	c.packetsTotal.Add(1)
	switch v {
	case core.VerdictPass:
		c.packetsPass.Add(1)
	case core.VerdictDesync:
		c.packetsDesync.Add(1)
	case core.VerdictRedirect:
		c.packetsRedir.Add(1)
	case core.VerdictDrop:
		c.packetsDrop.Add(1)
	}
}

// snapshot renders the counters into the cross-module struct. Cold path.
func (c *counters) snapshot() core.Counters {
	return core.Counters{
		PacketsTotal:  c.packetsTotal.Load(),
		PacketsPass:   c.packetsPass.Load(),
		PacketsDesync: c.packetsDesync.Load(),
		PacketsRedir:  c.packetsRedir.Load(),
		PacketsDrop:   c.packetsDrop.Load(),
		HandshakeOK:   c.handshakeOK.Load(),
		HandshakeFail: c.handshakeFail.Load(),
		TunnelRx:      c.tunnelRx.Load(),
		TunnelTx:      c.tunnelTx.Load(),
		SendErrors:    c.sendErrors.Load(),
		SendPauses:    c.sendPauses.Load(),
	}
}
