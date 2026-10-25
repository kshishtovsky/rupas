//go:build windows

package capture

import (
	"encoding/binary"

	"github.com/rupas/rupas/internal/core"
	"github.com/rupas/rupas/internal/flowtable"
	"github.com/rupas/rupas/pkg/windivert"
)

// natKey identifies the client side of a NAT-redirected flow. The loopback
// tproxy replies carry the client as destination, so the reverse translation
// is a single map lookup on (client IP, client port, proto) — the original
// server address is stored in Flow.OrigDst/OrigPort.
type natKey struct {
	ip    [16]byte // client address (v4-mapped)
	port  uint16   // client port
	proto uint8
}

// natOutbound rewrites the destination of an outbound client packet to
// 127.0.0.1:tproxyPort (SYSTEM_DESIGN §3.3: NETWORK-layer NAT replacing the
// unavailable REDIRECT layer), remembers the original destination in the
// flow and registers the reverse-translation entry.
//
// The packet is edited in place and re-injected by the caller; the Address is
// left untouched except for the checksum-valid hint bits — direction stays
// outbound and the driver routes by the (now loopback) destination address.
func (e *Engine) natOutbound(pkt []byte, p *pktInfo, key flowtable.FlowKey, f *flowtable.Flow, addr *windivert.Address) {
	// Remember the original destination exactly once per flow; re-saves are
	// idempotent because client packets always target the original server.
	// OrigPort == 0 marks "not yet registered": the map insert happens on
	// the first NAT rewrite only, keeping per-packet map operations off the
	// outbound hot path.
	first := f.OrigPort == 0
	f.OrigDst = v4mapped(p.dst4)
	f.OrigPort = p.dstPort

	// Rewrite destination address (offset 16 in the IPv4 header) and port.
	pkt[16], pkt[17], pkt[18], pkt[19] = loopback4[0], loopback4[1], loopback4[2], loopback4[3]
	portOff := p.ipLen + 2 // TCP/UDP DstPort field
	binary.BigEndian.PutUint16(pkt[portOff:portOff+2], e.opts.TProxyPort)

	// Checksum-valid hints are stale now; FixChecksums recomputes both the
	// IP and the transport checksum (and refreshes the hint bits in addr).
	if err := e.transport.FixChecksums(pkt, addr); err != nil {
		e.cnt.sendErrors.Add(1)
	}
	// The destination is now 127.0.0.1: deliver into the loopback stack.
	// Keep the outbound direction but raise the Loopback flag and point the
	// address at the loopback interface — otherwise the driver routes the
	// packet out the original (Ethernet) interface where it dies (wave-4B
	// live finding: redir=N, tproxy accepts=0).
	addr.SetLoopback(true)
	if na := addr.Network(); na != nil {
		na.IfIdx, na.SubIfIdx = loopbackIfIdx, 0
	}
	if first {
		nk := natKey{ip: v4mapped(p.src4), port: p.srcPort, proto: p.proto}
		e.natMu.Lock()
		e.nat[nk] = f
		e.natMu.Unlock()
	}
	e.cnt.tunnelTx.Add(1)
	e.cnt.countVerdict(core.VerdictRedirect)
	if err := e.transport.Send(pkt, addr); err != nil {
		e.cnt.sendErrors.Add(1)
	}
}

// Lookup resolves the pre-NAT destination of a redirected flow by its
// client src address/port (SYSTEM_DESIGN §3.3). It is the cold-path seam
// the tunnel's OriginalDstProvider consumes: the NETWORK-layer NAT stored
// OrigDst/OrigPort keyed by the client 4-tuple when it rewrote the packet
// to 127.0.0.1:tproxyPort. Addresses are 16-byte; IPv4 arrives in
// IPv4-mapped form (as in flowtable.FlowKey).
//
// The NAT map is keyed by (ip, port, proto); this lookup tries TCP first,
// then UDP — the two never share a client port in practice (the OS
// ephemeral allocators are per-protocol), and the packet hot path is not
// touched (RLock only, called once per accepted tunnel flow).
func (e *Engine) Lookup(srcIP [16]byte, srcPort uint16) (dst [16]byte, dport uint16, ok bool) {
	for _, proto := range [...]uint8{protoTCP, protoUDP} {
		nk := natKey{ip: srcIP, port: srcPort, proto: proto}
		e.natMu.RLock()
		f, known := e.nat[nk]
		e.natMu.RUnlock()
		if known {
			return f.OrigDst, f.OrigPort, true
		}
	}
	return [16]byte{}, 0, false
}

// processLoopback handles packets captured by the second (loopback) handle:
// replies of the tproxy listener on 127.0.0.1:tproxyPort back to the client.
// The source is translated back to the original destination recorded in the
// flow, so the client believes it is talking to the real server. The
// translated packet is re-injected through the same loopback handle.
//
// Address flags are preserved as received (inbound, loopback); only the
// packet contents and the checksum hints change.
func (e *Engine) processLoopback(t Transport, pkt []byte, addr *windivert.Address) {
	p, ok := parsePkt(pkt)
	if !ok || (p.proto != protoTCP && p.proto != protoUDP) {
		e.cnt.parseErrors.Add(1)
		e.passLoopback(t, pkt, addr)
		return
	}
	nk := natKey{ip: v4mapped(p.dst4), port: p.dstPort, proto: p.proto}
	e.natMu.RLock()
	f, known := e.nat[nk]
	e.natMu.RUnlock()
	if !known {
		// Not a flow we redirected (foreign traffic to the same port).
		e.passLoopback(t, pkt, addr)
		return
	}

	// Reverse rewrite: source 127.0.0.1:tproxyPort -> OrigDst:OrigPort.
	origIP := f.OrigDst
	copy(pkt[12:16], origIP[12:16])
	binary.BigEndian.PutUint16(pkt[p.ipLen:p.ipLen+2], f.OrigPort)
	if err := t.FixChecksums(pkt, addr); err != nil {
		e.cnt.sendErrors.Add(1)
	}
	e.cnt.tunnelRx.Add(1)
	if err := t.Send(pkt, addr); err != nil {
		e.cnt.sendErrors.Add(1)
	}

	if p.isTCP() && (p.fin() || p.rst()) {
		e.cleanupFlow(nk, flowKeyOf(nk, f))
	}
}

func (e *Engine) passLoopback(t Transport, pkt []byte, addr *windivert.Address) {
	e.cnt.countVerdict(core.VerdictPass)
	if err := t.Send(pkt, addr); err != nil {
		e.cnt.sendErrors.Add(1)
	}
}

// flowKeyOf reconstructs the client-side flow-table key of a NAT entry.
func flowKeyOf(nk natKey, f *flowtable.Flow) flowtable.FlowKey {
	return flowtable.FlowKey{
		SrcIP: nk.ip, SrcPort: nk.port,
		DstIP: f.OrigDst, DstPort: f.OrigPort,
		Proto: nk.proto,
	}
}

// cleanupFlow removes the NAT entry, the inspector stream, any pending
// ClientHello hold and the flow itself after FIN/RST. Safe from both
// receive goroutines.
func (e *Engine) cleanupFlow(nk natKey, k flowtable.FlowKey) {
	e.natMu.Lock()
	delete(e.nat, nk)
	e.natMu.Unlock()
	e.streamMu.Lock()
	delete(e.streams, k)
	h := e.holds[k]
	delete(e.holds, k)
	e.streamMu.Unlock()
	if h != nil {
		e.putHold(h) // flow is dead: drop the held segments
	}
	e.flows.Delete(k)
}

// sweepStreams releases inspector streams and ClientHello holds whose flow
// has expired (idle half-open connections removed by the flow-table GC).
// Cold path.
func (e *Engine) sweepStreams() {
	e.streamMu.Lock()
	for k, st := range e.streams {
		if _, ok := e.flows.Get(k); !ok {
			delete(e.streams, k)
			st.Reset()
			e.streamPool.Put(st)
		}
	}
	var stale []*chHold
	for k, h := range e.holds {
		if _, ok := e.flows.Get(k); !ok {
			delete(e.holds, k)
			stale = append(stale, h)
		}
	}
	e.streamMu.Unlock()
	for _, h := range stale {
		e.putHold(h)
	}
}
