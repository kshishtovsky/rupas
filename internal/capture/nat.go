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

// natFakeIP4 is the synthetic source the NAT presents to the local tproxy.
// LIVE MATRIX FINDING (2026-10-25): an inbound re-injection whose SOURCE is
// one of the machine's own addresses (the real NIC IP or 127/8) is
// martian-dropped by the stack — only a non-local source delivers. The
// 198.18.0.0/15 benchmark range is never a real destination on user paths.
var natFakeIP4 = [4]byte{198, 18, 0, 1}

func fakeIP4() [4]byte { return natFakeIP4 }

// natVal is one NAT-redirect entry: the flow (OrigDst/OrigPort), the
// client's real address (the reverse legs rewrite the tproxy replies'
// destination from the fake IP back to it) and the client-facing interface
// the re-injections must carry (inbound + client-NIC IfIdx is the only
// combination the live matrix proved delivers).
type natVal struct {
	f        *flowtable.Flow
	clientIP [4]byte
	ifIdx    uint32
	subIfIdx uint32
}

// natOutbound rewrites an outbound client packet into the tproxy relay:
//
//	src <clientIP>:eph     → <natFakeIP>:eph     (the stack martian-drops
//	                                             self-sourced inbound
//	                                             packets, so the tproxy
//	                                             must see a foreign source)
//	dst <serverIP>:port    → <clientIP>:tproxyPort (the machine's own
//	                                             address on the client
//	                                             interface)
//
// remembers the original destination in the flow and registers the
// reverse-translation entry keyed by the FAKE source (that is what the
// tproxy reports as the flow's remote). The packet is re-injected INBOUND
// through the loopback handle with the client NIC's IfIdx.
//
// (SYSTEM_DESIGN §3.3; all re-injection rules live-matrix-verified on
// WinDivert 2.2/Win11: outbound re-injections and 127.0.0.1 destinations
// never deliver; inbound + real-address destination + client-NIC IfIdx +
// non-local source does.)
func (e *Engine) natOutbound(pkt []byte, p *pktInfo, key flowtable.FlowKey, f *flowtable.Flow, addr *windivert.Address) {
	// Remember the original destination exactly once per flow; re-saves are
	// idempotent because client packets always target the original server.
	// OrigPort == 0 marks "not yet registered": the map insert happens on
	// the first NAT rewrite only, keeping per-packet map operations off the
	// outbound hot path.
	first := f.OrigPort == 0
	f.OrigDst = v4mapped(p.dst4)
	f.OrigPort = p.dstPort

	// Capture the client-facing interface BEFORE mutating the address (the
	// reverse direction needs it; see natVal).
	var nicIfIdx, nicSubIfIdx uint32
	if na := addr.Network(); na != nil {
		nicIfIdx, nicSubIfIdx = na.IfIdx, na.SubIfIdx
	}

	// Full rewrite: source → the fake foreign IP (martian rule), kept
	// source port (the NAT key); destination → the packet's own source
	// address (the local host's address on this interface) and the port to
	// the tproxy.
	fake := fakeIP4()
	copy(pkt[12:16], fake[:])
	copy(pkt[16:20], p.src4[:])
	portOff := p.ipLen + 2 // TCP/UDP DstPort field
	binary.BigEndian.PutUint16(pkt[portOff:portOff+2], e.opts.TProxyPort)

	// Checksum-valid hints are stale now; FixChecksums recomputes both the
	// IP and the transport checksum (and refreshes the hint bits in addr).
	if err := e.transport.FixChecksums(pkt, addr); err != nil {
		e.sendErr()
	}
	// Deliver to the local listener: re-inject INBOUND on the same (client)
	// interface — the only combination the live matrix proved delivers.
	addr.SetOutbound(false)
	addr.SetLoopback(false)
	if first {
		nk := natKey{ip: v4mapped(fake), port: p.srcPort, proto: p.proto}
		e.natMu.Lock()
		e.nat[nk] = natVal{f: f, clientIP: p.src4, ifIdx: nicIfIdx, subIfIdx: nicSubIfIdx}
		e.natMu.Unlock()
	}
	e.cnt.tunnelTx.Add(1)
	e.cnt.countVerdict(core.VerdictRedirect)
	if err := e.natSend(pkt, addr); err != nil {
		e.sendFailed(err)
	} else {
		e.sendOK()
	}
}

// natSend re-injects a NAT-rewritten packet: through the loopback handle
// when the tunnel branch is up (its filter covers the rewritten inbound
// direction), else through the main handle (fake-transport tests).
func (e *Engine) natSend(pkt []byte, addr *windivert.Address) error {
	if e.loopTransport != nil {
		return e.loopTransport.Send(pkt, addr)
	}
	return e.transport.Send(pkt, addr)
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
		v, known := e.nat[nk]
		if !known {
			// Wave-5 NAT registers entries under the FAKE IP it presents
			// to the tproxy. A local dial that reaches the tproxy with the
			// client's REAL source (loopback test/fake-transport paths —
			// the production stack shows the fake IP as the remote) still
			// resolves: retry under the fake key, but only when the entry
			// was created for this exact client address (no false hits on
			// foreign traffic that happens to share the port).
			fk := natKey{ip: v4mapped(fakeIP4()), port: srcPort, proto: proto}
			fv, fknown := e.nat[fk]
			if fknown && fv.clientIP != ([4]byte{}) && v4mapped(fv.clientIP) == srcIP {
				v, known = fv, true
			}
		}
		e.natMu.RUnlock()
		if known {
			return v.f.OrigDst, v.f.OrigPort, true
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
	// The tproxy's replies carry the FAKE source as their destination (the
	// tproxy answers the connection it accepted from <natFakeIP>:eph).
	nk := natKey{ip: v4mapped(p.dst4), port: p.dstPort, proto: p.proto}
	e.natMu.RLock()
	v, known := e.nat[nk]
	e.natMu.RUnlock()
	if !known {
		// Not a flow we redirected (foreign traffic to the same port).
		e.passLoopback(t, pkt, addr)
		return
	}
	f := v.f

	// Reverse rewrite: source tproxyPort -> OrigDst:OrigPort and the
	// destination fakeIP -> the client's real address, so the client
	// believes it is talking to the real server.
	origIP := f.OrigDst
	copy(pkt[12:16], origIP[12:16])
	copy(pkt[16:20], v.clientIP[:])
	binary.BigEndian.PutUint16(pkt[p.ipLen:p.ipLen+2], f.OrigPort)
	if err := t.FixChecksums(pkt, addr); err != nil {
		e.sendErr()
	}
	// The captured leg is the reply's OUTBOUND leg; the client socket needs
	// the translated packet INBOUND, on the client-facing interface
	// recorded at NAT time (live matrix: inbound + client-NIC IfIdx with a
	// non-local source is the combination that delivers).
	addr.SetOutbound(false)
	addr.SetLoopback(false)
	if na := addr.Network(); na != nil && v.ifIdx != 0 {
		na.IfIdx, na.SubIfIdx = v.ifIdx, v.subIfIdx
	}
	e.cnt.tunnelRx.Add(1)
	if err := t.Send(pkt, addr); err != nil {
		e.sendFailed(err)
	} else {
		e.sendOK()
	}

	if p.isTCP() && (p.fin() || p.rst()) {
		e.cleanupFlow(nk, flowKeyOf(nk, v))
	}
}

func (e *Engine) passLoopback(t Transport, pkt []byte, addr *windivert.Address) {
	e.cnt.countVerdict(core.VerdictPass)
	if err := t.Send(pkt, addr); err != nil {
		e.sendFailed(err)
	} else {
		e.sendOK()
	}
}

// flowKeyOf reconstructs the client-side flow-table key of a NAT entry.
// The NAT key itself carries the FAKE IP, so the client's real address
// comes from the entry value.
func flowKeyOf(nk natKey, v natVal) flowtable.FlowKey {
	return flowtable.FlowKey{
		SrcIP: v4mapped(v.clientIP), SrcPort: nk.port,
		DstIP: v.f.OrigDst, DstPort: v.f.OrigPort,
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
