//go:build windows

package capture

import (
	"encoding/binary"

	"github.com/rupas/rupas/internal/core"
	"github.com/rupas/rupas/internal/desync"
	"github.com/rupas/rupas/pkg/windivert"
)

// FAKE-INJECT TIMING DOCTRINE (wave 4A, fixed 2026-10-25; parity with the
// winws reference proven on-wire via tshark — see internal/app
// e2e_live_test.go and docs/SYSTEM_DESIGN §3.2/§5).
//
// The reference (zapret winws, --dpi-desync=fake --dpi-desync-ttl=T
// --dpi-desync-repeats=N) emits, in this exact order:
//
//	(pure ACKs pass) → fake ×N → real CH segment 1 → … → real CH segment k
//
// with every fake an exact header clone of the FIRST real CH segment:
// same seq (= client ISN+1), same ack (= server ISN+1), same window, same
// IP ID, same TCP flags; only the TTL is lowered and the payload is the
// fake template. Invariants for this engine:
//
//  1. FAKES STRICTLY FIRST. No real ClientHello byte may leave before the
//     last fake. Multi-segment CHs are therefore HELD (inspectClientHello)
//     and released only after the InjectFake ops ran. A fake that trails
//     the real CH is decorative: the DPI has already latched onto the real
//     SNI and the blackhole triggers.
//  2. SEQ/ACK NEVER SHIFTED. The fake keeps the first segment's seq/ack
//     verbatim. A shifted seq (the old `seq-1` heuristic) lands outside the
//     DPI's expected next-sequence window, so the DPI discards the fake and
//     parses the real CH unopposed (live wave-3 failure: desync=1, handshake
//     blocked; winws 3/3 OK on the same channel).
//  3. ONLY TTL/PAYLOAD/LENGTH/CKSUM DIFFER from the cloned segment, so the
//     fake dies at the calibrated hop count before the server while the
//     DPI — which sees a perfectly in-stream ClientHello — latches onto the
//     fake payload and treats the real CH as a duplicate/retransmission.
//  4. NO IMPOSTOR FLAG ON CRAFTED SENDS. WinDivert treats an impostor-
//     flagged injection as a TRANSIT (forwarded) packet and the Windows
//     stack decrements its TTL by one (live-measured: sent TTL 33, wire 32;
//     engine fakes sent with TTL 12 egressed as 11 and died one hop short
//     of the TSPU, so the DPI never saw them). Crafted packets are sent
//     with the captured address verbatim; checksums are fixed beforehand.
//  5. CRAFTED PACKETS USE THE SYNTHETIC rawsend ADDRESS (fakeSendAddr):
//     zeroed, Outbound, IfIdx from the capture, all checksum-valid flags
//     SET, checksums precomputed into the bytes. Sending a crafted packet
//     with the CAPTURED address inherits its offload-pending checksum
//     state (TCP checksum never computed on the wire) — live-observed as
//     fakes dying at the first hop and a hard blackhole of the flow while
//     the byte-identical winws reference punches through (zapret
//     darkmagic.c rawsend builds exactly this synthetic address).
//
// applyDesync executes the desync engine's op list against the ClientHello
// flow: (a) fake(s) ×N built from the first (held) real segment, (b) the
// held earlier segments released in order, (c) the completing segment —
// split in two when a SplitAt op is present. Ops are consumed in slice
// order so the desync engine controls the strategy.
//
// The original bytes are always forwarded exactly once: held segments via
// releaseHeld, the completing segment below.
func (e *Engine) applyDesync(pkt []byte, p *pktInfo, addr *windivert.Address, sni []byte, held *chHold) {
	ops := e.desync.Actions(sni)
	e.cnt.countVerdict(core.VerdictDesync)
	// The fake's header base: the FIRST real CH segment (held when the CH
	// spans multiple segments; the completing segment itself otherwise).
	base, baseAddr := pkt, addr
	if held != nil && held.n > 0 {
		base, baseAddr = held.seg(0), &held.addr[0]
	}
	split := false
	for _, op := range ops {
		switch o := op.(type) {
		case desync.InjectFake:
			e.injectFake(base, baseAddr, o)
		case desync.SplitAt:
			if !split {
				e.sendSplit(pkt, p, addr, o.Offset)
				split = true
			}
		default:
			// Unknown op from a newer desync engine: ignore, the original
			// is still forwarded below.
		}
	}
	e.releaseHeld(held)
	if !split {
		e.sendPkt(pkt, addr)
	}
}

// sendPkt re-injects pkt without verdict accounting (used for crafted or
// already-counted packets).
func (e *Engine) sendPkt(pkt []byte, addr *windivert.Address) {
	if err := e.transport.Send(pkt, addr); err != nil {
		e.cnt.sendErrors.Add(1)
	}
}

// fakeSendAddr builds the synthetic WinDivert address zapret's rawsend
// uses for crafted packets (winws parity, darkmagic.c rawsend): a ZEROED
// address with Outbound set, every checksum-valid flag SET (the fake's
// checksums are precomputed into the bytes — claiming validity makes the
// driver emit them verbatim instead of treating them as offload-pending),
// and the captured packet's interface. Reusing the CAPTURED address for a
// crafted packet leaves its checksum flags offload-pending, and this
// WinDivert build then sends garbage checksums — live-observed as every
// fake dying at the first hop (total blackhole while byte-identical winws
// fakes punch through). No allocation: value copy, flags flipped in place.
func fakeSendAddr(captured *windivert.Address) windivert.Address {
	a := windivert.Address{}
	a.Layer = captured.Layer
	a.SetOutbound(true)
	a.SetIPChecksum(true)
	a.SetTCPChecksum(true)
	a.SetUDPChecksum(true)
	na, ca := a.Network(), captured.Network()
	na.IfIdx, na.SubIfIdx = ca.IfIdx, ca.SubIfIdx
	return a
}

// injectFake builds and sends one fake ClientHello packet op.Count times.
// base is the FIRST real ClientHello segment: its IP+TCP headers are cloned
// into a pooled scratch buffer, the payload is replaced with the desync
// engine's fake template, the TTL lowered to op.TTL and the IP total length
// rewritten. seq/ack/window/flags/IP ID stay verbatim — winws parity; see
// the doctrine block above for why the seq must NOT be shifted. The fake
// must die at op.TTL hops before the real server while the client stack
// never sees it (outbound injection only).
func (e *Engine) injectFake(base []byte, addr *windivert.Address, op desync.InjectFake) {
	hl := len(base)
	if p, ok := parsePkt(base); ok {
		hl = p.hdrLen()
	}
	need := hl + len(e.fakeTpl)
	buf := e.getScratch(need)
	copy(buf, base[:hl])
	copy(buf[hl:], e.fakeTpl)

	// IPv4: TTL (offset 8) and total length (offset 2). Everything else —
	// seq, ack, window, flags, IP ID, DF — is the live segment's own
	// value, exactly as the reference does it.
	buf[8] = op.TTL
	binary.BigEndian.PutUint16(buf[2:4], uint16(need))

	// Crafted packet: checksums precomputed into the bytes, synthetic
	// send address claiming them valid (see fakeSendAddr).
	fakeAddr := fakeSendAddr(addr)
	if err := e.transport.FixChecksums(buf, &fakeAddr); err != nil {
		e.cnt.sendErrors.Add(1)
		e.putScratch(buf)
		return
	}
	for i := 0; i < op.Count; i++ {
		if err := e.transport.Send(buf, &fakeAddr); err != nil {
			e.cnt.sendErrors.Add(1)
			break
		}
	}
	e.putScratch(buf)
}

// sendSplit cuts the ClientHello segment at payload byte offset off and
// sends the two halves as independent TCP segments: the first off payload
// bytes as a truncated view of the original packet (only IP total length and
// checksums rewritten), the remainder as a new packet with cloned headers
// and the sequence number advanced by off.
//
// The TCP window field is deliberately left untouched: the advertised window
// is a property of the connection's socket buffer, not of the segment, and
// rewriting it would corrupt flow control.
func (e *Engine) sendSplit(orig []byte, p *pktInfo, addr *windivert.Address, off uint32) {
	if int(off) <= 0 || int(off) >= len(p.payload) {
		return // degenerate split: nothing to do
	}
	hl := p.hdrLen()

	// Part 1: first off payload bytes. The original batch buffer is edited
	// in place — it is fully re-initialized by the next RecvBatch reset.
	part1Len := hl + int(off)
	binary.BigEndian.PutUint16(orig[2:4], uint16(part1Len))
	if err := e.transport.FixChecksums(orig[:part1Len], addr); err != nil {
		e.cnt.sendErrors.Add(1)
		return
	}
	if err := e.transport.Send(orig[:part1Len], addr); err != nil {
		e.cnt.sendErrors.Add(1)
		return
	}

	// Part 2: cloned headers + payload[off:], sequence advanced by off.
	// Crafted packet → synthetic send address (fakeSendAddr: checksum
	// flags valid, no impostor — doctrine #4/#5).
	rest := len(p.payload) - int(off)
	buf := e.getScratch(hl + rest)
	copy(buf, orig[:hl])
	copy(buf[hl:], p.payload[off:])
	binary.BigEndian.PutUint16(buf[2:4], uint16(hl+rest))
	binary.BigEndian.PutUint32(buf[p.ipLen+4:p.ipLen+8], p.seq+off)
	part2Addr := fakeSendAddr(addr)
	if err := e.transport.FixChecksums(buf, &part2Addr); err != nil {
		e.cnt.sendErrors.Add(1)
		e.putScratch(buf)
		return
	}
	if err := e.transport.Send(buf, &part2Addr); err != nil {
		e.cnt.sendErrors.Add(1)
	}
	e.putScratch(buf)
}
