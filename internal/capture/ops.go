//go:build windows

package capture

import (
	"encoding/binary"

	"github.com/rupas/rupas/internal/core"
	"github.com/rupas/rupas/internal/desync"
	"github.com/rupas/rupas/pkg/windivert"
)

// applyDesync executes the desync engine's op list against the ClientHello
// segment and finishes the flow's desync verdict. Per SYSTEM_DESIGN §3.2 the
// order is: (a) inject fake(s) ×N ahead of the real data, (b) optionally
// split the real segment, (c) re-inject the original bytes last. Ops are
// consumed in slice order so the desync engine controls the strategy.
//
// The original packet is always forwarded exactly once: split into two
// segments when a SplitAt op is present, otherwise whole.
func (e *Engine) applyDesync(pkt []byte, p *pktInfo, addr *windivert.Address, sni []byte) {
	ops := e.desync.Actions(sni)
	e.cnt.countVerdict(core.VerdictDesync)
	split := false
	for _, op := range ops {
		switch o := op.(type) {
		case desync.InjectFake:
			e.injectFake(pkt, p, addr, o)
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

// impostorView returns a copy of addr with the Impostor flag set, marking a
// crafted (not stack-originated) packet on re-injection. pkg/windivert
// exposes no setter, so the flag byte is flipped in the 80-byte wire form.
func impostorView(a *windivert.Address) windivert.Address {
	raw := a.Raw()
	raw[10] |= 1 << 3 // Impostor: bit 3, LSB-first, of the flag byte
	out, err := windivert.ParseAddress(raw[:])
	if err != nil {
		return *a
	}
	return out
}

// injectFake builds and sends one fake ClientHello packet op.Count times:
// the original IP+TCP headers cloned from the live packet (bytes copied into
// a pooled scratch buffer), payload replaced with the desync engine's fake
// template, TTL lowered to op.TTL and the sequence number set to seq-1 so
// the fake precedes the real segment (the zapret-style SYN/seq fingerprint:
// the DPI sees the fake first; it must die at op.TTL hops before the real
// server while the client stack never accepts it).
func (e *Engine) injectFake(orig []byte, p *pktInfo, addr *windivert.Address, op desync.InjectFake) {
	tpl := e.fakeTpl
	hl := p.hdrLen()
	need := hl + len(tpl)
	buf := e.getScratch(need)
	copy(buf, orig[:hl])
	copy(buf[hl:], tpl)

	// IPv4: TTL (offset 8) and total length (offset 2).
	buf[8] = op.TTL
	binary.BigEndian.PutUint16(buf[2:4], uint16(need))
	// TCP: Seq = original seq - 1 (offset ipLen+4). ACK, window and flags
	// stay those of the live segment so the packet looks in-window.
	seqOff := p.ipLen + 4
	binary.BigEndian.PutUint32(buf[seqOff:seqOff+4], p.seq-1)

	// Crafted packet: mark as impostor, keep the outbound direction.
	fakeAddr := impostorView(addr)
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
	rest := len(p.payload) - int(off)
	buf := e.getScratch(hl + rest)
	copy(buf, orig[:hl])
	copy(buf[hl:], p.payload[off:])
	binary.BigEndian.PutUint16(buf[2:4], uint16(hl+rest))
	binary.BigEndian.PutUint32(buf[p.ipLen+4:p.ipLen+8], p.seq+off)
	part2Addr := impostorView(addr)
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
