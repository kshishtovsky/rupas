package tunnel

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
)

// Enabling interception must not silently kill an already-established
// connection: its flow has no SYN in our table, capture consumed the packet,
// so the terminator owes the client a RST (which makes it re-dial) instead of
// swallowing the segment and every retransmit after it.
func TestStrayDataGetsRST(t *testing.T) {
	snd := &fakeTermSender{}
	tm := NewTerminator(snd, func(ctx context.Context, dst string) (net.Conn, error) {
		return nil, context.DeadlineExceeded
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer tm.Close()

	// A mid-stream segment of a connection opened before interception.
	p := TermPkt{SrcIP: [4]byte{10, 0, 0, 2}, DstIP: [4]byte{149, 154, 167, 51},
		SrcPort: 41000, DstPort: 443, Seq: 9000, Ack: 7000,
		Flags: termACK | termPSH, Window: 65535, Payload: []byte("hello world"),
		IfIdx: 7, SubIfIdx: 0}
	tm.Feed(p)

	pkts := snd.sent()
	if len(pkts) != 1 {
		t.Fatalf("got %d injections, want exactly one RST (stray segment must not be dropped silently)", len(pkts))
	}
	r := parseTerm(t, pkts[0])
	if r.flags&termRST == 0 || r.flags&termACK == 0 {
		t.Fatalf("flags = %#x, want RST|ACK", r.flags)
	}
	if r.src != p.DstIP || r.dst != p.SrcIP || r.sport != p.DstPort || r.dport != p.SrcPort {
		t.Fatalf("reset not addressed server->client: %v:%d -> %v:%d", r.src, r.sport, r.dst, r.dport)
	}
	// RFC 793: seq = the segment's ack, ack = its seq + payload length.
	if r.seq != p.Ack {
		t.Fatalf("seq = %d, want the segment's ack %d", r.seq, p.Ack)
	}
	if r.ack != p.Seq+uint32(len(p.Payload)) {
		t.Fatalf("ack = %d, want seq+len %d", r.ack, p.Seq+uint32(len(p.Payload)))
	}
	if !r.ipOK || !r.tcpOK {
		t.Fatal("forged reset has bad checksums")
	}
	if got := tm.Stats().StrayRST; got != 1 {
		t.Fatalf("StrayRST = %d, want 1", got)
	}

	// A pure ACK / keep-alive must be answered the same way, not swallowed.
	ack := p
	ack.Flags = termACK
	ack.Payload = nil
	tm.Feed(ack)
	if got := len(snd.sent()); got != 2 {
		t.Fatalf("injections = %d, want 2", got)
	}
}
