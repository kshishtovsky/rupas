package tunnel

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeTermSender records forged inbound packets.
type fakeTermSender struct {
	mu     sync.Mutex
	pkts   [][]byte
	ifIdx  []uint32
}

func (s *fakeTermSender) SendInboundTCP(pkt []byte, ifIdx, subIfIdx uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := make([]byte, len(pkt))
	copy(b, pkt)
	s.pkts = append(s.pkts, b)
	s.ifIdx = append(s.ifIdx, ifIdx)
	return nil
}

func (s *fakeTermSender) sent() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]byte, len(s.pkts))
	copy(out, s.pkts)
	return out
}

type parsedTerm struct {
	src, dst         [4]byte
	sport, dport     uint16
	seq, ack         uint32
	flags            byte
	win              uint16
	mss              uint16
	hasMSS           bool
	payload          []byte
	ipOK, tcpOK      bool
}

func parseTerm(t *testing.T, pkt []byte) parsedTerm {
	t.Helper()
	var p parsedTerm
	if len(pkt) < 40 || pkt[0]>>4 != 4 || pkt[9] != 6 {
		t.Fatalf("not IPv4/TCP: % x", pkt[:min(len(pkt), 20)])
	}
	copy(p.src[:], pkt[12:16])
	copy(p.dst[:], pkt[16:20])
	// A correct checksum makes the one's-complement sum over the whole
	// header come out 0xFFFF → ^sum == 0.
	hdr := append([]byte(nil), pkt[:20]...)
	p.ipOK = ipChecksum(hdr) == 0
	ipLen := int(pkt[0]&0x0f) * 4
	tcp := pkt[ipLen:]
	p.sport = binary.BigEndian.Uint16(tcp[0:2])
	p.dport = binary.BigEndian.Uint16(tcp[2:4])
	p.seq = binary.BigEndian.Uint32(tcp[4:8])
	p.ack = binary.BigEndian.Uint32(tcp[8:12])
	p.win = binary.BigEndian.Uint16(tcp[14:16])
	p.flags = tcp[13]
	off := int(tcp[12] >> 4)
	if off < 5 {
		off = 5
	}
	// TCP checksum over pseudo-header (checksum field zeroed in the copy).
	var pseudo [12]byte
	copy(pseudo[0:4], pkt[12:16])
	copy(pseudo[4:8], pkt[16:20])
	pseudo[8] = 6
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(pkt)-ipLen))
	sums := append(pseudo[:], tcp[:]...)
	saved := binary.BigEndian.Uint16(tcp[16:18])
	binary.BigEndian.PutUint16(sums[12+16:12+18], 0)
	p.tcpOK = saved != 0 && ipChecksum(sums) == saved
	if off*4 > 20 && off*4 <= len(tcp) {
		opts := tcp[20 : off*4-0]
		for i := 0; i+3 < len(opts); {
			if opts[i] == 2 && opts[i+1] == 4 {
				p.hasMSS, p.mss = true, binary.BigEndian.Uint16(opts[i+2:i+4])
			}
			if opts[i] == 0 { // EOL
				break
			}
			l := int(opts[i+1])
			if l < 1 {
				break
			}
			i += l
		}
	}
	if off*4 <= len(tcp) {
		p.payload = tcp[off*4:]
	}
	return p
}

var (
	termClient = [4]byte{192, 168, 1, 10}
	termTG     = [4]byte{149, 154, 167, 51}
)

func termFeed(tm *Terminator, flags byte, seq, ack uint32, payload []byte) {
	tm.Feed(TermPkt{
		SrcIP: termClient, DstIP: termTG,
		SrcPort: 51000, DstPort: 443,
		Seq: seq, Ack: ack, Flags: flags, Window: 0xFFFF,
		Payload: payload, IfIdx: 4,
	})
}

func TestTerminatorHandshakeAndRelay(t *testing.T) {
	sender := &fakeTermSender{}
	clientEnd, serverEnd := net.Pipe()
	dialed := make(chan struct{})
	dial := func(ctx context.Context, dst string) (net.Conn, error) {
		close(dialed)
		return serverEnd, nil
	}
	tm := NewTerminator(sender, dial, nil)
	defer tm.Close()

	// 1. SYN → forged SYN-ACK.
	termFeed(tm, termSYN, 1000, 0, nil)
	time.Sleep(50 * time.Millisecond)
	sent := sender.sent()
	if len(sent) != 1 {
		t.Fatalf("sent %d after SYN, want 1 (SYN-ACK)", len(sent))
	}
	sa := parseTerm(t, sent[0])
	if !sa.ipOK || !sa.tcpOK {
		t.Fatalf("SYN-ACK checksums bad: ip=%v tcp=%v", sa.ipOK, sa.tcpOK)
	}
	if sa.src != termTG || sa.dst != termClient || sa.sport != 443 || sa.dport != 51000 {
		t.Fatalf("SYN-ACK tuple flipped: %+v", sa)
	}
	if sa.flags != termSYN|termACK || sa.ack != 1001 {
		t.Fatalf("SYN-ACK flags/ack: %02x ack=%d", sa.flags, sa.ack)
	}
	if !sa.hasMSS || sa.mss != termMSS {
		t.Fatalf("SYN-ACK MSS option missing: %+v", sa)
	}
	if sender.ifIdx[0] != 4 {
		t.Fatalf("SYN-ACK ifIdx = %d, want 4 (captured leg)", sender.ifIdx[0])
	}
	serverISN := sa.seq

	select {
	case <-dialed:
	case <-time.After(2 * time.Second):
		t.Fatal("carrier dial never started")
	}

	// 2. Handshake ACK + client data → payload reaches the carrier,
	//    terminator ACKs.
	termFeed(tm, termACK, 1001, serverISN+1, nil)
	termFeed(tm, termACK|termPSH, 1001, serverISN+1, []byte("MTProto-hello"))
	go func() {
		buf := make([]byte, 64)
		n, err := clientEnd.Read(buf) // the carrier-side end of the pipe
		if err != nil {
			return
		}
		if string(buf[:n]) != "MTProto-hello" {
			t.Errorf("carrier got %q", buf[:n])
		}
	}()
	sent = sender.sent()
	// SYN-ACK + ACK (for the data); the handshake ACK emits nothing.
	var dataACK parsedTerm
	found := false
	for _, p := range sent[1:] {
		pp := parseTerm(t, p)
		if pp.flags == termACK && pp.ack == 1001+13 && len(pp.payload) == 0 {
			dataACK, found = pp, true
		}
	}
	if !found {
		t.Fatalf("no ACK for the client data segment: %d packets", len(sent))
	}
	_ = dataACK

	// 3. Carrier reply → forged data segment with correct seq.
	go func() {
		_, _ = clientEnd.Write([]byte("server-reply"))
	}()
	deadline := time.Now().Add(3 * time.Second)
	var reply parsedTerm
	for time.Now().Before(deadline) {
		for _, p := range sender.sent() {
			pp := parseTerm(t, p)
			if len(pp.payload) > 0 && string(pp.payload) == "server-reply" {
				reply = pp
			}
		}
		if reply.payload != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if reply.payload == nil {
		t.Fatal("carrier reply never forged")
	}
	if reply.seq != serverISN+1 || reply.ack != 1014 {
		t.Fatalf("reply seq/ack = %d/%d, want %d/1014", reply.seq, reply.ack, serverISN+1)
	}

	// 4. Client ACKs the reply, then FIN → upstream closed, our FIN sent.
	termFeed(tm, termACK, 1014, reply.seq+uint32(len(reply.payload)), nil)
	termFeed(tm, termACK|termFIN, 1014, reply.seq+uint32(len(reply.payload)), nil)
	// pumpReads gets EOF (clientEnd closed via Close on FIN path) and FINs.
	time.Sleep(200 * time.Millisecond)
	var ourFIN parsedTerm
	for _, p := range sender.sent() {
		pp := parseTerm(t, p)
		if pp.flags&termFIN != 0 && pp.flags&termACK != 0 {
			ourFIN = pp
		}
	}
	if ourFIN.flags == 0 {
		t.Fatal("terminator FIN never sent")
	}
	// 5. Client ACKs our FIN → connection fully closed.
	termFeed(tm, termACK, 1015, ourFIN.seq+1, nil)
	time.Sleep(100 * time.Millisecond)
}

func TestTerminatorDialFailureRSTs(t *testing.T) {
	sender := &fakeTermSender{}
	dial := func(ctx context.Context, dst string) (net.Conn, error) {
		return nil, context.DeadlineExceeded
	}
	tm := NewTerminator(sender, dial, nil)
	defer tm.Close()

	termFeed(tm, termSYN, 2000, 0, nil)
	deadline := time.Now().Add(3 * time.Second)
	var rst parsedTerm
	for time.Now().Before(deadline) && rst.flags == 0 {
		for _, p := range sender.sent() {
			pp := parseTerm(t, p)
			if pp.flags&termRST != 0 {
				rst = pp
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if rst.flags == 0 {
		t.Fatal("no RST after dial failure")
	}
	if rst.ack != 2001 {
		t.Fatalf("RST ack = %d, want 2001", rst.ack)
	}
}

// TestTerminatorRSTFreesTuple: a killed (client RST) conn must leave the
// table, so the client's retried SYN on the SAME 4-tuple is answered with a
// fresh SYN-ACK instead of hitting the dead entry and being swallowed.
func TestTerminatorRSTFreesTuple(t *testing.T) {
	sender := &fakeTermSender{}
	dialed := make(chan struct{}, 1)
	dial := func(ctx context.Context, dst string) (net.Conn, error) {
		c, s := net.Pipe()
		_ = c.Close()
		select {
		case dialed <- struct{}{}:
		default:
		}
		return s, nil
	}
	tm := NewTerminator(sender, dial, nil)
	defer tm.Close()

	countSynACK := func() int {
		n := 0
		for _, p := range sender.sent() {
			if pp := parseTerm(t, p); pp.flags == termSYN|termACK {
				n++
			}
		}
		return n
	}

	termFeed(tm, termSYN, 4000, 0, nil)
	select {
	case <-dialed:
	case <-time.After(2 * time.Second):
		t.Fatal("carrier dial never started")
	}
	if n := countSynACK(); n != 1 {
		t.Fatalf("SYN-ACKs after first SYN = %d, want 1", n)
	}

	// Client RST: kills the conn and must drop it from the table.
	termFeed(tm, termRST, 4001, 0, nil)
	if n := tm.Stats().Conns; n != 0 {
		t.Fatalf("conns after client RST = %d, want 0 (dead conn left in the table)", n)
	}

	// Retried SYN, same source port: a new conn must answer.
	termFeed(tm, termSYN, 5000, 0, nil)
	if n := countSynACK(); n != 2 {
		t.Fatalf("SYN-ACKs after retried SYN = %d, want 2 (retry swallowed by a dead conn)", n)
	}
}

func TestTerminatorWindowBlocksUntilACK(t *testing.T) {
	sender := &fakeTermSender{}
	clientEnd, serverEnd := net.Pipe()
	defer clientEnd.Close()
	dial := func(ctx context.Context, dst string) (net.Conn, error) { return serverEnd, nil }
	tm := NewTerminator(sender, dial, nil)
	defer tm.Close()

	termFeed(tm, termSYN, 3000, 0, nil)
	time.Sleep(50 * time.Millisecond)
	sent := sender.sent()
	if len(sent) == 0 {
		t.Fatal("no SYN-ACK")
	}
	sa := parseTerm(t, sent[0])
	// Handshake + one tiny window.
	termFeed(tm, termACK, 3001, sa.seq+1, nil)
	// Advertise a 10-byte window.
	termFeed(tm, termACK, 3001, sa.seq+1, nil)

	// Carrier sends 30 bytes: only segments that fit the advertised window
	// may be forged. We simulate a small window by feeding a window update.
	tm.Feed(TermPkt{
		SrcIP: termClient, DstIP: termTG, SrcPort: 51000, DstPort: 443,
		Seq: 3001, Ack: sa.seq + 1, Flags: termACK, Window: 10,
		Payload: nil, IfIdx: 4,
	})
	go func() {
		_, _ = clientEnd.Write(make([]byte, 30))
	}()
	time.Sleep(300 * time.Millisecond)
	total := 0
	for _, p := range sender.sent() {
		pp := parseTerm(t, p)
		total += len(pp.payload)
	}
	if total > 10 {
		t.Fatalf("forged %d payload bytes against a 10-byte window", total)
	}
	// Window opens (client ACK + larger window): the rest flows.
	tm.Feed(TermPkt{
		SrcIP: termClient, DstIP: termTG, SrcPort: 51000, DstPort: 443,
		Seq: 3001, Ack: sa.seq + 1 + uint32(total), Flags: termACK, Window: 0xFFFF,
		Payload: nil, IfIdx: 4,
	})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		total = 0
		for _, p := range sender.sent() {
			pp := parseTerm(t, p)
			total += len(pp.payload)
		}
		if total == 30 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("window never drained: %d/30 bytes", total)
}

// TestTerminatorDupDataACKedOnce: a retransmitted in-flight segment is
// re-ACKed but its payload is NOT delivered twice.
func TestTerminatorDupDataACKedOnce(t *testing.T) {
	sender := &fakeTermSender{}
	clientEnd, serverEnd := net.Pipe()
	defer clientEnd.Close()
	got := make(chan int, 16)
	go func() {
		buf := make([]byte, 256)
		for {
			n, err := clientEnd.Read(buf)
			if err != nil {
				if err != io.EOF {
					return
				}
			}
			if n > 0 {
				got <- n
			}
			if err != nil {
				return
			}
		}
	}()
	dial := func(ctx context.Context, dst string) (net.Conn, error) { return serverEnd, nil }
	tm := NewTerminator(sender, dial, nil)
	defer tm.Close()

	termFeed(tm, termSYN, 4000, 0, nil)
	time.Sleep(50 * time.Millisecond)
	sa := parseTerm(t, sender.sent()[0])
	termFeed(tm, termACK, 4001, sa.seq+1, nil)
	termFeed(tm, termACK|termPSH, 4001, sa.seq+1, []byte("once"))
	termFeed(tm, termACK|termPSH, 4001, sa.seq+1, []byte("once")) // dup retransmit
	time.Sleep(300 * time.Millisecond)

	total := 0
	for range 2 {
		select {
		case n := <-got:
			total += n
		case <-time.After(500 * time.Millisecond):
		}
	}
	if total != 4 {
		t.Fatalf("carrier received %d bytes, want 4 (dup dropped)", total)
	}
	// And the dup got re-ACKed.
	acks := 0
	for _, p := range sender.sent() {
		pp := parseTerm(t, p)
		if pp.flags == termACK && pp.ack == 4005 {
			acks++
		}
	}
	if acks < 2 {
		t.Fatalf("dup segment re-ACKed %d times, want ≥2", acks)
	}
}

// TestTerminatorReorderDeliversInOrder: out-of-order arrivals (1,3,2) must
// reach the carrier as 1,2,3 — a segment ahead of a sequence hole is
// buffered until the gap closes, not silently dropped (the old code
// truncated upload streams at the first retransmit).
func TestTerminatorReorderDeliversInOrder(t *testing.T) {
	sender := &fakeTermSender{}
	clientEnd, serverEnd := net.Pipe()
	defer clientEnd.Close()
	dial := func(ctx context.Context, dst string) (net.Conn, error) { return serverEnd, nil }
	tm := NewTerminator(sender, dial, nil)
	defer tm.Close()

	readDone := make(chan []byte, 1)
	go func() {
		var acc []byte
		buf := make([]byte, 64)
		for len(acc) < 12 {
			n, err := clientEnd.Read(buf)
			if n > 0 {
				acc = append(acc, buf[:n]...)
			}
			if err != nil {
				break
			}
		}
		readDone <- acc
	}()

	termFeed(tm, termSYN, 5000, 0, nil)
	time.Sleep(50 * time.Millisecond)
	sa := parseTerm(t, sender.sent()[0])
	termFeed(tm, termACK, 5001, sa.seq+1, nil)
	// Segment 1, then 3 (hole at 2, plus a dup of it), then 2 (closes
	// the gap and must flush the backlog in order).
	termFeed(tm, termACK|termPSH, 5001, sa.seq+1, []byte("AAAA"))
	termFeed(tm, termACK|termPSH, 5001+8, sa.seq+1, []byte("CCCC"))
	termFeed(tm, termACK|termPSH, 5001+8, sa.seq+1, []byte("CCCC")) // dup of buffered
	termFeed(tm, termACK|termPSH, 5001+4, sa.seq+1, []byte("BBBB"))

	select {
	case acc := <-readDone:
		if string(acc) != "AAAABBBBCCCC" {
			t.Fatalf("carrier got %q, want %q", acc, "AAAABBBBCCCC")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reordered data never reached the carrier")
	}
	// No RST: reordering must not tear the flow down.
	for _, p := range sender.sent() {
		if pp := parseTerm(t, p); pp.flags&termRST != 0 {
			t.Fatal("connection was reset by out-of-order data")
		}
	}
}

// TestTerminatorBurstBeyondQueueSurvives: a burst deeper than the relay
// queue (128 segments) must neither kill the connection nor lose data.
// Deferred segments come back via the client's retransmit (dup-ack
// backpressure) — the old code reset the flow on queue overflow.
func TestTerminatorBurstBeyondQueueSurvives(t *testing.T) {
	const (
		segs   = 200 // > writeCh cap (128)
		segLen = 100
	)
	sender := &fakeTermSender{}
	clientEnd, serverEnd := net.Pipe()
	defer clientEnd.Close()
	dial := func(ctx context.Context, dst string) (net.Conn, error) { return serverEnd, nil }
	tm := NewTerminator(sender, dial, nil)
	defer tm.Close()

	readDone := make(chan []byte, 1)
	go func() {
		acc := make([]byte, 0, segs*segLen)
		buf := make([]byte, 4096)
		for len(acc) < segs*segLen {
			n, err := clientEnd.Read(buf)
			if n > 0 {
				acc = append(acc, buf[:n]...)
			}
			if err != nil {
				break
			}
		}
		readDone <- acc
	}()

	termFeed(tm, termSYN, 6000, 0, nil)
	time.Sleep(50 * time.Millisecond)
	sa := parseTerm(t, sender.sent()[0])
	termFeed(tm, termACK, 6001, sa.seq+1, nil)

	type seg struct {
		seq  uint32
		data []byte
	}
	pending := make([]seg, 0, segs)
	for i := 0; i < segs; i++ {
		d := make([]byte, segLen)
		binary.BigEndian.PutUint16(d, uint16(i)) // marker for integrity check
		pending = append(pending, seg{seq: uint32(6001 + i*segLen), data: d})
	}

	// Feed the burst; whatever the terminator did not consume (queue full
	// → no ACK) is retransmitted, like a real stack would.
	deadline := time.Now().Add(15 * time.Second)
	for len(pending) > 0 && time.Now().Before(deadline) {
		for _, s := range pending {
			termFeed(tm, termACK|termPSH, s.seq, sa.seq+1, s.data)
		}
		time.Sleep(100 * time.Millisecond)
		high := uint32(6001)
		for _, p := range sender.sent() {
			pp := parseTerm(t, p)
			if pp.flags&termACK != 0 && int32(pp.ack-high) > 0 {
				high = pp.ack
			}
		}
		kept := pending[:0]
		for _, s := range pending {
			if int32(high-s.seq) <= 0 {
				kept = append(kept, s)
			}
		}
		pending = kept
	}
	if len(pending) > 0 {
		t.Fatalf("%d segments never ACKed under backpressure", len(pending))
	}
	for _, p := range sender.sent() {
		if pp := parseTerm(t, p); pp.flags&termRST != 0 {
			t.Fatal("connection was reset by the queue burst")
		}
	}
	var acc []byte
	select {
	case acc = <-readDone:
	case <-time.After(5 * time.Second):
		t.Fatal("carrier never received the full burst")
	}
	if len(acc) != segs*segLen {
		t.Fatalf("carrier got %d bytes, want %d", len(acc), segs*segLen)
	}
	for i := 0; i < segs; i++ {
		chunk := acc[i*segLen : (i+1)*segLen]
		if binary.BigEndian.Uint16(chunk) != uint16(i) {
			t.Fatalf("chunk %d corrupt or out of order: % x", i, chunk[:8])
		}
	}
}

// TestTerminatorDialWaitCoversCarrierDialTimeout: the terminator must not
// give up on the carrier dial before the carrier's own DefaultDialTimeout
// does — a shorter deadline reset clients on slow (but legitimate) VLESS
// connects.
func TestTerminatorDialWaitCoversCarrierDialTimeout(t *testing.T) {
	if dialWait < DefaultDialTimeout {
		t.Fatalf("dialWait (%v) < DefaultDialTimeout (%v): the terminator resets the client before the carrier dial can time out", dialWait, DefaultDialTimeout)
	}
}

// termConnOf returns the single live terminator connection (test helper).
func termConnOf(tm *Terminator) *termConn {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	for _, c := range tm.conns {
		return c
	}
	return nil
}

// TestTerminatorHoleDupAcksFastRetransmit: a sequence hole followed by
// future segments must draw one dup-ACK per NEW out-of-order segment
// (deduplicated for retransmits of already-buffered ones) — three dup-ACKs
// in a row make the client fast-retransmit the hole within an RTT instead
// of waiting out its RTO. After the hole arrives, everything must reach
// the carrier in order.
func TestTerminatorHoleDupAcksFastRetransmit(t *testing.T) {
	sender := &fakeTermSender{}
	clientEnd, serverEnd := net.Pipe()
	defer clientEnd.Close()
	dial := func(ctx context.Context, dst string) (net.Conn, error) { return serverEnd, nil }
	tm := NewTerminator(sender, dial, nil)
	defer tm.Close()

	readDone := make(chan []byte, 1)
	go func() {
		var acc []byte
		buf := make([]byte, 64)
		for len(acc) < 16 {
			n, err := clientEnd.Read(buf)
			if n > 0 {
				acc = append(acc, buf[:n]...)
			}
			if err != nil {
				break
			}
		}
		readDone <- acc
	}()

	termFeed(tm, termSYN, 7000, 0, nil)
	time.Sleep(50 * time.Millisecond)
	sa := parseTerm(t, sender.sent()[0])
	termFeed(tm, termACK, 7001, sa.seq+1, nil)

	countDupAcks := func() int {
		n := 0
		for _, p := range sender.sent() {
			pp := parseTerm(t, p)
			if pp.flags == termACK && pp.ack == 7001 && len(pp.payload) == 0 {
				n++
			}
		}
		return n
	}

	// Hole at 7001; three future segments behind it.
	termFeed(tm, termACK|termPSH, 7005, sa.seq+1, []byte("CCCC"))
	termFeed(tm, termACK|termPSH, 7009, sa.seq+1, []byte("DDDD"))
	termFeed(tm, termACK|termPSH, 7013, sa.seq+1, []byte("EEEE"))
	if n := countDupAcks(); n < 3 {
		t.Fatalf("3 future segments drew %d dup-ACKs, want ≥3", n)
	}

	// Retransmit of an already-buffered segment: deduplicated — no
	// extra dup-ACK (at most one per NEW out-of-order segment).
	before := countDupAcks()
	termFeed(tm, termACK|termPSH, 7009, sa.seq+1, []byte("DDDD"))
	if n := countDupAcks(); n != before {
		t.Fatalf("buffered retransmit drew an extra dup-ACK (%d → %d), want dedup", before, n)
	}
	if c := termConnOf(tm); c == nil || c.dupAckN.Load() != uint64(before) {
		t.Fatalf("dupAckN = %d, want %d", termConnOf(tm).dupAckN.Load(), before)
	}

	// The hole arrives: fast retransmit path closes the gap and the
	// whole backlog must reach the carrier in order.
	termFeed(tm, termACK|termPSH, 7001, sa.seq+1, []byte("BBBB"))
	select {
	case acc := <-readDone:
		if string(acc) != "BBBBCCCCDDDDEEEE" {
			t.Fatalf("carrier got %q, want %q", acc, "BBBBCCCCDDDDEEEE")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("data never reached the carrier after the hole closed")
	}
	for _, p := range sender.sent() {
		if pp := parseTerm(t, p); pp.flags&termRST != 0 {
			t.Fatal("connection was reset by the hole/reorder sequence")
		}
	}
}

// TestTerminatorEvictionSendsDupAck: overflowing the reorder buffer evicts
// the oldest (never-ACKed) segment and must fire a dup-ACK immediately, so
// the client fast-retransmits it after one RTT instead of one RTO.
func TestTerminatorEvictionSendsDupAck(t *testing.T) {
	if oooSegLimit != 512 || oooByteLimit != 2<<20 {
		t.Fatalf("reorder buffer limits = %d segs / %d bytes, want 512 / 2MB", oooSegLimit, oooByteLimit)
	}
	sender := &fakeTermSender{}
	clientEnd, serverEnd := net.Pipe()
	defer clientEnd.Close()
	dial := func(ctx context.Context, dst string) (net.Conn, error) { return serverEnd, nil }
	tm := NewTerminator(sender, dial, nil)
	defer tm.Close()

	termFeed(tm, termSYN, 8000, 0, nil)
	time.Sleep(50 * time.Millisecond)
	sa := parseTerm(t, sender.sent()[0])
	termFeed(tm, termACK, 8001, sa.seq+1, nil)

	// Hole at 8001; fill the buffer with one-byte future segments and
	// push one past the limit (512) → the oldest is evicted.
	const total = oooSegLimit + 1
	for i := 1; i <= total; i++ {
		termFeed(tm, termACK|termPSH, uint32(8001+i), sa.seq+1, []byte{byte(i)})
	}
	c := termConnOf(tm)
	if c == nil {
		t.Fatal("no terminator connection")
	}
	if drops := c.oooDropN.Load(); drops < 1 {
		t.Fatalf("oooDropN = %d after %d future segments, want ≥1 eviction", drops, total)
	}
	if n := c.dupAckN.Load(); n != total {
		t.Fatalf("dupAckN = %d, want %d (one dup-ACK per new out-of-order segment)", n, total)
	}
	// The last packet is the dup-ACK for the evicting segment.
	sent := sender.sent()
	last := parseTerm(t, sent[len(sent)-1])
	if last.flags != termACK || last.ack != 8001 {
		t.Fatalf("last packet after eviction = flags %02x ack %d, want bare ACK 8001", last.flags, last.ack)
	}
	for _, p := range sent {
		if pp := parseTerm(t, p); pp.flags&termRST != 0 {
			t.Fatal("connection was reset by the reorder-buffer overflow")
		}
	}
}

// ---------------------------------------------------------------------------
// receive-window flow control (live upload finding 2026-10-25)
// ---------------------------------------------------------------------------

// TestTerminatorAdvertisesRealWindow: with the carrier blocked (nobody
// reads the pipe, so pumpWrites cannot drain) every fed byte must be
// charged against the advertised window: win == recvBufCap - queued, and
// a full buffer closes the window to zero — the point where a real
// client throttles itself instead of overflowing our buffers.
func TestTerminatorAdvertisesRealWindow(t *testing.T) {
	sender := &fakeTermSender{}
	clientEnd, serverEnd := net.Pipe()
	defer clientEnd.Close()
	dial := func(ctx context.Context, dst string) (net.Conn, error) { return serverEnd, nil }
	tm := NewTerminator(sender, dial, nil)
	defer tm.Close()

	termFeed(tm, termSYN, 9000, 0, nil)
	time.Sleep(50 * time.Millisecond)
	sa := parseTerm(t, sender.sent()[0])
	if sa.win != termWindow {
		t.Fatalf("SYN-ACK window = %d, want %d", sa.win, termWindow)
	}
	termFeed(tm, termACK, 9001, sa.seq+1, nil)

	const segLen = 1000
	feedSeg := func(i int) {
		termFeed(tm, termACK|termPSH, uint32(9001+i*segLen), sa.seq+1, make([]byte, segLen))
	}
	checkWin := func(queuedSegs int) {
		t.Helper()
		ack := parseTerm(t, sender.sent()[len(sender.sent())-1])
		want := uint64(recvBufCap) - uint64(queuedSegs*segLen)
		if want < 0 {
			want = 0
		}
		if uint64(ack.win) != want {
			t.Fatalf("after %d queued segments win = %d, want %d", queuedSegs, ack.win, want)
		}
		if ack.win > recvBufCap {
			t.Fatalf("advertised window %d exceeds the buffer cap %d", ack.win, recvBufCap)
		}
	}
	for i := 0; i < 30; i++ {
		feedSeg(i)
		checkWin(i + 1)
	}
	// Fill the rest of the buffer: the final ACK must advertise win=0.
	for i := 30; i <= int(recvBufCap)/segLen; i++ {
		feedSeg(i)
	}
	last := parseTerm(t, sender.sent()[len(sender.sent())-1])
	if last.win != 0 {
		t.Fatalf("win = %d with a full receive buffer, want 0", last.win)
	}
	// With window flow control active the relay queue never reaches its
	// slot cap: the old deferred-segment path must stay at zero.
	if c := termConnOf(tm); c.qFullN.Load() != 0 {
		t.Fatalf("qFullN = %d with window flow control active, want 0", c.qFullN.Load())
	}
}

// TestTerminatorZeroWindowUpdate: after a win=0 advertisement, the first
// drained space must produce a window-update ACK — the client should not
// have to wait out its persist timer to learn the window reopened.
func TestTerminatorZeroWindowUpdate(t *testing.T) {
	sender := &fakeTermSender{}
	clientEnd, serverEnd := net.Pipe()
	defer clientEnd.Close()
	dial := func(ctx context.Context, dst string) (net.Conn, error) { return serverEnd, nil }
	tm := NewTerminator(sender, dial, nil)
	defer tm.Close()

	termFeed(tm, termSYN, 9500, 0, nil)
	time.Sleep(50 * time.Millisecond)
	sa := parseTerm(t, sender.sent()[0])
	termFeed(tm, termACK, 9501, sa.seq+1, nil)

	const segLen = 1000
	for i := 0; i <= int(recvBufCap)/segLen; i++ {
		termFeed(tm, termACK|termPSH, uint32(9501+i*segLen), sa.seq+1, make([]byte, segLen))
	}
	zeroAt := -1
	for i, p := range sender.sent() {
		if pp := parseTerm(t, p); pp.flags == termACK && pp.win == 0 {
			zeroAt = i
			break
		}
	}
	if zeroAt < 0 {
		t.Fatal("no win=0 ACK while the receive buffer is full")
	}

	// Drain: reads unblock pumpWrites; the freed bytes must be advertised.
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := clientEnd.Read(buf); err != nil {
				return
			}
		}
	}()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, p := range sender.sent()[zeroAt+1:] {
			pp := parseTerm(t, p)
			if pp.flags == termACK && pp.win > 0 {
				return // window-update ACK received
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no window-update ACK after the queue drained")
}

// TestTerminatorSlowCarrierZeroLoss: a window-respecting client bursting
// 300KB (≫ the 64KB receive window) into a slow carrier must see ZERO
// reorder-buffer evictions and ZERO deferred segments — the window holds
// the client at the carrier's drain rate, so nothing is ever dropped and
// every byte arrives in order.
func TestTerminatorSlowCarrierZeroLoss(t *testing.T) {
	const (
		base   = uint64(9701)
		segs   = 300
		segLen = 1000 // 300KB total, ≈4.6× the receive window
	)
	sender := &fakeTermSender{}
	clientEnd, serverEnd := net.Pipe()
	defer clientEnd.Close()
	dial := func(ctx context.Context, dst string) (net.Conn, error) { return serverEnd, nil }
	tm := NewTerminator(sender, dial, nil)
	defer tm.Close()

	// SLOW carrier: the pipe is synchronous, so this paced reader is the
	// drain-rate bottleneck (≈0.5 MB/s).
	readDone := make(chan []byte, 1)
	go func() {
		var acc []byte
		buf := make([]byte, segLen)
		for len(acc) < segs*segLen {
			n, err := clientEnd.Read(buf)
			if n > 0 {
				acc = append(acc, buf[:n]...)
			}
			if err != nil {
				break
			}
			time.Sleep(2 * time.Millisecond)
		}
		readDone <- acc
	}()

	termFeed(tm, termSYN, uint32(base-1), 0, nil) // clientNext = base
	time.Sleep(50 * time.Millisecond)
	sa := parseTerm(t, sender.sent()[0])
	termFeed(tm, termACK, uint32(base), sa.seq+1, nil)

	// Window-respecting client: track the right edge (highest ack+win
	// over all feedback) and never push the next segment past it.
	edge := func() uint64 {
		e := base + recvBufCap // SYN-ACK: ack = base, win = termWindow
		for _, p := range sender.sent() {
			pp := parseTerm(t, p)
			if pp.flags&termACK != 0 {
				if re := uint64(pp.ack) + uint64(pp.win); re > e {
					e = re
				}
			}
		}
		return e
	}
	deadline := time.Now().Add(20 * time.Second)
	next := base
	for next < base+segs*segLen && time.Now().Before(deadline) {
		e := edge()
		for next+segLen <= e && next < base+segs*segLen {
			i := int(next-base) / segLen
			d := make([]byte, segLen)
			binary.BigEndian.PutUint32(d, uint32(i)) // integrity marker
			termFeed(tm, termACK|termPSH, uint32(next), sa.seq+1, d)
			next += segLen
		}
		time.Sleep(100 * time.Microsecond)
	}
	if next < base+segs*segLen {
		t.Fatalf("client stalled at %d/%d bytes: the window never reopened", next-base, segs*segLen)
	}

	var acc []byte
	select {
	case acc = <-readDone:
	case <-time.After(10 * time.Second):
		t.Fatal("carrier never received the full upload")
	}
	if uint64(len(acc)) != segs*segLen {
		t.Fatalf("carrier got %d bytes, want %d", len(acc), segs*segLen)
	}
	for i := 0; i < segs; i++ {
		chunk := acc[i*segLen : (i+1)*segLen]
		if binary.BigEndian.Uint32(chunk) != uint32(i) {
			t.Fatalf("chunk %d corrupt or out of order", i)
		}
	}
	c := termConnOf(tm)
	if c == nil {
		t.Fatal("no terminator connection")
	}
	if drops := c.oooDropN.Load(); drops != 0 {
		t.Fatalf("oooDropN = %d under window flow control, want 0 evictions", drops)
	}
	if def := c.qFullN.Load(); def != 0 {
		t.Fatalf("qFullN = %d under window flow control, want 0 deferrals", def)
	}

	// (c) every advertised window fits the cap and its right edge
	// (ack+win) never moved backwards across the flow.
	prevEdge := uint64(0)
	for _, p := range sender.sent() {
		pp := parseTerm(t, p)
		if pp.flags&termACK == 0 {
			continue
		}
		if pp.win > recvBufCap {
			t.Fatalf("advertised window %d exceeds the buffer cap %d", pp.win, recvBufCap)
		}
		re := uint64(pp.ack) + uint64(pp.win)
		if re < prevEdge {
			t.Fatalf("window right edge moved backwards: %d → %d", prevEdge, re)
		}
		prevEdge = re
	}
}
