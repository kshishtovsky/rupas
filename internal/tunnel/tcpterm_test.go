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
