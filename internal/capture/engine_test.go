//go:build windows

package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/rupas/rupas/internal/config"
	"github.com/rupas/rupas/internal/flowtable"
	"github.com/rupas/rupas/internal/rules"
	"github.com/rupas/rupas/pkg/windivert"
)

const (
	testClientIP   = "192.168.1.50"
	testClientPort = uint16(51000)
	testServerIP   = "93.184.216.34"
	testTGIP       = "149.154.175.100"
	testTProxyPort = uint16(9443)
)

var testFakeTemplate = append([]byte{0x16, 0x03}, bytes.Repeat([]byte("FAKE-CH-TEMPLATE"), 8)...)

func testDesyncParams(strategy string, split int) config.DesyncParams {
	return config.DesyncParams{Strategy: strategy, TTL: 8, Repeats: 2, SplitOffset: split}
}

// newTestEngine compiles rules and builds an engine wired to a fresh
// FakeTransport (main) and optionally a second one (loopback).
func newTestEngine(t *testing.T, rulesCfg *config.Config, params config.DesyncParams, withLoop bool) (*Engine, *FakeTransport, *FakeTransport) {
	t.Helper()
	if rulesCfg.Desync == (config.DesyncParams{}) {
		rulesCfg.Desync = params // Validate() needs a profile when a rule uses desync
	}
	tbl, err := rules.Compile(rulesCfg)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	e, err := New(Options{
		Rules:        tbl,
		Desync:       params,
		FakeTemplate: testFakeTemplate,
		TProxyPort:   testTProxyPort,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ft := NewFakeTransport()
	var loop *FakeTransport
	if withLoop {
		loop = NewFakeTransport()
	}
	e.InjectTransport(ft, loop)
	return e, ft, loop
}

func outboundAddr() windivert.Address {
	a := windivert.Address{}
	a.SetOutbound(true)
	return a
}

func inboundAddr() windivert.Address { return windivert.Address{} }

func feed(t *testing.T, e *Engine, pkt []byte, addr windivert.Address) {
	t.Helper()
	e.processPacket(pkt, &addr)
}

// flowOf returns the flow for a client→server tuple.
func flowOf(e *Engine, serverIP string, serverPort uint16) (*flowtable.Flow, bool) {
	srv := parseIP4(serverIP, [4]byte{})
	cli := parseIP4(testClientIP, [4]byte{})
	k := flowtable.FlowKey{
		SrcIP: v4mapped(cli), SrcPort: testClientPort,
		DstIP: v4mapped(srv), DstPort: serverPort,
		Proto: protoTCP,
	}
	return e.Flows().Get(k)
}

// ---------------------------------------------------------------------------
// DIRECT branch
// ---------------------------------------------------------------------------

// TestDirectPathUntouched: a DIRECT flow's packets are re-injected
// byte-for-byte, no fakes, no NAT, state transitions NEW→DIRECT.
func TestDirectPathUntouched(t *testing.T) {
	cfg := &config.Config{
		Profile: "test",
		Rules: []config.Rule{
			{SNI: "ok.example", Action: config.ActionDesync}, // proves desync is NOT applied
			{Action: config.ActionDirect},
		},
	}
	// SNI ok.example → DESYNC rule above is bypassed by the default DIRECT
	// rule only if no SNI match — use a CH whose SNI matches nothing.
	e, ft, _ := newTestEngine(t, cfg, testDesyncParams("fake", 0), false)

	syn := buildTCP(testClientIP, testClientPort, testServerIP, 443, 1000, 0, tcpFlagSYN, nil)
	feed(t, e, syn, outboundAddr())

	ch := buildClientHello("plain.example", false)
	chPkt := buildTCP(testClientIP, testClientPort, testServerIP, 443, 1001, 1, tcpFlagACK|tcpFlagPSH, ch)
	feed(t, e, chPkt, outboundAddr())

	sent := ft.Sent()
	if len(sent) != 2 {
		t.Fatalf("sent %d packets, want 2 (SYN + CH)", len(sent))
	}
	if !bytes.Equal(sent[0].Data, syn) {
		t.Fatal("SYN modified on DIRECT path")
	}
	if !bytes.Equal(sent[1].Data, chPkt) {
		t.Fatal("ClientHello segment modified on DIRECT path")
	}
	if dst := sent[1].Data[16:20]; dst[0] == 127 {
		t.Fatal("DIRECT packet NAT-redirected")
	}

	f, ok := flowOf(e, testServerIP, 443)
	if !ok {
		t.Fatal("flow missing")
	}
	if f.State.Load() != flowtable.FlowDirect {
		t.Fatalf("flow state = %d, want FlowDirect", f.State.Load())
	}
	if !f.CHSeen {
		t.Fatal("CHSeen not set")
	}
	c := e.Counters()
	if c.PacketsPass != 2 || c.PacketsDesync != 0 || c.PacketsRedir != 0 {
		t.Fatalf("counters: %+v", c)
	}
}

// ---------------------------------------------------------------------------
// DESYNC branch: fake packet correctness
// ---------------------------------------------------------------------------

// TestDesyncFakePacket: strategy "fake", TTL 8, 2 repeats. The fakes must
// precede the original, clone its IP/TCP headers, carry the template as
// payload, keep the original seq verbatim (winws parity: the fake must
// occupy the DPI's expected next-seq position, client ISN+1), use the
// op TTL, valid checksums and a PLAIN address (no Impostor flag: it
// costs one TTL hop on the wire, doctrine #4 in ops.go).
func TestDesyncFakePacket(t *testing.T) {
	cfg := &config.Config{
		Profile: "test",
		Rules: []config.Rule{
			{SNI: "blocked.example", Action: config.ActionDesync},
			{Action: config.ActionDirect},
		},
	}
	e, ft, _ := newTestEngine(t, cfg, testDesyncParams("fake", 0), false)

	syn := buildTCP(testClientIP, testClientPort, testServerIP, 443, 5000, 0, tcpFlagSYN, nil)
	feed(t, e, syn, outboundAddr())

	ch := buildClientHello("blocked.example", false)
	seq := uint32(5001)
	chPkt := buildTCP(testClientIP, testClientPort, testServerIP, 443, seq, 1, tcpFlagACK|tcpFlagPSH, ch)
	feed(t, e, chPkt, outboundAddr())

	sent := ft.Sent()
	if len(sent) != 4 { // SYN + fake + fake + original
		t.Fatalf("sent %d packets, want 4", len(sent))
	}
	if !bytes.Equal(sent[0].Data, syn) {
		t.Fatal("SYN modified")
	}
	for i := 1; i <= 2; i++ {
		fake := sent[i].Data
		p, ok := parsePkt(fake)
		if !ok {
			t.Fatalf("fake %d unparseable", i)
		}
		if fake[8] != 8 {
			t.Fatalf("fake %d TTL = %d, want 8 (op.TTL)", i, fake[8])
		}
		if p.seq != seq {
			t.Fatalf("fake %d seq = %d, want %d (verbatim, winws parity)", i, p.seq, seq)
		}
		if p.ackNum != 1 {
			t.Fatalf("fake %d ack = %d, want 1 (cloned from the real segment)", i, p.ackNum)
		}
		if !bytes.Equal(p.payload, testFakeTemplate) {
			t.Fatalf("fake %d payload is not the template", i)
		}
		if p.srcPort != testClientPort || p.dstPort != 443 {
			t.Fatalf("fake %d ports %d→%d", i, p.srcPort, p.dstPort)
		}
		if ip := parseIP4(testClientIP, [4]byte{}); p.src4 != ip {
			t.Fatalf("fake %d src %v", i, p.src4)
		}
		if !checksumsValid(fake) {
			t.Fatalf("fake %d checksums invalid", i)
		}
		if total := int(binary.BigEndian.Uint16(fake[2:4])); total != 40+len(testFakeTemplate) {
			t.Fatalf("fake %d total length %d, want %d", i, total, 40+len(testFakeTemplate))
		}
		if sent[i].Addr.Impostor() {
			t.Fatalf("fake %d impostor-flagged: would egress with TTL-1", i)
		}
		if !sent[i].Addr.Outbound() {
			t.Fatalf("fake %d lost outbound direction", i)
		}
	}
	if !bytes.Equal(sent[3].Data, chPkt) {
		t.Fatal("original CH not forwarded last / modified")
	}
	if sent[3].Addr.Impostor() {
		t.Fatal("original marked impostor")
	}

	f, _ := flowOf(e, testServerIP, 443)
	if f.State.Load() != flowtable.FlowDesynced {
		t.Fatalf("flow state = %d, want FlowDesynced", f.State.Load())
	}
	c := e.Counters()
	if c.PacketsDesync != 1 || c.PacketsPass != 1 {
		t.Fatalf("counters: %+v", c)
	}
}

// TestDesyncSplit: strategy fake_split with offset 4 — the real segment goes
// out as two parts whose payloads reassemble into the original, the second
// part's seq advanced by the offset.
func TestDesyncSplit(t *testing.T) {
	cfg := &config.Config{
		Profile: "test",
		Rules: []config.Rule{
			{SNI: "blocked.example", Action: config.ActionDesync},
		},
	}
	e, ft, _ := newTestEngine(t, cfg, testDesyncParams("fake_split", 4), false)

	ch := buildClientHello("blocked.example", false)
	seq := uint32(7001)
	chPkt := buildTCP(testClientIP, testClientPort, testServerIP, 443, seq, 1, tcpFlagACK|tcpFlagPSH, ch)
	chPristine := append([]byte(nil), chPkt...) // split edits the buffer in place
	feed(t, e, chPkt, outboundAddr())

	sent := ft.Sent()
	if len(sent) != 4 { // fake + part1 + part2
		t.Fatalf("sent %d packets, want 4 (1 fake + 2 parts)", len(sent))
	}
	origP, ok := parsePkt(chPristine)
	if !ok {
		t.Fatal("test packet unparseable")
	}

	p1, ok1 := parsePkt(sent[2].Data)
	p2, ok2 := parsePkt(sent[3].Data)
	if !ok1 || !ok2 {
		t.Fatalf("split parts unparseable: %v %v", ok1, ok2)
	}
	if !bytes.Equal(p1.payload, origP.payload[:4]) {
		t.Fatalf("part1 payload %q, want first 4 bytes", p1.payload)
	}
	if !bytes.Equal(p2.payload, origP.payload[4:]) {
		t.Fatal("part2 payload mismatch")
	}
	if got := append(append([]byte(nil), p1.payload...), p2.payload...); !bytes.Equal(got, origP.payload) {
		t.Fatal("split parts do not reassemble into the original segment")
	}
	if p1.seq != seq {
		t.Fatalf("part1 seq %d, want %d", p1.seq, seq)
	}
	if p2.seq != seq+4 {
		t.Fatalf("part2 seq %d, want %d", p2.seq, seq+4)
	}
	if sent[1].Data[8] != 8 {
		t.Fatalf("fake TTL = %d, want 8", sent[1].Data[8])
	}
	if !checksumsValid(sent[2].Data) || !checksumsValid(sent[3].Data) {
		t.Fatal("split part checksums invalid")
	}
	if sent[2].Data[8] != ipTTLDefault {
		t.Fatalf("part1 TTL changed: %d", sent[2].Data[8])
	}
	// Part2 is a crafted packet (cloned headers), but must NOT carry the
	// impostor flag: that would decrement its TTL on egress (doctrine #4).
	if sent[3].Addr.Impostor() {
		t.Fatal("part2 impostor-flagged: would egress with TTL-1")
	}

	f, _ := flowOf(e, testServerIP, 443)
	if f.State.Load() != flowtable.FlowDesynced {
		t.Fatalf("flow state = %d", f.State.Load())
	}
}

// TestClientHelloTwoSegments: a CH split across two segments (Go 1.26
// negotiates ML-KEM, so real CHs routinely exceed the MSS). The first
// segment is HELD (must not egress before the fakes — winws parity); the
// completing segment triggers the ops: fake ×2 built from the FIRST
// segment (seq = its seq, i.e. client ISN+1), then the held segment, then
// the completing one, all in that wire order.
func TestClientHelloTwoSegments(t *testing.T) {
	cfg := &config.Config{
		Profile: "test",
		Rules: []config.Rule{
			{SNI: "blocked.example", Action: config.ActionDesync},
		},
	}
	e, ft, _ := newTestEngine(t, cfg, testDesyncParams("fake", 0), false)

	ch := buildClientHello("blocked.example", false)
	cut := 10
	seg1 := buildTCP(testClientIP, testClientPort, testServerIP, 443, 1000, 1, tcpFlagACK|tcpFlagPSH, ch[:cut])
	seg2 := buildTCP(testClientIP, testClientPort, testServerIP, 443, 1000+uint32(cut), 1, tcpFlagACK|tcpFlagPSH, ch[cut:])
	feed(t, e, seg1, outboundAddr())
	if got := ft.Sent(); len(got) != 0 {
		t.Fatalf("partial CH segment leaked before the fakes: %d sent", len(got))
	}
	feed(t, e, seg2, outboundAddr())

	sent := ft.Sent()
	if len(sent) != 4 { // 2 fakes + held seg1 + completing seg2
		t.Fatalf("sent %d packets, want 4", len(sent))
	}
	for i := 0; i < 2; i++ {
		fp, ok := parsePkt(sent[i].Data)
		if !ok {
			t.Fatalf("fake %d unparseable", i)
		}
		if fp.seq != 1000 {
			t.Fatalf("fake %d seq = %d, want 1000 (FIRST segment's seq = client ISN+1)", i, fp.seq)
		}
		if fp.ackNum != 1 {
			t.Fatalf("fake %d ack = %d, want 1 (cloned from the first segment)", i, fp.ackNum)
		}
		if sent[i].Data[8] != 8 {
			t.Fatalf("fake %d TTL = %d, want 8", i, sent[i].Data[8])
		}
	}
	if !bytes.Equal(sent[2].Data, seg1) {
		t.Fatal("held first segment not released after the fakes / modified")
	}
	if !bytes.Equal(sent[3].Data, seg2) {
		t.Fatal("completing segment not forwarded after the fakes")
	}
	if c := e.Counters(); c.PacketsDesync != 1 {
		t.Fatalf("desync verdicts = %d, want 1: %+v", c.PacketsDesync, c)
	}
}

// TestClientHelloHoldDIRECT: a multi-segment non-TLS or DIRECT flow still
// delivers its held segments, in order, once the verdict fires.
func TestClientHelloHoldDIRECT(t *testing.T) {
	cfg := &config.Config{
		Profile: "test",
		Rules: []config.Rule{
			{SNI: "ok.example", Action: config.ActionDirect},
			{Action: config.ActionDirect},
		},
	}
	e, ft, _ := newTestEngine(t, cfg, testDesyncParams("fake", 0), false)

	ch := buildClientHello("ok.example", false)
	cut := 12
	seg1 := buildTCP(testClientIP, testClientPort, testServerIP, 443, 2000, 1, tcpFlagACK|tcpFlagPSH, ch[:cut])
	seg2 := buildTCP(testClientIP, testClientPort, testServerIP, 443, 2000+uint32(cut), 1, tcpFlagACK|tcpFlagPSH, ch[cut:])
	feed(t, e, seg1, outboundAddr())
	if got := ft.Sent(); len(got) != 0 {
		t.Fatalf("partial segment leaked: %d sent", len(got))
	}
	feed(t, e, seg2, outboundAddr())
	sent := ft.Sent()
	if len(sent) != 2 || !bytes.Equal(sent[0].Data, seg1) || !bytes.Equal(sent[1].Data, seg2) {
		t.Fatalf("held segments not released in order for DIRECT: %d sent", len(sent))
	}
}

// TestSYNStoresISN: the outbound SYN's seq is kept in the Flow as
// ClientISN (wave 4A), so the desync path can always derive the expected
// CH seq even if it never saw the SYN.
func TestSYNStoresISN(t *testing.T) {
	cfg := &config.Config{
		Profile: "test",
		Rules:   []config.Rule{{Action: config.ActionDirect}},
	}
	e, _, _ := newTestEngine(t, cfg, testDesyncParams("fake", 0), false)
	syn := buildTCP(testClientIP, testClientPort, testServerIP, 443, 424242, 0, tcpFlagSYN, nil)
	feed(t, e, syn, outboundAddr())
	f, ok := flowOf(e, testServerIP, 443)
	if !ok {
		t.Fatal("flow missing")
	}
	if f.ClientISN != 424242 {
		t.Fatalf("ClientISN = %d, want 424242", f.ClientISN)
	}
}

// TestNotTLSIsDirect: a non-TLS first segment (e.g. HTTP) is never desynced.
func TestNotTLSIsDirect(t *testing.T) {
	cfg := &config.Config{
		Profile: "test",
		Rules:   []config.Rule{{Action: config.ActionDesync}}, // default desync
	}
	e, ft, _ := newTestEngine(t, cfg, testDesyncParams("fake", 0), false)
	http := []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	pkt := buildTCP(testClientIP, testClientPort, testServerIP, 443, 1000, 1, tcpFlagACK|tcpFlagPSH, http)
	feed(t, e, pkt, outboundAddr())
	sent := ft.Sent()
	if len(sent) != 1 || !bytes.Equal(sent[0].Data, pkt) {
		t.Fatalf("non-TLS segment interfered with (%d sent)", len(sent))
	}
	if c := e.Counters(); c.PacketsDesync != 0 {
		t.Fatalf("desync counter = %d for non-TLS", c.PacketsDesync)
	}
}

// ---------------------------------------------------------------------------
// TUNNEL branch: NAT round-trip
// ---------------------------------------------------------------------------

func tunnelTestConfig() *config.Config {
	return &config.Config{
		Profile: "test",
		Rules: []config.Rule{
			{CIDR: "149.154.160.0/20", Action: config.ActionTunnel},
			{Action: config.ActionDirect},
		},
	}
}

// TestNATRoundtripTCP drives a full redirect life cycle under the §3.2
// reset-and-redial verdict: SYN (first pass, verdict unknown) → CH TUNNEL →
// forged RST + dst cached (the CH itself never egresses) → re-dial SYN
// redirected → data redirected → loopback reply reverse-translated →
// OrigDst preserved all along → FIN tears everything down.
func TestNATRoundtripTCP(t *testing.T) {
	e, ft, loop := newTestEngine(t, tunnelTestConfig(), testDesyncParams("fake", 0), true)

	// 1. First SYN: flow is NEW, verdict unknown yet → passed untouched.
	syn := buildTCP(testClientIP, testClientPort, testTGIP, 443, 9000, 0, tcpFlagSYN, nil)
	feed(t, e, syn, outboundAddr())

	// 2. ClientHello: CIDR rule → TUNNEL → §3.2 reset-and-redial. The CH
	// never leaves; the client gets a forged RST from the real server.
	ch := buildClientHello("telegram.zzz", false) // SNI matches nothing; CIDR decides
	chPkt := buildTCP(testClientIP, testClientPort, testTGIP, 443, 9001, 1, tcpFlagACK|tcpFlagPSH, ch)
	feed(t, e, chPkt, outboundAddr())

	sent := ft.Sent()
	if len(sent) != 2 { // SYN + forged RST
		t.Fatalf("sent %d, want 2 (SYN + forged RST)", len(sent))
	}
	rp, ok := parsePkt(sent[1].Data)
	if !ok {
		t.Fatal("forged RST unparseable")
	}
	if rp.src4 != parseIP4(testTGIP, [4]byte{}) || rp.srcPort != 443 ||
		rp.dst4 != parseIP4(testClientIP, [4]byte{}) || rp.dstPort != testClientPort {
		t.Fatalf("forged RST addresses = %v:%d→%v:%d", rp.src4, rp.srcPort, rp.dst4, rp.dstPort)
	}
	if rp.flags&tcpFlagRST == 0 || rp.flags&tcpFlagACK == 0 {
		t.Fatalf("forged RST flags = 0x%02x", rp.flags)
	}
	if rp.seq != 1 || rp.ackNum != 9001+uint32(len(ch)) {
		t.Fatalf("forged RST seq/ack = %d/%d, want 1/%d", rp.seq, rp.ackNum, 9001+uint32(len(ch)))
	}
	if !checksumsValid(sent[1].Data) {
		t.Fatal("forged RST checksums invalid")
	}
	if sent[1].Addr.Outbound() {
		t.Fatal("forged RST must be injected INBOUND")
	}
	if lo := loop.Sent(); len(lo) != 0 {
		t.Fatalf("loopback sent %d, want 0 (the CH is never NAT'd)", len(lo))
	}
	if _, ok := flowOf(e, testTGIP, 443); ok {
		t.Fatal("flow table kept the reset flow")
	}
	if got := e.TunnelRedirects(); got != 1 {
		t.Fatalf("tunnel redirects = %d, want 1", got)
	}
	if !e.tcache.get(parseIP4(testTGIP, [4]byte{}), 443) {
		t.Fatal("dst not cached for redial")
	}

	// 3. Re-dial SYN (the browser's retry after the RST): cached dst →
	// tunnel fast path → NAT-redirected (§3.2 "next SYN via redirect").
	feed(t, e, syn, outboundAddr())
	if n := len(loop.Sent()); n != 1 {
		t.Fatalf("loopback sent %d after re-dial SYN, want 1", n)
	}
	np, _ := parsePkt(loop.Sent()[0].Data)
	if np.dst4 != parseIP4(testClientIP, [4]byte{}) || np.dstPort != testTProxyPort {
		t.Fatal("re-dial SYN not redirected")
	}

	f, ok := flowOf(e, testTGIP, 443)
	if !ok {
		t.Fatal("flow missing")
	}
	if f.State.Load() != flowtable.FlowTunnel {
		t.Fatalf("flow state %d, want FlowTunnel", f.State.Load())
	}
	wantOrig := v4mapped(parseIP4(testTGIP, [4]byte{}))
	if f.OrigDst != wantOrig || f.OrigPort != 443 {
		t.Fatalf("OrigDst/OrigPort = %v:%d", f.OrigDst, f.OrigPort)
	}

	// 4. Subsequent data is redirected too. (Keep a pristine copy: the
	// engine edits the packet buffer in place on the NAT path.)
	data := buildTCP(testClientIP, testClientPort, testTGIP, 443, 9001+uint32(len(ch)), 1, tcpFlagACK|tcpFlagPSH, []byte("MTProtoData"))
	dataPristine := append([]byte(nil), data...)
	feed(t, e, data, outboundAddr())
	last := loop.Sent()
	np, _ = parsePkt(last[len(last)-1].Data)
	if np.dst4 != parseIP4(testClientIP, [4]byte{}) || np.dstPort != testTProxyPort {
		t.Fatal("tunnel data segment not redirected")
	}
	if bytes.Equal(last[len(last)-1].Data, dataPristine) {
		t.Fatal("tunnel data forwarded un-NATed")
	}

	// 5. Loopback reply: src 127.0.0.1:9443 → reverse-translated to the
	// original server, dst = client.
	reply := buildTCP("127.0.0.1", testTProxyPort, "198.18.0.1", testClientPort, 1, 9001+uint32(len(ch))+14, tcpFlagACK|tcpFlagPSH, []byte("ServerHello+"))
	e.processLoopback(loop, reply, ptrOf(inboundAddr()))

	loopSent := loop.Sent()
	if len(loopSent) != 3 { // re-dial SYN + data NAT legs + the reverse leg
		t.Fatalf("loopback sent %d, want 3", len(loopSent))
	}
	rp, ok = parsePkt(loopSent[len(loopSent)-1].Data)
	if !ok {
		t.Fatal("reverse-NAT packet unparseable")
	}
	if rp.src4 != parseIP4(testTGIP, [4]byte{}) || rp.srcPort != 443 {
		t.Fatalf("reverse-NAT src = %v:%d, want original server", rp.src4, rp.srcPort)
	}
	if rp.dst4 != parseIP4(testClientIP, [4]byte{}) || rp.dstPort != testClientPort {
		t.Fatalf("reverse-NAT dst = %v:%d, want client", rp.dst4, rp.dstPort)
	}
	// OrigDst must survive the round-trip unchanged.
	f2, _ := flowOf(e, testTGIP, 443)
	if f2.OrigDst != wantOrig || f2.OrigPort != 443 {
		t.Fatalf("OrigDst leaked/mutated after round-trip: %v:%d", f2.OrigDst, f2.OrigPort)
	}

	// 6. FIN from the client: redirected, then full teardown.
	fin := buildTCP(testClientIP, testClientPort, testTGIP, 443, 9001+uint32(len(ch))+14, 1, tcpFlagACK|tcpFlagFIN, nil)
	feed(t, e, fin, outboundAddr())
	last = loop.Sent()
	np, _ = parsePkt(last[len(last)-1].Data)
	if np.dst4 != parseIP4(testClientIP, [4]byte{}) {
		t.Fatal("FIN not redirected")
	}
	if n := e.Flows().Len(); n != 0 {
		t.Fatalf("flow table not empty after FIN: %d", n)
	}
	// After teardown the NAT entry is gone: a stray loopback packet passes
	// through untouched.
	stray := buildTCP("127.0.0.1", testTProxyPort, "198.18.0.1", testClientPort, 1, 1, tcpFlagACK, nil)
	e.processLoopback(loop, stray, ptrOf(inboundAddr()))
	loopSent = loop.Sent()
	if len(loopSent) != 5 { // 3 NAT/reverse legs + FIN + the stray passthrough
		t.Fatalf("stray loopback packet: %d sent", len(loopSent))
	}
	if sp, _ := parsePkt(loopSent[len(loopSent)-1].Data); sp.src4 != loopback4 {
		t.Fatal("stray loopback packet was reverse-NATed without a flow")
	}

	if c := e.Counters(); c.PacketsRedir != 3 { // re-dial SYN + data + FIN
		t.Fatalf("redirect counter = %d, want 3: %+v", c.PacketsRedir, c)
	}
}

// TestNATUDPRelay: UDP relay traffic to the TG CIDR is NAT-redirected and
// reverse-translated on the loopback handle.
func TestNATUDPRelay(t *testing.T) {
	e, _, loop := newTestEngine(t, tunnelTestConfig(), testDesyncParams("fake", 0), true)

	udp := buildUDP(testClientIP, 53333, testTGIP, 50001, []byte("voice-packet"))
	feed(t, e, udp, outboundAddr())

	sent := loop.Sent() // NAT legs re-inject via the loopback handle
	if len(sent) != 1 {
		t.Fatalf("sent %d, want 1", len(sent))
	}
	p, ok := parsePkt(sent[0].Data)
	if !ok || !p.isUDP() {
		t.Fatal("NAT UDP packet unparseable")
	}
	if p.dst4 != parseIP4(testClientIP, [4]byte{}) || p.dstPort != testTProxyPort {
		t.Fatalf("UDP NAT dst %v:%d", p.dst4, p.dstPort)
	}
	if !checksumsValid(sent[0].Data) {
		t.Fatal("UDP NAT checksums invalid")
	}

	reply := buildUDP("127.0.0.1", testTProxyPort, "198.18.0.1", 53333, []byte("voice-reply"))
	e.processLoopback(loop, reply, ptrOf(inboundAddr()))
	rp, ok := parsePkt(loop.Sent()[1].Data)
	if !ok {
		t.Fatal("UDP reverse-NAT unparseable")
	}
	if rp.src4 != parseIP4(testTGIP, [4]byte{}) || rp.srcPort != 50001 {
		t.Fatalf("UDP reverse-NAT src %v:%d", rp.src4, rp.srcPort)
	}
	if !bytes.Equal(rp.payload, []byte("voice-reply")) {
		t.Fatal("UDP reverse-NAT payload corrupted")
	}
}

// TestECHForcesTunnel: a desync-matched SNI still goes to the tunnel when
// the ClientHello carries an ECH extension — via §3.2 reset-and-redial:
// the CH (and any held segments) never egress, the client gets a forged
// RST from the real server and the dst joins the redial cache, so the
// browser's re-dial SYN enters the tunnel fast path.
func TestECHForcesTunnel(t *testing.T) {
	cfg := &config.Config{
		Profile: "test",
		Rules: []config.Rule{
			{SNI: "blocked.example", Action: config.ActionDesync},
		},
	}
	e, ft, loop := newTestEngine(t, cfg, testDesyncParams("fake", 0), true)

	ch := buildClientHello("blocked.example", true)
	pkt := buildTCP(testClientIP, testClientPort, testServerIP, 443, 1000, 1, tcpFlagACK|tcpFlagPSH, ch)
	feed(t, e, pkt, outboundAddr())

	if sent := loop.Sent(); len(sent) != 0 {
		t.Fatalf("loopback sent %d, want 0 (ECH CH never NAT'd/egresses)", len(sent))
	}
	sent := ft.Sent()
	if len(sent) != 1 {
		t.Fatalf("sent %d, want 1 (forged RST)", len(sent))
	}
	p, ok := parsePkt(sent[0].Data)
	if !ok {
		t.Fatal("forged RST unparseable")
	}
	if p.src4 != parseIP4(testServerIP, [4]byte{}) || p.srcPort != 443 ||
		p.dst4 != parseIP4(testClientIP, [4]byte{}) || p.dstPort != testClientPort {
		t.Fatalf("forged RST addresses = %v:%d→%v:%d", p.src4, p.srcPort, p.dst4, p.dstPort)
	}
	if p.flags&tcpFlagRST == 0 || p.flags&tcpFlagACK == 0 {
		t.Fatalf("forged RST flags = 0x%02x", p.flags)
	}
	if p.seq != 1 || p.ackNum != 1000+uint32(len(ch)) {
		t.Fatalf("forged RST seq/ack = %d/%d", p.seq, p.ackNum)
	}
	if !checksumsValid(sent[0].Data) {
		t.Fatal("forged RST checksums invalid")
	}
	if sent[0].Addr.Outbound() {
		t.Fatal("forged RST must be injected INBOUND")
	}
	if c := e.Counters(); c.PacketsDesync != 0 || c.PacketsDrop != 1 {
		t.Fatalf("counters: %+v", c)
	}
	if got := e.TunnelRedirects(); got != 1 {
		t.Fatalf("tunnel redirects = %d, want 1", got)
	}
	if !e.tcache.get(parseIP4(testServerIP, [4]byte{}), 443) {
		t.Fatal("dst not cached for redial")
	}
	if _, ok := flowOf(e, testServerIP, 443); ok {
		t.Fatal("flow table kept the reset flow")
	}
	// The re-dial SYN rides the cached fast path straight into the tunnel.
	h := &hookRecorder{}
	e.SetTunnelTCP(h)
	feed(t, e, buildTCP(testClientIP, testClientPort+1, testServerIP, 443, 7000, 0, tcpFlagSYN, nil), outboundAddr())
	fed := h.fed()
	if len(fed) != 1 || fed[0].Flags != tcpFlagSYN || fed[0].DstPort != 443 {
		t.Fatalf("re-dial SYN not fast-pathed into the tunnel: %+v", fed)
	}
}

// ---------------------------------------------------------------------------
// ESTABLISHED detection + lifecycle
// ---------------------------------------------------------------------------

// TestEstablishedAfterServerData: any inbound data segment promotes a
// DESYNCED flow to ESTABLISHED and counts the handshake (§3.2 simplified).
func TestEstablishedAfterServerData(t *testing.T) {
	cfg := &config.Config{
		Profile: "test",
		Rules: []config.Rule{
			{SNI: "blocked.example", Action: config.ActionDesync},
		},
	}
	e, _, _ := newTestEngine(t, cfg, testDesyncParams("fake", 0), false)

	ch := buildClientHello("blocked.example", false)
	feed(t, e, buildTCP(testClientIP, testClientPort, testServerIP, 443, 1000, 1, tcpFlagACK|tcpFlagPSH, ch), outboundAddr())

	f, _ := flowOf(e, testServerIP, 443)
	if f.State.Load() != flowtable.FlowDesynced {
		t.Fatalf("precondition: state %d", f.State.Load())
	}
	// Server data segment (inbound).
	srv := buildTCP(testServerIP, 443, testClientIP, testClientPort, 1, 1000+uint32(len(ch)), tcpFlagACK|tcpFlagPSH, []byte("ServerHello"))
	feed(t, e, srv, inboundAddr())

	if f.State.Load() != flowtable.FlowEstablished {
		t.Fatalf("state %d, want FlowEstablished", f.State.Load())
	}
	if c := e.Counters(); c.HandshakeOK != 1 {
		t.Fatalf("HandshakeOK = %d", c.HandshakeOK)
	}
	// Post-establishement client data is passed untouched (no re-desync).
	before := e.Counters().PacketsDesync
	feed(t, e, buildTCP(testClientIP, testClientPort, testServerIP, 443, 1000+uint32(len(ch)), 1, tcpFlagACK|tcpFlagPSH, []byte("request")), outboundAddr())
	if e.Counters().PacketsDesync != before {
		t.Fatal("established flow re-desynced")
	}
}

// TestRunStopGraceful drives the full Run loop over a fake queue and stops.
func TestRunStopGraceful(t *testing.T) {
	cfg := tunnelTestConfig()
	tbl, err := rules.Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(Options{
		Rules:        tbl,
		Desync:       testDesyncParams("fake", 0),
		FakeTemplate: testFakeTemplate,
		TProxyPort:   testTProxyPort,
	})
	if err != nil {
		t.Fatal(err)
	}
	ft := NewFakeTransport()
	e.InjectTransport(ft, nil)

	syn := buildTCP(testClientIP, testClientPort, testTGIP, 443, 1000, 0, tcpFlagSYN, nil)
	chPkt := buildTCP(testClientIP, testClientPort, testTGIP, 443, 1001, 1, tcpFlagACK|tcpFlagPSH, buildClientHello("x.y", false))
	ack := buildTCP(testClientIP, testClientPort, testTGIP, 443, 1100, 1, tcpFlagACK, nil)
	ft.Enqueue(syn, true)
	ft.Enqueue(chPkt, true)
	ft.Enqueue(ack, true)

	done := make(chan error, 1)
	go func() { done <- e.Run(context.Background()) }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if len(ft.Sent()) == 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("engine did not process the queue: %d sent", len(ft.Sent()))
		}
		time.Sleep(5 * time.Millisecond)
	}

	e.Stop()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after Stop")
	}
	e.Stop() // idempotent
	if c := e.Counters(); c.PacketsTotal != 3 {
		t.Fatalf("processed %d packets, want 3", c.PacketsTotal)
	}
}

// TestConcurrentLoopsRace drives the main receive loop and the loopback
// (reverse-NAT) loop concurrently — pinned for the race detector: both
// goroutines touch the nat/streams maps. The §3.2 reset-and-redial cycle
// populates the tables: SYN pass → CH verdict (RST + cache) → re-dial SYN
// (fast-path NAT leg) → data (fast-path NAT leg), then loopback reply +
// FIN reverse legs from the loop goroutine.
func TestConcurrentLoopsRace(t *testing.T) {
	e, ft, loop := newTestEngine(t, tunnelTestConfig(), testDesyncParams("fake", 0), true)

	ch := buildClientHello("tg.zzz", false)
	syn := buildTCP(testClientIP, testClientPort, testTGIP, 443, 1000, 0, tcpFlagSYN, nil)
	chPkt := buildTCP(testClientIP, testClientPort, testTGIP, 443, 1001, 1, tcpFlagACK|tcpFlagPSH, ch)
	data := buildTCP(testClientIP, testClientPort, testTGIP, 443, 1001+uint32(len(ch)), 1, tcpFlagACK|tcpFlagPSH, []byte("payload"))
	ft.Enqueue(syn, true)
	ft.Enqueue(chPkt, true)
	ft.Enqueue(syn, true) // re-dial SYN: cached dst → fast-path NAT leg
	ft.Enqueue(data, true)

	reply := buildTCP("127.0.0.1", testTProxyPort, "198.18.0.1", testClientPort, 1, 1200, tcpFlagACK|tcpFlagPSH, []byte("srv-data"))
	finReply := buildTCP("127.0.0.1", testTProxyPort, testClientIP, testClientPort, 2, 1200, tcpFlagACK|tcpFlagFIN, nil)
	loop.Enqueue(reply, false)
	loop.Enqueue(finReply, false) // triggers nat cleanup from the loop goroutine

	done := make(chan error, 1)
	go func() { done <- e.Run(context.Background()) }()

	deadline := time.Now().Add(5 * time.Second)
	for len(loop.Sent()) < 4 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if len(loop.Sent()) < 4 {
		t.Fatalf("loops stalled: loopback=%d", len(loop.Sent()))
	}

	e.Stop()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after Stop")
	}
}

// TestNewValidation: guard rails against filter self-match loops.
func TestNewValidation(t *testing.T) {
	tbl, err := rules.Compile(tunnelTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	base := Options{Rules: tbl, Desync: testDesyncParams("fake", 0), FakeTemplate: testFakeTemplate}
	// TProxyPort 0 (tunnel branch disabled) must be accepted.
	if _, err := New(base); err != nil {
		t.Fatalf("New(TProxyPort 0) = %v, want nil", err)
	}
	if _, err := New(Options{Desync: testDesyncParams("fake", 0), FakeTemplate: testFakeTemplate}); err == nil {
		t.Fatal("New accepted nil Rules")
	}
	bad := base
	bad.TProxyPort = 443
	if _, err := New(bad); err == nil {
		t.Fatal("New accepted TProxyPort 443")
	}
	bad.TProxyPort = 50000
	if _, err := New(bad); err == nil {
		t.Fatal("New accepted TProxyPort inside the UDP relay range")
	}
}

func ptrOf(a windivert.Address) *windivert.Address { return &a }

// ---------------------------------------------------------------------------
// §3.2 reset-and-redial: CH-verdict TUNNEL
// ---------------------------------------------------------------------------

// tunnelRedialTestConfig routes one SNI to TUNNEL (the SNI-rule shape the
// ECH finding produces; the CIDR shape is covered by TestNATRoundtripTCP).
func tunnelRedialTestConfig() *config.Config {
	return &config.Config{
		Profile: "test",
		Rules: []config.Rule{
			{SNI: "ech.example", Action: config.ActionTunnel},
			{Action: config.ActionDirect},
		},
	}
}

// TestTunnelVerdictResetsRedial (a): a multi-segment CH resolving TUNNEL
// must (1) inject exactly one forged inbound RST|ACK from the real dst,
// (2) cache the dst, (3) let NO held segment and NOT the CH itself egress,
// (4) free the flow's state and (5) bump tunnelRedirect.
func TestTunnelVerdictResetsRedial(t *testing.T) {
	e, ft, loop := newTestEngine(t, tunnelRedialTestConfig(), testDesyncParams("fake", 0), true)

	syn := buildTCP(testClientIP, testClientPort, testServerIP, 443, 1000, 0, tcpFlagSYN, nil)
	feed(t, e, syn, outboundAddr()) // pre-verdict SYN passes to the REAL server

	// Multi-segment CH: the first segment is held, the completing one
	// fires the TUNNEL verdict.
	ch := buildClientHello("ech.example", true)
	cut := 10
	seg1 := buildTCP(testClientIP, testClientPort, testServerIP, 443, 1001, 1, tcpFlagACK|tcpFlagPSH, ch[:cut])
	seg2 := buildTCP(testClientIP, testClientPort, testServerIP, 443, 1001+uint32(cut), 1, tcpFlagACK|tcpFlagPSH, ch[cut:])
	feed(t, e, seg1, outboundAddr())
	if got := ft.Sent(); len(got) != 1 { // only the SYN so far
		t.Fatalf("held CH segment leaked: %d sent", len(got)-1)
	}
	feed(t, e, seg2, outboundAddr())

	sent := ft.Sent()
	if len(sent) != 2 { // SYN + forged RST — held seg1 and the CH NEVER egress
		t.Fatalf("sent %d packets, want 2 (SYN + RST); held segments must not relay", len(sent))
	}
	rst, ok := parsePkt(sent[1].Data)
	if !ok {
		t.Fatal("forged RST unparseable")
	}
	srv := parseIP4(testServerIP, [4]byte{})
	cli := parseIP4(testClientIP, [4]byte{})
	if rst.src4 != srv || rst.srcPort != 443 || rst.dst4 != cli || rst.dstPort != testClientPort {
		t.Fatalf("RST addresses = %v:%d→%v:%d", rst.src4, rst.srcPort, rst.dst4, rst.dstPort)
	}
	if rst.flags&tcpFlagRST == 0 || rst.flags&tcpFlagACK == 0 {
		t.Fatalf("RST flags = 0x%02x, want RST|ACK", rst.flags)
	}
	if rst.seq != 1 { // client's current ack = server's send-next
		t.Fatalf("RST seq = %d, want 1", rst.seq)
	}
	if rst.ackNum != 1001+uint32(len(ch)) { // clientNext = seg2.seq + payload
		t.Fatalf("RST ack = %d, want %d", rst.ackNum, 1001+uint32(len(ch)))
	}
	if !checksumsValid(sent[1].Data) {
		t.Fatal("forged RST checksums invalid")
	}
	if sent[1].Addr.Outbound() || sent[1].Addr.Impostor() {
		t.Fatal("forged RST must be inbound and not impostor-flagged")
	}
	if len(loop.Sent()) != 0 {
		t.Fatalf("loopback legs for a reset flow: %d", len(loop.Sent()))
	}
	if !e.tcache.get(srv, 443) {
		t.Fatal("dst not cached after the TUNNEL verdict")
	}
	if _, ok := flowOf(e, testServerIP, 443); ok {
		t.Fatal("reset flow left in the flow table")
	}
	if e.TunnelRedirects() != 1 {
		t.Fatalf("tunnel redirects = %d, want 1", e.TunnelRedirects())
	}
}

// TestTunnelCacheFastPathSYN (b): a NEW client connection (fresh source
// port — the browser's re-dial) to a cached tunnel dst enters the tunnel
// fast path from its first SYN, with no CH exchange on the real leg.
func TestTunnelCacheFastPathSYN(t *testing.T) {
	e, ft, _ := newTestEngine(t, tunnelRedialTestConfig(), testDesyncParams("fake", 0), false)
	h := &hookRecorder{}
	e.SetTunnelTCP(h)

	// Verdict pass: CH → TUNNEL → RST + cache.
	chPkt := buildTCP(testClientIP, testClientPort, testServerIP, 443, 1000, 1, tcpFlagACK|tcpFlagPSH, buildClientHello("ech.example", true))
	feed(t, e, chPkt, outboundAddr())
	if n := len(ft.Sent()); n != 1 {
		t.Fatalf("precondition: %d sent, want 1 (forged RST)", n)
	}

	// Re-dial from a NEW client port: straight into the terminator.
	redial := buildTCP(testClientIP, testClientPort+1, testServerIP, 443, 7000, 0, tcpFlagSYN, nil)
	feed(t, e, redial, outboundAddr())

	fed := h.fed()
	if len(fed) != 1 {
		t.Fatalf("hook fed %d packets, want 1 (the re-dial SYN)", len(fed))
	}
	p := fed[0]
	if p.Flags != tcpFlagSYN || p.SrcPort != testClientPort+1 || p.DstPort != 443 ||
		p.Seq != 7000 || p.DstIP != parseIP4(testServerIP, [4]byte{}) {
		t.Fatalf("hook packet = %+v", p)
	}
	if n := len(ft.Sent()); n != 1 {
		t.Fatalf("re-dial SYN leaked to the network: %d sent", n)
	}
	k := flowtable.FlowKey{
		SrcIP:   v4mapped(parseIP4(testClientIP, [4]byte{})),
		DstIP:   v4mapped(parseIP4(testServerIP, [4]byte{})),
		SrcPort: testClientPort + 1, DstPort: 443, Proto: protoTCP,
	}
	if f, ok := e.Flows().Get(k); !ok || f.State.Load() != flowtable.FlowTunnel {
		t.Fatalf("re-dial flow state = %v ok=%v, want FlowTunnel", f, ok)
	}
}

// TestTunnelCacheExpiryFallsBackToInspect (c): once the cache entry's
// deadline passed, a SYN to the same dst takes the ordinary branch again
// (flow NEW, passed to the network, terminator NOT fed).
func TestTunnelCacheExpiryFallsBackToInspect(t *testing.T) {
	e, ft, _ := newTestEngine(t, tunnelRedialTestConfig(), testDesyncParams("fake", 0), false)
	h := &hookRecorder{}
	e.SetTunnelTCP(h)

	chPkt := buildTCP(testClientIP, testClientPort, testServerIP, 443, 1000, 1, tcpFlagACK|tcpFlagPSH, buildClientHello("ech.example", true))
	feed(t, e, chPkt, outboundAddr())
	if !e.tcache.get(parseIP4(testServerIP, [4]byte{}), 443) {
		t.Fatal("precondition: dst not cached")
	}

	// Force the deadline into the past (package-internal: expire the entry
	// exactly as the 60s TTL would).
	srv := parseIP4(testServerIP, [4]byte{})
	past := time.Now().Add(-time.Second).UnixNano()
	for bi := range e.tcache.buckets {
		for wi := range e.tcache.buckets[bi] {
			if ent := &e.tcache.buckets[bi][wi]; ent.ip == srv && ent.port == 443 {
				ent.exp.Store(past)
			}
		}
	}

	late := buildTCP(testClientIP, testClientPort+1, testServerIP, 443, 8000, 0, tcpFlagSYN, nil)
	feed(t, e, late, outboundAddr())

	if fed := h.fed(); len(fed) != 0 {
		t.Fatalf("expired cache entry fast-pathed the SYN: %d fed", len(fed))
	}
	sent := ft.Sent()
	if len(sent) != 2 { // forged RST + the late SYN passed through
		t.Fatalf("sent %d packets, want 2 (RST + passed SYN)", len(sent))
	}
	if sp, ok := parsePkt(sent[1].Data); !ok || sp.seq != 8000 || !sp.syn() {
		t.Fatal("late SYN not passed through the ordinary branch")
	}
	k := flowtable.FlowKey{
		SrcIP:   v4mapped(parseIP4(testClientIP, [4]byte{})),
		DstIP:   v4mapped(srv),
		SrcPort: testClientPort + 1, DstPort: 443, Proto: protoTCP,
	}
	if f, ok := e.Flows().Get(k); !ok || f.State.Load() != flowtable.FlowNew {
		t.Fatalf("late SYN flow state = %v ok=%v, want FlowNew (inspect pipeline)", f, ok)
	}
}

// TestProcessUDPBlockQuic443 verifies the PRD §5 QUIC block end-to-end on
// the capture hot path: a udp/443 datagram under a proto-scoped block rule
// is DROPPED (counted, never re-injected — the browser falls back to TCP),
// while udp on another port and a TCP:443 SYN are passed untouched.
func TestProcessUDPBlockQuic443(t *testing.T) {
	cfg := &config.Config{
		Profile: "quic-block",
		Rules: []config.Rule{
			{Ports: "443", Proto: config.ProtoUDP, Action: config.ActionBlock},
			{Action: config.ActionDirect},
		},
	}
	e, ft, _ := newTestEngine(t, cfg, testDesyncParams("fake", 0), false)

	// QUIC Initial to :443 → BLOCK → drop.
	quic := buildUDP(testClientIP, testClientPort, testServerIP, 443, []byte("fake-quic-initial"))
	feed(t, e, quic, outboundAddr())
	// UDP to another port → pass.
	dns := buildUDP(testClientIP, testClientPort, testServerIP, 53, []byte("dns-query"))
	feed(t, e, dns, outboundAddr())
	// TCP:443 SYN → the udp rule is invisible to the TCP path → pass.
	syn := buildTCP(testClientIP, testClientPort, testServerIP, 443, 1000, 0, tcpFlagSYN, nil)
	feed(t, e, syn, outboundAddr())

	sent := ft.Sent()
	if len(sent) != 2 {
		t.Fatalf("sent %d packets, want 2 (dns + syn; the QUIC datagram must be dropped)", len(sent))
	}
	if got := sent[0].Data; len(got) != len(dns) {
		t.Errorf("sent[0] is not the udp:53 datagram (%d bytes)", len(got))
	}
	if got := sent[1].Data; len(got) != len(syn) {
		t.Errorf("sent[1] is not the tcp:443 SYN (%d bytes)", len(got))
	}
	cnt := e.Counters()
	if cnt.PacketsDrop != 1 {
		t.Errorf("PacketsDrop = %d, want 1", cnt.PacketsDrop)
	}
	if cnt.PacketsPass != 2 {
		t.Errorf("PacketsPass = %d, want 2", cnt.PacketsPass)
	}
}
