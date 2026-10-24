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
// payload, use seq-1, TTL from the op, valid checksums and the Impostor
// address flag.
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
		if p.seq != seq-1 {
			t.Fatalf("fake %d seq = %d, want %d (seq-1)", i, p.seq, seq-1)
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
		if !sent[i].Addr.Impostor() {
			t.Fatalf("fake %d not marked impostor", i)
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
	// Part2 is a crafted packet (cloned headers): impostor flag expected.
	if !sent[3].Addr.Impostor() {
		t.Fatal("part2 not marked impostor")
	}

	f, _ := flowOf(e, testServerIP, 443)
	if f.State.Load() != flowtable.FlowDesynced {
		t.Fatalf("flow state = %d", f.State.Load())
	}
}

// TestClientHelloTwoSegments: a CH split across two segments is passed
// through until the completing segment, which then triggers the desync ops
// with fake seq = completing segment's seq - 1.
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
	if got := ft.Sent(); len(got) != 1 || !bytes.Equal(got[0].Data, seg1) {
		t.Fatalf("partial CH not passed through untouched: %d sent", len(got))
	}
	feed(t, e, seg2, outboundAddr())

	sent := ft.Sent()
	if len(sent) != 4 { // seg1 + 2 fakes + seg2
		t.Fatalf("sent %d packets, want 4", len(sent))
	}
	fp, ok := parsePkt(sent[1].Data)
	if !ok {
		t.Fatal("fake unparseable")
	}
	if fp.seq != 1000+uint32(cut)-1 {
		t.Fatalf("fake seq %d, want %d (completing segment seq - 1)", fp.seq, 1000+uint32(cut)-1)
	}
	if !bytes.Equal(sent[3].Data, seg2) {
		t.Fatal("completing segment not forwarded after the fakes")
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

// TestNATRoundtripTCP drives a full redirect life cycle:
// SYN (first pass, verdict needs the CH) → CH redirected → SYN retransmit
// redirected → data redirected → loopback reply reverse-translated →
// OrigDst preserved all along → FIN tears everything down.
func TestNATRoundtripTCP(t *testing.T) {
	e, ft, loop := newTestEngine(t, tunnelTestConfig(), testDesyncParams("fake", 0), true)

	// 1. First SYN: flow is NEW, verdict unknown yet → passed untouched.
	syn := buildTCP(testClientIP, testClientPort, testTGIP, 443, 9000, 0, tcpFlagSYN, nil)
	feed(t, e, syn, outboundAddr())

	// 2. ClientHello: CIDR rule → TUNNEL → dst rewritten to 127.0.0.1:9443.
	ch := buildClientHello("telegram.zzz", false) // SNI matches nothing; CIDR decides
	chPkt := buildTCP(testClientIP, testClientPort, testTGIP, 443, 9001, 1, tcpFlagACK|tcpFlagPSH, ch)
	feed(t, e, chPkt, outboundAddr())

	sent := ft.Sent()
	if len(sent) != 2 {
		t.Fatalf("sent %d, want 2", len(sent))
	}
	natPkt := sent[1].Data
	p, ok := parsePkt(natPkt)
	if !ok {
		t.Fatal("NAT packet unparseable")
	}
	if p.dst4 != loopback4 {
		t.Fatalf("NAT dst = %v, want 127.0.0.1", p.dst4)
	}
	if p.dstPort != testTProxyPort {
		t.Fatalf("NAT dstPort = %d, want %d", p.dstPort, testTProxyPort)
	}
	if p.src4 != parseIP4(testClientIP, [4]byte{}) || p.srcPort != testClientPort {
		t.Fatalf("NAT src changed: %v:%d", p.src4, p.srcPort)
	}
	if !checksumsValid(natPkt) {
		t.Fatal("NAT packet checksums invalid")
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

	// 3. SYN retransmission of a TUNNEL flow is re-redirected (§3.2).
	feed(t, e, syn, outboundAddr())
	last := ft.Sent()
	np, _ := parsePkt(last[len(last)-1].Data)
	if np.dst4 != loopback4 || np.dstPort != testTProxyPort {
		t.Fatal("SYN retransmit not redirected")
	}

	// 4. Subsequent data is redirected too. (Keep a pristine copy: the
	// engine edits the packet buffer in place on the NAT path.)
	data := buildTCP(testClientIP, testClientPort, testTGIP, 443, 9001+uint32(len(ch)), 1, tcpFlagACK|tcpFlagPSH, []byte("MTProtoData"))
	dataPristine := append([]byte(nil), data...)
	feed(t, e, data, outboundAddr())
	last = ft.Sent()
	np, _ = parsePkt(last[len(last)-1].Data)
	if np.dst4 != loopback4 || np.dstPort != testTProxyPort {
		t.Fatal("tunnel data segment not redirected")
	}
	if bytes.Equal(last[len(last)-1].Data, dataPristine) {
		t.Fatal("tunnel data forwarded un-NATed")
	}

	// 5. Loopback reply: src 127.0.0.1:9443 → reverse-translated to the
	// original server, dst = client.
	reply := buildTCP("127.0.0.1", testTProxyPort, testClientIP, testClientPort, 1, 9001+uint32(len(ch))+14, tcpFlagACK|tcpFlagPSH, []byte("ServerHello+"))
	e.processLoopback(loop, reply, ptrOf(inboundAddr()))

	loopSent := loop.Sent()
	if len(loopSent) != 1 {
		t.Fatalf("loopback sent %d, want 1", len(loopSent))
	}
	rp, ok := parsePkt(loopSent[0].Data)
	if !ok {
		t.Fatal("reverse-NAT packet unparseable")
	}
	if rp.src4 != parseIP4(testTGIP, [4]byte{}) || rp.srcPort != 443 {
		t.Fatalf("reverse-NAT src = %v:%d, want original server", rp.src4, rp.srcPort)
	}
	if rp.dst4 != parseIP4(testClientIP, [4]byte{}) || rp.dstPort != testClientPort {
		t.Fatalf("reverse-NAT dst = %v:%d, want client", rp.dst4, rp.dstPort)
	}
	if !checksumsValid(loopSent[0].Data) {
		t.Fatal("reverse-NAT checksums invalid")
	}
	// OrigDst must survive the round-trip unchanged.
	f2, _ := flowOf(e, testTGIP, 443)
	if f2.OrigDst != wantOrig || f2.OrigPort != 443 {
		t.Fatalf("OrigDst leaked/mutated after round-trip: %v:%d", f2.OrigDst, f2.OrigPort)
	}

	// 6. FIN from the client: redirected, then full teardown.
	fin := buildTCP(testClientIP, testClientPort, testTGIP, 443, 9001+uint32(len(ch))+14, 1, tcpFlagACK|tcpFlagFIN, nil)
	feed(t, e, fin, outboundAddr())
	last = ft.Sent()
	np, _ = parsePkt(last[len(last)-1].Data)
	if np.dst4 != loopback4 {
		t.Fatal("FIN not redirected")
	}
	if n := e.Flows().Len(); n != 0 {
		t.Fatalf("flow table not empty after FIN: %d", n)
	}
	// After teardown the NAT entry is gone: a stray loopback packet passes
	// through untouched.
	stray := buildTCP("127.0.0.1", testTProxyPort, testClientIP, testClientPort, 1, 1, tcpFlagACK, nil)
	e.processLoopback(loop, stray, ptrOf(inboundAddr()))
	loopSent = loop.Sent()
	if len(loopSent) != 2 {
		t.Fatalf("stray loopback packet: %d sent", len(loopSent))
	}
	if sp, _ := parsePkt(loopSent[1].Data); sp.src4 != loopback4 {
		t.Fatal("stray loopback packet was reverse-NATed without a flow")
	}

	if c := e.Counters(); c.PacketsRedir != 4 { // CH + SYN-retrans + data + FIN
		t.Fatalf("redirect counter = %d, want 4: %+v", c.PacketsRedir, c)
	}
}

// TestNATUDPRelay: UDP relay traffic to the TG CIDR is NAT-redirected and
// reverse-translated on the loopback handle.
func TestNATUDPRelay(t *testing.T) {
	e, ft, loop := newTestEngine(t, tunnelTestConfig(), testDesyncParams("fake", 0), true)

	udp := buildUDP(testClientIP, 53333, testTGIP, 50001, []byte("voice-packet"))
	feed(t, e, udp, outboundAddr())

	sent := ft.Sent()
	if len(sent) != 1 {
		t.Fatalf("sent %d, want 1", len(sent))
	}
	p, ok := parsePkt(sent[0].Data)
	if !ok || !p.isUDP() {
		t.Fatal("NAT UDP packet unparseable")
	}
	if p.dst4 != loopback4 || p.dstPort != testTProxyPort {
		t.Fatalf("UDP NAT dst %v:%d", p.dst4, p.dstPort)
	}
	if !checksumsValid(sent[0].Data) {
		t.Fatal("UDP NAT checksums invalid")
	}

	reply := buildUDP("127.0.0.1", testTProxyPort, testClientIP, 53333, []byte("voice-reply"))
	e.processLoopback(loop, reply, ptrOf(inboundAddr()))
	rp, ok := parsePkt(loop.Sent()[0].Data)
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
// the ClientHello carries an ECH extension.
func TestECHForcesTunnel(t *testing.T) {
	cfg := &config.Config{
		Profile: "test",
		Rules: []config.Rule{
			{SNI: "blocked.example", Action: config.ActionDesync},
		},
	}
	e, ft, _ := newTestEngine(t, cfg, testDesyncParams("fake", 0), true)

	ch := buildClientHello("blocked.example", true)
	pkt := buildTCP(testClientIP, testClientPort, testServerIP, 443, 1000, 1, tcpFlagACK|tcpFlagPSH, ch)
	feed(t, e, pkt, outboundAddr())

	sent := ft.Sent()
	if len(sent) != 1 {
		t.Fatalf("sent %d, want 1 (NAT-redirected, no fakes)", len(sent))
	}
	p, _ := parsePkt(sent[0].Data)
	if p.dst4 != loopback4 || p.dstPort != testTProxyPort {
		t.Fatal("ECH flow not redirected to the tunnel")
	}
	if c := e.Counters(); c.PacketsDesync != 0 || c.PacketsRedir != 1 {
		t.Fatalf("counters: %+v", c)
	}
	f, _ := flowOf(e, testServerIP, 443)
	if !f.ECH || f.State.Load() != flowtable.FlowTunnel {
		t.Fatalf("flow ECH=%v state=%d", f.ECH, f.State.Load())
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
// goroutines touch the nat/streams maps.
func TestConcurrentLoopsRace(t *testing.T) {
	e, ft, loop := newTestEngine(t, tunnelTestConfig(), testDesyncParams("fake", 0), true)

	ch := buildClientHello("tg.zzz", false)
	syn := buildTCP(testClientIP, testClientPort, testTGIP, 443, 1000, 0, tcpFlagSYN, nil)
	chPkt := buildTCP(testClientIP, testClientPort, testTGIP, 443, 1001, 1, tcpFlagACK|tcpFlagPSH, ch)
	data := buildTCP(testClientIP, testClientPort, testTGIP, 443, 1001+uint32(len(ch)), 1, tcpFlagACK|tcpFlagPSH, []byte("payload"))
	ft.Enqueue(syn, true)
	ft.Enqueue(chPkt, true)
	ft.Enqueue(data, true)

	reply := buildTCP("127.0.0.1", testTProxyPort, testClientIP, testClientPort, 1, 1200, tcpFlagACK|tcpFlagPSH, []byte("srv-data"))
	finReply := buildTCP("127.0.0.1", testTProxyPort, testClientIP, testClientPort, 2, 1200, tcpFlagACK|tcpFlagFIN, nil)
	loop.Enqueue(reply, false)
	loop.Enqueue(finReply, false) // triggers nat cleanup from the loop goroutine

	done := make(chan error, 1)
	go func() { done <- e.Run(context.Background()) }()

	deadline := time.Now().Add(5 * time.Second)
	for (len(ft.Sent()) < 3 || len(loop.Sent()) < 2) && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if len(ft.Sent()) < 3 || len(loop.Sent()) < 2 {
		t.Fatalf("loops stalled: main=%d loopback=%d", len(ft.Sent()), len(loop.Sent()))
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
