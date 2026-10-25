//go:build windows

package capture

// Phase-1 desync harness: a packet-level TSPU emulator that closes the loop
// around the engine WITHOUT WinDivert. Every packet the engine SENDS through
// the FakeTransport is consumed by tcpSim:
//
//   - TTL <= simFakeTTL  → fake: never delivered to the server's byte stream,
//     but fed to the DPI model (the TSPU sits before the drop hop);
//   - TTL  > simFakeTTL  → real data: reassembled by seq into the server's
//     stream (duplicates tolerated);
//   - RST flagged        → recorded (the engine must never forge one here);
//
// The DPI model feeds every arriving payload byte, in wire order, into one
// inspector.Stream and latches the FIRST terminal parse — the same
// "first ClientHello wins" semantics the doctrine's fake exploits. The
// server answers SYN (SYN-ACK) and, once the full CH is reassembled, with
// inbound application data so the engine marks the flow Established.
//
// Assertions per segmentation (CH split into 1/2/3/5 segments):
//   server sees the byte-exact ClientHello (no lost completing segment,
//   no seq/checksum damage), fakes strictly precede the first real CH byte,
//   the DPI latched the FAKE's SNI, no RST, flow Established.

import (
	"bytes"
	"fmt"
	"sort"
	"testing"

	"github.com/rupas/rupas/internal/config"
	"github.com/rupas/rupas/internal/flowtable"
	"github.com/rupas/rupas/internal/inspector"
	"github.com/rupas/rupas/internal/rules"
	"github.com/rupas/rupas/pkg/windivert"
)

const (
	simFakeTTL  = 8 // testDesyncParams TTL: packets at/below die before the server
	simSrvPort  = 443
	simAppBytes = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
)

// tcpSim is the TSPU-emulator endpoint.
type tcpSim struct {
	srvISN uint32

	segs     map[uint32][]byte // seq → real payload (server reassembly)
	rst      int               // RST packets seen
	fakes    int               // fake packets seen
	order    []string          // wire order: "fake" / "real:<len>@<seq>"
	dpi      *inspector.Stream // latches the first parseable CH on the wire
	dpiSNI   string            // SNI the DPI latched ("" = nothing parseable yet)
	appSent  bool
	synAcked bool
	consumed int // FakeTransport sends already ingested
}

func newTCPSim() *tcpSim {
	return &tcpSim{srvISN: 0x5A5A0000, segs: map[uint32][]byte{}, dpi: inspector.NewStream()}
}

// consume processes one packet the engine sent (the wire toward the TSPU).
func (s *tcpSim) consume(t *testing.T, data []byte) {
	t.Helper()
	p, ok := parsePkt(data)
	if !ok || !p.isTCP() {
		return
	}
	ttl := data[8]
	if p.rst() {
		s.rst++
		return
	}
	if len(p.payload) == 0 {
		return
	}
	if ttl <= simFakeTTL {
		s.fakes++
		s.order = append(s.order, "fake")
		s.dpiFeed(t, p.payload)
		return
	}
	s.order = append(s.order, fmt.Sprintf("real:%d@%d", len(p.payload), p.seq))
	s.segs[p.seq] = append([]byte(nil), p.payload...)
	s.dpiFeed(t, p.payload)
}

// dpiFeed runs the DPI model over one wire chunk.
func (s *tcpSim) dpiFeed(t *testing.T, chunk []byte) {
	t.Helper()
	if s.dpiSNI != "" || s.dpi.Done() {
		return
	}
	res, err := s.dpi.Feed(chunk)
	if s.dpi.Done() {
		if err != nil || !res.SNIFound {
			s.dpiSNI = "<unparseable>"
			return
		}
		s.dpiSNI = string(res.SNI)
	}
}

// serverStream rebuilds the contiguous byte stream the server received.
func (s *tcpSim) serverStream(first uint32) []byte {
	seqs := make([]uint32, 0, len(s.segs))
	for seq := range s.segs {
		seqs = append(seqs, seq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	var out []byte
	next := first
	for _, seq := range seqs {
		if seq != next {
			break // gap: the rest is unreceived
		}
		out = append(out, s.segs[seq]...)
		next += uint32(len(s.segs[seq]))
	}
	return out
}

// drainSim consumes everything the engine has sent so far and answers like
// the server: SYN → SYN-ACK once; full CH reassembled → inbound app data once.
func drainSim(t *testing.T, e *Engine, ft *FakeTransport, sim *tcpSim, cliISN, chLen int) {
	t.Helper()
	sent := ft.Sent()
	for _, sp := range sent[sim.consumed:] {
		sim.consume(t, sp.Data)
	}
	sim.consumed = len(sent)
	if !sim.synAcked {
		sim.synAcked = true
		synack := simBuildTCP(testServerIP, simSrvPort, testClientIP, testClientPort,
			sim.srvISN, uint32(cliISN+1), tcpFlagSYN|tcpFlagACK, nil)
		feed(t, e, synack, inboundAddr())
	}
	if !sim.appSent && len(sim.serverStream(uint32(cliISN+1))) >= chLen {
		sim.appSent = true
		srvData := simBuildTCP(testServerIP, simSrvPort, testClientIP, testClientPort,
			sim.srvISN+1, uint32(cliISN+1+chLen), tcpFlagACK|tcpFlagPSH, []byte(simAppBytes))
		feed(t, e, srvData, inboundAddr())
	}
}

// buildLargeClientHello serializes a CH of exactly total bytes: SNI plus a
// padding extension (0x0015).
func buildLargeClientHello(sni string, total int) []byte {
	small := buildClientHello(sni, false)
	// 5 record + 4 handshake + 2 ver + 32 random + 1 sid + 2 csLen +
	// 2 suites + 1 compLen + 1 comp + 2 extLen = 52 → extensions block.
	exts := append([]byte(nil), small[52:]...)
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)                   // session_id length
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher_suites
	body = append(body, 0x01, 0x00)             // compression methods

	pad := total - (5 + 4 + len(body) + 2 + len(exts)) - 4
	if pad < 0 {
		panic("buildLargeClientHello: target too small")
	}
	padExt := []byte{0x00, 0x15, byte(pad >> 8), byte(pad)}
	padExt = append(padExt, make([]byte, pad)...)
	exts = append(exts, padExt...)
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)

	out := make([]byte, 0, 5+4+len(body))
	out = append(out, 0x16, 0x03, 0x01, byte((4+len(body))>>8), byte(4+len(body)))
	out = append(out, 0x01, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	return append(out, body...)
}

// simBuildTCP builds a wire-realistic packet: buildTCP + precomputed
// checksums (the production NIC/driver computes them before WinDivert
// captures; the engine never re-fixes pass-through packets).
func simBuildTCP(src string, sport uint16, dst string, dport uint16, seq, ack uint32, flags byte, payload []byte) []byte {
	pkt := buildTCP(src, sport, dst, dport, seq, ack, flags, payload)
	a := windivert.Address{}
	_ = fixChecksumsGo(pkt, &a)
	return pkt
}

// newTestEngineTpl is newTestEngine with a custom fake template (the
// production engine ships a real uTLS ClientHello as fake-chrome.bin, so
// the DPI model here needs a parseable decoy CH too).
func newTestEngineTpl(t *testing.T, rulesCfg *config.Config, params config.DesyncParams, tpl []byte) (*Engine, *FakeTransport) {
	t.Helper()
	if rulesCfg.Desync == (config.DesyncParams{}) {
		rulesCfg.Desync = params
	}
	tbl, err := rules.Compile(rulesCfg)
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	e, err := New(Options{
		Rules:        tbl,
		Desync:       params,
		FakeTemplate: tpl,
		TProxyPort:   testTProxyPort,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ft := NewFakeTransport()
	e.InjectTransport(ft, nil)
	return e, ft
}

// runDesyncHandshake drives one full client session against the engine and
// the emulator: SYN → SYN-ACK → CH in k near-equal segments → server data.
func runDesyncHandshake(t *testing.T, e *Engine, ft *FakeTransport, sni string, chLen, k int) (*tcpSim, []byte, uint32) {
	t.Helper()
	ch := buildLargeClientHello(sni, chLen)
	cliISN := uint32(1000)
	sim := newTCPSim()

	syn := simBuildTCP(testClientIP, testClientPort, testServerIP, simSrvPort, cliISN, 0, tcpFlagSYN, nil)
	feed(t, e, syn, outboundAddr())

	chunk := (chLen + k - 1) / k
	seq := cliISN + 1
	for off := 0; off < len(ch); off += chunk {
		end := off + chunk
		if end > len(ch) {
			end = len(ch)
		}
		seg := simBuildTCP(testClientIP, testClientPort, testServerIP, simSrvPort,
			seq, sim.srvISN+1, tcpFlagACK|tcpFlagPSH, ch[off:end])
		feed(t, e, seg, outboundAddr())
		drainSim(t, e, ft, sim, int(cliISN), len(ch))
		seq += uint32(end - off)
	}
	drainSim(t, e, ft, sim, int(cliISN), len(ch))
	return sim, ch, cliISN + 1
}

// assertDoctrineWireShape checks every Phase-1 criterion against one run.
func assertDoctrineWireShape(t *testing.T, e *Engine, ft *FakeTransport, sim *tcpSim, ch []byte, cliSeq uint32) {
	t.Helper()
	// (a) completing segment not lost: the server's stream is byte-exact.
	got := sim.serverStream(cliSeq)
	if !bytes.Equal(got, ch) {
		t.Fatalf("server CH mismatch: got %d bytes, want %d (first diff at %d)",
			len(got), len(ch), firstDiff(got, ch))
	}
	// (b) checksums of released real segments survive the hold.
	for _, sp := range ft.Sent() {
		if p, ok := parsePkt(sp.Data); ok && len(p.payload) > 0 && sp.Data[8] > simFakeTTL {
			if !checksumsValid(sp.Data) {
				t.Fatalf("released real segment seq=%d has broken checksums", p.seq)
			}
		}
	}
	// (c) doctrine: exactly Repeats fakes, strictly before ANY real byte.
	if sim.fakes != 2 {
		t.Fatalf("fakes = %d, want 2 (Repeats)", sim.fakes)
	}
	firstReal, lastFake := -1, -1
	for i, o := range sim.order {
		if o == "fake" {
			lastFake = i
		} else if firstReal < 0 {
			firstReal = i
		}
	}
	if firstReal >= 0 && lastFake > firstReal {
		t.Fatalf("doctrine violated: fake (idx %d) follows the first real CH byte (idx %d)", lastFake, firstReal)
	}
	for _, sp := range ft.Sent() {
		p, ok := parsePkt(sp.Data)
		if !ok || len(p.payload) == 0 || sp.Data[8] > simFakeTTL {
			continue
		}
		if p.seq != cliSeq {
			t.Fatalf("fake seq = %d, want %d (first CH segment's seq)", p.seq, cliSeq)
		}
		if p.ackNum != sim.srvISN+1 {
			t.Fatalf("fake ack = %d, want %d", p.ackNum, sim.srvISN+1)
		}
	}
	// The DPI latched the DECOY (the fake), not the real SNI.
	if sim.dpiSNI != "decoy.example" {
		t.Fatalf("DPI latched SNI = %q, want decoy.example", sim.dpiSNI)
	}
	// (d) the engine never forged an RST on this path.
	if sim.rst != 0 {
		t.Fatalf("engine sent %d RST(s) on the desync path", sim.rst)
	}
	if !sim.appSent {
		t.Fatal("server never received the full CH — no app response sent")
	}
	f, ok := flowOf(e, testServerIP, simSrvPort)
	if !ok || f.State.Load() != flowtable.FlowEstablished {
		st := "missing"
		if ok {
			st = fmt.Sprint(f.State.Load())
		}
		t.Fatalf("flow not Established after handshake (state %s)", st)
	}
	if c := e.Counters(); c.HandshakeOK != 1 {
		t.Fatalf("HandshakeOK = %d, want 1: %+v", c.HandshakeOK, c)
	}
}

// TestDesyncMultiSegmentTSPU drives the fake-strategy desync against the
// TSPU emulator with the CH split into 1/2/3/5 segments.
func TestDesyncMultiSegmentTSPU(t *testing.T) {
	const realSNI = "www.youtube.com"
	const chLen = 1647

	cfg := &config.Config{
		Profile: "test",
		Rules:   []config.Rule{{SNI: realSNI, Action: config.ActionDesync}},
	}

	for _, k := range []int{1, 2, 3, 5} {
		t.Run(fmt.Sprintf("segs=%d", k), func(t *testing.T) {
			e, ft := newTestEngineTpl(t, cfg, testDesyncParams("fake", 0), buildClientHello("decoy.example", false))
			sim, ch, cliSeq := runDesyncHandshake(t, e, ft, realSNI, chLen, k)
			assertDoctrineWireShape(t, e, ft, sim, ch, cliSeq)
		})
	}
}

// TestDesyncMultiSegmentLiveShape replays the exact live-measured split of
// the failing Schannel/PQ CH: 1436 + 211 bytes across 2 segments.
func TestDesyncMultiSegmentLiveShape(t *testing.T) {
	const realSNI = "www.youtube.com"
	cfg := &config.Config{
		Profile: "test",
		Rules:   []config.Rule{{SNI: realSNI, Action: config.ActionDesync}},
	}
	e, ft := newTestEngineTpl(t, cfg, testDesyncParams("fake", 0), buildClientHello("decoy.example", false))

	ch := buildLargeClientHello(realSNI, 1647)
	if len(ch) != 1647 {
		t.Fatalf("builder produced %d bytes, want 1647", len(ch))
	}
	cliISN := uint32(0x11223300)
	sim := newTCPSim()

	syn := simBuildTCP(testClientIP, testClientPort, testServerIP, simSrvPort, cliISN, 0, tcpFlagSYN, nil)
	feed(t, e, syn, outboundAddr())

	cuts := []int{1436, len(ch) - 1436}
	seq := cliISN + 1
	off := 0
	for _, cut := range cuts {
		end := off + cut
		seg := simBuildTCP(testClientIP, testClientPort, testServerIP, simSrvPort,
			seq, sim.srvISN+1, tcpFlagACK|tcpFlagPSH, ch[off:end])
		feed(t, e, seg, outboundAddr())
		drainSim(t, e, ft, sim, int(cliISN), len(ch))
		seq += uint32(end - off)
		off = end
	}

	assertDoctrineWireShape(t, e, ft, sim, ch, cliISN+1)
}

func firstDiff(got, want []byte) int {
	n := len(got)
	if len(want) < n {
		n = len(want)
	}
	for i := 0; i < n; i++ {
		if got[i] != want[i] {
			return i
		}
	}
	return n
}
