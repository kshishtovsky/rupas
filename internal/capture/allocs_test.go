//go:build windows

package capture

import (
	"testing"

	"github.com/rupas/rupas/internal/config"
	"github.com/rupas/rupas/internal/flowtable"
	"github.com/rupas/rupas/internal/rules"
)

// TestAllocsPerRunZero pins the §3.2 invariant: 0 heap allocations per
// processed packet in the steady state (warm flow, retransmitted SYN, pure
// ACK, established data). The send path is a no-op transport so the
// measurement covers exactly the engine's hot path.
func TestAllocsPerRunZero(t *testing.T) {
	cfg := &config.Config{
		Profile: "test",
		Rules: []config.Rule{
			{SNI: "blocked.example", Action: config.ActionDesync},
			{Action: config.ActionDirect},
		},
		Desync: testDesyncParams("fake", 0),
	}
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
	e.InjectTransport(noopTransport{}, nil)

	ch := buildClientHello("blocked.example", false)
	syn := buildTCP(testClientIP, testClientPort, testServerIP, 443, 1000, 0, tcpFlagSYN, nil)
	chPkt := buildTCP(testClientIP, testClientPort, testServerIP, 443, 1001, 1, tcpFlagACK|tcpFlagPSH, ch)
	dataPkt := buildTCP(testClientIP, testClientPort, testServerIP, 443, 1001+uint32(len(ch)), 1, tcpFlagACK|tcpFlagPSH, []byte("application data follows"))
	ackPkt := buildTCP(testClientIP, testClientPort, testServerIP, 443, 1400, 1001+uint32(len(ch)), tcpFlagACK, nil)
	out := outboundAddr()

	// Warm-up: SYN + ClientHello decision + server data → ESTABLISHED, and
	// one round through every measured packet shape.
	e.processPacket(syn, &out)
	e.processPacket(chPkt, &out)
	srvData := buildTCP(testServerIP, 443, testClientIP, testClientPort, 1, 1400, tcpFlagACK|tcpFlagPSH, []byte("ServerHello"))
	in := inboundAddr()
	e.processPacket(srvData, &in)
	e.processPacket(dataPkt, &out)
	e.processPacket(ackPkt, &out)

	if f, _ := flowOf(e, testServerIP, 443); f == nil || f.State.Load() != flowtable.FlowEstablished {
		t.Fatal("precondition: flow not ESTABLISHED after warm-up")
	}

	allocs := testing.AllocsPerRun(200, func() {
		e.processPacket(dataPkt, &out) // warm data on decided flow
		e.processPacket(ackPkt, &out)  // pure ACK
		e.processPacket(syn, &out)     // SYN retransmission (existing flow)
		e.processPacket(chPkt, &out)   // CH retransmission after decision
	})
	if allocs != 0 {
		t.Fatalf("hot path allocated %v objects per iteration; want 0", allocs)
	}
}

// TestNATWarmPathAllocs: redirected (TUNNEL) flows must also be
// allocation-free once the NAT entry exists.
func TestNATWarmPathAllocs(t *testing.T) {
	tbl, err := rules.Compile(tunnelTestConfig())
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
	e.InjectTransport(noopTransport{}, nil)

	out := outboundAddr()
	in := inboundAddr()
	ch := buildClientHello("x.y", false)
	chPkt := buildTCP(testClientIP, testClientPort, testTGIP, 443, 1000, 1, tcpFlagACK|tcpFlagPSH, ch)
	dataPkt := buildTCP(testClientIP, testClientPort, testTGIP, 443, 1000+uint32(len(ch)), 1, tcpFlagACK|tcpFlagPSH, []byte("more mtproto"))
	ackPkt := buildTCP(testClientIP, testClientPort, testTGIP, 443, 1100, 1, tcpFlagACK, nil)
	reply := buildTCP("127.0.0.1", testTProxyPort, testClientIP, testClientPort, 1, 1100, tcpFlagACK|tcpFlagPSH, []byte("srv"))

	// Warm-up: create the flow + NAT entry (CH → redirect), one loopback
	// reverse translation, one data redirect.
	e.processPacket(chPkt, &out)
	e.processLoopback(noopTransport{}, reply, &in)
	e.processPacket(dataPkt, &out)
	e.processPacket(ackPkt, &out)

	allocs := testing.AllocsPerRun(200, func() {
		e.processPacket(dataPkt, &out)
		e.processPacket(ackPkt, &out)
		e.processLoopback(noopTransport{}, reply, &in)
	})
	if allocs != 0 {
		t.Fatalf("NAT warm path allocated %v objects per iteration; want 0", allocs)
	}
}

// TestFiltersGolden pins the exact filter strings (§3.1) and, when the DLL
// is loadable, validates them through the real filter compiler.
func TestFiltersGolden(t *testing.T) {
	main, err := BuildMainFilter([]string{"149.154.160.0/20", "91.108.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	wantMain := "(outbound and tcp and tcp.DstPort == 443) or " +
		"(outbound and ((ip.DstAddr >= 149.154.160.0 and ip.DstAddr <= 149.154.175.255) or " +
		"(ip.DstAddr >= 91.108.0.0 and ip.DstAddr <= 91.108.255.255))) or " +
		"(outbound and udp and udp.DstPort >= 50000 and udp.DstPort <= 65535)"
	if main != wantMain {
		t.Fatalf("main filter:\n got %s\nwant %s", main, wantMain)
	}

	lo, err := BuildLoopbackFilter(testTProxyPort)
	if err != nil {
		t.Fatal(err)
	}
	wantLo := "(inbound and tcp and tcp.SrcPort == 9443 and ip.SrcAddr == 127.0.0.1) or " +
		"(inbound and udp and udp.SrcPort == 9443 and ip.SrcAddr == 127.0.0.1)"
	if lo != wantLo {
		t.Fatalf("loopback filter:\n got %s\nwant %s", lo, wantLo)
	}

	if dllAvailable(t) {
		if err := windivertValidate(main); err != nil {
			t.Fatalf("main filter rejected by WinDivert: %v", err)
		}
		if err := windivertValidate(lo); err != nil {
			t.Fatalf("loopback filter rejected by WinDivert: %v", err)
		}
	} else {
		t.Log("WinDivert.dll not loadable; skipping compiler validation")
	}
}
