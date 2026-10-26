package android

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// makeClientHello builds a minimal TLS 1.3 record carrying one
// ClientHello with a server_name extension and, when echPayload is
// non-nil, an ECH extension (0xfe0d) with exactly that payload.
func makeClientHello(t *testing.T, sni string, echPayload []byte) []byte {
	t.Helper()
	var exts []byte
	if sni != "" {
		var nameList []byte
		nameList = append(nameList, 0x00) // name_type: host_name
		nameList = append(nameList, byte(len(sni)>>8), byte(len(sni)))
		nameList = append(nameList, sni...)
		listLen := len(nameList)
		sniExt := append([]byte{byte(listLen >> 8), byte(listLen)}, nameList...)
		exts = append(exts, 0x00, 0x00, byte(len(sniExt)>>8), byte(len(sniExt)))
		exts = append(exts, sniExt...)
	}
	if echPayload != nil {
		exts = append(exts, 0xfe, 0x0d, byte(len(echPayload)>>8), byte(len(echPayload)))
		exts = append(exts, echPayload...)
	}
	var body []byte
	body = append(body, 0x03, 0x03)             // legacy_version
	body = append(body, make([]byte, 32)...)    // random
	body = append(body, 0x00)                   // session_id: empty
	body = append(body, 0x00, 0x02, 0x13, 0x01) // cipher_suites: TLS_AES_128_GCM_SHA256
	body = append(body, 0x01, 0x00)             // compression: null
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)

	hs := append([]byte{0x01, 0x00, byte(len(body) >> 8), byte(len(body))}, body...)
	rec := append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)
	return rec
}

func TestPeekClientHelloExtractsSNI(t *testing.T) {
	ch := makeClientHello(t, "Example.RU", nil)

	server, client := net.Pipe()
	defer client.Close()
	go func() {
		server.Write(ch) //nolint:errcheck
		server.Close()
	}()

	sni, ech, wrapped := peekClientHello(client)
	if sni != "example.ru" {
		t.Fatalf("sni = %q, want example.ru", sni)
	}
	if ech {
		t.Fatal("no ECH ext present, ech must be false")
	}
	// The peek must be non-destructive: every byte comes back.
	got, err := io.ReadAll(wrapped)
	if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
		t.Fatalf("read after peek: %v", err)
	}
	if string(got) != string(ch) {
		t.Fatalf("peek damaged the stream: got %d bytes, want %d", len(got), len(ch))
	}
}

func TestPeekGREASEIsNotECH(t *testing.T) {
	// Chrome attaches a single 0x00 byte ECH (GREASE) to almost every CH:
	// it must NOT set the ECH flag.
	grease := makeClientHello(t, "example.com", []byte{0x00})
	server, client := net.Pipe()
	defer client.Close()
	go func() { server.Write(grease); server.Close() }()

	sni, ech, _ := peekClientHello(client)
	if sni != "example.com" || ech {
		t.Fatalf("GREASE CH: sni=%q ech=%v, want ech=false", sni, ech)
	}
}

func TestPeekRealECHDetected(t *testing.T) {
	// Payload > 1 byte = a real HPKE-encrypted inner ClientHello.
	real := makeClientHello(t, "discord.com", []byte{0x01, 0x02, 0x03, 0x04})
	server, client := net.Pipe()
	defer client.Close()
	go func() { server.Write(real); server.Close() }()

	_, ech, _ := peekClientHello(client)
	if !ech {
		t.Fatal("4-byte ECH payload must set ech=true")
	}
}

func TestPeekNonTLSTimesOutCleanly(t *testing.T) {
	// Server-speaks-first protocol: no bytes arrive; peek must return
	// within the timeout with empty SNI and a usable conn.
	server, client := net.Pipe()
	defer client.Close()
	defer server.Close()

	start := time.Now()
	sni, _, wrapped := peekClientHello(client)
	if sni != "" {
		t.Fatalf("sni = %q, want empty", sni)
	}
	if elapsed := time.Since(start); elapsed > sniPeekTimeout+time.Second {
		t.Fatalf("peek waited %v, want <= %v", elapsed, sniPeekTimeout)
	}
	// The conn still works for the relay: a write on the other end must
	// be readable (prefix empty → passthrough).
	go func() { server.Write([]byte("SSH-2.0")) }()          //nolint:errcheck
	wrapped.SetReadDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
	buf := make([]byte, 7)
	if _, err := io.ReadFull(wrapped, buf); err != nil {
		t.Fatalf("read through wrapped conn: %v", err)
	}
	if string(buf) != "SSH-2.0" {
		t.Fatalf("got %q", buf)
	}
}

// deadRelayEngine builds a W3 engine whose relay points at a refused
// loopback port (a mock of a dead socks inbound).
func deadRelayEngine(t *testing.T, fallback bool, log *syncBuffer) *Engine {
	t.Helper()
	return &Engine{
		verdict:  DirectVerdict,
		protect:  func(int) bool { return true },
		logFn:    log.line,
		dialer:   ProtectedDialer(func(int) bool { return true }),
		settings: &Settings{UUID: "u", Server: "127.0.0.1", Port: 1, Fallback: fallback},
		rules:    CompileRules(),
		// Relay present but never started → socks dial refused fast.
		relay: NewRelay(&Settings{UUID: "u", Server: "127.0.0.1", Port: 1, Fallback: fallback},
			func(line string) { log.line(line) }),
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  []byte
}

func (s *syncBuffer) line(l string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.b = append(s.b, l...)
	s.b = append(s.b, '\n')
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(s.b)
}

func TestSocksFallbackEscalatesToDirect(t *testing.T) {
	var log syncBuffer
	e := deadRelayEngine(t, true, &log)
	// Aim the socks handshake at a port nothing listens on: refusal is
	// immediate on loopback.
	e.relay.socksAddr = "127.0.0.1:1"

	// The direct destination is a real loopback listener: escalation must
	// land on it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, lErr := ln.Accept()
		if lErr == nil {
			c.Close()
		}
	}()

	dst := ln.Addr().(*net.TCPAddr).AddrPort()
	meta := FlowMeta{Network: "tcp", Destination: dst, SNI: "google.com"} // default rule → TUNNEL
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, escalated, err := e.dialEgress(ctx, meta)
	if err != nil {
		t.Fatalf("dialEgress: %v", err)
	}
	conn.Close()
	if !escalated {
		t.Fatal("flow must be marked escalated (honest tunnel->direct)")
	}
	snap := e.Snapshot()
	if snap.TunnelDials != 1 || snap.TunnelEscalated != 1 {
		t.Fatalf("counters: dials=%d escalated=%d, want 1/1", snap.TunnelDials, snap.TunnelEscalated)
	}
	if !strings.Contains(log.String(), "ESCALATED tunnel->direct") {
		t.Fatalf("log must mark the escalation honestly, got:\n%s", log.String())
	}
}

func TestSocksFallbackDisabledDrops(t *testing.T) {
	var log syncBuffer
	e := deadRelayEngine(t, false, &log)
	e.relay.socksAddr = "127.0.0.1:1"

	meta := FlowMeta{Network: "tcp", Destination: netip.MustParseAddrPort("1.2.3.4:443"), SNI: "google.com"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, escalated, err := e.dialEgress(ctx, meta)
	if err == nil {
		conn.Close()
		t.Fatal("fallback=false must refuse the flow when the tunnel fails")
	}
	if !escalated {
		t.Fatal("refusal must still be counted as an escalation event")
	}
	if snap := e.Snapshot(); snap.TunnelEscalated != 1 {
		t.Fatalf("escalated counter = %d, want 1", snap.TunnelEscalated)
	}
}

func TestDialEgressBlockAndDirect(t *testing.T) {
	var log syncBuffer
	e := deadRelayEngine(t, true, &log)
	e.relay.socksAddr = "127.0.0.1:1"

	// QUIC → BLOCK (no dial attempted, sentinel error).
	_, _, err := e.dialEgress(context.Background(),
		FlowMeta{Network: "udp", Destination: netip.MustParseAddrPort("8.8.8.8:443")})
	if !errors.Is(err, errFlowBlocked) {
		t.Fatalf("udp/443: got %v, want errFlowBlocked", err)
	}
	// LAN → DIRECT: no tunnel dial counter (192.168.x is in the LAN
	// table; the direct dial to .1 fails harmlessly — we only assert the
	// routing, not the connectivity).
	before := e.Snapshot()
	conn, escalated, err := e.dialEgress(context.Background(),
		FlowMeta{Network: "tcp", Destination: netip.MustParseAddrPort("192.168.1.1:1")})
	if err == nil {
		conn.Close()
	}
	if escalated {
		t.Fatal("LAN flow must not be escalated")
	}
	if after := e.Snapshot(); after.TunnelDials != before.TunnelDials {
		t.Fatal("DIRECT flow must not touch the tunnel")
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		len(needle) == 0 ||
		indexOf(haystack, needle) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
