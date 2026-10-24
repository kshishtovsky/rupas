package tunnel

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rupas/rupas/internal/config"
	"github.com/sagernet/sing-box/option"
)

// mapProvider is an OriginalDstProvider backed by a map, with lookup
// counting to observe 4-tuple keying and session reuse.
type mapProvider struct {
	mu      sync.Mutex
	m       map[string]netip.AddrPort
	lookups map[string]int
	drops   map[string]bool // keys that report ok=false
}

func newMapProvider() *mapProvider {
	return &mapProvider{
		m:       make(map[string]netip.AddrPort),
		lookups: make(map[string]int),
		drops:   make(map[string]bool),
	}
}

func key16(ip [16]byte, port uint16) string {
	return netip.AddrPortFrom(netip.AddrFrom16(ip).Unmap(), port).String()
}

func (p *mapProvider) add(src netip.AddrPort, dst netip.AddrPort) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.m[src.String()] = dst
}

func (p *mapProvider) drop(src netip.AddrPort) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.drops[src.String()] = true
}

func (p *mapProvider) Lookup(srcIP [16]byte, srcPort uint16) ([16]byte, uint16, bool) {
	key := key16(srcIP, srcPort)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lookups[key]++
	if p.drops[key] {
		return [16]byte{}, 0, false
	}
	dst, ok := p.m[key]
	if !ok {
		return [16]byte{}, 0, false
	}
	a16 := dst.Addr().As16()
	return a16, dst.Port(), true
}

func (p *mapProvider) lookupCount(src netip.AddrPort) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lookups[src.String()]
}

// fakeTransport replaces the sing-box transport with direct loopback
// dialing (no tunnel), enough to unit-test the tproxy machinery.
type fakeTransport struct{}

func (fakeTransport) dial(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", dst.String())
}

func (fakeTransport) dialHost(ctx context.Context, host string, port uint16) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprint(port)))
}

// fakeUDPAssoc is a packetRelay that relays raw UDP datagrams to the
// destination — the session-table logic is identical to the real relay path.
type fakeUDPAssoc struct {
	socket *net.UDPConn
}

func (f *fakeUDPAssoc) send(dst netip.AddrPort, payload []byte) error {
	_, err := f.socket.WriteToUDPAddrPort(payload, dst)
	return err
}

func (f *fakeUDPAssoc) receive(buf []byte) (netip.AddrPort, []byte, error) {
	n, src, err := f.socket.ReadFromUDPAddrPort(buf)
	return src, buf[:n], err
}

func (f *fakeUDPAssoc) close() { f.socket.Close() }

func (fakeTransport) udpAssociate(ctx context.Context) (packetRelay, error) {
	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	return &fakeUDPAssoc{socket: socket}, nil
}

var _ transport = fakeTransport{}

// newUnitTunnel builds a tunnel with the fake transport (no sing-box).
func newUnitTunnel(t *testing.T, tproxyPort uint16, provider *mapProvider) *tunnel {
	t.Helper()
	tun := NewTunnel(config.TunnelEndpoint{
		Protocol:    "vless",
		Address:     "127.0.0.1",
		Port:        1,
		UUID:        "00000000-0000-0000-0000-000000000000",
		RealityPBK:  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		RealitySID:  "0123abcd",
		SNI:         "www.example.com",
		Fingerprint: "chrome",
		UDPMode:     "xudp",
	}, tproxyPort, Options{
		OriginalDstProvider: provider,
		Logger:              slog.New(slog.NewTextHandler(io.Discard, nil)),
	}).(*tunnel)
	tun.tr = fakeTransport{}
	t.Cleanup(func() { tun.Stop() })
	return tun
}

func freePort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

// bindTCPPort reserves and releases a loopback port for use as a client
// source port, so the 4-tuple is known before dialing.
func bindTCPPort(t *testing.T) uint16 { return freePort(t) }

// tcpTagEcho runs a TCP server replying "tag:data\n" for every line read.
func tcpTagEcho(t *testing.T, tag string) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if _, err := fmt.Fprintf(c, "%s:%s", tag, line); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return netip.MustParseAddrPort(ln.Addr().String())
}

// udpTagEcho runs a UDP server replying "tag:payload" to every datagram.
func udpTagEcho(t *testing.T, tag string) netip.AddrPort {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			reply := append([]byte(tag+":"), buf[:n]...)
			if _, err := conn.WriteTo(reply, from); err != nil {
				return
			}
		}
	}()
	return netip.MustParseAddrPort(conn.LocalAddr().String())
}

func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

// TestTCPFlowsAreKeyedBySrc4Tuple verifies that NAT'd TCP connections are
// routed by their src 4-tuple to the per-flow original destination, and that
// unknown 4-tuples are dropped.
func TestTCPFlowsAreKeyedBySrc4Tuple(t *testing.T) {
	provider := newMapProvider()
	tproxy := freePort(t)
	tun := newUnitTunnel(t, tproxy, provider)
	if err := tun.startCore(); err != nil {
		t.Fatal(err)
	}

	echoA := tcpTagEcho(t, "A")
	echoB := tcpTagEcho(t, "B")

	srcA := netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", bindTCPPort(t)))
	srcB := netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", bindTCPPort(t)))
	srcUnknown := netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", bindTCPPort(t)))
	provider.add(srcA, echoA)
	provider.add(srcB, echoB)

	dial := func(src netip.AddrPort) net.Conn {
		t.Helper()
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(src.Port())}}
		conn, err := d.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tproxy))
		if err != nil {
			t.Fatal(err)
		}
		return conn
	}

	// Flow A → echo A.
	connA := dial(srcA)
	defer connA.Close()
	if _, err := connA.Write([]byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(connA).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line != "A:hello\n" {
		t.Fatalf("flow A: got %q, want A:hello", line)
	}

	// Flow B → echo B (different dst for a different src port).
	connB := dial(srcB)
	defer connB.Close()
	if _, err := connB.Write([]byte("world\n")); err != nil {
		t.Fatal(err)
	}
	line, err = bufio.NewReader(connB).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line != "B:world\n" {
		t.Fatalf("flow B: got %q, want B:world", line)
	}

	// Unknown src 4-tuple → connection dropped by the tunnel.
	connX := dial(srcUnknown)
	defer connX.Close()
	connX.SetReadDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
	if _, err := connX.Read(make([]byte, 16)); err == nil {
		t.Fatal("unknown src: expected connection close, got data")
	}

	if got := provider.lookupCount(srcA); got != 1 {
		t.Errorf("srcA lookups = %d, want 1", got)
	}
	if got := provider.lookupCount(srcUnknown); got != 1 {
		t.Errorf("unknown src lookups = %d, want 1", got)
	}
}

// TestUDPPseudoSessions verifies per-src-4-tuple UDP routing, session reuse
// (one lookup per session) and the idle timeout.
func TestUDPPseudoSessions(t *testing.T) {
	provider := newMapProvider()
	tproxy := freePort(t)
	tun := newUnitTunnel(t, tproxy, provider)
	tun.udpTimeout = 200 * time.Millisecond
	if err := tun.startCore(); err != nil {
		t.Fatal(err)
	}

	echo1 := udpTagEcho(t, "U1")
	echo2 := udpTagEcho(t, "U2")

	client := func(dst netip.AddrPort) *net.UDPConn {
		t.Helper()
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		src := netip.MustParseAddrPort(c.LocalAddr().String())
		provider.add(src, dst)
		return c
	}

	c1 := client(echo1)
	c2 := client(echo2)

	sendRecv := func(c *net.UDPConn, payload string) string {
		t.Helper()
		if _, err := c.WriteToUDPAddrPort([]byte(payload), netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", tproxy))); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 1024)
		c.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
		n, _, err := c.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		return string(buf[:n])
	}

	src1 := netip.MustParseAddrPort(c1.LocalAddr().String())

	// Same source sends 3 datagrams: one session, one NAT lookup, distinct
	// destination from the other client's.
	for i := 0; i < 3; i++ {
		if got := sendRecv(c1, fmt.Sprintf("p%d", i)); got != "U1:p"+fmt.Sprint(i) {
			t.Fatalf("c1 packet %d: got %q", i, got)
		}
	}
	if got := sendRecv(c2, "q"); got != "U2:q" {
		t.Fatalf("c2: got %q", got)
	}
	if got := provider.lookupCount(src1); got != 1 {
		t.Errorf("c1 lookups = %d, want 1 (session reuse)", got)
	}
	waitFor(t, "session reuse", 3*time.Second, func() bool { return tun.sessions.len() == 2 })

	// Idle timeout closes sessions…
	waitFor(t, "idle timeout to close sessions", 3*time.Second, func() bool { return tun.sessions.len() == 0 })
	time.Sleep(50 * time.Millisecond)
	// …and a new datagram creates a fresh session (second lookup).
	if got := sendRecv(c1, "again"); got != "U1:again" {
		t.Fatalf("c1 after idle: got %q", got)
	}
	if got := provider.lookupCount(src1); got != 2 {
		t.Errorf("c1 lookups after idle = %d, want 2", got)
	}
}

// TestHealthTransitions drives the marker state machine against a mock
// marker server: 1 success → healthy, 2 more failures keep it up, the 3rd
// consecutive failure marks it down, a later success restores it.
func TestHealthTransitions(t *testing.T) {
	var status atomic.Int32
	status.Store(200)
	marker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s := status.Load(); s != 200 {
			w.WriteHeader(int(s))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer marker.Close()

	provider := newMapProvider()
	tproxy := freePort(t)
	tun := newUnitTunnel(t, tproxy, provider)
	tun.probeFunc = func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, marker.URL, nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close() //nolint:errcheck
		if resp.StatusCode/100 != 2 {
			return fmt.Errorf("marker status %d", resp.StatusCode)
		}
		return nil
	}
	tun.healthInterval = time.Hour // drive ticks manually
	if err := tun.startCore(); err != nil {
		t.Fatal(err)
	}

	if tun.Healthy() {
		t.Fatal("Healthy() should start false")
	}
	// The initial immediate probe should mark the tunnel healthy.
	waitFor(t, "initial healthy", 3*time.Second, tun.Healthy)

	status.Store(500)
	tun.tickNow()
	tun.tickNow()
	if !tun.Healthy() {
		t.Fatal("healthy should survive 2 consecutive failures")
	}
	tun.tickNow() // 3rd consecutive failure
	if tun.Healthy() {
		t.Fatal("healthy should flip to false after 3 consecutive failures")
	}
	// Staying down on further failures.
	status.Store(503)
	tun.tickNow()
	if tun.Healthy() {
		t.Fatal("still down after 4th failure")
	}
	// Recovery.
	status.Store(204)
	tun.tickNow()
	if !tun.Healthy() {
		t.Fatal("healthy should recover on first success")
	}
}

// TestBoxOptionsMapping pins the config.TunnelEndpoint → sing-box mapping.
func TestBoxOptionsMapping(t *testing.T) {
	cfg := config.TunnelEndpoint{
		Protocol:    "vless",
		Address:     "vps.example.net",
		Port:        443,
		UUID:        "11111111-2222-3333-4444-555555555555",
		RealityPBK:  "PUBKEYBASE64URL",
		RealitySID:  "0123abcd",
		SNI:         "www.cloudflare.com",
		Fingerprint: "chrome_pq",
		UDPMode:     "xudp",
	}
	opts := boxOptions(cfg, 23456)

	if len(opts.Inbounds) != 1 || opts.Inbounds[0].Type != "mixed" {
		t.Fatalf("inbounds = %+v, want single mixed", opts.Inbounds)
	}
	mixed := opts.Inbounds[0].Options.(*option.HTTPMixedInboundOptions)
	if mixed.Listen == nil || mixed.Listen.Build(netip.MustParseAddr("0.0.0.0")) != netip.MustParseAddr("127.0.0.1") || mixed.ListenPort != 23456 {
		t.Errorf("mixed inbound listen = %v:%d, want 127.0.0.1:23456", mixed.Listen, mixed.ListenPort)
	}

	var vlessOut *option.VLESSOutboundOptions
	for _, o := range opts.Outbounds {
		if o.Tag == vlessTag {
			vlessOut = o.Options.(*option.VLESSOutboundOptions)
		}
	}
	if vlessOut == nil {
		t.Fatal("no vless outbound")
	}
	if vlessOut.Server != cfg.Address || vlessOut.ServerPort != cfg.Port || vlessOut.UUID != cfg.UUID {
		t.Errorf("vless server fields = %+v", vlessOut.ServerOptions)
	}
	if vlessOut.Flow != "xtls-rprx-vision" {
		t.Errorf("flow = %q", vlessOut.Flow)
	}
	if vlessOut.PacketEncoding == nil || *vlessOut.PacketEncoding != "xudp" {
		t.Errorf("packet_encoding = %v, want xudp", vlessOut.PacketEncoding)
	}
	tls := vlessOut.TLS
	if tls == nil || !tls.Enabled || tls.ServerName != cfg.SNI {
		t.Fatalf("vless tls = %+v", tls)
	}
	if tls.UTLS == nil || !tls.UTLS.Enabled || tls.UTLS.Fingerprint != "chrome_pq" {
		t.Errorf("utls = %+v, want chrome_pq", tls.UTLS)
	}
	if tls.Reality == nil || !tls.Reality.Enabled || tls.Reality.PublicKey != cfg.RealityPBK || tls.Reality.ShortID != cfg.RealitySID {
		t.Errorf("reality = %+v", tls.Reality)
	}

	if opts.Route == nil || opts.Route.Final != vlessTag {
		t.Errorf("route.final = %+v, want %s", opts.Route, vlessTag)
	}

	// The JSON rendering must carry the same facts (used in debug logs/diag).
	raw, err := marshalBoxOptions(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	js := string(raw)
	for _, want := range []string{
		`"type":"mixed"`, `"listen":"127.0.0.1"`, `"listen_port":23456`,
		`"type":"vless"`, `"server":"vps.example.net"`, `"server_port":443`,
		`"uuid":"11111111-2222-3333-4444-555555555555"`,
		`"flow":"xtls-rprx-vision"`, `"packet_encoding":"xudp"`,
		`"server_name":"www.cloudflare.com"`, `"fingerprint":"chrome_pq"`,
		`"public_key":"PUBKEYBASE64URL"`, `"short_id":"0123abcd"`,
		`"final":"rupas-vless"`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("sing-box JSON missing %s\njson: %s", want, js)
		}
	}
}

// TestFingerprintNormalization checks uTLS fingerprint fallback.
func TestFingerprintNormalization(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "chrome"},
		{"chrome", "chrome"},
		{"Chrome", "chrome"},
		{"firefox", "firefox"},
		{"chrome_pq", "chrome_pq"},
		{"nope", "chrome"},
	}
	for _, c := range cases {
		got := fingerprintOf(config.TunnelEndpoint{Fingerprint: c.in})
		if got != c.want {
			t.Errorf("fingerprintOf(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestValidateEndpoint checks Start-time validation.
func TestValidateEndpoint(t *testing.T) {
	base := config.TunnelEndpoint{Protocol: "vless", Address: "a", Port: 1, UUID: "u", RealityPBK: "k", SNI: "s"}
	if err := validateEndpoint(base); err != nil {
		t.Fatalf("valid endpoint rejected: %v", err)
	}
	bad := []func(*config.TunnelEndpoint){
		func(c *config.TunnelEndpoint) { c.Protocol = "vmess" },
		func(c *config.TunnelEndpoint) { c.Address = "" },
		func(c *config.TunnelEndpoint) { c.Port = 0 },
		func(c *config.TunnelEndpoint) { c.UUID = "" },
		func(c *config.TunnelEndpoint) { c.RealityPBK = "" },
		func(c *config.TunnelEndpoint) { c.SNI = "" },
	}
	for i, mutate := range bad {
		c := base
		mutate(&c)
		if err := validateEndpoint(c); err == nil {
			t.Errorf("case %d: invalid endpoint accepted", i)
		}
	}
}

// TestAddr16RoundTrip checks the [16]byte NAT key helpers.
func TestAddr16RoundTrip(t *testing.T) {
	v4 := netip.MustParseAddr("149.154.167.51")
	var ip16 [16]byte
	b := v4.As16()
	copy(ip16[:], b[:])
	dst := joinAddr(ip16, 443)
	if dst.Addr().Compare(v4) != 0 || dst.Port() != 443 {
		t.Fatalf("v4 round trip: %v", dst)
	}
	v6 := netip.MustParseAddr("2001:db8::1")
	b6 := v6.As16()
	copy(ip16[:], b6[:])
	dst6 := joinAddr(ip16, 8443)
	if dst6.Addr().Compare(v6) != 0 || dst6.Port() != 8443 {
		t.Fatalf("v6 round trip: %v", dst6)
	}
}

// TestUDPFrameParse pins the SOCKS5 UDP datagram framing.
func TestUDPFrameParse(t *testing.T) {
	dst := netip.MustParseAddrPort("93.184.216.34:443")
	frame := socks5RequestHeader(0x00, dst)
	frame = appendUint16BE(frame, dst.Port())
	frame = append(frame, "payload"...)
	src, n, err := parseUDPFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	if src != dst || string(frame[n:]) != "payload" {
		t.Fatalf("frame parse: src=%v n=%d payload=%q", src, n, frame[n:])
	}
	if _, _, err := parseUDPFrame([]byte{0, 1, 0, 1}); err == nil {
		t.Fatal("fragmented frame should fail")
	}
}

func appendUint16BE(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v&0xff))
}
