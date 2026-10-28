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

	"github.com/kshishtovsky/rupas/internal/config"
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
	ep := &config.Endpoint{
		Kind:        config.KindVLESSReality,
		Host:        "127.0.0.1",
		Port:        1,
		UUID:        "00000000-0000-0000-0000-000000000000",
		RealityPBK:  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		RealitySID:  "0123abcd",
		SNI:         "www.example.com",
		Fingerprint: "chrome",
		UDPMode:     "xudp",
	}
	if err := ep.Validate(); err != nil {
		t.Fatal(err)
	}
	tun := NewTunnel(config.TunnelConfig{TCP: ep, UDP: ep}, tproxyPort, Options{
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

// TestBoxOptionsMapping pins the config.TunnelConfig → sing-box mapping
// for every sing-box-carried kind (vless_tcp without Reality/flow,
// vless_reality with Reality+vision, hysteria2 with password/h3) plus the
// network-split routing when TCP and UDP ride distinct endpoints.
func TestBoxOptionsMapping(t *testing.T) {
	tcp := &config.Endpoint{
		Kind: config.KindVLESSTCP,
		Host: "vps.example.net", Port: 12341,
		UUID: "11111111-2222-3333-4444-555555555555",
		SNI:  "vps.example.net", ALPN: []string{"h2", "http/1.1"},
		Fingerprint: "chrome", UDPMode: "xudp",
	}
	hy2 := &config.Endpoint{
		Kind: config.KindHysteria2,
		Host: "vps.example.net", Port: 53552,
		Password: "sekret", SNI: "vps.example.net",
		Fingerprint: "chrome",
	}
	fb := &config.Endpoint{
		Kind: config.KindVLESSReality,
		Host: "vps.example.net", Port: 443,
		UUID: "11111111-2222-3333-4444-555555555555",
		RealityPBK: "PUBKEYBASE64URL", RealitySID: "0123abcd",
		SNI: "www.cloudflare.com", Fingerprint: "chrome_pq", UDPMode: "xudp",
	}
	cfg := config.TunnelConfig{TCP: tcp, UDP: hy2, Fallback: fb}
	ports := sbPorts{Main: 23456, TCPFB: 23457, UDPFB: 23458}
	opts := boxOptions(cfg, ports)

	if len(opts.Inbounds) != 3 {
		t.Fatalf("inbounds = %d, want 3 (main, tcp-fallback, udp-fallback)", len(opts.Inbounds))
	}
	main := opts.Inbounds[0].Options.(*option.HTTPMixedInboundOptions)
	if main.ListenPort != 23456 {
		t.Errorf("main mixed listen_port = %d, want 23456", main.ListenPort)
	}
	for i, want := range []struct{ tag string; port uint16 }{
		{mixedFBTag, 23457}, {mixedUFBTag, 23458},
	} {
		got := opts.Inbounds[i+1]
		if got.Tag != want.tag || got.Options.(*option.HTTPMixedInboundOptions).ListenPort != want.port {
			t.Errorf("inbound %d = %s:%d, want %s:%d", i+1, got.Tag,
				got.Options.(*option.HTTPMixedInboundOptions).ListenPort, want.tag, want.port)
		}
	}

	outs := map[string]any{}
	for _, o := range opts.Outbounds {
		outs[o.Tag] = o.Options
	}
	// vless_tcp: TLS enabled, NO Reality, NO flow (the user link has none).
	vtc, ok := outs[tcpTag].(*option.VLESSOutboundOptions)
	if !ok {
		t.Fatalf("no %s outbound (%T)", tcpTag, outs[tcpTag])
	}
	if vtc.Server != tcp.Host || vtc.ServerPort != tcp.Port || vtc.UUID != tcp.UUID {
		t.Errorf("vless_tcp server fields = %+v", vtc.ServerOptions)
	}
	if vtc.Flow != "" {
		t.Errorf("vless_tcp flow = %q, want empty (not Vision)", vtc.Flow)
	}
	if vtc.PacketEncoding == nil || *vtc.PacketEncoding != "xudp" {
		t.Errorf("vless_tcp packet_encoding = %v, want xudp", vtc.PacketEncoding)
	}
	if vtc.TLS == nil || !vtc.TLS.Enabled || vtc.TLS.ServerName != tcp.SNI || vtc.TLS.Reality != nil {
		t.Errorf("vless_tcp tls = %+v (reality must be nil)", vtc.TLS)
	}
	if len(vtc.TLS.ALPN) != 2 || vtc.TLS.ALPN[0] != "h2" || vtc.TLS.ALPN[1] != "http/1.1" {
		t.Errorf("vless_tcp alpn = %v", vtc.TLS.ALPN)
	}
	// hysteria2: password + TLS h3.
	hc, ok := outs[udpTag].(*option.Hysteria2OutboundOptions)
	if !ok {
		t.Fatalf("no %s outbound (%T)", udpTag, outs[udpTag])
	}
	if hc.Server != hy2.Host || hc.ServerPort != hy2.Port || hc.Password != "sekret" {
		t.Errorf("hysteria2 fields = %+v", hc)
	}
	if hc.TLS == nil || !hc.TLS.Enabled || hc.TLS.ServerName != hy2.SNI || len(hc.TLS.ALPN) != 1 || hc.TLS.ALPN[0] != "h3" {
		t.Errorf("hysteria2 tls = %+v", hc.TLS)
	}
	// vless_reality: Reality pins + default vision flow.
	fbc, ok := outs[fbTag].(*option.VLESSOutboundOptions)
	if !ok {
		t.Fatalf("no %s outbound (%T)", fbTag, outs[fbTag])
	}
	if fbc.Flow != "xtls-rprx-vision" {
		t.Errorf("reality flow = %q, want vision default", fbc.Flow)
	}
	if fbc.TLS.Reality == nil || !fbc.TLS.Reality.Enabled ||
		fbc.TLS.Reality.PublicKey != "PUBKEYBASE64URL" || fbc.TLS.Reality.ShortID != "0123abcd" {
		t.Errorf("reality = %+v", fbc.TLS.Reality)
	}

	// Routing: udp-fallback inbound → tcp outbound; tcp-fallback inbound →
	// fallback outbound; network udp → udp outbound; final → tcp outbound.
	if len(opts.Route.Rules) != 3 {
		t.Fatalf("route rules = %d, want 3", len(opts.Route.Rules))
	}
	if r := opts.Route.Rules[0]; r.DefaultOptions.RouteOptions.Outbound != tcpTag || len(r.DefaultOptions.Inbound) != 1 || r.DefaultOptions.Inbound[0] != mixedUFBTag {
		t.Errorf("rule 0 = inbound %v → %s, want %s → %s", r.DefaultOptions.Inbound, r.DefaultOptions.RouteOptions.Outbound, mixedUFBTag, tcpTag)
	}
	if r := opts.Route.Rules[1]; r.DefaultOptions.RouteOptions.Outbound != fbTag || r.DefaultOptions.Inbound[0] != mixedFBTag {
		t.Errorf("rule 1 = inbound %v → %s, want %s → %s", r.DefaultOptions.Inbound, r.DefaultOptions.RouteOptions.Outbound, mixedFBTag, fbTag)
	}
	r := opts.Route.Rules[2]
	if r.DefaultOptions.RouteOptions.Outbound != udpTag || len(r.DefaultOptions.Network) != 1 || r.DefaultOptions.Network[0] != "udp" {
		t.Errorf("rule 2 = network %v → %s, want udp → %s", r.DefaultOptions.Network, r.DefaultOptions.RouteOptions.Outbound, udpTag)
	}
	if opts.Route.Final != tcpTag {
		t.Errorf("route.final = %s, want %s", opts.Route.Final, tcpTag)
	}

	// The JSON rendering must carry the same facts (used in debug logs/diag).
	raw, err := marshalBoxOptions(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	js := string(raw)
	for _, want := range []string{
		`"type":"mixed"`, `"listen":"127.0.0.1"`, `"listen_port":23456`,
		`"type":"vless"`, `"server":"vps.example.net"`, `"server_port":12341`,
		`"uuid":"11111111-2222-3333-4444-555555555555"`,
		`"packet_encoding":"xudp"`,
		`"type":"hysteria2"`, `"server_port":53552`, `"password":"sekret"`, `"alpn":"h3"`,
		`"public_key":"PUBKEYBASE64URL"`, `"short_id":"0123abcd"`,
		`"network":"udp"`, `"outbound":"` + udpTag + `"`,
		`"final":"` + tcpTag + `"`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("sing-box JSON missing %s\njson: %s", want, js)
		}
	}
	// vless_tcp must NOT carry a flow or reality stanza.
	if strings.Contains(js, `"flow":"xtls-rprx-vision","packet_encoding"`) {
		t.Errorf("vless_tcp unexpectedly carries a flow: %s", js)
	}
}

// TestBoxOptionsSingleEndpoint pins the legacy/single-endpoint layout: one
// mixed inbound, one outbound, no rules, final = the endpoint.
func TestBoxOptionsSingleEndpoint(t *testing.T) {
	ep := &config.Endpoint{
		Kind: config.KindVLESSReality, Host: "vps.example.net", Port: 443,
		UUID: "11111111-2222-3333-4444-555555555555",
		RealityPBK: "PUBKEYBASE64URL", SNI: "www.cloudflare.com",
		Fingerprint: "chrome_pq", UDPMode: "xudp",
	}
	opts := boxOptions(config.TunnelConfig{TCP: ep, UDP: ep}, sbPorts{Main: 23456})
	if len(opts.Inbounds) != 1 || len(opts.Route.Rules) != 0 {
		t.Fatalf("single endpoint: %d inbounds, %d rules; want 1/0", len(opts.Inbounds), len(opts.Route.Rules))
	}
	if opts.Route.Final != tcpTag {
		t.Errorf("final = %s, want %s", opts.Route.Final, tcpTag)
	}
	var found bool
	for _, o := range opts.Outbounds {
		if o.Tag == udpTag {
			found = true
		}
	}
	if found {
		t.Error("same TCP/UDP endpoint must not duplicate the outbound")
	}
}

// TestBoxOptionsXHTTPExcluded pins that vless_xhttp endpoints never reach
// the sing-box config (Rupas' own XHTTP client carries them), while the
// sing-box-able UDP endpoint still does.
func TestBoxOptionsXHTTPExcluded(t *testing.T) {
	xh := &config.Endpoint{
		Kind: config.KindVLESSXHTTP, Host: "vps.example.net", Port: 4443,
		UUID: "11111111-2222-3333-4444-555555555555", SNI: "vps.example.net",
		Path: "/steamVideo", Mode: "packet-up", XPadding: "100-1000",
		Fingerprint: "chrome",
	}
	hy2 := &config.Endpoint{
		Kind: config.KindHysteria2, Host: "vps.example.net", Port: 53552,
		Password: "sekret", SNI: "vps.example.net",
	}
	if err := xh.Validate(); err != nil {
		t.Fatal(err)
	}
	opts := boxOptions(config.TunnelConfig{TCP: xh, UDP: hy2}, sbPorts{Main: 23456})
	for _, o := range opts.Outbounds {
		if o.Type == "vless" {
			t.Errorf("xhttp endpoint leaked into sing-box as a vless outbound: %+v", o)
		}
	}
	if opts.Route.Final != udpTag {
		t.Errorf("final = %s, want %s (hysteria2 carries TCP when the TCP endpoint is xhttp)", opts.Route.Final, udpTag)
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
		got := fingerprintOf(c.in)
		if got != c.want {
			t.Errorf("fingerprintOf(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestValidatePlan checks Start-time validation of the wave-5 plan.
func TestValidatePlan(t *testing.T) {
	base := func(kind string) *config.Endpoint {
		return &config.Endpoint{
			Kind: kind, Host: "a", Port: 1, SNI: "s",
			UUID: "00000000-0000-0000-0000-000000000000",
			Password: "p", RealityPBK: "k", Path: "/x",
		}
	}
	for _, kind := range config.EndpointKinds() {
		if err := validatePlan(config.TunnelConfig{TCP: base(kind)}); err != nil {
			t.Errorf("kind %s: valid plan rejected: %v", kind, err)
		}
	}
	if err := validatePlan(config.TunnelConfig{}); err == nil {
		t.Error("empty plan accepted")
	}
	bad := []func(*config.Endpoint){
		func(c *config.Endpoint) { c.Kind = "vmess" },
		func(c *config.Endpoint) { c.Host = "" },
		func(c *config.Endpoint) { c.Port = 0 },
		func(c *config.Endpoint) { c.SNI = "" },
		func(c *config.Endpoint) { c.UUID = "" },
		func(c *config.Endpoint) { c.Kind = config.KindHysteria2; c.Password = "" },
		func(c *config.Endpoint) { c.Kind = config.KindVLESSReality; c.RealityPBK = "" },
		func(c *config.Endpoint) { c.Kind = config.KindVLESSXHTTP; c.Path = "" },
		func(c *config.Endpoint) { c.Flow = "weird" },
	}
	for i, mutate := range bad {
		c := base(config.KindVLESSTCP)
		mutate(c)
		if err := validatePlan(config.TunnelConfig{TCP: c}); err == nil {
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
	// A domain-form source (ATYP=3) is legal per RFC 1928: the payload must
	// still be delivered, the address is simply not dialable.
	name := []byte("example.com")
	dom := []byte{0, 0, 0, 3, byte(len(name))}
	dom = append(dom, name...)
	dom = appendUint16BE(dom, 443)
	dom = append(dom, "payload"...)
	// Both callers discard the address, so only the payload offset matters.
	if _, n, err := parseUDPFrame(dom); err != nil || string(dom[n:]) != "payload" {
		t.Fatalf("domain frame: n=%d payload=%q err=%v", n, dom[n:], err)
	}
}

func appendUint16BE(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v&0xff))
}
