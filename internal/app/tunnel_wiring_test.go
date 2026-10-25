//go:build windows && with_utls

package app

// Hermetic battle-pipeline e2e for the wave-4B tunnel wiring: no external
// network, no driver. The capture engine runs on fake transports, the
// tunnel core is the real sing-box VLESS+Reality client, and the "VPS" is
// an in-process sing-box vless+reality SERVER whose exit is a scriptable
// SOCKS5 relay (it records the CONNECT/UDP targets — i.e. exactly the
// OrigDst the capture NAT recovered — and answers from local echo
// origins).
//
// Chain under test (SYSTEM_DESIGN §3.3 + §6):
//
//	synthetic packet → capture ENGINE (fake transport)
//	  → rules: TG-CIDR → TUNNEL → NETWORK-layer NAT (dst → 127.0.0.1:tproxy)
//	  → real TCP/UDP socket to the loopback tproxy
//	  → tunnel: NAT Lookup (OrigDst) → SOCKS5 → mixed inbound → VLESS+Reality
//	  → local reality server → socks exit relay → echo origin
//	  → bytes echoed all the way back.
//
// Run with: go test ./internal/app -tags with_utls -run TunnelWiring -v

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rupas/rupas/internal/capture"
	"github.com/rupas/rupas/internal/config"
	box "github.com/sagernet/sing-box"
	boxAdapterCertificate "github.com/sagernet/sing-box/adapter/certificate"
	boxAdapterEndpoint "github.com/sagernet/sing-box/adapter/endpoint"
	boxAdapterInbound "github.com/sagernet/sing-box/adapter/inbound"
	boxAdapterOutbound "github.com/sagernet/sing-box/adapter/outbound"
	boxAdapterService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	dnsLocal "github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing/common/json/badoption"
	"golang.org/x/crypto/curve25519"
)

// ---------------------------------------------------------------------------
// Test exit: a SOCKS5 relay that records targets and answers from the
// local echo origins (TCP: HTTP echo; UDP: datagram echo).
// ---------------------------------------------------------------------------

type socksExit struct {
	ln      net.Listener
	udpSock *net.UDPConn
	echoTCP string // echo HTTP origin
	echoUDP netip.AddrPort

	mu         sync.Mutex
	tcpTargets []string
	udpTargets []string
}

func startSocksExit(t *testing.T, echoTCP string, echoUDP netip.AddrPort) *socksExit {
	t.Helper()
	e := &socksExit{echoTCP: echoTCP, echoUDP: echoUDP}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e.ln = ln
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		ln.Close()
		t.Fatal(err)
	}
	e.udpSock = uc
	go e.acceptLoop()
	go e.udpLoop()
	t.Cleanup(func() { ln.Close(); uc.Close() })
	return e
}

func (e *socksExit) acceptLoop() {
	for {
		c, err := e.ln.Accept()
		if err != nil {
			return
		}
		go e.serve(c)
	}
}

func (e *socksExit) serve(c net.Conn) {
	defer c.Close()
	// greeting: VER NMETHODS METHODS...
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return
	}
	if _, err := io.ReadFull(c, make([]byte, hdr[1])); err != nil {
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil { // no-auth selected
		return
	}
	var head [4]byte // VER CMD RSV ATYP
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return
	}
	target, err := readSocksAddrPort(c, head[3])
	if err != nil {
		return
	}
	switch head[1] {
	case 1: // CONNECT: record the target, answer from the TCP echo.
		e.mu.Lock()
		e.tcpTargets = append(e.tcpTargets, target)
		e.mu.Unlock()
		up, err := net.DialTimeout("tcp", e.echoTCP, 3*time.Second)
		if err != nil {
			c.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 0}) //nolint:errcheck // general failure
			return
		}
		defer up.Close()
		if _, err := c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
			return
		}
		done := make(chan struct{}, 1)
		go func() {
			io.Copy(up, c)            //nolint:errcheck
			c.SetDeadline(time.Now()) //nolint:errcheck
			done <- struct{}{}
		}()
		io.Copy(c, up)            //nolint:errcheck
		c.SetDeadline(time.Now()) //nolint:errcheck
		<-done
	case 3: // UDP ASSOCIATE: hand out the shared relay socket.
		port := uint16(e.udpSock.LocalAddr().(*net.UDPAddr).Port)
		var p [2]byte
		binary.BigEndian.PutUint16(p[:], port)
		if _, err := c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, p[0], p[1]}); err != nil {
			return
		}
		io.Copy(io.Discard, c) //nolint:errcheck // hold control open
	}
}

// udpLoop relays framed client datagrams to the UDP echo and wraps the
// echo replies back to the client address (per-client echo sockets so
// replies return to the right flow).
func (e *socksExit) udpLoop() {
	echoSocks := map[netip.AddrPort]*net.UDPConn{}
	var mu sync.Mutex
	buf := make([]byte, 65535+512)
	for {
		n, from, err := e.udpSock.ReadFromUDPAddrPort(buf[:])
		if err != nil {
			return
		}
		dst, off, err := parseSocksUDPHeader(buf[:n])
		if err != nil {
			continue
		}
		e.mu.Lock()
		e.udpTargets = append(e.udpTargets, dst.String())
		e.mu.Unlock()
		mu.Lock()
		esc, ok := echoSocks[from]
		if !ok {
			esc, err = net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(e.echoUDP))
			if err != nil {
				mu.Unlock()
				continue
			}
			echoSocks[from] = esc
			client := from
			go func() {
				rbuf := make([]byte, 65535)
				for {
					rn, _, err := esc.ReadFromUDP(rbuf)
					if err != nil {
						return
					}
					frame := appendSocksUDPHeader(e.echoUDP, rbuf[:rn])
					if _, err := e.udpSock.WriteToUDPAddrPort(frame, client); err != nil {
						return
					}
				}
			}()
		}
		mu.Unlock()
		if _, err := esc.Write(buf[off:n]); err != nil {
			continue
		}
	}
}

func (e *socksExit) sawTCP(target string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, t := range e.tcpTargets {
		if t == target {
			return true
		}
	}
	return false
}

func (e *socksExit) sawUDP(target string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, t := range e.udpTargets {
		if t == target {
			return true
		}
	}
	return false
}

func readSocksAddrPort(c net.Conn, atyp byte) (string, error) {
	var host string
	switch atyp {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return "", err
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(c, name); err != nil {
			return "", err
		}
		host = string(name)
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	default:
		return "", errors.New("bad atyp")
	}
	var p [2]byte
	if _, err := io.ReadFull(c, p[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(p[:])))), nil
}

// parseSocksUDPHeader decodes RSV FRAG ATYP ADDR PORT, returning the
// target and the header length.
func parseSocksUDPHeader(b []byte) (netip.AddrPort, int, error) {
	if len(b) < 4 || b[1] != 0 {
		return netip.AddrPort{}, 0, errors.New("bad udp frame")
	}
	switch b[3] {
	case 1:
		if len(b) < 10 {
			return netip.AddrPort{}, 0, errors.New("short v4 frame")
		}
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[4:8])), binary.BigEndian.Uint16(b[8:10])), 10, nil
	case 4:
		if len(b) < 22 {
			return netip.AddrPort{}, 0, errors.New("short v6 frame")
		}
		return netip.AddrPortFrom(netip.AddrFrom16([16]byte(b[4:20])), binary.BigEndian.Uint16(b[20:22])), 22, nil
	}
	return netip.AddrPort{}, 0, errors.New("bad frame atyp")
}

// appendSocksUDPHeader builds RSV FRAG ATYP ADDR PORT around payload.
func appendSocksUDPHeader(src netip.AddrPort, payload []byte) []byte {
	var out []byte
	out = append(out, 0, 0, 0)
	a := src.Addr().Unmap()
	if a.Is4() {
		b4 := a.As4()
		out = append(out, 1)
		out = append(out, b4[:]...)
	} else {
		b16 := a.As16()
		out = append(out, 4)
		out = append(out, b16[:]...)
	}
	out = binary.BigEndian.AppendUint16(out, src.Port())
	return append(out, payload...)
}

// ---------------------------------------------------------------------------
// The in-process "VPS": sing-box vless+reality inbound, socks outbound to
// the scriptable exit relay.
// ---------------------------------------------------------------------------

func genRealityKeys(t *testing.T) (privateKey, publicKey string) {
	t.Helper()
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(seed[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(seed[:]),
		base64.RawURLEncoding.EncodeToString(pub[:])
}

func genUUID(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func startRealityVPS(t *testing.T, vpPort uint16, tlsDestPort uint16, uuid, privKey, shortID, sni string, exitPort uint16) {
	t.Helper()
	listen := badAddr("127.0.0.1")
	vlessFlow := "xtls-rprx-vision"
	opts := option.Options{
		Log: &option.LogOptions{Disabled: true},
		DNS: &option.DNSOptions{RawDNSOptions: option.RawDNSOptions{Servers: []option.DNSServerOptions{
			{Type: "local", Tag: "srv-dns", Options: &option.LocalDNSServerOptions{}},
		}}},
		Inbounds: []option.Inbound{
			{
				Type: "vless",
				Tag:  "srv-vless",
				Options: &option.VLESSInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     listen,
						ListenPort: vpPort,
					},
					Users: []option.VLESSUser{{Name: "rupas", UUID: uuid, Flow: vlessFlow}},
					InboundTLSOptionsContainer: option.InboundTLSOptionsContainer{
						TLS: &option.InboundTLSOptions{
							Enabled:    true,
							ServerName: sni,
							Reality: &option.InboundRealityOptions{
								Enabled: true,
								Handshake: option.InboundRealityHandshakeOptions{
									ServerOptions: option.ServerOptions{
										Server:     "127.0.0.1",
										ServerPort: tlsDestPort,
									},
								},
								PrivateKey: privKey,
								ShortID:    listable1(shortID),
							},
						},
					},
				},
			},
		},
		Outbounds: []option.Outbound{
			{
				Type: "socks",
				Tag:  "srv-exit",
				Options: &option.SOCKSOutboundOptions{
					ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: exitPort},
					Version:       "5",
				},
			},
			{
				Type:    "direct",
				Tag:     "srv-direct",
				Options: &option.DirectOutboundOptions{},
			},
		},
		Route: &option.RouteOptions{
			Final:                 "srv-exit",
			DefaultDomainResolver: &option.DomainResolveOptions{Server: "srv-dns"},
			AutoDetectInterface:   true,
		},
	}
	inbounds := boxAdapterInbound.NewRegistry()
	vless.RegisterInbound(inbounds)
	direct.RegisterInbound(inbounds)
	outbounds := boxAdapterOutbound.NewRegistry()
	vless.RegisterOutbound(outbounds)
	direct.RegisterOutbound(outbounds)
	socks.RegisterOutbound(outbounds)
	dnsReg := dns.NewTransportRegistry()
	dnsLocal.RegisterTransport(dnsReg)
	boxCtx := box.Context(context.Background(), inbounds, outbounds,
		boxAdapterEndpoint.NewRegistry(), dnsReg,
		boxAdapterService.NewRegistry(), boxAdapterCertificate.NewRegistry())
	engine, err := box.New(box.Options{Context: boxCtx, Options: opts})
	if err != nil {
		t.Fatalf("vps box.New: %v", err)
	}
	if err := engine.Start(); err != nil {
		t.Fatalf("vps box.Start: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
}

// ---------------------------------------------------------------------------
// Fake capture transport + synthetic packet builders (mirrors the capture
// package's own test utilities; duplicated here because test files are

func badAddr(ip string) *badoption.Addr {
	a := badoption.Addr(netip.MustParseAddr(ip))
	return &a
}

func listable1(s string) badoption.Listable[string] { return badoption.Listable[string]{s} }

// ---------------------------------------------------------------------------
// The e2e itself.
// ---------------------------------------------------------------------------

// TestTunnelWiringFullPath drives the complete wave-4B chain with a
// synthetic TG packet on one side and a real socket on the other:
//
//	TCP: ClientHello to 149.154.167.51:443 (TG CIDR) → NAT → tproxy →
//	     vless+reality → exit relay (records OrigDst) → HTTP echo.
//	UDP: datagram to :50000 (relay port rule) → NAT → tproxy → XUDP →
//	     exit relay → UDP echo.
//
// It also exercises the loopback reverse-NAT rewrite and the HOLD
// degradation (marker loss → 3 fails → new flows dropped, counted).
func TestTunnelWiringFullPath(t *testing.T) {
	// The "internet" behind the VPS.
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ECHO:%s", r.URL.Path)
	}))
	echoUDP := startUDPEcho(t)

	// Reality's camouflage handshake target must speak TLS.
	tlsDest := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tlsDest.Close()
	tlsDestPort := uint16(tlsDest.Listener.Addr().(*net.TCPAddr).Port)

	// The scriptable exit, then the VPS in front of it.
	exit := startSocksExit(t, echo.Listener.Addr().String(), echoUDP)
	exitPort := uint16(exit.ln.Addr().(*net.TCPAddr).Port)
	privKey, pubKey := genRealityKeys(t)
	uuid := genUUID(t)
	shortID, sni := "0123abcd", "www.example.com"
	vpPort := freeTCPPort(t)
	startRealityVPS(t, vpPort, tlsDestPort, uuid, privKey, shortID, sni, exitPort)

	// The battle config: TG CIDR + UDP relay ports → tunnel; the endpoint
	// points at the in-process VPS.
	cfg := &config.Config{
		Profile: "tunnel-wiring-e2e",
		Rules: []config.Rule{
			{CIDR: "149.154.160.0/20", Action: config.ActionTunnel},
			{Ports: "50000-65535", Action: config.ActionTunnel},
			{Action: config.ActionDirect},
		},
		Tunnel: config.TunnelEndpoint{
			Protocol: "vless", Address: "127.0.0.1", Port: vpPort,
			UUID: uuid, RealityPBK: pubKey, RealitySID: shortID,
			SNI: sni, Fingerprint: "chrome", UDPMode: "xudp",
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	tproxyPort := freeTCPPort(t)
	mainT := newAppFakeTransport()
	loopT := newAppFakeTransport()
	p := newPipeline(pipelineDeps{
		tpl:    validTpl(),
		tunnel: true, tproxyPort: tproxyPort,
		tunnelOpts: tunnelRunOpts{
			markerURL:      echo.URL + "/marker",
			healthInterval: 300 * time.Millisecond,
			dialTimeout:    5 * time.Second,
		},
		log:        discardLogger(),
		engineHook: func(eng *capture.Engine) { eng.InjectTransport(mainT, loopT) },
	})
	if err := p.Start(cfg); err != nil {
		t.Fatalf("pipeline start: %v", err)
	}
	defer func() { _ = p.Stop() }()

	st := p.Stats()
	if st.TunnelMode != tunnelModeLive || st.Tunnel == nil {
		t.Fatalf("tunnel mode = %q (stats %+v), want live tunnel", st.TunnelMode, st)
	}

	lo := netip.MustParseAddr("127.0.0.1")
	tgDst := netip.MustParseAddr("149.154.167.51") // inside 149.154.160.0/20

	// --- TCP: synthetic packet plays the TG client ---
	// Reserve a client port, then feed the engine a SYN + ClientHello
	// whose src 4-tuple matches the socket we dial from below.
	res, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sport := uint16(res.Addr().(*net.TCPAddr).Port)
	res.Close()
	mainT.Enqueue(buildTCP4(lo, sport, tgDst, 443, 1000, 0x02, nil), true)                              // SYN
	mainT.Enqueue(buildTCP4(lo, sport, tgDst, 443, 1001, 0x18, buildClientHello("telegram.org")), true) // PSH+ACK, CH

	// The engine must NAT-rewrite the ClientHello to the loopback tproxy.
	waitFor(t, "NAT rewrite to the tproxy", 5*time.Second, func() bool {
		for _, pkt := range mainT.Sent() {
			if len(pkt) >= 24 && pkt[9] == 6 &&
				binary.BigEndian.Uint16(pkt[20+2:20+4]) == tproxyPort &&
				net.IP(pkt[16:20]).Equal(net.IPv4(127, 0, 0, 1)) {
				return true
			}
		}
		return false
	})

	// The NAT map must now resolve the client 4-tuple to the pre-NAT TG
	// destination (the OrigDst seam, §3.3). v4-mapped form: ::ffff:a.b.c.d.
	var src16 [16]byte
	src16[10], src16[11] = 0xFF, 0xFF
	src4 := lo.As4()
	copy(src16[12:16], src4[:])
	dst16, dport, ok := p.(*capturePipeline).provider.Lookup(src16, sport)
	if !ok {
		t.Fatal("NAT lookup missed for the synthetic TG flow")
	}
	if dport != 443 || dst16[12] != 149 || dst16[13] != 154 || dst16[14] != 167 || dst16[15] != 51 {
		t.Fatalf("OrigDst = %d.%d.%d.%d:%d, want 149.154.167.51:443",
			dst16[12], dst16[13], dst16[14], dst16[15], dport)
	}

	// The real client socket (same src 4-tuple) dials the tproxy and
	// speaks HTTP through the tunnel to the echo origin.
	dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(sport)}}
	conn, err := dialer.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tproxyPort))
	if err != nil {
		t.Fatalf("dial tproxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second)) //nolint:errcheck
	if _, err := conn.Write([]byte("GET /tgwired HTTP/1.0\r\nHost: tg\r\n\r\n")); err != nil {
		t.Fatalf("write through tunnel: %v", err)
	}
	resp, err := io.ReadAll(bufio.NewReader(conn))
	if err != nil {
		t.Fatalf("read through tunnel: %v", err)
	}
	if !strings.Contains(string(resp), "ECHO:/tgwired") {
		t.Fatalf("echo body missing through the full chain:\n%.200s", resp)
	}
	// OrigDst correctness end-to-end: the exit relay saw the CONNECT
	// target equal the pre-NAT TG destination, not the tproxy.
	waitFor(t, "exit relay to record the TG OrigDst", 5*time.Second, func() bool {
		return exit.sawTCP("149.154.167.51:443")
	})

	// --- Loopback reverse NAT: a tproxy reply packet must be rewritten
	// back so the client believes it talks to 149.154.167.51:443.
	loopT.Enqueue(buildTCP4(lo, tproxyPort, lo, sport, 500, 0x18, []byte("srv")), false)
	tg4 := tgDst.As4()
	waitFor(t, "reverse NAT rewrite", 5*time.Second, func() bool {
		for _, pkt := range loopT.Sent() {
			if len(pkt) >= 24 && pkt[9] == 6 &&
				binary.BigEndian.Uint16(pkt[20:20+2]) == 443 &&
				pkt[12] == tg4[0] && pkt[13] == tg4[1] && pkt[14] == tg4[2] && pkt[15] == tg4[3] {
				return true
			}
		}
		return false
	})

	// --- Health marker through the tunnel ---
	waitFor(t, "tunnel healthy", 10*time.Second, func() bool {
		_, h := p.TunnelHealth()
		return h
	})

	// --- UDP: synthetic datagram to the relay port range ---
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	uport := uint16(uc.LocalAddr().(*net.UDPAddr).Port)
	udpDst := netip.MustParseAddr("192.0.2.66") // TEST-NET: any non-loopback host
	mainT.Enqueue(buildUDP4(lo, uport, udpDst, 50000, []byte("discord-media-packet")), true)
	waitFor(t, "UDP NAT rewrite to the tproxy", 5*time.Second, func() bool {
		for _, pkt := range mainT.Sent() {
			if len(pkt) >= 28 && pkt[9] == 17 &&
				binary.BigEndian.Uint16(pkt[20+2:20+4]) == tproxyPort &&
				net.IP(pkt[16:20]).Equal(net.IPv4(127, 0, 0, 1)) {
				return true
			}
		}
		return false
	})
	if _, err := uc.WriteToUDPAddrPort([]byte("discord-media-packet"),
		netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", tproxyPort))); err != nil {
		t.Fatal(err)
	}
	ubuf := make([]byte, 1024)
	uc.SetReadDeadline(time.Now().Add(20 * time.Second)) //nolint:errcheck
	un, _, err := uc.ReadFromUDP(ubuf)
	if err != nil {
		t.Fatalf("UDP echo through the tunnel: %v", err)
	}
	if got := string(ubuf[:un]); got != "UDPECHO:discord-media-packet" {
		t.Fatalf("UDP echo payload = %q", got)
	}
	waitFor(t, "exit relay to record the UDP OrigDst", 5*time.Second, func() bool {
		return exit.sawUDP("192.0.2.66:50000")
	})

	// Counters: engine NAT counters moved; tunnel stats carry bytes/flows.
	pstats := p.Stats()
	if pstats.Counters.PacketsRedir == 0 || pstats.Counters.TunnelTx == 0 || pstats.Counters.TunnelRx == 0 {
		t.Fatalf("engine tunnel counters did not move: %+v", pstats.Counters)
	}
	if pstats.Tunnel == nil || pstats.Tunnel.RxBytes == 0 || pstats.Tunnel.TxBytes == 0 ||
		pstats.Tunnel.TCPConns == 0 || pstats.Tunnel.UDPDgrams == 0 {
		t.Fatalf("tunnel stats incomplete: %+v", pstats.Tunnel)
	}

	// --- HOLD degradation: kill the marker origin; after 3 marker
	// failures new flows must be dropped with a counter (not relayed into
	// a dead tunnel, not escalated to direct).
	echo.Close()
	waitFor(t, "tunnel to enter HOLD", 15*time.Second, func() bool {
		st := p.Stats()
		return st.Tunnel != nil && st.Tunnel.Held
	})
	_, healthy := p.TunnelHealth()
	if healthy {
		t.Fatal("tunnel still reported healthy after 3 marker failures")
	}

	// A new TG flow: NAT it (SYN+CH with a fresh src port), dial the
	// tproxy and expect a PROMPT close (no hang, no relay into the dead
	// tunnel) with the drop counter incremented.
	res2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sport2 := uint16(res2.Addr().(*net.TCPAddr).Port)
	res2.Close()
	mainT.Enqueue(buildTCP4(lo, sport2, tgDst, 443, 1000, 0x02, nil), true)
	mainT.Enqueue(buildTCP4(lo, sport2, tgDst, 443, 1001, 0x18, buildClientHello("telegram.org")), true)
	waitFor(t, "second NAT rewrite", 5*time.Second, func() bool {
		for _, pkt := range mainT.Sent() {
			if len(pkt) >= 24 && pkt[9] == 6 &&
				binary.BigEndian.Uint16(pkt[20:20+2]) == sport2 &&
				binary.BigEndian.Uint16(pkt[20+2:20+4]) == tproxyPort {
				return true
			}
		}
		return false
	})
	droppedBefore := p.Stats().Tunnel.Dropped
	d2 := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(sport2)}}
	held, err := d2.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tproxyPort))
	if err != nil {
		t.Fatalf("dial tproxy while HELD: %v", err)
	}
	defer held.Close()
	held.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
	if _, err := held.Write([]byte("GET /held HTTP/1.0\r\n\r\n")); err != nil {
		t.Fatalf("write while HELD: %v", err)
	}
	_, rerr := bufio.NewReader(held).ReadString('\n')
	if rerr == nil {
		t.Fatal("held flow must be closed, not answered")
	}
	waitFor(t, "held drop counter", 5*time.Second, func() bool {
		st := p.Stats()
		return st.Tunnel != nil && st.Tunnel.Dropped > droppedBefore
	})
}

// startUDPEcho runs a one-datagram-echo UDP "media server".
func startUDPEcho(t *testing.T) netip.AddrPort {
	t.Helper()
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { uc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := uc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			reply := append([]byte("UDPECHO:"), buf[:n]...)
			uc.WriteToUDP(reply, from) //nolint:errcheck
		}
	}()
	return netip.MustParseAddrPort(uc.LocalAddr().String())
}
