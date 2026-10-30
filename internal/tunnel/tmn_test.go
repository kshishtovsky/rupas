package tunnel

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kshishtovsky/rupas/internal/config"
	"github.com/kshishtovsky/tuman/client"
	"github.com/kshishtovsky/tuman/mux"
	"github.com/kshishtovsky/tuman/proto"
)

// tmnTestAuth — метка exporter'а из mux (клиентская константа в tuman
// не экспортирована, значение зафиксировано протоколом §4).
const tmnTestAuth = "TMN1-AUTH-RANDOM"

var tmnTestPSK = bytes.Repeat([]byte{0x5A}, 32)

// tmnServer — TLS+mux сервер TMN в процессе: каждый поток эхом возвращает
// полученное, цель разбирается протоколом (домен тоже принимается — эхо-цель
// не резолвится, сервер отвечает сам).
type tmnServer struct {
	addr string

	mu      sync.Mutex
	targets []string // host:port принятых потоков
}

func newTMNServer(t *testing.T) *tmnServer {
	t.Helper()
	s := &tmnServer{}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t)},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	s.addr = ln.Addr().String()
	t.Cleanup(func() { ln.Close() })
	go s.serve(ln)
	return s
}

func (s *tmnServer) serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go s.serveConn(c.(*tls.Conn))
	}
}

func (s *tmnServer) serveConn(c *tls.Conn) {
	defer c.Close()
	if err := c.Handshake(); err != nil {
		return
	}
	state := c.ConnectionState()
	exp, err := state.ExportKeyingMaterial(tmnTestAuth, nil, 32)
	if err != nil {
		return
	}
	sess, err := mux.New(c, mux.Config{PSK: tmnTestPSK, Exporter: exp})
	if err != nil {
		return
	}
	defer sess.Close()
	for {
		st, err := sess.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go func() {
			defer st.Close()
			host, port, err := proto.DecodeTarget(st.Target())
			if err != nil {
				return
			}
			s.mu.Lock()
			s.targets = append(s.targets, net.JoinHostPort(host, port))
			s.mu.Unlock()
			io.Copy(st, st) //nolint:errcheck // эхо
		}()
	}
}

// lastTarget — цель последнего принятого потока.
func (s *tmnServer) lastTarget() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.targets) == 0 {
		return ""
	}
	return s.targets[len(s.targets)-1]
}

// endpoint собирает конфиг tmn на тестовый сервер.
func (s *tmnServer) endpoint() config.Endpoint {
	ap := netip.MustParseAddrPort(s.addr)
	return config.Endpoint{
		Kind:  config.KindTMN,
		Host:  ap.Addr().String(),
		Port:  ap.Port(),
		SNI:   "localhost",
		PSK:   strings.Repeat("5a", 32),
		Conns: 1,
	}
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tmn-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// insecureTMN включает Insecure у клиента: серт тестового сервера самоподписан.
func insecureTMN(t *testing.T) {
	t.Helper()
	old := tmnClientNew
	tmnClientNew = func(cfg client.Config) (*client.Client, error) {
		cfg.Insecure = true
		return client.New(cfg)
	}
	t.Cleanup(func() { tmnClientNew = old })
}

// tmnCarrier поднимает ленивый carrier на тестовый сервер.
func tmnCarrier(t *testing.T, s *tmnServer) *lazyTMN {
	t.Helper()
	insecureTMN(t)
	l := &lazyTMN{ep: s.endpoint(), logger: slog.New(slog.DiscardHandler)}
	t.Cleanup(func() { l.Close() }) //nolint:errcheck // идемпотентен
	return l
}

func echoRoundtrip(t *testing.T, c net.Conn) {
	t.Helper()
	want := bytes.Repeat([]byte("tmn!"), 2048)
	errc := make(chan error, 1)
	go func() {
		_, err := c.Write(want)
		errc <- err
	}()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("write: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("эхо не совпало")
	}
}

func dialCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// (a) dial по IP-адресу: поток ходит туда-обратно.
func TestTMNDialEcho(t *testing.T) {
	s := newTMNServer(t)
	l := tmnCarrier(t, s)
	conn, err := l.dial(dialCtx(t), netip.MustParseAddrPort(s.addr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	echoRoundtrip(t, conn)
	if got := s.lastTarget(); got != s.addr {
		t.Fatalf("цель на выходе %q, ждали %q", got, s.addr)
	}
}

// (b) dialHost с доменом: имя уходит на выход нерезолвленным, поток живёт.
func TestTMNDialHostDomain(t *testing.T) {
	s := newTMNServer(t)
	l := tmnCarrier(t, s)
	port := netip.MustParseAddrPort(s.addr).Port()
	conn, err := l.dialHost(dialCtx(t), "echo.tmn.invalid", port)
	if err != nil {
		t.Fatalf("dialHost: %v", err)
	}
	defer conn.Close()
	echoRoundtrip(t, conn)
	if got := s.lastTarget(); got != net.JoinHostPort("echo.tmn.invalid", strconv.Itoa(int(port))) {
		t.Fatalf("цель на выходе %q, ждали домен echo.tmn.invalid:%d", got, port)
	}
}

// (c) Close идемпотентен, поток после Close не открывается.
func TestTMNClose(t *testing.T) {
	s := newTMNServer(t)
	l := &lazyTMN{ep: s.endpoint(), logger: slog.New(slog.DiscardHandler)}
	insecureTMN(t)
	conn, err := l.dial(dialCtx(t), netip.MustParseAddrPort(s.addr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	echoRoundtrip(t, conn)
	conn.Close()

	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("второй Close: %v", err)
	}
	if c, err := l.dial(dialCtx(t), netip.MustParseAddrPort(s.addr)); err == nil {
		c.Close()
		t.Fatal("dial после Close открыл поток")
	}
}

// (d) Carrier, который ни разу не диалел, закрывается без паники.
func TestTMNLazyCloseNeverDialed(t *testing.T) {
	l := &lazyTMN{
		ep:     config.Endpoint{Kind: config.KindTMN, Host: "127.0.0.1", Port: 1, PSK: strings.Repeat("5a", 32)},
		logger: slog.New(slog.DiscardHandler),
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("второй Close: %v", err)
	}
}

// Единственный tmn-ендпоинт не требует sing-box: ни портов, ни UDP-пути,
// ни outbound'ов.
func TestTMNOnlyPlanNeedsNoSingbox(t *testing.T) {
	ep := &config.Endpoint{Kind: config.KindTMN, Host: "h", Port: 1, SNI: "s", PSK: strings.Repeat("5a", 32), Conns: 4}
	cfg := config.TunnelConfig{TCP: ep}
	plan := effectivePlan(cfg)
	if plan.tcp != ep || plan.udp != nil {
		t.Fatalf("план: tcp=%v udp=%v, ждали только tcp", plan.tcp, plan.udp)
	}
	ports, err := sbPortsForPlan(cfg)
	if err != nil {
		t.Fatalf("sbPortsForPlan: %v", err)
	}
	if ports != (sbPorts{}) {
		t.Fatalf("порты sing-box: %+v, ждали нулевые", ports)
	}
	for _, ob := range boxOptions(cfg, ports).Outbounds {
		if ob.Type != "direct" {
			t.Fatalf("sing-box outbound %q на tmn-ендпоинт", ob.Type)
		}
	}
}
