package android

// TMN/1 carrier tests: the fifth transport is carried in-process (like
// xhttp), never by sing-box. What must hold: a tmn-only profile builds
// exactly one carrier named after the endpoint (with AND without a relay),
// a flow through dialChain reaches the server, and every socket the client
// opens goes through the protecting dialer — otherwise the tunnel loops into
// its own TUN.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kshishtovsky/tuman/mux"
)

// tmnAuthLabel is the TLS exporter label the server derives the mux key from
// (tuman client/authLabel, §4: exporter instead of client_random).
const tmnAuthLabel = "TMN1-AUTH-RANDOM"

// tmnTestServer is an in-process TMN/1 endpoint: TLS 1.3 + ALPN h2 + mux,
// every stream echoes what it receives (the pattern of tuman's own
// client_test.go).
type tmnTestServer struct {
	addr string
	psk  []byte

	mu       sync.Mutex
	sessions int
}

func newTMNTestServer(t *testing.T) *tmnTestServer {
	t.Helper()
	s := &tmnTestServer{psk: bytes.Repeat([]byte{0x5A}, 32)}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tmnSelfSigned(t)},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	s.addr = ln.Addr().String()
	go s.serve(ln)
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *tmnTestServer) serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go s.serveConn(c.(*tls.Conn))
	}
}

func (s *tmnTestServer) serveConn(c *tls.Conn) {
	defer c.Close()
	if err := c.Handshake(); err != nil {
		return
	}
	state := c.ConnectionState()
	exp, err := state.ExportKeyingMaterial(tmnAuthLabel, nil, 32)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.sessions++
	s.mu.Unlock()
	sess, err := mux.New(c, mux.Config{PSK: s.psk, Exporter: exp})
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
			io.Copy(st, st) // echo: the client gets back what it sent
		}()
	}
}

// link renders the share link the app would paste for this server.
func (s *tmnTestServer) link() string {
	return "tmn://" + hex.EncodeToString(s.psk) + "@" + s.addr +
		"?sni=localhost&conns=1&insecure=1#tmn-test"
}

func (s *tmnTestServer) sessionCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions
}

func tmnSelfSigned(t *testing.T) tls.Certificate {
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

// tmnEngine builds an engine over one tmn link the way the app does: settings
// → Endpoints() → buildCarriers. protect nil means "no VpnService".
func tmnEngine(t *testing.T, link string, protect ProtectFunc) *Engine {
	t.Helper()
	s := &Settings{Links: []string{link}} // fallback=false: no direct tail
	eps, err := s.Endpoints()
	if err != nil {
		t.Fatalf("Endpoints: %v", err)
	}
	e := NewEngine(nil, protect, func(string) {})
	e.settings = s
	e.endpoints = eps
	e.buildCarriers(context.Background())
	return e
}

// echoThroughChain sends payload through the dial chain and checks it comes
// back (the echo server answers with whatever it received).
func echoThroughChain(t *testing.T, e *Engine) {
	t.Helper()
	conn, err := e.dialChain(netip.MustParseAddrPort("203.0.113.9:443"))
	if err != nil {
		t.Fatalf("dialChain: %v", err)
	}
	defer conn.Close()
	if e.carriers[0].name == "direct" {
		t.Fatal("flow escalated to direct instead of using the tmn carrier")
	}
	payload := []byte("GET /generate_204 HTTP/1.1\r\nHost: cover\r\n\r\n")
	errs := make(chan error, 1)
	go func() {
		_, wErr := conn.Write(payload)
		errs <- wErr
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if err := <-errs; err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: %q", got)
	}
}

// A tmn-only profile builds exactly one carrier, named after the endpoint,
// and a flow through dialChain reaches the server (no relay exists here —
// the chain must build anyway).
func TestTMNOnlyProfileBuildsOneCarrier(t *testing.T) {
	srv := newTMNTestServer(t)
	e := tmnEngine(t, srv.link(), nil)
	if e.relay != nil {
		t.Fatal("test premise: a tmn-only engine must have no relay")
	}
	if len(e.carriers) != 1 {
		t.Fatalf("carriers: %d, want exactly the tmn one", len(e.carriers))
	}
	want := "tmn/tls/tcp@" + srv.addr
	if got := e.carriers[0].name; got != want {
		t.Fatalf("carrier name %q, want %q", got, want)
	}
	if len(e.health) != 1 {
		t.Fatalf("health: %d, want 1", len(e.health))
	}
	echoThroughChain(t, e)
	if n := srv.sessionCount(); n == 0 {
		t.Fatal("no TMN session reached the server")
	}

	// The pool dies with the run: a leaked client would keep its TLS
	// sessions (and their goroutines) alive across every reconnect.
	e.closeTMN()
	if _, err := e.dialChain(netip.MustParseAddrPort("203.0.113.9:443")); err == nil {
		t.Fatal("dial after closeTMN must fail: the client is closed")
	}
}

// A relay-less run still yields a carrier: the old e.relay == nil early
// return silently swallowed a native-only chain. No server needed — the
// client opens nothing until the first dial.
func TestTMNCarrierWithoutRelay(t *testing.T) {
	link := "tmn://" + hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32)) +
		"@127.0.0.1:1?sni=localhost&conns=1"
	e := tmnEngine(t, link, nil)
	if e.relay != nil {
		t.Fatal("test premise: no relay")
	}
	if len(e.carriers) != 1 || e.carriers[0].name == "direct" {
		t.Fatalf("carriers: %+v, want one tmn carrier", e.carriers)
	}
}

// Every socket the TMN client opens must pass the protect hook: without it
// the tunnel's own sockets loop back into the TUN it carries.
func TestTMNCarrierUsesProtectedDialer(t *testing.T) {
	srv := newTMNTestServer(t)
	var calls atomic.Int64
	e := tmnEngine(t, srv.link(), func(fd int) bool {
		calls.Add(1)
		return true
	})
	echoThroughChain(t, e)
	if calls.Load() == 0 {
		t.Fatal("tmn sockets bypassed the protecting dialer (they would loop into the TUN)")
	}
}
