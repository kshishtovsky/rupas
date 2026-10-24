//go:build with_utls

package tunnel

// End-to-end integration test, no external network: a sing-box
// VLESS+Reality SERVER runs in-process on 127.0.0.1 (self-signed x25519
// Reality keys generated below), with a plain echo-HTTP and a UDP-echo
// "internet" behind it. The client is the real tunnel (sing-box
// vless+reality outbound, uTLS chrome, XUDP). A plain TCP client socket
// plays the NAT'd Telegram/Discord flow: it connects to the tproxy listener
// and its src 4-tuple is mapped to the echo origin by the provider.

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rupas/rupas/internal/config"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"golang.org/x/crypto/curve25519"
)

// genRealityKeys generates an x25519 keypair encoded the Reality way
// (base64 RawURL, 32 bytes).
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

// genUUID generates a random v4 UUID.
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

// serverBoxOptions builds the in-process "VPS" config: vless+reality
// inbound on loopback, direct outbound (to the local echo services).
func serverBoxOptions(vpPort, echoPort uint16, uuid, privKey, shortID, sni string) option.Options {
	listen := badoption.Addr(netip.MustParseAddr(loopbackIP))
	return option.Options{
		Log: sbLogOptions(),
		DNS: &option.DNSOptions{
			RawDNSOptions: option.RawDNSOptions{
				Servers: []option.DNSServerOptions{
					{Type: "local", Tag: "srv-dns", Options: &option.LocalDNSServerOptions{}},
				},
			},
		},
		Inbounds: []option.Inbound{
			{
				Type: "vless",
				Tag:  "srv-vless",
				Options: &option.VLESSInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     &listen,
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
										Server:     loopbackIP,
										ServerPort: echoPort,
									},
								},
								PrivateKey: privKey,
								ShortID:    badoption.Listable[string]{shortID},
							},
						},
					},
				},
			},
		},
		Outbounds: []option.Outbound{
			{
				Type: "direct",
				Tag:  "srv-direct",
				Options: &option.DirectOutboundOptions{
					DialerOptions: option.DialerOptions{
						AbstractDialerOptions: option.AbstractDialerOptions{
							DomainResolver: &option.DomainResolveOptions{Server: "srv-dns"},
						},
					},
				},
			},
		},
		Route: &option.RouteOptions{
			Final:                 "srv-direct",
			DefaultDomainResolver: &option.DomainResolveOptions{Server: "srv-dns"},
		},
	}
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// TestVLESSRealityE2E drives a full HTTP request and a UDP datagram through
// the tunnel against a local VLESS+Reality server.
func TestVLESSRealityE2E(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// The "internet" behind the VPS: plain echo HTTP + UDP echo.
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ECHO:%s", r.URL.Path)
	}))
	defer echo.Close()
	echoUDP := udpTagEcho(t, "UDPECHO")
	echoAddr := netip.MustParseAddrPort(echo.Listener.Addr().String())

	// Reality's handshake dest must speak TLS (the server borrows its
	// ServerHello for the camouflage handshake); authorized connections
	// never reach it.
	tlsDest := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer tlsDest.Close()
	tlsDestPort := uint16(tlsDest.Listener.Addr().(*net.TCPAddr).Port)

	// The VPS: sing-box vless+reality server on loopback.
	privKey, pubKey := genRealityKeys(t)
	uuid := genUUID(t)
	shortID := "0123abcd"
	sni := "www.example.com"
	vpPort := freePort(t)
	serverSB, err := startSingbox(context.Background(), logger,
		serverBoxOptions(vpPort, tlsDestPort, uuid, privKey, shortID, sni))
	if err != nil {
		t.Fatalf("start sing-box server: %v", err)
	}
	defer serverSB.close()

	// The client: our tunnel.
	tproxy := freePort(t)
	provider := newMapProvider()
	tun := NewTunnel(config.TunnelEndpoint{
		Protocol:    "vless",
		Address:     loopbackIP,
		Port:        vpPort,
		UUID:        uuid,
		RealityPBK:  pubKey,
		RealitySID:  shortID,
		SNI:         sni,
		Fingerprint: "chrome",
		UDPMode:     "xudp",
	}, tproxy, Options{
		OriginalDstProvider: provider,
		MarkerURL:           echo.URL + "/marker",
		Logger:              logger,
	}).(*tunnel)
	tun.healthInterval = 300 * time.Millisecond
	t.Cleanup(func() { tun.Stop() })
	if err := tun.Start(context.Background()); err != nil {
		t.Fatalf("tunnel start: %v", err)
	}

	// TCP: a NAT'd client with a pre-registered src 4-tuple.
	srcTCP := netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", bindTCPPort(t)))
	provider.add(srcTCP, echoAddr)
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(srcTCP.Port())}}
	conn, err := d.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tproxy))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second)) //nolint:errcheck
	if _, err := conn.Write([]byte("GET /e2e HTTP/1.0\r\nHost: echo.local\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	resp, err := io.ReadAll(bufio.NewReader(conn))
	if err != nil {
		t.Fatalf("reading HTTP response through tunnel: %v", err)
	}
	statusLine := string(resp)
	if nl := indexByte(statusLine, '\n'); nl > 0 {
		statusLine = statusLine[:nl]
	}
	if !hasPrefix(statusLine, "HTTP/1.0 200") && !hasPrefix(statusLine, "HTTP/1.1 200") {
		t.Fatalf("through-tunnel HTTP status not 200: %q", statusLine)
	}
	if !strings.Contains(string(resp), "ECHO:/e2e") {
		t.Fatalf("echo body missing:\n%.200s", resp)
	}

	// Health: the marker request goes through the tunnel to the echo.
	waitFor(t, "tunnel healthy", 10*time.Second, tun.Healthy)

	// UDP: a NAT'd Discord-ish client.
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	srcUDP := netip.MustParseAddrPort(uc.LocalAddr().String())
	provider.add(srcUDP, echoUDP)
	if _, err := uc.WriteToUDPAddrPort([]byte("discord-media-packet"),
		netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", tproxy))); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	uc.SetReadDeadline(time.Now().Add(15 * time.Second)) //nolint:errcheck
	n, _, err := uc.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("reading UDP echo through tunnel: %v", err)
	}
	if got := string(buf[:n]); got != "UDPECHO:discord-media-packet" {
		t.Fatalf("UDP echo through tunnel: got %q", got)
	}

	// Degradation: kill the marker origin → 3 consecutive failures flip
	// Healthy() to false.
	echo.Close()
	waitFor(t, "tunnel unhealthy after marker loss", 10*time.Second, func() bool { return !tun.Healthy() })
}
