package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rupas/rupas/internal/config"
)

// --- test carriers -----------------------------------------------------------

// deadTCP fails every dial (plays a dead primary endpoint).
type deadTCP struct{ dials atomic.Int64 }

func (d *deadTCP) dial(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	d.dials.Add(1)
	return nil, errors.New("dead primary")
}
func (d *deadTCP) dialHost(ctx context.Context, host string, port uint16) (net.Conn, error) {
	d.dials.Add(1)
	return nil, errors.New("dead primary")
}

// deadUDP fails every UDP ASSOCIATE (plays a dead UDP endpoint).
type deadUDP struct{ associates atomic.Int64 }

func (d *deadUDP) udpAssociate(ctx context.Context) (packetRelay, error) {
	d.associates.Add(1)
	return nil, errors.New("dead udp endpoint")
}

// rawUDPRelay relays raw datagrams to the destination (the session-table
// logic is identical to the real relay path).
type rawUDPRelay struct{ socket *net.UDPConn }

func rawUDPRelayOn(t *testing.T) *rawUDPRelay {
	t.Helper()
	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { socket.Close() })
	return &rawUDPRelay{socket: socket}
}

func (r *rawUDPRelay) send(dst netip.AddrPort, payload []byte) error {
	_, err := r.socket.WriteToUDPAddrPort(payload, dst)
	return err
}

func (r *rawUDPRelay) receive(buf []byte) (netip.AddrPort, []byte, error) {
	n, src, err := r.socket.ReadFromUDPAddrPort(buf)
	return src, buf[:n], err
}

func (r *rawUDPRelay) close() { r.socket.Close() }

func (r *rawUDPRelay) udpAssociate(ctx context.Context) (packetRelay, error) {
	return r, nil
}

// toggleUDP switches between a dead endpoint and a raw relay (test probe of
// the fallback switch-back).
type toggleUDP struct {
	ok  atomic.Bool
	rel *rawUDPRelay
}

func (t *toggleUDP) udpAssociate(ctx context.Context) (packetRelay, error) {
	if !t.ok.Load() {
		return nil, errors.New("toggled off")
	}
	return t.rel, nil
}

// fakeSTUN responds to any datagram with a valid binding success carrying
// the request's transaction id.
func fakeSTUN(t *testing.T) netip.AddrPort {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 20 {
				continue
			}
			resp := make([]byte, n)
			copy(resp, buf[:n])
			binary.BigEndian.PutUint16(resp[0:2], stunMsgSuccess)
			if _, err := conn.WriteTo(resp, from); err != nil {
				return
			}
		}
	}()
	return netip.MustParseAddrPort(conn.LocalAddr().String())
}

// newPlanTunnel builds a startCore-level tunnel with explicit chains.
func newPlanTunnel(t *testing.T, tproxyPort uint16, provider *mapProvider, tcp []namedTCP, udp []namedUDP, stun string) *tunnel {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tun := &tunnel{
		tproxyPort:        tproxyPort,
		opts:              Options{STUNServer: stun, OriginalDstProvider: provider, Logger: logger},
		logger:            logger.With("component", "tunnel"),
		healthInterval:    time.Hour, // marker driven manually
		udpHealthInterval: 40 * time.Millisecond,
		dialTimeout:       3 * time.Second,
		udpTimeout:        30 * time.Second,
	}
	tun.tcpPaths = tcp
	tun.udpPaths = udp
	t.Cleanup(func() { tun.Stop() })
	if err := tun.startCore(); err != nil {
		t.Fatal(err)
	}
	return tun
}

// TestTCPFallbackChain: the primary TCP path fails, the flow must ride the
// fallback carrier (§6 wave 5: tcp vless_tcp → xhttp).
func TestTCPFallbackChain(t *testing.T) {
	provider := newMapProvider()
	tproxy := freePort(t)
	dead := &deadTCP{}
	echo := tcpTagEcho(t, "FB")
	_ = newPlanTunnel(t, tproxy, provider,
		[]namedTCP{{name: "primary", c: dead}, {name: "fallback", c: fakeTransport{}}},
		[]namedUDP{{name: "udp", c: rawUDPRelayOn(t)}},
		"off")

	src := netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", bindTCPPort(t)))
	provider.add(src, echo)
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(src.Port())}}
	conn, err := d.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tproxy))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	if _, err := conn.Write([]byte("ping\n")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("no reply through the fallback path: %v", err)
	}
	if string(buf[:n]) != "FB:ping\n" {
		t.Fatalf("reply = %q, want FB:ping", buf[:n])
	}
	if dead.dials.Load() == 0 {
		t.Error("primary path was never tried")
	}
}

// TestUDPFallbackSwitch: a dead UDP endpoint flips the active UDP carrier
// to the xudp fallback after HealthFailThreshold probe failures, datagrams
// then flow through it; a recovering primary switches back.
func TestUDPFallbackSwitch(t *testing.T) {
	provider := newMapProvider()
	tproxy := freePort(t)
	stun := fakeSTUN(t)
	toggle := &toggleUDP{rel: rawUDPRelayOn(t)}
	toggle.ok.Store(false) // hy2 "dead" (ISP drops UDP)
	echo := udpTagEcho(t, "XUDP")
	fallback := rawUDPRelayOn(t)

	tun := newPlanTunnel(t, tproxy, provider,
		[]namedTCP{{name: "tcp", c: fakeTransport{}}},
		[]namedUDP{{name: "hysteria2", c: toggle}, {name: "vless_tcp+xudp", c: fallback}},
		stun.String())

	waitFor(t, "udp fallback to engage", 5*time.Second, func() bool {
		return tun.Stats().UDPFallback
	})
	if tun.Stats().UDPHealthy {
		t.Fatal("udpHealthy must be false while the primary fails")
	}

	// A UDP pseudo-session must now ride the fallback (xudp over the TCP
	// endpoint) and reach the echo.
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	src := netip.MustParseAddrPort(uc.LocalAddr().String())
	provider.add(src, echo)
	if _, err := uc.WriteToUDPAddrPort([]byte("voice"), netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", tproxy))); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	uc.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	n, _, err := uc.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no UDP reply through the xudp fallback: %v", err)
	}
	if string(buf[:n]) != "XUDP:voice" {
		t.Fatalf("reply = %q, want XUDP:voice", buf[:n])
	}

	// Recovery: primary answers STUN again → traffic returns to it.
	toggle.ok.Store(true)
	waitFor(t, "udp primary recovery", 5*time.Second, func() bool {
		st := tun.Stats()
		return st.UDPHealthy && !st.UDPFallback
	})
}

// TestUDPProbeDisabled pins the "off" switch: no probe, no fallback.
func TestUDPProbeDisabled(t *testing.T) {
	provider := newMapProvider()
	tproxy := freePort(t)
	tun := newPlanTunnel(t, tproxy, provider,
		[]namedTCP{{name: "tcp", c: fakeTransport{}}},
		[]namedUDP{{name: "dead", c: &deadUDP{}}, {name: "fb", c: rawUDPRelayOn(t)}},
		"off")
	time.Sleep(150 * time.Millisecond)
	if tun.Stats().UDPFallback {
		t.Error("fallback engaged with the probe disabled")
	}
}

// TestEffectivePlanSelection pins the endpoint-by-flow-type selection.
func TestEffectivePlanSelection(t *testing.T) {
	vless := &config.Endpoint{Kind: config.KindVLESSTCP, Host: "a", Port: 1, UUID: "u", SNI: "s"}
	hy2 := &config.Endpoint{Kind: config.KindHysteria2, Host: "a", Port: 2, Password: "p", SNI: "s"}
	xh := &config.Endpoint{Kind: config.KindVLESSXHTTP, Host: "a", Port: 3, UUID: "u", SNI: "s", Path: "/x"}

	// Both set: TCP→vless, UDP→hy2.
	p := effectivePlan(config.TunnelConfig{TCP: vless, UDP: hy2})
	if p.tcp != vless || p.udp != hy2 {
		t.Errorf("both set: tcp=%v udp=%v", p.tcp, p.udp)
	}
	// UDP-only: the UDP endpoint carries TCP too.
	p = effectivePlan(config.TunnelConfig{UDP: hy2})
	if p.tcp != hy2 || p.udp != hy2 {
		t.Errorf("udp-only: tcp=%v udp=%v", p.tcp, p.udp)
	}
	// TCP-only vless: xudp rides the same endpoint.
	p = effectivePlan(config.TunnelConfig{TCP: vless})
	if p.tcp != vless || p.udp != vless {
		t.Errorf("tcp-only: tcp=%v udp=%v", p.tcp, p.udp)
	}
	// TCP-only xhttp: no UDP path (XUDP rides VLESS; xhttp carries none).
	p = effectivePlan(config.TunnelConfig{TCP: xh})
	if p.tcp != xh || p.udp != nil {
		t.Errorf("tcp-xhttp-only: tcp=%v udp=%v", p.tcp, p.udp)
	}
}

// TestSBPortsForPlan pins which per-path mixed inbounds the plan needs.
func TestSBPortsForPlan(t *testing.T) {
	vless := &config.Endpoint{Kind: config.KindVLESSTCP, Host: "a", Port: 1, UUID: "u", SNI: "s"}
	hy2 := &config.Endpoint{Kind: config.KindHysteria2, Host: "a", Port: 2, Password: "p", SNI: "s"}
	xh := &config.Endpoint{Kind: config.KindVLESSXHTTP, Host: "a", Port: 3, UUID: "u", SNI: "s", Path: "/x"}
	reality := &config.Endpoint{Kind: config.KindVLESSReality, Host: "a", Port: 4, UUID: "u", SNI: "s", RealityPBK: "k"}

	cases := []struct {
		name                string
		cfg                 config.TunnelConfig
		main, tcpfb, udpfb  bool
	}{
		// Wave 6: a distinct hy2 endpoint doubles as the TCP fallback
		// carrier when the configured fallback is xhttp (out of the
		// default chain) or absent — hence tcpfb=true for these layouts.
		{"user layout (vless+hy2+xhttp-fb)", config.TunnelConfig{TCP: vless, UDP: hy2, Fallback: xh}, true, true, true},
		{"singbox fallback", config.TunnelConfig{TCP: vless, UDP: hy2, Fallback: reality}, true, true, true},
		{"single endpoint", config.TunnelConfig{TCP: reality, UDP: reality}, true, false, false},
		{"xhttp tcp + hy2 udp", config.TunnelConfig{TCP: xh, UDP: hy2}, true, true, false},
		{"udp only", config.TunnelConfig{UDP: hy2}, true, false, false},
	}
	for _, c := range cases {
		ports, err := sbPortsForPlan(c.cfg)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if (ports.Main != 0) != c.main || (ports.TCPFB != 0) != c.tcpfb || (ports.UDPFB != 0) != c.udpfb {
			t.Errorf("%s: ports = %+v, want main=%v tcpfb=%v udpfb=%v", c.name, ports, c.main, c.tcpfb, c.udpfb)
		}
	}
}
