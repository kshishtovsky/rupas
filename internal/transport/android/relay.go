package android

// W3 tunnel relay: an embedded sing-box instance with a local SOCKS5
// (mixed) inbound on 127.0.0.1 — the desktop PRD MVP-3 shape. Marked
// (TUNNEL) flows are dialed through it: TCP via socks5-CONNECT, UDP via
// socks5-UDP-ASSOCIATE (XUDP over the VLESS outbound).
//
// The sing-box outbound socket must bypass the VPN like every other egress
// socket: on Android the protector hook (protect_unix.go) runs a local
// fd-passing server and the outbound's protect_path points at it; its
// received fds are unhooked through the Java VpnService.protect callback.

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/sagernet/sing-box"
	boxAdapterCertificate "github.com/sagernet/sing-box/adapter/certificate"
	boxAdapterEndpoint "github.com/sagernet/sing-box/adapter/endpoint"
	boxAdapterInbound "github.com/sagernet/sing-box/adapter/inbound"
	boxAdapterOutbound "github.com/sagernet/sing-box/adapter/outbound"
	boxAdapterService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	dnsLocal "github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/mixed"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing/common/json/badoption"
)

// Relay owns the embedded sing-box engine and its loopback socks inbound.
// A relay with a dead/absent socksAddr is "unavailable": every dial fails
// fast and the caller escalates (engine.dialEgress).
type Relay struct {
	settings *Settings
	logFn    func(string)

	socksAddr string
	box       *box.Box
	// stopProtector tears the fd-passing protect server down (unix).
	stopProtector func()
}

// NewRelay assembles (but does not start) the tunnel relay.
func NewRelay(s *Settings, logFn func(string)) *Relay {
	return &Relay{settings: s, logFn: logFn}
}

// Available reports whether the relay can accept dials.
func (r *Relay) Available() bool { return r != nil && r.socksAddr != "" }

// Start builds and launches the sing-box instance. protect is used to
// unhook the outbound sockets from the VPN (may be nil on non-Android).
func (r *Relay) Start(ctx context.Context, protect ProtectFunc) error {
	if r == nil {
		return fmt.Errorf("android: relay: not configured")
	}
	if r.settings == nil {
		return fmt.Errorf("android: relay: no settings")
	}
	port, err := freeTCPPort()
	if err != nil {
		return fmt.Errorf("android: relay: pick socks port: %w", err)
	}
	r.socksAddr = netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), port).String()

	var protectPath string
	if protect != nil {
		path, stop, perr := startProtector(protect)
		if perr != nil {
			return fmt.Errorf("android: relay: protect server: %w", perr)
		}
		protectPath, r.stopProtector = path, stop
	}

	opts := relayOptions(r.settings, port, protectPath)
	engine, err := box.New(box.Options{
		Context: relayBoxContext(ctx),
		Options: opts,
	})
	if err != nil {
		r.stop()
		return fmt.Errorf("android: relay: box.New: %w", err)
	}
	if err := engine.Start(); err != nil {
		engine.Close() //nolint:errcheck // already failing
		r.stop()
		return fmt.Errorf("android: relay: box.Start: %w", err)
	}
	r.box = engine
	if r.logFn != nil {
		r.logFn("android: tunnel relay up: " + r.settings.Kind() + "@" + r.settings.ServerAddr() +
			" socks=" + r.socksAddr)
	}
	return nil
}

// Close shuts the engine and the protector down.
func (r *Relay) Close() error {
	if r == nil {
		return nil
	}
	var err error
	if r.box != nil {
		err = r.box.Close()
		r.box = nil
	}
	r.stop()
	r.socksAddr = ""
	return err
}

func (r *Relay) stop() {
	if r != nil && r.stopProtector != nil {
		r.stopProtector()
		r.stopProtector = nil
	}
}

// DialTCP connects dst through the socks inbound (CONNECT → VLESS).
func (r *Relay) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	if !r.Available() {
		return nil, fmt.Errorf("android: relay: tunnel unavailable")
	}
	return socks5Connect(ctx, r.socksAddr, dst)
}

// DialUDP opens a UDP ASSOCIATE session through the socks inbound
// (XUDP over the VLESS outbound).
func (r *Relay) DialUDP(ctx context.Context) (*socksUDP, error) {
	if !r.Available() {
		return nil, fmt.Errorf("android: relay: tunnel unavailable")
	}
	return socks5UDPAssociate(ctx, r.socksAddr)
}

// relayBoxContext registers only the protocols the mobile relay needs —
// the same minimal-registry pattern as the desktop (internal/tunnel
// sbinstance.go): mixed (our SOCKS5 feeder), vless, direct.
func relayBoxContext(ctx context.Context) context.Context {
	inbounds := boxAdapterInbound.NewRegistry()
	mixed.RegisterInbound(inbounds)
	vless.RegisterInbound(inbounds)
	direct.RegisterInbound(inbounds)

	outbounds := boxAdapterOutbound.NewRegistry()
	vless.RegisterOutbound(outbounds)
	direct.RegisterOutbound(outbounds)

	dnsReg := dns.NewTransportRegistry()
	dnsLocal.RegisterTransport(dnsReg)

	return box.Context(ctx,
		inbounds,
		outbounds,
		boxAdapterEndpoint.NewRegistry(),
		dnsReg,
		boxAdapterService.NewRegistry(),
		boxAdapterCertificate.NewRegistry(),
	)
}

const (
	relayInTag  = "rupas-in"
	relayOutTag = "rupas-out"
	relayDNSTag = "rupas-dns"
	// vlessFlowVision is the standard VLESS+Reality flow.
	vlessFlowVision = "xtls-rprx-vision"
)

// relayOptions builds the sing-box client configuration: one loopback
// mixed inbound, one VLESS outbound (protected via protect_path), route
// final → the outbound, local DNS for server-name resolution.
func relayOptions(s *Settings, port uint16, protectPath string) option.Options {
	flow := ""
	packetEncoding := "xudp"
	var reality *option.OutboundRealityOptions
	if s.Kind() == "vless_reality" {
		flow = vlessFlowVision
		reality = &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: s.PublicKey,
			ShortID:   s.ShortID,
		}
	}
	outbound := option.Outbound{
		Type: "vless",
		Tag:  relayOutTag,
		Options: &option.VLESSOutboundOptions{
			ServerOptions:  option.ServerOptions{Server: s.Server, ServerPort: s.Port},
			UUID:           s.UUID,
			Flow:           flow,
			PacketEncoding: &packetEncoding,
			DialerOptions: option.DialerOptions{
				AbstractDialerOptions: option.AbstractDialerOptions{
					DomainResolver: &option.DomainResolveOptions{Server: relayDNSTag},
					ProtectPath:    protectPath,
				},
			},
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
				TLS: &option.OutboundTLSOptions{
					Enabled:    true,
					ServerName: s.SNI,
					ALPN:       badoption.Listable[string]{"h2", "http/1.1"},
					UTLS: &option.OutboundUTLSOptions{
						Enabled:     true,
						Fingerprint: "chrome",
					},
					Reality: reality,
				},
			},
		},
	}
	return option.Options{
		Log: &option.LogOptions{Disabled: true},
		DNS: &option.DNSOptions{
			RawDNSOptions: option.RawDNSOptions{
				Servers: []option.DNSServerOptions{
					{Type: "local", Tag: relayDNSTag, Options: &option.LocalDNSServerOptions{}},
				},
			},
		},
		Inbounds: []option.Inbound{{
			Type: "mixed",
			Tag:  relayInTag,
			Options: &option.HTTPMixedInboundOptions{
				ListenOptions: option.ListenOptions{
					Listen:     listenAddr("127.0.0.1"),
					ListenPort: port,
				},
			},
		}},
		Outbounds: []option.Outbound{outbound},
		Route: &option.RouteOptions{
			Final:                 relayOutTag,
			DefaultDomainResolver: &option.DomainResolveOptions{Server: relayDNSTag},
			// No AutoDetectInterface on Android: interface binding is
			// root-only there — bypass happens through protect_path.
		},
	}
}

// freeTCPPort reserves an ephemeral loopback TCP port and releases it
// (same pattern as internal/tunnel sbconfig.go; benign TOCTOU).
func freeTCPPort() (uint16, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		return 0, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0, err
	}
	return uint16(port), nil
}

// listenAddr builds the badoption.Addr for a loopback listener.
func listenAddr(ip string) *badoption.Addr {
	a := badoption.Addr(netip.MustParseAddr(ip))
	return &a
}
