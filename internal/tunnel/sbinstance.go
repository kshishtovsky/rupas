package tunnel

import (
	"context"
	"fmt"
	"log/slog"
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
)

// singbox owns an embedded sing-box engine (ADR-4: sing-box as a library).
// The protocol registry is intentionally minimal — mixed (our SOCKS5 feeder),
// vless (client and, in tests, server) and direct — so the heavyweight
// optional protocols (tun, quic, wireguard, …) stay out of the binary.
type singbox struct {
	box       *box.Box
	mixedPort uint16
}

// startSingbox builds a fresh registry context, creates and starts a
// sing-box instance for opts.
func startSingbox(ctx context.Context, logger *slog.Logger, opts option.Options) (*singbox, error) {
	boxCtx := minimalBoxContext(ctx)
	engine, err := box.New(box.Options{
		Context: boxCtx,
		Options: opts,
	})
	if err != nil {
		return nil, fmt.Errorf("box.New: %w", err)
	}
	if err := engine.Start(); err != nil {
		engine.Close() //nolint:errcheck // already failing
		return nil, fmt.Errorf("box.Start: %w", err)
	}
	if jsonCfg, err := marshalBoxOptions(boxCtx, opts); err == nil {
		logger.Debug("sing-box config", slog.String("json", string(jsonCfg)))
	}
	return &singbox{box: engine}, nil
}

func (s *singbox) close() error {
	if s.box == nil {
		return nil
	}
	return s.box.Close()
}

// mixedAddr is the loopback address of the internal mixed inbound.
func (s *singbox) mixedAddr() string {
	return net.JoinHostPort(loopbackIP, strconv.Itoa(int(s.mixedPort)))
}

// dial opens a TCP connection to dst through the tunnel (transport).
func (s *singbox) dial(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	return socks5Connect(ctx, s.mixedAddr(), dst)
}

// dialHost dials host:port (host may be a domain) through the tunnel
// (transport).
func (s *singbox) dialHost(ctx context.Context, host string, port uint16) (net.Conn, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		return s.dial(ctx, netip.AddrPortFrom(addr, port))
	}
	return socks5DialHost(ctx, s.mixedAddr(), host, port)
}

// udpAssociate starts a SOCKS5 UDP ASSOCIATE pseudo-session (transport).
func (s *singbox) udpAssociate(ctx context.Context) (packetRelay, error) {
	return socks5UDPAssociate(ctx, s.mixedAddr())
}

var _ transport = (*singbox)(nil)

// minimalBoxContext registers only the protocols Rupas needs, on fresh,
// non-global registries (the include package would pull tun/quic/wireguard
// and more into the process).
func minimalBoxContext(ctx context.Context) context.Context {
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
