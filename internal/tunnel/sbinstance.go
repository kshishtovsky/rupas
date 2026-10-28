package tunnel

import (
	"context"
	"fmt"
	"log/slog"
	"net"
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
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/mixed"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/vless"
)

// singbox owns an embedded sing-box engine (ADR-4: sing-box as a library).
// The protocol registry is intentionally minimal — mixed (our SOCKS5 feeder),
// vless (client and, in tests, server; TCP/Reality/XUDP), hysteria2 (QUIC
// UDP path) and direct — so the heavyweight optional protocols (tun,
// wireguard, plain quic-based extras, …) stay out of the binary.
type singbox struct {
	box   *box.Box
	ports sbPorts
}

// startSingbox builds a fresh registry context, creates and starts a
// sing-box instance for opts with the given per-path mixed ports.
func startSingbox(ctx context.Context, logger *slog.Logger, opts option.Options, ports sbPorts) (*singbox, error) {
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
	return &singbox{box: engine, ports: ports}, nil
}

func (s *singbox) close() error {
	if s.box == nil {
		return nil
	}
	return s.box.Close()
}

// mainAddr is the loopback address of the main mixed inbound (TCP CONNECT
// via route final; UDP ASSOCIATE via the network rule).
func (s *singbox) mainAddr() string {
	return net.JoinHostPort(loopbackIP, strconv.Itoa(int(s.ports.Main)))
}

// fbAddr is the loopback address of the TCP-fallback mixed inbound.
func (s *singbox) fbAddr() string {
	return net.JoinHostPort(loopbackIP, strconv.Itoa(int(s.ports.TCPFB)))
}

// udpFBAddr is the loopback address of the UDP-fallback mixed inbound
// (xudp over the TCP endpoint).
func (s *singbox) udpFBAddr() string {
	return net.JoinHostPort(loopbackIP, strconv.Itoa(int(s.ports.UDPFB)))
}

// minimalBoxContext registers only the protocols Rupas needs, on fresh,
// non-global registries (the include package would pull tun/quic-extras/
// wireguard and more into the process).
func minimalBoxContext(ctx context.Context) context.Context {
	inbounds := boxAdapterInbound.NewRegistry()
	mixed.RegisterInbound(inbounds)
	vless.RegisterInbound(inbounds)
	direct.RegisterInbound(inbounds)

	outbounds := boxAdapterOutbound.NewRegistry()
	vless.RegisterOutbound(outbounds)
	hysteria2.RegisterOutbound(outbounds)
	direct.RegisterOutbound(outbounds)
	// socks outbound: used by the in-process test "VPS" whose exit is a
	// scriptable SOCKS5 relay (hermetic e2e); production configs never
	// reference it.
	socks.RegisterOutbound(outbounds)

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
