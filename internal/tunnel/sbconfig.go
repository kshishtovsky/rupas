package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/rupas/rupas/internal/config"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

// Tags used in the generated sing-box configuration.
const (
	mixedTag   = "rupas-mixed"
	vlessTag   = "rupas-vless"
	directTag  = "rupas-direct"
	dnsTag     = "rupas-dns"
	vlessFlow  = "xtls-rprx-vision" // standard VLESS+Reality flow
	loopbackIP = "127.0.0.1"
)

// sbLogOptions silences sing-box logging unless RUPAS_TUNNEL_SBLOG is set
// (debug aid).
func sbLogOptions() *option.LogOptions {
	if os.Getenv("RUPAS_TUNNEL_SBLOG") != "" {
		return &option.LogOptions{Level: "trace", Timestamp: true}
	}
	return &option.LogOptions{Disabled: true}
}

// boxOptions maps a config.TunnelEndpoint to the sing-box client
// configuration (§6): one mixed inbound on loopback (fed by our tproxy
// listeners), one vless+reality outbound with uTLS fingerprint, DNS via the
// local resolver, and a route sending everything through vless.
func boxOptions(cfg config.TunnelEndpoint, mixedPort uint16) option.Options {
	packetEncoding := "xudp"
	switch strings.ToLower(cfg.UDPMode) {
	case "xudp", "":
		packetEncoding = "xudp"
	case "packetaddr":
		packetEncoding = "packetaddr"
	}
	return option.Options{
		Log: sbLogOptions(),
		DNS: &option.DNSOptions{
			RawDNSOptions: option.RawDNSOptions{
				Servers: []option.DNSServerOptions{
					{Type: "local", Tag: dnsTag, Options: &option.LocalDNSServerOptions{}},
				},
			},
		},
		Inbounds: []option.Inbound{
			{
				Type: "mixed",
				Tag:  mixedTag,
				Options: &option.HTTPMixedInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     listenAddr(loopbackIP),
						ListenPort: mixedPort,
					},
				},
			},
		},
		Outbounds: []option.Outbound{
			{
				Type: "vless",
				Tag:  vlessTag,
				Options: &option.VLESSOutboundOptions{
					ServerOptions: option.ServerOptions{
						Server:     cfg.Address,
						ServerPort: cfg.Port,
					},
					UUID:           cfg.UUID,
					Flow:           vlessFlow,
					PacketEncoding: &packetEncoding,
					DialerOptions: option.DialerOptions{
						AbstractDialerOptions: option.AbstractDialerOptions{
							DomainResolver: &option.DomainResolveOptions{Server: dnsTag},
						},
					},
					OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
						TLS: &option.OutboundTLSOptions{
							Enabled:    true,
							ServerName: cfg.SNI,
							UTLS: &option.OutboundUTLSOptions{
								Enabled:     true,
								Fingerprint: fingerprintOf(cfg),
							},
							Reality: &option.OutboundRealityOptions{
								Enabled:   true,
								PublicKey: cfg.RealityPBK,
								ShortID:   cfg.RealitySID,
							},
						},
					},
				},
			},
			{
				Type: "direct",
				Tag:  directTag,
				Options: &option.DirectOutboundOptions{
					DialerOptions: option.DialerOptions{
						AbstractDialerOptions: option.AbstractDialerOptions{
							DomainResolver: &option.DomainResolveOptions{Server: dnsTag},
						},
					},
				},
			},
		},
		Route: &option.RouteOptions{
			Final:                 vlessTag,
			DefaultDomainResolver: &option.DomainResolveOptions{Server: dnsTag},
			AutoDetectInterface:   true,
		},
	}
}

// fingerprintOf normalizes the uTLS fingerprint; unknown values fall back to
// the sing-box default (chrome), which is also the config default.
func fingerprintOf(cfg config.TunnelEndpoint) string {
	switch strings.ToLower(strings.TrimSpace(cfg.Fingerprint)) {
	case "":
		return "chrome"
	case "chrome", "chrome_psk", "chrome_psk_shuffle", "chrome_padding_psk_shuffle",
		"chrome_pq", "chrome_pq_psk", "firefox", "edge", "safari", "360", "qq",
		"ios", "android", "random", "randomized":
		return strings.ToLower(strings.TrimSpace(cfg.Fingerprint))
	default:
		return "chrome"
	}
}

// listenAddr builds the badoption.Addr for a loopback listener.
func listenAddr(ip string) *badoption.Addr {
	a := badoption.Addr(netip.MustParseAddr(ip))
	return &a
}

// validateEndpoint checks the tunnel endpoint before engine start.
func validateEndpoint(cfg config.TunnelEndpoint) error {
	if strings.ToLower(cfg.Protocol) != "vless" {
		return fmt.Errorf("tunnel: protocol %q: only \"vless\" is supported", cfg.Protocol)
	}
	if cfg.Address == "" || cfg.Port == 0 {
		return errors.New("tunnel: endpoint address/port is empty")
	}
	if cfg.UUID == "" {
		return errors.New("tunnel: endpoint uuid is empty")
	}
	if cfg.RealityPBK == "" {
		return errors.New("tunnel: reality public key is empty")
	}
	if cfg.SNI == "" {
		return errors.New("tunnel: sni is empty")
	}
	if port := int(cfg.Port); port < 1 || port > 65535 {
		return fmt.Errorf("tunnel: port %d out of range", cfg.Port)
	}
	return nil
}

// marshalBoxOptions renders the generated sing-box config as JSON (used for
// debug logs and diagnostics).
func marshalBoxOptions(ctx context.Context, opts option.Options) ([]byte, error) {
	return json.MarshalContext(ctx, opts)
}

// freeTCPPort reserves an ephemeral loopback TCP port and releases it.
func freeTCPPort() (uint16, error) {
	ln, err := net.Listen("tcp", loopbackIP+":0")
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
