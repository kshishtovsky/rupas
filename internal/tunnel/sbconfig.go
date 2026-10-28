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

	"github.com/kshishtovsky/rupas/internal/config"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

// Tags used in the generated sing-box configuration.
const (
	mixedTag    = "rupas-mixed"     // main path: TCP CONNECT + UDP ASSOCIATE
	mixedFBTag  = "rupas-mixed-fb"  // TCP fallback path (own mixed inbound)
	mixedUFBTag = "rupas-mixed-ufb" // UDP fallback: xudp over the TCP endpoint
	tcpTag      = "rupas-tcp"
	udpTag      = "rupas-udp"
	fbTag       = "rupas-fallback"
	directTag   = "rupas-direct"
	dnsTag      = "rupas-dns"
	vlessFlow   = "xtls-rprx-vision" // standard VLESS+Reality flow
	loopbackIP  = "127.0.0.1"
)

// sbPorts are the loopback ports of the per-path sing-box mixed inbounds
// (0 = path absent). They are reserved by the caller before the options
// are built and handed to the singbox engine.
type sbPorts struct {
	// Main serves TCP CONNECT (→ the TCP endpoint via route final) and
	// UDP ASSOCIATE (→ the UDP endpoint via the network route rule).
	Main uint16
	// TCPFB serves the Fallback TCP endpoint (sing-box kinds only).
	TCPFB uint16
	// UDPFB serves the UDP fallback path: xudp over the TCP endpoint's
	// outbound, used after 3 consecutive STUN failures.
	UDPFB uint16
}

// tunnelPlan is the effective endpoint layout derived from the configured
// TunnelConfig: which endpoint carries TCP, which carries UDP, and the TCP
// fallback (SYSTEM_DESIGN §6, wave 5).
type tunnelPlan struct {
	tcp      *config.Endpoint
	udp      *config.Endpoint
	fallback *config.Endpoint
}

// effectivePlan resolves the implicit defaults: with no TCP endpoint the
// UDP endpoint carries TCP too (hysteria2/vless are full proxies); with no
// UDP endpoint the TCP endpoint carries UDP (xudp) when its kind can.
func effectivePlan(cfg config.TunnelConfig) tunnelPlan {
	p := tunnelPlan{tcp: cfg.TCP, udp: cfg.UDP, fallback: cfg.Fallback}
	if p.tcp == nil {
		p.tcp = cfg.UDP
	}
	if p.udp == nil && cfg.TCP != nil && cfg.TCP.SupportsUDP() {
		p.udp = cfg.TCP
	}
	return p
}

// sameEndpoint reports whether two endpoint pointers describe the same
// exit (kind+host+port) — such endpoints share one sing-box outbound.
func sameEndpoint(a, b *config.Endpoint) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Kind == b.Kind && a.Host == b.Host && a.Port == b.Port
}

// sbLogOptions silences sing-box logging unless RUPAS_TUNNEL_SBLOG is set
// (debug aid).
func sbLogOptions() *option.LogOptions {
	if os.Getenv("RUPAS_TUNNEL_SBLOG") != "" {
		return &option.LogOptions{Level: "trace", Timestamp: true}
	}
	return &option.LogOptions{Disabled: true}
}

// boxOptions maps a config.TunnelConfig to the sing-box client
// configuration (§6, wave 5): one mixed inbound per proxy path on loopback
// (fed by our tproxy listeners over SOCKS5), one outbound per distinct
// sing-box-carried endpoint, and route rules splitting TCP streams to the
// TCP outbound and UDP pseudo-sessions to the UDP outbound (network rule)
// — plus inbound-tag rules for the fallback paths. vless_xhttp endpoints
// have no sing-box representation (sing-box v1.14 has no XHTTP transport);
// they are carried by the in-package XHTTP client instead.
func boxOptions(cfg config.TunnelConfig, ports sbPorts) option.Options {
	plan := effectivePlan(cfg)

	outbounds := []option.Outbound{directOutbound(directTag)}
	var rules []option.Rule

	// Distinct sing-box outbounds per endpoint.
	tcpSB := plan.tcp != nil && plan.tcp.SingBoxKind()
	udpSB := plan.udp != nil && plan.udp.SingBoxKind() && !sameEndpoint(plan.udp, plan.tcp)
	if udpSB {
		outbounds = append(outbounds, endpointOutbound(*plan.udp, udpTag))
	}
	if tcpSB {
		outbounds = append(outbounds, endpointOutbound(*plan.tcp, tcpTag))
	}
	if plan.fallback != nil && plan.fallback.SingBoxKind() {
		outbounds = append(outbounds, endpointOutbound(*plan.fallback, fbTag))
	}

	// Final outbound: the TCP endpoint when sing-box carries it, else the
	// UDP endpoint, else the fallback.
	final := directTag
	switch {
	case tcpSB:
		final = tcpTag
	case udpSB:
		final = udpTag
	case plan.fallback != nil && plan.fallback.SingBoxKind():
		final = fbTag
	}

	// Route rules (evaluated in order):
	//  1. UDP fallback inbound → the TCP endpoint's outbound (xudp).
	//  2. TCP fallback inbound → the fallback outbound, or — when the
	//     configured fallback is not sing-box-carried (vless_xhttp or
	//     none) — the hysteria2 UDP endpoint's outbound (hy2 carries TCP
	//     streams too; wave 6: the default TCP chain is vless_tcp → hy2).
	//  3. network udp → the UDP endpoint (applies to the main mixed
	//     inbound, whose TCP flows fall through to route final = TCP).
	if ports.UDPFB != 0 {
		rules = append(rules, routeRule(routeInbound(mixedUFBTag), tcpTag))
	}
	if ports.TCPFB != 0 {
		fbRoute := fbRouteTag(plan, udpSB)
		if fbRoute != "" {
			rules = append(rules, routeRule(routeInbound(mixedFBTag), fbRoute))
		}
	}
	if udpSB && tcpSB {
		rules = append(rules, routeRule(routeNetworkUDP(), udpTag))
	}

	inbounds := []option.Inbound{mixedInbound(mixedTag, ports.Main)}
	if ports.TCPFB != 0 {
		inbounds = append(inbounds, mixedInbound(mixedFBTag, ports.TCPFB))
	}
	if ports.UDPFB != 0 {
		inbounds = append(inbounds, mixedInbound(mixedUFBTag, ports.UDPFB))
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
		Inbounds:  inbounds,
		Outbounds: outbounds,
		Route: &option.RouteOptions{
			Rules:                 rules,
			Final:                 final,
			DefaultDomainResolver: &option.DomainResolveOptions{Server: dnsTag},
			AutoDetectInterface:   true,
		},
	}
}

// fbRouteTag returns the outbound tag the TCP-fallback mixed inbound routes
// to: the configured fallback when sing-box carries it, else the distinct
// hysteria2 endpoint's outbound (hy2 carries TCP streams — wave-6 default
// chain vless_tcp → hy2). Empty when neither exists.
func fbRouteTag(plan tunnelPlan, udpSB bool) string {
	if plan.fallback != nil && plan.fallback.SingBoxKind() {
		return fbTag
	}
	if udpSB {
		return udpTag
	}
	return ""
}

// mixedInbound builds one loopback mixed (SOCKS5+HTTP) inbound.
func mixedInbound(tag string, port uint16) option.Inbound {
	return option.Inbound{
		Type: "mixed",
		Tag:  tag,
		Options: &option.HTTPMixedInboundOptions{
			ListenOptions: option.ListenOptions{
				Listen:     listenAddr(loopbackIP),
				ListenPort: port,
			},
		},
	}
}

func directOutbound(tag string) option.Outbound {
	return option.Outbound{
		Type: "direct",
		Tag:  tag,
		Options: &option.DirectOutboundOptions{
			DialerOptions: option.DialerOptions{
				AbstractDialerOptions: option.AbstractDialerOptions{
					DomainResolver: &option.DomainResolveOptions{Server: dnsTag},
				},
			},
		},
	}
}

func routeInbound(tags ...string) func(*option.RawDefaultRule) {
	return func(r *option.RawDefaultRule) { r.Inbound = tags }
}

func routeNetworkUDP() func(*option.RawDefaultRule) {
	return func(r *option.RawDefaultRule) { r.Network = badoption.Listable[string]{"udp"} }
}

// routeRule builds a default route rule with matcher fn and a route action
// to outbound.
func routeRule(match func(*option.RawDefaultRule), outbound string) option.Rule {
	raw := option.RawDefaultRule{}
	match(&raw)
	return option.Rule{
		Type: "default",
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: raw,
			RuleAction: option.RuleAction{
				Action:       "route",
				RouteOptions: option.RouteActionOptions{Outbound: outbound},
			},
		},
	}
}

// endpointOutbound maps one endpoint to its sing-box outbound. Kinds:
// vless_tcp (TLS, no Reality, no flow unless configured), vless_reality
// (TLS+Reality+vision flow), hysteria2 (QUIC+TLS h3).
func endpointOutbound(ep config.Endpoint, tag string) option.Outbound {
	switch ep.Kind {
	case config.KindHysteria2:
		return option.Outbound{
			Type: "hysteria2",
			Tag:  tag,
			Options: &option.Hysteria2OutboundOptions{
				ServerOptions: option.ServerOptions{Server: ep.Host, ServerPort: ep.Port},
				Password:      ep.Password,
				DialerOptions: option.DialerOptions{
					AbstractDialerOptions: option.AbstractDialerOptions{
						DomainResolver: &option.DomainResolveOptions{Server: dnsTag},
					},
				},
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
					// NOTE: no UTLS here — sing-box's QUIC stack rejects
					// uTLS for packet connections ("unsupported usage for
					// uTLS", live-verified); Hysteria2 QUIC chrome
					// parroting is built in.
					TLS: &option.OutboundTLSOptions{
						Enabled:    true,
						ServerName: ep.SNI,
						ALPN:       alpnOf(ep),
					},
				},
			},
		}
	default: // vless_tcp | vless_reality
		flow := ep.Flow
		if ep.Kind == config.KindVLESSReality && flow == "" {
			flow = vlessFlow
		}
		packetEncoding := "xudp"
		switch strings.ToLower(ep.UDPMode) {
		case "packetaddr":
			packetEncoding = "packetaddr"
		}
		tls := &option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: ep.SNI,
			ALPN:       alpnOf(ep),
			UTLS: &option.OutboundUTLSOptions{
				Enabled:     true,
				Fingerprint: fingerprintOf(ep.Fingerprint),
			},
		}
		if ep.Kind == config.KindVLESSReality {
			tls.Reality = &option.OutboundRealityOptions{
				Enabled:   true,
				PublicKey: ep.RealityPBK,
				ShortID:   ep.RealitySID,
			}
		}
		vlessOpts := &option.VLESSOutboundOptions{
			ServerOptions:  option.ServerOptions{Server: ep.Host, ServerPort: ep.Port},
			UUID:           ep.UUID,
			Flow:           flow,
			PacketEncoding: &packetEncoding,
			DialerOptions: option.DialerOptions{
				AbstractDialerOptions: option.AbstractDialerOptions{
					DomainResolver: &option.DomainResolveOptions{Server: dnsTag},
				},
			},
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tls},
		}
		if muxOf(ep) {
			// Wave 6 (live finding 2026-10-25): multiplex every stream over
			// ONE long-lived TLS connection. Un-multiplexed, each CONNECT
			// opens a fresh TLS connection to the VPS and the TSPU
			// quarantines the endpoint (~2 min silent SYN drop) after a
			// handful of connections — the TG connect storms killed the
			// whole carrier this way.
			//
			// MaxConnections > 1 keeps the count bounded while buying speed:
			// one TLS connection is capped by its own TCP window (measured
			// 227 of 540 Mbit/s at RTT 55 ms), four reach the path bandwidth
			// (422 Mbit/s). h2mux is the Xray-compatible protocol.
			vlessOpts.Multiplex = &option.OutboundMultiplexOptions{
				Enabled:        true,
				Protocol:       "h2mux",
				MaxConnections: ep.MuxConns,
				Padding:        ep.MuxPadding,
			}
		}
		return option.Outbound{Type: "vless", Tag: tag, Options: vlessOpts}
	}
}

// muxOf reports whether the endpoint's VLESS outbound multiplexes streams.
// Opt-in ("on"); xray servers do not demux sing-mux (live finding wave 6).
func muxOf(ep config.Endpoint) bool {
	return strings.ToLower(strings.TrimSpace(ep.Mux)) == "on"
}

func alpnOf(ep config.Endpoint) badoption.Listable[string] {
	if len(ep.ALPN) == 0 {
		if ep.Kind == config.KindHysteria2 {
			return badoption.Listable[string]{"h3"}
		}
		return badoption.Listable[string]{"h2", "http/1.1"}
	}
	return append(badoption.Listable[string]{}, ep.ALPN...)
}

// fingerprintOf normalizes the uTLS fingerprint; unknown values fall back to
// the sing-box default (chrome), which is also the config default.
func fingerprintOf(fp string) string {
	switch v := strings.ToLower(strings.TrimSpace(fp)); v {
	case "":
		return "chrome"
	case "chrome", "chrome_psk", "chrome_psk_shuffle", "chrome_padding_psk_shuffle",
		"chrome_pq", "chrome_pq_psk", "firefox", "edge", "safari", "360", "qq",
		"ios", "android", "random", "randomized":
		return v
	default:
		return "chrome"
	}
}

// listenAddr builds the badoption.Addr for a loopback listener.
func listenAddr(ip string) *badoption.Addr {
	a := badoption.Addr(netip.MustParseAddr(ip))
	return &a
}

// validatePlan checks the tunnel plan before engine start (config.Validate
// normally ran first; this is the tunnel-side defense).
func validatePlan(cfg config.TunnelConfig) error {
	if !cfg.Configured() {
		return errors.New("tunnel: no endpoint configured")
	}
	plan := effectivePlan(cfg)
	for name, ep := range map[string]*config.Endpoint{"tcp": plan.tcp, "udp": plan.udp, "fallback": plan.fallback} {
		if ep == nil {
			continue
		}
		if err := ep.Validate(); err != nil {
			return fmt.Errorf("tunnel: %s endpoint: %v", name, err)
		}
	}
	if plan.tcp == nil {
		return errors.New("tunnel: no TCP-capable endpoint")
	}
	return nil
}

// sbPortsForPlan reserves the mixed inbound ports the plan needs.
func sbPortsForPlan(cfg config.TunnelConfig) (sbPorts, error) {
	plan := effectivePlan(cfg)
	var p sbPorts
	needMain := (plan.tcp != nil && plan.tcp.SingBoxKind()) ||
		(plan.udp != nil && plan.udp.SingBoxKind() && !sameEndpoint(plan.udp, plan.tcp))
	if needMain {
		port, err := freeTCPPort()
		if err != nil {
			return p, fmt.Errorf("tunnel: pick mixed port: %w", err)
		}
		p.Main = port
	}
	if plan.fallback != nil && plan.fallback.SingBoxKind() {
		port, err := freeTCPPort()
		if err != nil {
			return p, fmt.Errorf("tunnel: pick fallback mixed port: %w", err)
		}
		p.TCPFB = port
	}
	// Wave 6: when the configured fallback is NOT sing-box-carried
	// (vless_xhttp — excluded from the default chain, live finding F3 —
	// or absent), a DISTINCT hysteria2 endpoint becomes the automatic TCP
	// fallback (hy2 carries TCP streams; its outbound already exists for
	// the UDP path), riding the same TCPFB mixed inbound.
	fbSB := plan.fallback != nil && plan.fallback.SingBoxKind()
	udpDistinct := plan.udp != nil && plan.udp.SingBoxKind() && !sameEndpoint(plan.udp, plan.tcp)
	if !fbSB && udpDistinct && p.TCPFB == 0 {
		port, err := freeTCPPort()
		if err != nil {
			return p, fmt.Errorf("tunnel: pick hy2-fallback mixed port: %w", err)
		}
		p.TCPFB = port
	}
	// UDP fallback (xudp over the TCP endpoint) exists when the UDP path is
	// a DISTINCT sing-box endpoint and the TCP endpoint is a VLESS one
	// sing-box carries (XUDP rides the VLESS outbound).
	udpXUDP := plan.udp != nil && plan.tcp != nil && !sameEndpoint(plan.udp, plan.tcp) && plan.udp.SingBoxKind()
	tcpIsVLESS := plan.tcp != nil && plan.tcp.SingBoxKind() &&
		(plan.tcp.Kind == config.KindVLESSTCP || plan.tcp.Kind == config.KindVLESSReality)
	if udpXUDP && tcpIsVLESS {
		port, err := freeTCPPort()
		if err != nil {
			return p, fmt.Errorf("tunnel: pick udp-fallback mixed port: %w", err)
		}
		p.UDPFB = port
	}
	return p, nil
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
