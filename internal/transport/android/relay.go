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
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box"
	adapter2 "github.com/sagernet/sing-box/adapter"
	boxAdapterCertificate "github.com/sagernet/sing-box/adapter/certificate"
	boxAdapterEndpoint "github.com/sagernet/sing-box/adapter/endpoint"
	boxAdapterInbound "github.com/sagernet/sing-box/adapter/inbound"
	boxAdapterOutbound "github.com/sagernet/sing-box/adapter/outbound"
	boxAdapterService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	dnsLocal "github.com/sagernet/sing-box/dns/transport/local"
	boxLog "github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/mixed"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"
)

// Relay owns the embedded sing-box engine and its loopback socks inbounds.
// A relay with a dead/absent socksAddr is "unavailable": every dial fails
// fast and the caller escalates (engine.dialEgress).
type Relay struct {
	settings       *Settings
	endpoints      []Endpoint
	resolvedServer string
	logFn          func(string)

	socksAddr  string   // primary inbound (dial chain index 0)
	socksAddrs []string // per-endpoint inbound; "" for xhttp slots
	box        *box.Box
	// stopProtector tears the fd-passing protect server down (unix).
	stopProtector func()
}

// NewRelay assembles (but does not start) the tunnel relay.
func NewRelay(s *Settings, logFn func(string)) *Relay {
	return &Relay{settings: s, logFn: logFn}
}

// Available reports whether the relay can accept dials.
func (r *Relay) Available() bool { return r != nil && r.socksAddr != "" }

// resolveServerIP converts a hostname into an IP address using public DNS servers
// via a protected dialer. If server is already an IP, it returns server untouched.
func resolveServerIP(ctx context.Context, server string, protect ProtectFunc) (string, error) {
	server = strings.TrimSpace(server)
	if net.ParseIP(server) != nil {
		return server, nil
	}
	dnsServers := []string{"8.8.8.8:53", "1.1.1.1:53", "77.88.8.8:53"}
	var lastErr error
	for _, dnsServer := range dnsServers {
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(dialCtx context.Context, network, address string) (net.Conn, error) {
				d := ProtectedDialer(protect)
				d.Timeout = 3 * time.Second
				return d.DialContext(dialCtx, "udp", dnsServer)
			},
		}
		resolveCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		ips, err := r.LookupIP(resolveCtx, "ip4", server)
		cancel()
		if err == nil && len(ips) > 0 {
			for _, ip := range ips {
				if ip4 := ip.To4(); ip4 != nil {
					return ip4.String(), nil
				}
			}
			return ips[0].String(), nil
		}
		lastErr = err
	}
	return "", fmt.Errorf("lookup server IP %q: %w", server, lastErr)
}

// Start builds and launches the sing-box instance. protect is used to
// unhook the outbound sockets from the VPN (may be nil on non-Android).
// The dial chain comes from settings.Endpoints(): every non-xhttp endpoint
// becomes its own mixed inbound → outbound pair routed by an inbound rule;
// xhttp endpoints are NOT put into the box (sing-box v1.14 has no XHTTP
// transport) — the engine carries them through Rupas' own XHTTP client.
// A relay with zero box-capable endpoints reports Available()==false.
func (r *Relay) Start(ctx context.Context, protect ProtectFunc, filesDir string) error {
	if r == nil {
		return fmt.Errorf("android: relay: not configured")
	}
	if r.settings == nil {
		return fmt.Errorf("android: relay: no settings")
	}
	eps, err := r.settings.Endpoints()
	if err != nil {
		return fmt.Errorf("android: relay: %w", err)
	}
	r.endpoints = eps

	var boxEps []indexedEndpoint
	for i, ep := range eps {
		if !ep.NeedsXHTTP() {
			boxEps = append(boxEps, indexedEndpoint{idx: i, ep: ep})
		}
	}
	if len(boxEps) == 0 {
		if r.logFn != nil {
			r.logFn("android: relay: all endpoints are xhttp — sing-box not started (own client carries them)")
		}
		return nil
	}

	// One loopback port per endpoint inbound.
	ports := make([]uint16, len(boxEps))
	for i := range boxEps {
		p, err := freeTCPPort()
		if err != nil {
			return fmt.Errorf("android: relay: pick socks port %d: %w", i, err)
		}
		ports[i] = p
	}
	r.socksAddr = netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), ports[0]).String()
	r.socksAddrs = make([]string, len(eps)) // full chain shape, xhttp slots empty
	for i := range boxEps {
		r.socksAddrs[boxEps[i].idx] = netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), ports[i]).String()
	}

	// Resolve each endpoint host once (protected resolver, VPN bypass via
	// disallowed-package on modern builds).
	servers := make([]string, len(boxEps))
	for i, ie := range boxEps {
		resolved, rErr := resolveServerIP(ctx, ie.ep.Host, protect)
		if rErr != nil {
			if r.logFn != nil {
				r.logFn(fmt.Sprintf("android: relay: resolve %s: %v (using host as-is)", ie.ep.Host, rErr))
			}
			resolved = ie.ep.Host
		}
		servers[i] = resolved
		if ie.idx == 0 {
			r.resolvedServer = resolved
		}
	}

	// Note: RupasVpnService adds ru.rupas.android as a disallowed application
	// (b.addDisallowedApplication(getPackageName())), so all outbound sockets
	// created by sing-box already bypass the VPN. Using a unix domain socket
	// protect server with SCM_RIGHTS causes socket hangs on modern Android kernels.
	var protectPath string

	opts := relayOptions(boxEps, servers, ports, protectPath)
	// box.New forces a cache-file whenever a PlatformLogWriter is set; the
	// default relative "cache.db" resolves against the Android process cwd
	// "/" (read-only) and kills box.Start ("initialize cache-file: open
	// cache.db: read-only file system"). Give it an absolute app-private
	// path from Java's filesDir.
	if opts.Experimental == nil {
		opts.Experimental = &option.ExperimentalOptions{}
	}
	opts.Experimental.CacheFile = &option.CacheFileOptions{
		Enabled: true,
		Path:    filepath.Join(filesDir, "rupas-relay-cache.db"),
	}
	engine, err := box.New(box.Options{
		Context:           relayBoxContext(ctx),
		Options:           opts,
		PlatformLogWriter: &relayLogWriter{fn: r.logFn, secrets: relaySecrets(eps)},
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
		names := make([]string, len(eps))
		for i, ep := range eps {
			names[i] = endpointName(ep)
		}
		r.logFn("android: tunnel relay chain: " + strings.Join(names, " -> ") +
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
	r.socksAddrs = nil
	return err
}

func (r *Relay) stop() {
	if r != nil && r.stopProtector != nil {
		r.stopProtector()
		r.stopProtector = nil
	}
}

// indexedEndpoint pairs an endpoint with its position in the dial chain.
type indexedEndpoint struct {
	idx int
	ep  Endpoint
}

// endpointName returns a log-safe carrier name.
func endpointName(e Endpoint) string {
	sec := e.Security
	if sec == "" {
		sec = secNone
	}
	return fmt.Sprintf("%s/%s/%s@%s:%d", e.Kind, sec, e.Transport, e.Host, e.Port)
}

// relaySecrets collects the secret strings to redact from relay logs.
func relaySecrets(eps []Endpoint) []string {
	var out []string
	for _, e := range eps {
		if e.UUID != "" {
			out = append(out, e.UUID)
		}
	}
	return out
}

// DialTCP connects dst through the primary inbound (CONNECT → VLESS).
func (r *Relay) DialTCP(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	return r.DialTCPIndex(0, ctx, dst)
}

// DialTCPIndex connects dst through endpoint idx's inbound. Index must be
// a non-xhttp chain position; xhttp endpoints are carried by the engine's
// own dialer instead.
func (r *Relay) DialTCPIndex(idx int, ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	if !r.Available() {
		return nil, fmt.Errorf("android: relay: tunnel unavailable")
	}
	if idx < 0 || idx >= len(r.socksAddrs) || r.socksAddrs[idx] == "" {
		return nil, fmt.Errorf("android: relay: endpoint %d is not a sing-box carrier", idx)
	}
	return socks5Connect(ctx, r.socksAddrs[idx], dst)
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
// sbinstance.go): mixed (our SOCKS5 feeder), vless, trojan, hysteria2,
// direct. XHTTP is NOT here (no transport in sing-box v1.14) — the engine
// carries xhttp endpoints through internal/tunnel's own client.
func relayBoxContext(ctx context.Context) context.Context {
	inbounds := boxAdapterInbound.NewRegistry()
	mixed.RegisterInbound(inbounds)
	vless.RegisterInbound(inbounds)
	direct.RegisterInbound(inbounds)

	outbounds := boxAdapterOutbound.NewRegistry()
	vless.RegisterOutbound(outbounds)
	trojan.RegisterOutbound(outbounds)
	hysteria2.RegisterOutbound(outbounds)
	direct.RegisterOutbound(outbounds)

	dnsReg := dns.NewTransportRegistry()
	dnsLocal.RegisterTransport(dnsReg)

	// Android + a nil platform interface makes the sing-box network manager
	// try to build its own PackageManager (reads /data/system/packages.xml —
	// permission denied for apps), and the half-initialised manager crashed
	// the app with a nil deref right after start. A non-nil stub steers it
	// to the neutral path; VPN bypass is handled app-side anyway (the
	// package itself is a VpnService disallowed application).
	// NON-Android builds (the server-side tests) run WITHOUT the stub:
	// a non-nil platform interface changes sing-box's network-manager paths
	// and broke the Vision downlink (live finding 2026-10-26: EOF after
	// target dial against xray 25.4.30, fixed by the nil platform).
	if runtime.GOOS == "android" {
		ctx = service.ContextWith[adapter2.PlatformInterface](ctx, nopPlatform{})
	}

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
// mixed inbound + one outbound per box-capable endpoint, inbound→outbound
// route rules (dial-chain order preserved), final = the primary outbound,
// local DNS for server-name resolution.
func relayOptions(boxEps []indexedEndpoint, servers []string, ports []uint16, protectPath string) option.Options {
	inbounds := make([]option.Inbound, len(boxEps))
	outbounds := make([]option.Outbound, len(boxEps))
	rules := make([]option.Rule, len(boxEps))
	for i, ie := range boxEps {
		inTag := fmt.Sprintf("%s-%d", relayInTag, ie.idx)
		outTag := fmt.Sprintf("%s-%d", relayOutTag, ie.idx)
		inbounds[i] = option.Inbound{
			Type: "mixed",
			Tag:  inTag,
			Options: &option.HTTPMixedInboundOptions{
				ListenOptions: option.ListenOptions{
					Listen:     listenAddr("127.0.0.1"),
					ListenPort: ports[i],
				},
			},
		}
		outbounds[i] = endpointOutbound(ie.ep, servers[i], outTag, protectPath)
		var inb badoption.Listable[string] = []string{inTag}
		// RuleAction.Action MUST be "route": NewRuleAction maps "" to a
		// nil action (rule_action.go: switch action.Action { case "": return nil, nil }),
		// and a nil action crashes Router.matchRule on the first matched
		// connection (found live: SIGSEGV route.go:715).
		rules[i] = option.Rule{Type: "default", DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{Inbound: inb},
			RuleAction: option.RuleAction{
				Action:       "route",
				RouteOptions: option.RouteActionOptions{Outbound: outTag},
			},
		}}
	}
	return option.Options{
		Log: &option.LogOptions{Disabled: false, Level: "warn", DisableColor: true},
		DNS: &option.DNSOptions{
			RawDNSOptions: option.RawDNSOptions{
				Servers: []option.DNSServerOptions{
					{Type: "local", Tag: relayDNSTag, Options: &option.LocalDNSServerOptions{}},
				},
			},
		},
		Inbounds:  inbounds,
		Outbounds: outbounds,
		Route: &option.RouteOptions{
			Rules:                 rules,
			Final:                 fmt.Sprintf("%s-%d", relayOutTag, boxEps[0].idx),
			DefaultDomainResolver: &option.DomainResolveOptions{Server: relayDNSTag},
			// No AutoDetectInterface on Android: interface binding is
			// root-only there — bypass happens through protect_path.
		},
	}
}

// endpointOutbound builds one sing-box outbound from a parsed endpoint.
// vless (tcp/ws/grpc/httpupgrade; tls/reality/none), trojan, hysteria2.
// vless+xhttp never reaches this: the engine carries it via internal/tunnel.
func endpointOutbound(e Endpoint, server, tag, protectPath string) option.Outbound {
	dialer := option.DialerOptions{
		AbstractDialerOptions: option.AbstractDialerOptions{
			DomainResolver: &option.DomainResolveOptions{Server: relayDNSTag},
			ProtectPath:    protectPath,
		},
	}
	tlsOut := buildTLS(e)
	switch e.Kind {
	case KindHysteria2:
		return option.Outbound{
			Type: "hysteria2",
			Tag:  tag,
			Options: &option.Hysteria2OutboundOptions{
				DialerOptions: dialer,
				ServerOptions: option.ServerOptions{Server: server, ServerPort: e.Port},
				Password:      e.UUID,
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
					TLS: tlsOut,
				},
			},
		}
	case KindTrojan:
		return option.Outbound{
			Type: "trojan",
			Tag:  tag,
			Options: &option.TrojanOutboundOptions{
				DialerOptions: dialer,
				ServerOptions: option.ServerOptions{Server: server, ServerPort: e.Port},
				Password:      e.UUID,
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
					TLS: tlsOut,
				},
				Transport: buildTransport(e),
			},
		}
	default: // vless
		flow := e.Flow
		packetEncoding := "xudp"
		return option.Outbound{
			Type: "vless",
			Tag:  tag,
			Options: &option.VLESSOutboundOptions{
				DialerOptions:  dialer,
				ServerOptions:  option.ServerOptions{Server: server, ServerPort: e.Port},
				UUID:           e.UUID,
				Flow:           flow,
				PacketEncoding: &packetEncoding,
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
					TLS: tlsOut,
				},
				Transport: buildTransport(e),
			},
		}
	}
}

// buildTLS maps the endpoint security onto sing-box TLS options.
func buildTLS(e Endpoint) *option.OutboundTLSOptions {
	if e.Security == secNone {
		return nil
	}
	sni := e.SNI
	if sni == "" && net.ParseIP(e.Host) == nil {
		sni = e.Host
	}
	alpn := e.ALPN
	if len(alpn) == 0 {
		if e.Kind == KindHysteria2 || e.Security == secReality {
			// REALITY+Vision: no ALPN at all — h2 negotiation breaks the
			// Vision stream, and xray reality profiles ship without ALPN.
			// hysteria2: sing-quic substitutes h3 ONLY for an empty list
			// (its hysteria2 inbound refuses anything else), so leave it
			// empty and let the QUIC stack pick http/3.
			alpn = nil
		} else {
			// Live finding 2026-10-26: without ALPN the xray vless_tcp
			// endpoint answers its HTTP fallback ("unknown version: 72" on
			// the client) — mirror the desktop profile (h2 + http/1.1).
			alpn = badoption.Listable[string]{"h2", "http/1.1"}
		}
	}
	tls := &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: sni,
		Insecure:   e.Insecure,
		ALPN:       alpn,
	}
	if e.Kind == KindHysteria2 {
		// Desktop parity (internal/tunnel sbconfig.go): sing-box's QUIC
		// stack rejects uTLS ("unsupported usage for uTLS", live-verified);
		// Hysteria2 QUIC chrome parroting is built in. No UTLS here.
		return tls
	}
	if e.Fingerprint != "" {
		tls.UTLS = &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: e.Fingerprint,
		}
	} else {
		// Desktop parity (internal/tunnel sbconfig.go endpointOutbound):
		// uTLS is ALWAYS on for vless/trojan over TLS with the chrome
		// fingerprint — a bare Go-stdlib ClientHello gets the xray HTTP
		// fallback ("unknown version: 72/32" on the client side).
		tls.UTLS = &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: "chrome",
		}
	}
	if e.Security == secReality {
		tls.Reality = &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: e.PBK,
			ShortID:   e.SID,
		}
	}
	return tls
}

// buildTransport maps the endpoint transport onto sing-box v2ray transport
// options (nil = plain stream).
func buildTransport(e Endpoint) *option.V2RayTransportOptions {
	switch e.Transport {
	case transportWS:
		return &option.V2RayTransportOptions{
			Type: "ws",
			WebsocketOptions: option.V2RayWebsocketOptions{
				Path:    e.Path,
				Headers: hostHeaders(e.WSHost),
			},
		}
	case transportHTTPUpgrade:
		return &option.V2RayTransportOptions{
			Type: "httpupgrade",
			HTTPUpgradeOptions: option.V2RayHTTPUpgradeOptions{
				Host:    e.WSHost,
				Path:    e.Path,
				Headers: hostHeaders(e.WSHost),
			},
		}
	case transportGRPC:
		return &option.V2RayTransportOptions{
			Type: "grpc",
			GRPCOptions: option.V2RayGRPCOptions{
				ServiceName: e.Service,
			},
		}
	default:
		return nil
	}
}

func hostHeaders(host string) badoption.HTTPHeader {
	if host == "" {
		return nil
	}
	return badoption.HTTPHeader{"Host": []string{host}}
}

// relayLogWriter forwards only warnings/errors to the Android callback.
// Identical messages (same 80-char tail — the volatile conn ids and uptime
// counters live at the front) are collapsed within a short window: a
// server-side refusal storm ("unknown version: 72" per connection) must not
// flood the on-screen log.
const relayDupWindow = 5 * time.Second

type relayLogWriter struct {
	mu      sync.Mutex
	fn      func(string)
	secrets []string

	lastKey    string
	lastAt     time.Time
	suppressed int
}

func (w *relayLogWriter) WriteMessage(level boxLog.Level, message string) {
	if w.fn == nil || level > boxLog.LevelDebug {
		return
	}
	for _, secret := range w.secrets {
		if secret != "" {
			message = strings.ReplaceAll(message, secret, "<redacted>")
		}
	}
	if len(message) > 1200 {
		message = message[:1200] + "…"
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	// Key = text after the last "] ": sing-box prefixes every message with
	// volatile per-connection ids and uptime counters; the stable error text
	// follows the last bracket group.
	key := message
	if i := strings.LastIndex(key, "] "); i >= 0 {
		key = key[i+2:]
	}
	now := time.Now()
	if key == w.lastKey && now.Sub(w.lastAt) < relayDupWindow {
		w.suppressed++
		return
	}
	if w.suppressed > 0 {
		w.fn(fmt.Sprintf("android: sing-box: (+%d identical messages suppressed)", w.suppressed))
		w.suppressed = 0
	}
	w.lastKey, w.lastAt = key, now
	w.fn("android: sing-box " + boxLog.FormatLevel(level) + ": " + message)
}

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
