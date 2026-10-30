package android

// Universal tunnel endpoint description, parsed from standard share links
// (vless://, hysteria2://, hy2://, trojan://). One endpoint = one carrier
// in the engine's dial chain: the first is primary, the rest are fallbacks
// (desktop dial-order parity, internal/tunnel tunnel.go).
//
// sing-box carries every kind except vless+xhttp (sing-box v1.14 has no
// XHTTP transport — it is Xray-core's); xhttp endpoints ride Rupas' own
// client (internal/tunnel xhttp.go) instead of the relay.

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/kshishtovsky/rupas/internal/config"
)

// Endpoint kinds and constants.
const (
	KindVLESS     = "vless"
	KindTrojan    = "trojan"
	KindHysteria2 = "hysteria2"
	// KindTMN is TMN/1: Rupas' own transport, carried in-process by the
	// tuman client library (TLS 1.3 + mux + cover site + PSK auth). TCP
	// streams only — the protocol has no UDP flows.
	KindTMN = "tmn"

	secNone    = "none"
	secTLS     = "tls"
	secReality = "reality"

	transportTCP         = "tcp"
	transportWS          = "ws"
	transportGRPC        = "grpc"
	transportXHTTP       = "xhttp"
	transportHTTPUpgrade = "httpupgrade"
)

// Endpoint is one parsed tunnel carrier.
type Endpoint struct {
	Kind        string // vless | trojan | hysteria2
	Host        string
	Port        uint16
	UUID        string // vless uuid / trojan+hysteria2 password
	Security    string // none | tls | reality
	SNI         string
	ALPN        []string
	Fingerprint string
	Flow        string // vless flow (reality)
	PBK         string // reality public key
	SID         string // reality short id
	Insecure    bool   // tls allowInsecure/insecure=1

	Transport string // tcp | ws | grpc | xhttp | httpupgrade
	Path      string // ws/httpupgrade/xhttp path
	WSHost    string // ws/httpupgrade HTTP Host; also the xhttp :authority pin
	Service   string // grpc service name
	Mode      string // xhttp mode (packet-up supported)

	// Mux turns on sing-mux multiplexing for VLESS (all flows share a small
	// pool of long-lived TLS connections). Off by default: xray servers do
	// not demux sing-mux, and un-multiplexed behaviour is the wave-6 default.
	Mux string // "on" | ""
	// MuxConns is the pool size (1..8). One TLS connection is capped by its
	// own TCP window (measured: 227 of 540 Mbit/s at RTT 55 ms); four reach
	// the path bandwidth (422 Mbit/s) while the connection count stays
	// browser-like.
	MuxConns int

	// PSK is the TMN/1 pre-shared key as 64 hex characters (KindTMN only).
	PSK string
	// Conns is the TMN/1 session pool size (1..8, default 4).
	Conns int

	Name string // fragment (#tag), logging only
}

// MaxMuxConns caps the mux pool (same bound as config.MaxMuxConns).
const MaxMuxConns = 8

// MuxOn reports whether the endpoint multiplexes its flows.
func (e Endpoint) MuxOn() bool { return strings.EqualFold(strings.TrimSpace(e.Mux), "on") }

// MuxPool is the effective pool size: 1..MaxMuxConns, 1 when mux is off.
func (e Endpoint) MuxPool() int {
	if !e.MuxOn() {
		return 1
	}
	if e.MuxConns < 1 {
		return 1
	}
	if e.MuxConns > MaxMuxConns {
		return MaxMuxConns
	}
	return e.MuxConns
}

// NeedsXHTTP reports whether the endpoint must be carried by Rupas' own
// XHTTP client instead of the sing-box relay.
func (e Endpoint) NeedsXHTTP() bool {
	return e.Kind == KindVLESS && e.Transport == transportXHTTP
}

// NeedsNative reports whether the endpoint is carried in-process instead of
// by the sing-box relay: xhttp (sing-box has no XHTTP transport) and tmn
// (its own protocol library).
func (e Endpoint) NeedsNative() bool {
	return e.NeedsXHTTP() || e.Kind == KindTMN
}

// ParseShareLink parses one share-link URI into an Endpoint.
func ParseShareLink(raw string) (Endpoint, error) {
	raw = strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(raw, "vless://"):
		return parseVLESSLink(raw)
	case strings.HasPrefix(raw, "hysteria2://"), strings.HasPrefix(raw, "hy2://"):
		return parseHysteria2Link(raw)
	case strings.HasPrefix(raw, "trojan://"):
		return parseTrojanLink(raw)
	case strings.HasPrefix(raw, "tmn://"):
		return parseTMNLink(raw)
	default:
		return Endpoint{}, fmt.Errorf("sharelink: unsupported scheme in %q (want vless://, hysteria2://, hy2://, trojan:// or tmn://)", truncate(raw, 48))
	}
}

// parseTMNLink parses:
//
//	tmn://<psk-hex64>@host:port?sni=<cover>&conns=4&profile=off&insecure=0#name
//
// The PSK rides the userinfo slot like a vless uuid. SNI is mandatory for an
// IP host (the cover domain is what the server's certificate is issued for);
// when the host is a domain it doubles as SNI. Every error message is
// phrased without the key: a self-made transport's PSK in a log line is a
// dead transport.
func parseTMNLink(raw string) (Endpoint, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Endpoint{}, fmt.Errorf("sharelink: tmn: %w", err)
	}
	if u.User == nil || u.User.Username() == "" {
		return Endpoint{}, errors.New("sharelink: tmn: missing psk")
	}
	psk, err := config.NormalizePSK(u.User.Username())
	if err != nil {
		return Endpoint{}, fmt.Errorf("sharelink: tmn: %v", err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		return Endpoint{}, fmt.Errorf("sharelink: tmn: bad host:port %q", u.Host)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return Endpoint{}, fmt.Errorf("sharelink: tmn: bad port %q", portStr)
	}
	q := u.Query()
	sni := q.Get("sni")
	if sni == "" {
		if net.ParseIP(host) != nil {
			return Endpoint{}, errors.New("sharelink: tmn: sni is required when the host is an IP")
		}
		sni = host
	}
	conns := 4
	if v := q.Get("conns"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > config.MaxTMNConns {
			return Endpoint{}, fmt.Errorf("sharelink: tmn: conns %q: want 1..%d", v, config.MaxTMNConns)
		}
		conns = n
	}
	if p := q.Get("profile"); p != "" {
		switch p {
		case "off", "browse", "video", "bulk", "voice":
		default:
			return Endpoint{}, fmt.Errorf("sharelink: tmn: profile %q: want off|browse|video|bulk|voice", p)
		}
	}
	return Endpoint{
		Kind:      KindTMN,
		Host:      host,
		Port:      uint16(port),
		PSK:       psk,
		SNI:       sni,
		Conns:     conns,
		Insecure:  isTrue(q.Get("insecure")),
		Security:  secTLS,
		Transport: transportTCP,
		Name:      u.Fragment,
	}, nil
}

func parseVLESSLink(raw string) (Endpoint, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Endpoint{}, fmt.Errorf("sharelink: vless: %w", err)
	}
	if u.User == nil || u.User.Username() == "" {
		return Endpoint{}, fmt.Errorf("sharelink: vless: missing uuid")
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		return Endpoint{}, fmt.Errorf("sharelink: vless: bad host:port %q", u.Host)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return Endpoint{}, fmt.Errorf("sharelink: vless: bad port %q", portStr)
	}
	q := u.Query()
	e := Endpoint{
		Kind:      KindVLESS,
		Host:      host,
		Port:      uint16(port),
		UUID:      u.User.Username(),
		Name:      u.Fragment,
		Transport: strings.ToLower(q.Get("type")),
		Flow:      q.Get("flow"),
	}
	if e.Transport == "" {
		e.Transport = transportTCP
	}
	switch q.Get("security") {
	case "tls":
		e.Security = secTLS
	case "reality":
		e.Security = secReality
		e.PBK = q.Get("pbk")
		e.SID = q.Get("sid")
		if e.PBK == "" {
			return Endpoint{}, fmt.Errorf("sharelink: vless: reality without pbk")
		}
	case "", "none":
		e.Security = secNone
	default:
		return Endpoint{}, fmt.Errorf("sharelink: vless: unsupported security %q", q.Get("security"))
	}
	if e.Security != secNone {
		e.SNI = q.Get("sni")
		e.Fingerprint = q.Get("fp")
		e.Insecure = isTrue(q.Get("allowInsecure")) || isTrue(q.Get("insecure"))
		if alpn := q.Get("alpn"); alpn != "" {
			for _, a := range strings.Split(alpn, ",") {
				if a = strings.TrimSpace(a); a != "" {
					e.ALPN = append(e.ALPN, a)
				}
			}
		}
	}
	// Transport-specific parameters.
	switch e.Transport {
	case transportTCP:
	case transportWS, transportHTTPUpgrade:
		e.Path = q.Get("path")
		e.WSHost = q.Get("host")
	case transportGRPC:
		e.Service = q.Get("serviceName")
	case transportXHTTP:
		e.Path = q.Get("path")
		e.Mode = q.Get("mode")
		e.WSHost = q.Get("host") // HTTP Host/:authority pin for the own client
		if e.Mode != "" && e.Mode != "packet-up" {
			return Endpoint{}, fmt.Errorf("sharelink: vless: xhttp mode %q: only packet-up is supported", e.Mode)
		}
	default:
		return Endpoint{}, fmt.Errorf("sharelink: vless: unsupported transport %q", e.Transport)
	}
	// Mux knobs: Xray panels ship them as ?mux=on&mux_conns=N (some use
	// muxConcurrency/muxMaxConnections for xmux; we only read the pool size).
	e.Mux = strings.TrimSpace(q.Get("mux"))
	if e.Mux != "" && !strings.EqualFold(e.Mux, "on") && !strings.EqualFold(e.Mux, "off") {
		return Endpoint{}, fmt.Errorf("sharelink: vless: mux %q: want on|off", e.Mux)
	}
	if raw := q.Get("mux_conns"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > MaxMuxConns {
			return Endpoint{}, fmt.Errorf("sharelink: vless: mux_conns %q: want 1..%d", raw, MaxMuxConns)
		}
		e.MuxConns = n
	}
	if e.Transport == transportXHTTP && e.MuxOn() {
		// Our own XHTTP client carries one request stream per flow; it has no
		// mux layer, so silently ignoring mux would be a lie.
		return Endpoint{}, errors.New("sharelink: vless: mux is not supported on xhttp")
	}
	return e, nil
}

func parseHysteria2Link(raw string) (Endpoint, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Endpoint{}, fmt.Errorf("sharelink: hysteria2: %w", err)
	}
	if u.User == nil || u.User.Username() == "" {
		return Endpoint{}, fmt.Errorf("sharelink: hysteria2: missing password")
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		return Endpoint{}, fmt.Errorf("sharelink: hysteria2: bad host:port %q", u.Host)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return Endpoint{}, fmt.Errorf("sharelink: hysteria2: bad port %q", portStr)
	}
	q := u.Query()
	e := Endpoint{
		Kind:        KindHysteria2,
		Host:        host,
		Port:        uint16(port),
		UUID:        u.User.Username(), // password
		Security:    secTLS,            // hysteria2 is always TLS
		Name:        u.Fragment,
		Transport:   transportTCP,
		Insecure:    isTrue(q.Get("insecure")),
		Fingerprint: q.Get("fp"),
	}
	if sni := q.Get("sni"); sni != "" {
		e.SNI = sni
	}
	if alpn := q.Get("alpn"); alpn != "" {
		for _, a := range strings.Split(alpn, ",") {
			if a = strings.TrimSpace(a); a != "" {
				e.ALPN = append(e.ALPN, a)
			}
		}
	}
	// obfs changes the wire framing; dropping it silently yields a carrier
	// that connects and then speaks the wrong protocol — refuse instead.
	if obfs := q.Get("obfs"); obfs != "" {
		return Endpoint{}, fmt.Errorf("sharelink: hysteria2: obfs %q is not supported", obfs)
	}
	return e, nil
}

func parseTrojanLink(raw string) (Endpoint, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Endpoint{}, fmt.Errorf("sharelink: trojan: %w", err)
	}
	if u.User == nil || u.User.Username() == "" {
		return Endpoint{}, fmt.Errorf("sharelink: trojan: missing password")
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		return Endpoint{}, fmt.Errorf("sharelink: trojan: bad host:port %q", u.Host)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return Endpoint{}, fmt.Errorf("sharelink: trojan: bad port %q", portStr)
	}
	q := u.Query()
	e := Endpoint{
		Kind:        KindTrojan,
		Host:        host,
		Port:        uint16(port),
		UUID:        u.User.Username(), // password
		Security:    secTLS,            // trojan is always TLS
		SNI:         q.Get("sni"),
		Fingerprint: q.Get("fp"),
		Name:        u.Fragment,
		Transport:   strings.ToLower(q.Get("type")),
		Insecure:    isTrue(q.Get("allowInsecure")) || isTrue(q.Get("insecure")),
	}
	if e.Transport == "" {
		e.Transport = transportTCP
	}
	if alpn := q.Get("alpn"); alpn != "" {
		for _, a := range strings.Split(alpn, ",") {
			if a = strings.TrimSpace(a); a != "" {
				e.ALPN = append(e.ALPN, a)
			}
		}
	}
	switch e.Transport {
	case transportTCP:
	case transportWS, transportHTTPUpgrade:
		e.Path = q.Get("path")
		e.WSHost = q.Get("host")
	case transportGRPC:
		e.Service = q.Get("serviceName")
	default:
		return Endpoint{}, fmt.Errorf("sharelink: trojan: unsupported transport %q", e.Transport)
	}
	return e, nil
}

func isTrue(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes":
		return true
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
