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
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Endpoint kinds and constants.
const (
	KindVLESS     = "vless"
	KindTrojan    = "trojan"
	KindHysteria2 = "hysteria2"

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

	Name string // fragment (#tag), logging only
}

// NeedsXHTTP reports whether the endpoint must be carried by Rupas' own
// XHTTP client instead of the sing-box relay.
func (e Endpoint) NeedsXHTTP() bool {
	return e.Kind == KindVLESS && e.Transport == transportXHTTP
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
	default:
		return Endpoint{}, fmt.Errorf("sharelink: unsupported scheme in %q (want vless://, hysteria2://, hy2:// or trojan://)", truncate(raw, 48))
	}
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
