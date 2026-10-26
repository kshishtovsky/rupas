// vless.go — parser for vless:// share links (docs/GUI_DESIGN.md §5a).
// Port of rupas-android ParseVless.java: vless://uuid@host:port?params#label
// with reality params pbk=/sid=/sni=; transport type tcp/xhttp, ws/grpc → warning.
package guictrl

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// VlessLink is the parsed share link (field-for-field the Android Result).
type VlessLink struct {
	UUID      string `json:"uuid"`
	Server    string `json:"server"`
	Port      int    `json:"port"`
	SNI       string `json:"sni"`
	PublicKey string `json:"publicKey"`
	ShortID   string `json:"shortId"`
	Fallback  bool   `json:"fallback"`
	Warning   string `json:"warning"`
	Transport string `json:"transport"` // tcp | xhttp (others → warning)
}

// ParseVlessLink parses a vless:// share link. It never touches the clipboard
// or disk; clearing the clipboard after paste is the caller's job (§8).
func ParseVlessLink(link string) (VlessLink, error) {
	s := strings.TrimSpace(link)
	if s == "" {
		return VlessLink{}, fmt.Errorf("пустая ссылка")
	}
	if !strings.HasPrefix(s, "vless://") {
		return VlessLink{}, fmt.Errorf("это не vless://-ссылка")
	}
	rest := strings.TrimPrefix(s, "vless://")

	// #label
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	// ?query
	query := ""
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		query = rest[i+1:]
		rest = rest[:i]
	}

	// uuid@host:port — uuid may itself contain no '@'; split on the LAST '@'
	// is wrong for passwords, but vless links have no password: split on first.
	at := strings.IndexByte(rest, '@')
	if at < 0 {
		return VlessLink{}, fmt.Errorf("нет uuid@host:port")
	}
	uuid := rest[:at]
	hostport := rest[at+1:]
	colon := strings.LastIndexByte(hostport, ':')
	if colon < 0 {
		return VlessLink{}, fmt.Errorf("нет порта")
	}
	host := hostport[:colon]
	port, err := strconv.Atoi(hostport[colon+1:])
	if err != nil || port < 1 || port > 65535 {
		return VlessLink{}, fmt.Errorf("порт должен быть от 1 до 65535")
	}
	if uuid == "" || host == "" {
		return VlessLink{}, fmt.Errorf("пустой uuid или сервер")
	}

	var v VlessLink
	v.UUID = uuid
	v.Server = host
	v.Port = port
	v.Transport = "tcp"

	if query != "" {
		q, err := url.ParseQuery(query)
		if err != nil {
			return VlessLink{}, fmt.Errorf("параметры ссылки: %w", err)
		}
		v.SNI = q.Get("sni")
		v.PublicKey = q.Get("pbk")
		v.ShortID = q.Get("sid")
		if t := q.Get("type"); t != "" {
			v.Transport = t
		}
		switch v.Transport {
		case "tcp", "xhttp":
			// supported (xhttp maps to endpoint kind vless_xhttp)
		default:
			v.Warning = "неподдерживаемый transport: " + v.Transport + " (поддерживаются tcp и xhttp)"
		}
	}
	// Reality without pbk: endpoint still possible (plain TLS) → fallback flag.
	v.Fallback = v.PublicKey == ""
	return v, nil
}
