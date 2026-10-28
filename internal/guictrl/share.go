// share.go — universal share-link channels for the GUI, mirroring the
// Android W3 "universal config" (SettingsStore.links): a newline-separated
// list of vless:// hysteria2:// hy2:// trojan:// links in dial order.
// Parsing is delegated to the core (internal/transport/android sharelink.go);
// this file maps parsed endpoints onto the desktop config.Endpoint roles
// (tunnels.tcp / tunnels.udp / tunnels.fallback).
package guictrl

import (
	"fmt"
	"strings"

	"github.com/kshishtovsky/rupas/internal/config"
	android "github.com/kshishtovsky/rupas/internal/transport/android"
)

// Channel is one parsed share link with its desktop role and warnings.
type Channel struct {
	Link    string `json:"link"`
	Name    string `json:"name"` // #fragment or host:port
	Kind    string `json:"kind"` // vless-reality | vless-tls | vless-xhttp | hysteria2 | trojan | …
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Role    string `json:"role"`              // tcp | udp | fallback | unsupported
	Warning string `json:"warning,omitempty"` // human-readable, non-fatal
}

// ParseChannels parses the links blob (one link per line) in dial order.
func ParseChannels(blob string) ([]Channel, error) {
	var chans []Channel
	for _, raw := range strings.Split(blob, "\n") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		ep, err := android.ParseShareLink(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", short(raw), err)
		}
		c := Channel{
			Link: raw,
			Name: ep.Name,
			Host: ep.Host,
			Port: int(ep.Port),
		}
		if c.Name == "" {
			c.Name = fmt.Sprintf("%s:%d", ep.Host, ep.Port)
		}
		c.Kind, c.Role, c.Warning = classify(ep)
		chans = append(chans, c)
	}
	return chans, nil
}

// classify maps one parsed endpoint to a desktop role. Order matters only at
// save time; here every channel gets its potential role.
func classify(ep android.Endpoint) (kind, role, warning string) {
	switch {
	case ep.Kind == android.KindHysteria2:
		return "hysteria2", "udp", ""
	case ep.Kind == android.KindTrojan:
		return "trojan", "unsupported", "trojan:// не поддерживается десктоп-ядром"
	case ep.Kind != android.KindVLESS:
		return ep.Kind, "unsupported", "неизвестный тип ссылки"
	}
	switch ep.Transport {
	case "tcp":
		if ep.Security == "reality" {
			return "vless-reality", "tcp", ""
		}
		return "vless-tls", "tcp", ""
	case "xhttp":
		return "vless-xhttp", "fallback", ""
	default:
		return "vless-" + ep.Transport, "unsupported", "transport " + ep.Transport + " не поддерживается десктоп-ядром (tcp/xhttp)"
	}
}

// endpointFor maps a channel back to a config.Endpoint (role must be tcp|udp|fallback).
func endpointFor(ep android.Endpoint) (config.Endpoint, string) {
	switch {
	case ep.Kind == android.KindHysteria2:
		return config.Endpoint{
			Kind:     "hysteria2",
			Host:     ep.Host,
			Port:     ep.Port,
			Password: ep.UUID, // hy2 password rides the userinfo field
			SNI:      ep.SNI,
			ALPN:     []string{"h3"},
		}, "udp"
	case ep.Kind == android.KindVLESS && ep.Transport == "xhttp":
		out := config.Endpoint{
			Kind:        "vless_xhttp",
			Host:        ep.Host,
			Port:        ep.Port,
			UUID:        ep.UUID,
			SNI:         ep.SNI,
			ALPN:        ep.ALPN,
			Fingerprint: orDefault(ep.Fingerprint, "chrome"),
			Path:        ep.Path,
			Mode:        orDefault(ep.Mode, "packet-up"),
			XPadding:    "100-1000",
			HTTPHost:    ep.WSHost, // xhttp :authority pin (panel "host")
		}
		return out, "fallback"
	case ep.Kind == android.KindVLESS:
		out := config.Endpoint{
			Kind:        "vless_tcp",
			Host:        ep.Host,
			Port:        ep.Port,
			UUID:        ep.UUID,
			SNI:         ep.SNI,
			ALPN:        orDefault2(ep.ALPN, []string{"h2", "http/1.1"}),
			Fingerprint: orDefault(ep.Fingerprint, "chrome"),
		}
		if ep.Security == "reality" {
			out.Kind = "vless_reality"
			out.RealityPBK = ep.PBK
			out.RealitySID = ep.SID
			out.Flow = ep.Flow
		}
		return out, "tcp"
	default:
		return config.Endpoint{}, ""
	}
}

// channelsToPlan assigns the first vless-tcp → tunnels.tcp, the first
// hysteria2 → tunnels.udp, the first xhttp → fallback (dial order = link
// order). Returns the endpoints and the skipped links' warnings.
func channelsToPlan(blob string) (tcp, udp, fallback *config.Endpoint, warnings []string, err error) {
	chans, perr := ParseChannels(blob)
	if perr != nil {
		return nil, nil, nil, nil, perr
	}
	for _, ch := range chans {
		if ch.Warning != "" {
			warnings = append(warnings, fmt.Sprintf("%s: %s", ch.Name, ch.Warning))
		}
		if ch.Role == "unsupported" {
			continue
		}
		ep, err := android.ParseShareLink(ch.Link)
		if err != nil {
			continue
		}
		mapped, role := endpointFor(ep)
		switch role {
		case "tcp":
			if tcp == nil {
				e := mapped
				tcp = &e
			}
		case "udp":
			if udp == nil {
				e := mapped
				udp = &e
			}
		case "fallback":
			if fallback == nil {
				e := mapped
				fallback = &e
			}
		}
	}
	return tcp, udp, fallback, warnings, nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func orDefault2(s []string, def []string) []string {
	if len(s) == 0 {
		return def
	}
	return s
}

func short(s string) string {
	if len(s) > 48 {
		return s[:48] + "…"
	}
	return s
}
