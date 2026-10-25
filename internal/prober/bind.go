// Interface binding for probe traffic (SYSTEM_DESIGN §7.1 accuracy).
//
// The classifier must measure the ISP path, not whatever currently owns
// the default route: TUN clients running on the same host (e.g. Happ)
// install a low-metric 0.0.0.0/0 route, and a plain net.Dialer then
// sends probe flows into that TUN — where they are blackholed or proxied
// elsewhere, and the classifier reports false "sni blocked" verdicts
// (live finding 2026-10-25: a plain CH bound to the physical NIC passes
// in ~0.05 s while the default-route probes time out). Windows uses the
// strong host send model: binding the source address pins the egress
// interface, so binding to the physical NIC's IPv4 address makes the
// probe path deterministic.
package prober

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// virtualIfaceMarkers are name substrings of known virtual/TUN adapters
// (case-insensitive) that must never carry probe traffic. "tun" also
// covers wintun/utun; "tap" covers TAP adapters.
var virtualIfaceMarkers = []string{
	"loopback", "virtual", "vethernet", "wsl", "hyper-v", "bluetooth",
	"tun", "tap", "tailscale", "zerotier", "wireguard", "sing", "happ",
	"clash", "mihomo", "meta", "ppp", "vpn", "teredo", "isatap", "hamachi",
}

// ProbeBindIP returns the IPv4 address and the name of the interface
// probe traffic should leave through: the RUPAS_PROBE_IFACE override
// (an IP address or an interface name) when set, otherwise the first
// physical-looking interface (up, non-loopback, hardware MAC, IPv4, no
// virtual marker in the name — Go enumerates interfaces in adapter
// order, physical NICs first on stock Windows).
func ProbeBindIP() (net.IP, string, error) {
	if o := strings.TrimSpace(os.Getenv("RUPAS_PROBE_IFACE")); o != "" {
		if ip := net.ParseIP(o).To4(); ip != nil {
			return ip, o, nil
		}
		ifaces, err := net.Interfaces()
		if err == nil {
			for _, ifc := range ifaces {
				if strings.EqualFold(ifc.Name, o) {
					if ip, ok := firstIPv4(ifc); ok {
						return ip, ifc.Name, nil
					}
				}
			}
		}
		return nil, "", fmt.Errorf("prober: RUPAS_PROBE_IFACE %q: no up IPv4 interface matched", o)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, "", fmt.Errorf("prober: enumerate interfaces: %w", err)
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(ifc.HardwareAddr) == 0 {
			continue // software adapters have no MAC
		}
		name := strings.ToLower(ifc.Name)
		virtual := false
		for _, m := range virtualIfaceMarkers {
			if strings.Contains(name, m) {
				virtual = true
				break
			}
		}
		if virtual {
			continue
		}
		if ip, ok := firstIPv4(ifc); ok {
			return ip, ifc.Name, nil
		}
	}
	return nil, "", fmt.Errorf("prober: no physical IPv4 interface found (%d interfaces)", len(ifaces))
}

func firstIPv4(ifc net.Interface) (net.IP, bool) {
	addrs, err := ifc.Addrs()
	if err != nil {
		return nil, false
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipn.IP.To4()
		if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
			continue
		}
		return ip4, true
	}
	return nil, false
}

// PhysicalTransport is a production Transport: TCP dials bound to the
// physical NIC (LocalIP; empty → default route, e.g. in tests or when
// autodetection is disabled). Timeout 0 → DefaultDialTimeout.
type PhysicalTransport struct {
	// Timeout overrides DefaultDialTimeout when positive.
	Timeout time.Duration
	// LocalIP is the source address (the physical NIC's IPv4). Binding
	// it pins the egress interface under the Windows strong host model.
	LocalIP net.IP
	// IfaceName is diagnostic only (which interface LocalIP belongs to).
	IfaceName string
}

// Dial establishes a TCP connection to ip:port from the bound interface.
func (t *PhysicalTransport) Dial(ip string, port uint16) (Conn, error) {
	d := net.Dialer{Timeout: DefaultDialTimeout}
	if t.Timeout > 0 {
		d.Timeout = t.Timeout
	}
	if t.LocalIP != nil {
		d.LocalAddr = &net.TCPAddr{IP: t.LocalIP}
	}
	return d.Dial("tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)))
}
