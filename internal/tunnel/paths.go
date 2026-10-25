package tunnel

import (
	"context"
	"net"
	"net/netip"
	"strconv"
)

// tcpCarrier carries TCP streams through one proxy path (the primary TCP
// endpoint or the fallback). Implementations: socksPath (sing-box mixed
// inbound over SOCKS5 CONNECT) and xhttpPath (Rupas' own VLESS+XHTTP
// client).
type tcpCarrier interface {
	// dial opens a TCP connection to dst through the path.
	dial(ctx context.Context, dst netip.AddrPort) (net.Conn, error)
	// dialHost opens a TCP connection to host:port (host may be a domain,
	// resolved at the tunnel exit).
	dialHost(ctx context.Context, host string, port uint16) (net.Conn, error)
}

// udpCarrier starts UDP pseudo-session relays through one proxy path.
// Implementations: socksPath (sing-box mixed inbound over SOCKS5 UDP
// ASSOCIATE — the inbound routes the flow to the UDP endpoint outbound or,
// on the fallback inbound, to the TCP endpoint's VLESS/XUDP outbound).
type udpCarrier interface {
	udpAssociate(ctx context.Context) (packetRelay, error)
}

// transport is the combined test seam: unit tests substitute one fake for
// every path.
type transport interface {
	tcpCarrier
	udpCarrier
}

// namedTCP/namedUDP attach a human-readable endpoint name to a carrier for
// logs and stats. paced marks carriers whose transport opens ONE network
// connection per dial and is therefore rate-limited by the TSPU (vless:
// ~3 rapid connections → ~2-5 min silent-SYN quarantine of the endpoint,
// live finding wave 6).
type namedTCP struct {
	name  string
	c     tcpCarrier
	paced bool
}

type namedUDP struct {
	name string
	c    udpCarrier
}

// socksPath speaks RFC 1928 to one sing-box mixed inbound on loopback:
// CONNECT for TCP paths, UDP ASSOCIATE for UDP paths.
type socksPath struct{ addr string }

func (p socksPath) dial(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	return socks5Connect(ctx, p.addr, dst)
}

func (p socksPath) dialHost(ctx context.Context, host string, port uint16) (net.Conn, error) {
	return socks5DialHost(ctx, p.addr, host, port)
}

func (p socksPath) udpAssociate(ctx context.Context) (packetRelay, error) {
	return socks5UDPAssociate(ctx, p.addr)
}

// socksAddrFromPort builds the loopback mixed inbound address.
func socksAddrFromPort(port uint16) string {
	return net.JoinHostPort(loopbackIP, strconv.Itoa(int(port)))
}
