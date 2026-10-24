package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"
)

// This file speaks RFC 1928 to the internal sing-box mixed inbound on
// loopback. TCP flows use CONNECT; UDP pseudo-sessions use UDP ASSOCIATE and
// the UDP datagram framing (RSV/FRAG/ATYP/DST/PORT header around payloads),
// which the inbound relays through the VLESS outbound as XUDP.

const (
	socks5Version = 0x05
	socks5NoAuth  = 0x00
	socks5CmdTCP  = 0x01
	socks5CmdUDP  = 0x03

	atypIPv4 = 0x01
	atypName = 0x03
	atypIPv6 = 0x04

	socks5HandshakeTimeout = 10 * time.Second
	// maxUDPFrame is the largest SOCKS5 UDP datagram we build or parse
	// (header + 64 KiB payload).
	maxUDPFrame = 65535 + 512
)

var errSocks5 = errors.New("socks5")

// socks5Connect performs a SOCKS5 CONNECT to dst through proxy and returns
// the raw relay connection.
func socks5Connect(ctx context.Context, proxy string, dst netip.AddrPort) (net.Conn, error) {
	conn, err := socks5Handshake(ctx, proxy)
	if err != nil {
		return nil, err
	}
	req := socks5RequestHeader(socks5CmdTCP, dst)
	req = binary.BigEndian.AppendUint16(req, dst.Port())
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("%w: write connect: %w", errSocks5, err)
	}
	if err := socks5ReadReply(conn); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// socks5DialHost is socks5Connect for a host that may be a domain name (used
// by the health marker: the destination is resolved at the tunnel exit).
func socks5DialHost(ctx context.Context, proxy, host string, port uint16) (net.Conn, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return socks5Connect(ctx, proxy, netip.AddrPortFrom(addr.Unmap().WithZone(""), port))
	}
	conn, err := socks5Handshake(ctx, proxy)
	if err != nil {
		return nil, err
	}
	req := make([]byte, 0, 7+len(host))
	req = append(req, socks5Version, socks5CmdTCP, 0x00, atypName, byte(len(host)))
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, port)
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("%w: write connect: %w", errSocks5, err)
	}
	if err := socks5ReadReply(conn); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// udpRelay is one SOCKS5 UDP ASSOCIATE session: a TCP control connection
// plus the datagram socket towards the relay address.
type udpRelay struct {
	control net.Conn
	socket  *net.UDPConn // bound to 127.0.0.1:0, talks to relayAddr
	relay   netip.AddrPort
}

// socks5UDPAssociate establishes a UDP ASSOCIATE through proxy.
func socks5UDPAssociate(ctx context.Context, proxy string) (*udpRelay, error) {
	conn, err := socks5Handshake(ctx, proxy)
	if err != nil {
		return nil, err
	}
	zero := netip.MustParseAddrPort("0.0.0.0:0")
	req := socks5RequestHeader(socks5CmdUDP, zero)
	req = binary.BigEndian.AppendUint16(req, 0)
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("%w: write associate: %w", errSocks5, err)
	}
	relay, err := socks5ReadReplyAddr(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if !relay.IsValid() || relay.Addr().IsUnspecified() {
		conn.Close()
		return nil, fmt.Errorf("%w: invalid relay addr %s", errSocks5, relay)
	}
	if relay.Addr().Is6() && relay.Addr().Is4In6() {
		relay = netip.AddrPortFrom(relay.Addr().Unmap(), relay.Port())
	}
	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("%w: relay socket: %w", errSocks5, err)
	}
	return &udpRelay{control: conn, socket: socket, relay: relay}, nil
}

// send frames payload for dst and sends it to the relay.
func (u *udpRelay) send(dst netip.AddrPort, payload []byte) error {
	frame := socks5RequestHeader(0x00, dst)
	frame = binary.BigEndian.AppendUint16(frame, dst.Port())
	frame = append(frame, payload...)
	_, err := u.socket.WriteToUDPAddrPort(frame, u.relay)
	return err
}

// receive reads one framed datagram from the relay, returning the reported
// source and the payload (a slice of buf, valid until the next call).
func (u *udpRelay) receive(buf []byte) (netip.AddrPort, []byte, error) {
	m, from, err := u.socket.ReadFromUDPAddrPort(buf)
	if err != nil {
		return netip.AddrPort{}, nil, err
	}
	_ = from // always the relay
	src, n, err := parseUDPFrame(buf[:m])
	if err != nil {
		return netip.AddrPort{}, nil, err
	}
	return src, buf[n:m], nil
}

func (u *udpRelay) close() {
	u.socket.Close()
	u.control.Close()
}

func socks5Handshake(ctx context.Context, proxy string) (net.Conn, error) {
	d := net.Dialer{Timeout: socks5HandshakeTimeout}
	if deadline, ok := ctx.Deadline(); ok {
		d.Timeout = time.Until(deadline)
	}
	conn, err := d.DialContext(ctx, "tcp", proxy)
	if err != nil {
		return nil, fmt.Errorf("%w: dial %s: %w", errSocks5, proxy, err)
	}
	conn.SetDeadline(time.Now().Add(socks5HandshakeTimeout)) //nolint:errcheck
	if _, err := conn.Write([]byte{socks5Version, 1, socks5NoAuth}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("%w: write greeting: %w", errSocks5, err)
	}
	var m [2]byte
	if _, err := io.ReadFull(conn, m[:]); err != nil {
		conn.Close()
		return nil, fmt.Errorf("%w: read greeting reply: %w", errSocks5, err)
	}
	if m[0] != socks5Version || m[1] != socks5NoAuth {
		conn.Close()
		return nil, fmt.Errorf("%w: unexpected greeting reply %x", errSocks5, m)
	}
	conn.SetDeadline(time.Time{}) //nolint:errcheck
	return conn, nil
}

// socks5RequestHeader builds the fixed part (VER CMD RSV ATYP ADDR) of a
// request for an IP destination; the caller appends the port.
func socks5RequestHeader(cmd byte, dst netip.AddrPort) []byte {
	b := make([]byte, 0, 22)
	b = append(b, socks5Version, cmd, 0x00)
	if dst.IsValid() {
		if a := dst.Addr().Unmap(); a.Is4() {
			b = append(b, atypIPv4)
			b4 := a.As4()
			return append(b, b4[:]...)
		} else if a.Is6() {
			b = append(b, atypIPv6)
			b16 := a.As16()
			return append(b, b16[:]...)
		}
	}
	// no address (UDP ASSOCIATE with 0.0.0.0:0)
	b = append(b, atypIPv4, 0, 0, 0, 0)
	return b
}

// socks5ReadReply reads a reply, verifying success; the bound address is
// discarded (we do not need it for CONNECT).
func socks5ReadReply(conn net.Conn) error {
	_, err := socks5ReadReplyAddr(conn)
	return err
}

// socks5ReadReplyAddr reads a reply and returns BND.ADDR:PORT (for UDP
// ASSOCIATE), or an invalid AddrPort for CONNECT.
func socks5ReadReplyAddr(conn net.Conn) (netip.AddrPort, error) {
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return netip.AddrPort{}, fmt.Errorf("%w: read reply: %w", errSocks5, err)
	}
	if head[0] != socks5Version {
		return netip.AddrPort{}, fmt.Errorf("%w: bad reply version %d", errSocks5, head[0])
	}
	if head[1] != 0x00 {
		return netip.AddrPort{}, fmt.Errorf("%w: reply code %d", errSocks5, head[1])
	}
	var addr netip.Addr
	switch head[3] {
	case atypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return netip.AddrPort{}, fmt.Errorf("%w: read bnd v4: %w", errSocks5, err)
		}
		addr = netip.AddrFrom4(b)
	case atypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return netip.AddrPort{}, fmt.Errorf("%w: read bnd v6: %w", errSocks5, err)
		}
		addr = netip.AddrFrom16(b)
	case atypName:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return netip.AddrPort{}, fmt.Errorf("%w: read bnd name len: %w", errSocks5, err)
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(conn, name); err != nil {
			return netip.AddrPort{}, fmt.Errorf("%w: read bnd name: %w", errSocks5, err)
		}
		parsed, err := netip.ParseAddr(string(name))
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("%w: bnd name %q: %v", errSocks5, name, err)
		}
		addr = parsed
	default:
		return netip.AddrPort{}, fmt.Errorf("%w: bad atyp %d", errSocks5, head[3])
	}
	var p [2]byte
	if _, err := io.ReadFull(conn, p[:]); err != nil {
		return netip.AddrPort{}, fmt.Errorf("%w: read bnd port: %w", errSocks5, err)
	}
	return netip.AddrPortFrom(addr, binary.BigEndian.Uint16(p[:])), nil
}

// parseUDPFrame decodes RSV FRAG ATYP ADDR PORT payload.
func parseUDPFrame(b []byte) (netip.AddrPort, int, error) {
	if len(b) < 4 {
		return netip.AddrPort{}, 0, fmt.Errorf("%w: short udp frame %d", errSocks5, len(b))
	}
	if b[1] != 0x00 {
		return netip.AddrPort{}, 0, fmt.Errorf("%w: fragmented udp unsupported", errSocks5)
	}
	var addr netip.Addr
	var off int
	switch b[3] {
	case atypIPv4:
		if len(b) < 10 {
			return netip.AddrPort{}, 0, fmt.Errorf("%w: short v4 frame", errSocks5)
		}
		addr = netip.AddrFrom4([4]byte(b[4:8]))
		off = 8
	case atypIPv6:
		if len(b) < 22 {
			return netip.AddrPort{}, 0, fmt.Errorf("%w: short v6 frame", errSocks5)
		}
		addr = netip.AddrFrom16([16]byte(b[4:20]))
		off = 20
	case atypName:
		if len(b) < 5 {
			return netip.AddrPort{}, 0, fmt.Errorf("%w: short name frame", errSocks5)
		}
		n := int(b[4])
		if len(b) < 5+n+2 {
			return netip.AddrPort{}, 0, fmt.Errorf("%w: short name frame", errSocks5)
		}
		parsed, err := netip.ParseAddr(string(b[5 : 5+n]))
		if err != nil {
			return netip.AddrPort{}, 0, fmt.Errorf("%w: frame name: %v", errSocks5, err)
		}
		addr = parsed
		off = 5 + n
	default:
		return netip.AddrPort{}, 0, fmt.Errorf("%w: bad frame atyp %d", errSocks5, b[3])
	}
	port := binary.BigEndian.Uint16(b[off : off+2])
	return netip.AddrPortFrom(addr, port), off + 2, nil
}
