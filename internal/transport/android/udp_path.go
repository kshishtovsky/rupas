package android

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/kshishtovsky/rupas/internal/tunnel"
)

// udpUpstream is the shape both UDP paths expose: the sing-box socks
// associate (XUDP over a VLESS outbound) and a native tmn association.
type udpUpstream interface {
	send(dst netip.AddrPort, payload []byte) error
	receive(buf []byte) ([]byte, error)
	close()
}

// tmnUDP adapts a tmn association to udpUpstream: the shared relay also
// reports the source, which a per-destination stream already implies.
type tmnUDP struct{ r *tunnel.UDPRelay }

func (u tmnUDP) send(dst netip.AddrPort, payload []byte) error { return u.r.Send(dst, payload) }
func (u tmnUDP) close()                                        { u.r.Close() }
func (u tmnUDP) receive(buf []byte) ([]byte, error) {
	_, payload, err := u.r.Receive(buf)
	return payload, err
}

// openUDP picks the UDP path: the sing-box relay when the plan needs it,
// otherwise the first tmn carrier that answers. A tmn-only profile used to
// have no UDP path at all (relay not started), so voice and QUIC from the
// phone fell through to direct.
func (e *Engine) openUDP(ctx context.Context) (udpUpstream, error) {
	if e.relay.Available() {
		return e.relay.DialUDP(ctx)
	}
	var last error
	for i, c := range e.tmn {
		r, err := tunnel.NewUDPRelay(ctx, c)
		if err == nil {
			e.logf("udp: tmn carrier %d", i)
			return tmnUDP{r}, nil
		}
		last = err
	}
	if last == nil {
		st, detail := e.TunnelInfo()
		last = fmt.Errorf("%s: %s", st, detail)
	}
	return nil, last
}
