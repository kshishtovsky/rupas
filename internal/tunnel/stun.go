package tunnel

// UDP-path health probing (wave 5). The §6 wave-5 spec probes with a STUN
// binding request (stun.cloudflare.com:3478). Live acceptance on the user
// VPS found a deployment reality the spec did not anticipate: many VPS
// egress policies pass only UDP/53 — every STUN target timed out through
// the tunnel while a DNS query answered, on a path that was demonstrably
// alive. A failed STUN round is therefore retried once as a DNS query
// before the path is declared dead: any answer — STUN or DNS — means the
// UDP path carries datagrams (udpProbePath reports which one answered).

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net/netip"
)

const (
	stunMagicCookie = 0x2112A442
	stunMsgRequest  = 0x0001
	stunMsgSuccess  = 0x0101
	// udpProbeDNSServer is the DNS verdict-fallback target (UDP/53 is the
	// one UDP port even cheap VPS egress policies pass).
	udpProbeDNSServer = "8.8.8.8:53"
)

// stunBuildRequest encodes a binding request with a random transaction id.
func stunBuildRequest() ([]byte, [12]byte, error) {
	var txid [12]byte
	if _, err := rand.Read(txid[:]); err != nil {
		return nil, txid, fmt.Errorf("stun: txid: %w", err)
	}
	msg := make([]byte, 0, 20)
	msg = binary.BigEndian.AppendUint16(msg, stunMsgRequest)
	msg = binary.BigEndian.AppendUint16(msg, 0) // length
	msg = binary.BigEndian.AppendUint32(msg, stunMagicCookie)
	msg = append(msg, txid[:]...)
	return msg, txid, nil
}

// stunIsSuccess reports whether msg is a binding success response matching
// txid.
func stunIsSuccess(msg []byte, txid [12]byte) bool {
	if len(msg) < 20 {
		return false
	}
	if binary.BigEndian.Uint16(msg[0:2]) != stunMsgSuccess {
		return false
	}
	if binary.BigEndian.Uint32(msg[4:8]) != stunMagicCookie {
		return false
	}
	return string(msg[8:20]) == string(txid[:])
}

// dnsBuildQuery encodes a minimal A query ("example.com.") with a random
// transaction id.
func dnsBuildQuery() ([]byte, uint16, error) {
	var id [2]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, 0, fmt.Errorf("dns: txid: %w", err)
	}
	q := make([]byte, 0, 29)
	q = append(q, id[:]...)
	q = append(q, 0x01, 0x00) // flags: recursion desired
	q = append(q, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	q = append(q, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0)
	q = append(q, 0x00, 0x01, 0x00, 0x01) // A IN
	return q, binary.BigEndian.Uint16(id[:]), nil
}

// dnsIsReply reports whether msg looks like a DNS answer with the given
// transaction id.
func dnsIsReply(msg []byte, id uint16) bool {
	return len(msg) >= 12 && binary.BigEndian.Uint16(msg[0:2]) == id
}

// datagramRound sends payload through the relay to server and waits
// (ctx-bounded) for a datagram satisfying check. receive() blocks on a raw
// socket, so each read runs under a select with ctx.Done.
func datagramRound(ctx context.Context, relay packetRelay, server netip.AddrPort, payload []byte, check func([]byte) bool, maxLen int) error {
	if err := relay.send(server, payload); err != nil {
		return fmt.Errorf("probe: send: %w", err)
	}
	buf := make([]byte, maxLen)
	for {
		type recvResult struct {
			payload []byte
			err     error
		}
		ch := make(chan recvResult, 1)
		go func() {
			_, p, err := relay.receive(buf)
			ch <- recvResult{p, err}
		}()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case r := <-ch:
			if r.err != nil {
				return fmt.Errorf("probe: receive: %w", r.err)
			}
			if check(r.payload) {
				return nil
			}
			// unrelated datagram: keep waiting
		}
	}
}

// stunProbe sends one binding request through the UDP carrier to server
// and waits for the matching response.
func stunProbe(ctx context.Context, carrier udpCarrier, server netip.AddrPort, maxLen int) error {
	req, txid, err := stunBuildRequest()
	if err != nil {
		return err
	}
	relay, err := carrier.udpAssociate(ctx)
	if err != nil {
		return fmt.Errorf("stun: associate: %w", err)
	}
	defer relay.close()
	return datagramRound(ctx, relay, server, req, func(b []byte) bool { return stunIsSuccess(b, txid) }, maxLen)
}

// dnsProbe sends one DNS A query through the UDP carrier to server (any
// answer with the matching transaction id counts).
func dnsProbe(ctx context.Context, carrier udpCarrier, server netip.AddrPort, maxLen int) error {
	q, id, err := dnsBuildQuery()
	if err != nil {
		return err
	}
	relay, err := carrier.udpAssociate(ctx)
	if err != nil {
		return fmt.Errorf("dns: associate: %w", err)
	}
	defer relay.close()
	return datagramRound(ctx, relay, server, q, func(b []byte) bool { return dnsIsReply(b, id) }, maxLen)
}

// udpProbePath runs the §6 wave-5 UDP health probe over carrier: STUN
// first (DefaultSTUNServer), then — when the STUN round fails because the
// exit filters STUN ports — a DNS round as the verdict fallback. Each
// round gets its own deadline. It returns the method that answered
// ("stun"|"dns") or an error.
func (t *tunnel) udpProbePath(ctx context.Context, carrier udpCarrier) (string, error) {
	maxLen := maxUDPFrame
	if server, err := t.udpSTUNAddr(ctx); err == nil {
		rctx, cancel := context.WithTimeout(ctx, stunTimeout)
		err := stunProbe(rctx, carrier, server, maxLen)
		cancel()
		switch {
		case err == nil:
			return "stun", nil
		case ctx.Err() != nil:
			return "", ctx.Err()
		}
	} else {
		t.logger.Warn("udp health: stun server unresolved", slog.Any("err", err))
	}
	if server, err := t.resolveProbeAddr(ctx, udpProbeDNSServer); err == nil {
		rctx, cancel := context.WithTimeout(ctx, stunTimeout)
		err := dnsProbe(rctx, carrier, server, maxLen)
		cancel()
		switch {
		case err == nil:
			return "dns", nil
		case ctx.Err() != nil:
			return "", ctx.Err()
		}
	}
	return "", fmt.Errorf("udp path carried no probe answer (stun+dns)")
}
