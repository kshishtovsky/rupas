//go:build !windows

package android

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"runtime/debug"
	"sync"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// run assembles the TUN device (from the Java-owned file descriptor) and
// the gVisor netstack, then blocks until ctx is cancelled. The fd comes
// from VpnService via ParcelFileDescriptor.getFd(); addressing/routing was
// configured Java-side by VpnService.Builder — sing-tun only takes over
// packet I/O (SYSTEM_DESIGN §3: "TUN fd").
func (e *Engine) run(ctx context.Context, fd int) error {
	opts := tun.Options{
		FileDescriptor: fd,
		MTU:            DefaultMTU,
		Inet4Address:   []netip.Prefix{netip.MustParsePrefix(DefaultTUNAddress)},
		Inet6Address:   []netip.Prefix{netip.MustParsePrefix(DefaultTUNAddress6)},
	}
	device, err := tun.New(opts)
	if err != nil {
		return fmt.Errorf("create tun from fd %d: %w", fd, err)
	}
	defer device.Close()
	if err := device.Start(); err != nil {
		return fmt.Errorf("start tun: %w", err)
	}
	e.logf("tun up: fd=%d addr=%s addr6=%s mtu=%d stack=gvisor", fd, DefaultTUNAddress, DefaultTUNAddress6, DefaultMTU)

	// W3: bring the tunnel relay up before any flow can be judged. A
	// failed relay start does not kill the transport: TUNNEL flows will
	// escalate honestly (fallbackAllowed policy).
	if e.relay == nil {
		e.setTunnel("off", "no endpoint settings")
	} else {
		if rErr := e.relay.Start(ctx, e.protect, e.filesDir); rErr != nil {
			e.logf("tunnel relay start failed (TUNNEL rules will escalate): %v", rErr)
			_ = e.relay.Close()
			e.setTunnel("failed", "relay: "+rErr.Error())
		}
		defer e.relay.Close() //nolint:errcheck
	}
	// Build the TUNNEL dial chain (relay inbounds + own xhttp client).
	// Works even when the relay start failed: carriers may be empty and
	// TUNNEL flows escalate honestly.
	e.buildCarriers(ctx)
	// Honest state for the app: "direct" is the escalation tail, so a chain
	// without a real carrier means the tunnel never came up.
	if n := e.tunnelCarrierCount(); n > 0 {
		e.setTunnel("on", fmt.Sprintf("%d carrier(s)", n))
	} else if st, _ := e.TunnelInfo(); st != "failed" {
		e.setTunnel("failed", "no usable carrier")
	}

	stack, err := tun.NewStack("gvisor", tun.StackOptions{
		Context:    ctx,
		Tun:        device,
		TunOptions: opts,
		UDPTimeout: UDPTimeout,
		Handler:    &flowHandler{engine: e},
		Logger:     engineLogger{e},
	})
	if err != nil {
		return fmt.Errorf("create gvisor netstack: %w", err)
	}
	if err := stack.Start(); err != nil {
		return fmt.Errorf("start gvisor netstack: %w", err)
	}
	defer stack.Close()

	e.logln("transport ready (W2: direct-only)")

	<-ctx.Done()
	return nil
}

// flowHandler is the sing-tun Handler: it maps the wave-2 Verdict seam onto
// netstack flow actions and relays every accepted flow through the
// protected egress.
type flowHandler struct {
	engine *Engine
}

// JudgeFlow runs once per new TCP flow / UDP session (never per packet).
// UDP sessions carry no ClientHello: the whole decision happens here.
// TCP flows are accepted and finally judged in NewConnectionEx after the
// ClientHello peek.
func (h *flowHandler) JudgeFlow(proto uint8, source, destination netip.AddrPort, firstPacket []byte) (v tun.FlowVerdict) {
	defer h.engine.panicGuard("JudgeFlow", &v)
	meta := FlowMeta{
		Network:     networkName(proto),
		Source:      source,
		Destination: destination,
	}
	// PreferIPv4: native IPv6 destinations are fast-dropped — the server
	// cannot carry v6, and an instant fail lets apps fall back to IPv4
	// (4-in-6 mapped addresses are IPv4 and pass through).
	if a := destination.Addr(); h.engine.preferIPv4 && a.Is6() && !a.Is4In6() {
		h.engine.counters.Drop()
		return tun.FlowVerdict{Action: tun.ActionDrop}
	}
	// UDP is decided entirely here, so the app UID is resolved here too.
	// TCP is judged again in relayTCP (after the ClientHello peek), which
	// resolves its own UID — resolving it here as well would double the
	// per-flow JNI cost for no gain.
	if meta.Network == "udp" {
		meta.UID = h.engine.resolveUID(meta)
	}
	action := h.engine.decide(meta)
	h.engine.logAppRule(meta)
	if action == ActionBlock {
		return tun.FlowVerdict{Action: tun.ActionDrop}
	}
	return tun.FlowVerdict{Action: tun.ActionAccept}
}

// NewDNSPacket is only invoked on ActionHijackDNS, which wave 2 never
// returns: DNS:53 is relayed like any other UDP session (ТЗ W2).
func (h *flowHandler) NewDNSPacket(payload []byte, source, destination M.Socksaddr, writer N.PacketWriter) {
	defer h.engine.panicGuard("NewDNSPacket")
}

// NewConnectionEx relays one TCP flow: netstack endpoint ↔ egress socket,
// bidirectional, byte-counted. The final action is decided here, after the
// passive ClientHello peek (SNI/ECH).
func (h *flowHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer h.engine.panicGuard("NewConnectionEx")
	h.relayTCP(ctx, conn, source, destination, onClose)
}

func (h *flowHandler) relayTCP(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer h.engine.panicGuard("relayTCP")
	e := h.engine
	e.counters.TCPFlowOpen()
	defer e.counters.TCPFlowClose()

	dst := destination.AddrPort()
	// Pre-decision without payload: conclusive for LAN / DNS:53 / ports.
	meta := FlowMeta{Network: "tcp", Source: source.AddrPort(), Destination: dst}
	// The app UID is resolved once per TCP flow, here — the flow entry
	// point (docs/PERAPP_ROUTING.md §2). It is free unless per-app rules
	// are configured.
	meta.UID = e.resolveUID(meta)
	if action, final := e.decidePre(meta); final {
		e.logAppRule(meta)
		if action == ActionBlock {
			e.counters.Drop()
			e.logf("tcp %s: blocked by rules", dst)
			conn.Close()
			if onClose != nil {
				onClose(nil)
			}
			return
		}
		if action == ActionDirect {
			h.relayTCPDirect(ctx, conn, dst, onClose)
			return
		}
		// ActionTunnel by CIDR (Telegram): no SNI needed.
		h.dialAndRelayTCP(ctx, conn, meta, onClose)
		return
	}

	// SNI-dependent rules: passively peek the first ClientHello (bounded,
	// non-destructive — the bytes are replayed to the egress).
	sni, ech, wrapped := peekClientHello(conn)
	conn = wrapped
	meta.SNI = sni
	meta.ECH = ech
	if sni != "" || ech {
		e.logf("tcp %s: CH sni=%q ech=%v", dst, sni, ech)
	}
	h.dialAndRelayTCP(ctx, conn, meta, onClose)
}

// dialAndRelayTCP resolves the action via dialEgress (rules + tunnel +
// escalation) and pumps the relay.
func (h *flowHandler) dialAndRelayTCP(ctx context.Context, conn net.Conn, meta FlowMeta, onClose N.CloseHandlerFunc) {
	defer h.engine.panicGuard("dialAndRelayTCP")
	e := h.engine
	remote, _, err := e.dialEgress(ctx, meta)
	if err != nil {
		e.counters.Drop()
		e.logf("tcp %s: dial refused: %v", meta.Destination, err)
		conn.Close()
		if onClose != nil {
			onClose(err)
		}
		return
	}
	defer remote.Close()
	defer conn.Close()
	if onClose != nil {
		defer onClose(nil)
	}
	e.logf("tcp flow: %v -> %s", conn.RemoteAddr(), meta.Destination)

	go e.pump(remote, conn, e.counters.AddRx) // app → internet
	e.pump(conn, remote, e.counters.AddTx)    // internet → app
}

// relayTCPDirect is the wave-2 path: protected dialer, no rules beyond the
// pre-decision that routed the flow here.
func (h *flowHandler) relayTCPDirect(ctx context.Context, conn net.Conn, destination netip.AddrPort, onClose N.CloseHandlerFunc) {
	defer h.engine.panicGuard("relayTCPDirect")
	e := h.engine
	remote, err := e.dialer.DialContext(ctx, "tcp", destination.String())
	if err != nil {
		// Non-blocking refusal: no retry, no queue — the netstack
		// endpoint is closed and the flow counted as dropped.
		e.counters.Drop()
		e.logf("tcp %s: dial refused: %v", destination, err)
		conn.Close()
		if onClose != nil {
			onClose(err)
		}
		return
	}
	defer remote.Close()
	defer conn.Close()
	if onClose != nil {
		defer onClose(nil)
	}
	e.logf("tcp flow: %v -> %s", conn.RemoteAddr(), destination)

	go e.pump(remote, conn, e.counters.AddRx) // app → internet
	e.pump(conn, remote, e.counters.AddTx)    // internet → app
}

// NewPacketConnectionEx relays one UDP pseudo-session: DIRECT through a
// protected connected UDP socket, TUNNEL through the relay's SOCKS5 UDP
// ASSOCIATE (XUDP) — with the same honest escalation policy as TCP
// (SYSTEM_DESIGN §5: "UDP-сокеты тоже защищать").
func (h *flowHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer h.engine.panicGuard("NewPacketConnectionEx")
	go h.relayUDP(ctx, conn, source, destination, onClose)
}

func (h *flowHandler) relayUDP(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	e := h.engine
	e.counters.UDPSessionOpen()
	defer e.counters.UDPSessionClose()
	closeOnce := sync.OnceFunc(func() {
		conn.Close()
	})
	defer closeOnce()

	dst := destination.AddrPort()
	// DNS is hijacked for adblock (any app, any resolver), and for the
	// PreferIPv4 AAAA filtering. With the filter off and PreferIPv4 off the
	// session is a plain relay above.
	if dst.Port() == 53 && (e.adblock != nil || e.preferIPv4) {
		h.serveDNS53(ctx, conn, destination, closeOnce)
		return
	}
	// The packet-connection callback gets no FlowMeta from JudgeFlow, so the
	// session resolves its own UID again: once per session (never per
	// packet) and free when no per-app rules are configured. Without it the
	// tunnel-by-app decision made in JudgeFlow would be lost here, because
	// this is the call that actually picks direct vs tunnel.
	meta := FlowMeta{Network: "udp", Source: source.AddrPort(), Destination: dst}
	meta.UID = e.resolveUID(meta)
	action := e.decide(meta)
	if action == ActionBlock {
		e.counters.Drop()
		e.logf("udp %s: blocked by rules", dst)
		return
	}
	if action == ActionTunnel {
		if h.relayUDPTunnel(ctx, conn, dst, closeOnce) {
			if onClose != nil {
				defer onClose(nil)
			}
			return
		}
		// Tunnel unavailable/refused: fall through to direct when the
		// fallback policy allows it (the escalation is counted/logged).
	}

	remote, err := e.dialer.DialContext(ctx, "udp", dst.String())
	if err != nil {
		e.counters.Drop()
		e.logf("udp %s: dial refused: %v", dst, err)
		if onClose != nil {
			onClose(err)
		}
		return
	}
	udpRemote := remote.(*net.UDPConn)
	defer remote.Close()
	if onClose != nil {
		defer onClose(nil)
	}
	e.logf("udp session: %v -> %s", conn.LocalAddr(), dst)

	// internet → app.
	go func() {
		for {
			b := buf.NewPacket()
			n, rErr := b.ReadOnceFrom(remote)
			if n > 0 {
				if wErr := conn.WritePacket(b, destination); wErr != nil {
					return
				}
				e.counters.AddTx(int64(n)) // internet → app
				continue
			}
			b.Release()
			if rErr != nil {
				return
			}
		}
	}()

	// app → internet.
	for {
		b := buf.NewPacket()
		_, rErr := conn.ReadPacket(b)
		if rErr != nil {
			b.Release()
			return
		}
		n := len(b.Bytes())
		_, wErr := udpRemote.Write(b.Bytes())
		b.Release()
		if wErr != nil {
			return
		}
		e.counters.AddRx(int64(n)) // app → internet
	}
}

// relayUDPTunnel pumps one UDP pseudo-session through the socks relay. It
// returns false when the tunnel path is not possible (escalation to direct
// is up to the caller); on true the session was served and closed.
func (h *flowHandler) relayUDPTunnel(ctx context.Context, conn N.PacketConn, dst netip.AddrPort, closeOnce func()) bool {
	defer h.engine.panicGuard("relayUDPTunnel")
	e := h.engine
	e.counters.TunnelDial()
	if !e.relay.Available() {
		st, detail := e.TunnelInfo()
		e.logf("udp %s: tunnel unavailable (%s: %s)", dst, st, detail)
		e.counters.TunnelEscalate()
		if !e.fallbackAllowed() {
			e.counters.Drop()
			closeOnce()
			return true
		}
		return false
	}
	up, err := e.relay.DialUDP(ctx)
	if err != nil {
		e.logf("udp %s: tunnel associate failed: %v", dst, err)
		e.counters.TunnelEscalate()
		if !e.fallbackAllowed() {
			e.counters.Drop()
			closeOnce()
			return true
		}
		e.logf("udp %s: ESCALATED tunnel->direct (counter honest)", dst)
		return false
	}
	e.logf("udp session (tunnel): %v -> %s", conn.LocalAddr(), dst)

	// internet → app.
	go func() {
		bufR := make([]byte, maxUDPFrame)
		for {
			payload, rErr := up.receive(bufR)
			if rErr != nil {
				closeOnce()
				return
			}
			if len(payload) == 0 {
				continue // associate ack / keepalive frame
			}
			b := buf.NewPacket()
			b.Write(payload) //nolint:errcheck
			if wErr := conn.WritePacket(b, M.SocksaddrFrom(dst.Addr(), dst.Port())); wErr != nil {
				b.Release()
				closeOnce()
				return
			}
			b.Release()
			e.counters.AddTx(int64(len(payload))) // internet → app
		}
	}()

	// app → internet.
	for {
		b := buf.NewPacket()
		_, rErr := conn.ReadPacket(b)
		if rErr != nil {
			b.Release()
			up.close()
			return true
		}
		payload := b.Bytes()
		wErr := up.send(dst, payload)
		n := len(payload)
		b.Release()
		if wErr != nil {
			up.close()
			return true
		}
		e.counters.AddRx(int64(n)) // app → internet
	}
}

// serveDNS53 is the DNS session body: a blocked name is answered locally
// (adblock: A→0.0.0.0, AAAA→::, other qtypes→NXDOMAIN) and, under PreferIPv4,
// AAAA for anything else gets an empty NOERROR so apps fall back to A. Every
// other datagram relays transparently to the original resolver through the
// protected dialer.
func (h *flowHandler) serveDNS53(ctx context.Context, conn N.PacketConn, dst M.Socksaddr, closeOnce func()) {
	defer h.engine.panicGuard("serveDNS53")
	e := h.engine
	defer closeOnce()
	var upstream net.Conn // lazily connected relay socket for passthrough
	defer func() {
		if upstream != nil {
			upstream.Close() //nolint:errcheck
		}
	}()
	// respBuf is reused across datagrams: a synthesized answer never allocates
	// after the first grow.
	respBuf := make([]byte, 0, 512)
	writeBack := func(payload []byte) bool {
		pkt := buf.NewPacket()
		pkt.Write(payload) //nolint:errcheck
		wErr := conn.WritePacket(pkt, M.SocksaddrFrom(dst.Addr, dst.Port))
		pkt.Release()
		return wErr == nil
	}
	for {
		b := buf.NewPacket()
		_, rErr := conn.ReadPacket(b)
		if rErr != nil {
			b.Release()
			return
		}
		payload := make([]byte, len(b.Bytes()))
		copy(payload, b.Bytes())
		b.Release()

		if resp, list := dnsAnswer(e.adblock, e.preferIPv4, payload, respBuf); resp != nil {
			respBuf = resp
			if list != "" {
				e.counters.AdblockDNS()
				e.logf("adblock: %s (dns, %s)", dnsQName(payload), list)
			}
			e.counters.AddRx(int64(len(payload)))
			if !writeBack(resp) {
				return
			}
			continue
		}
		// Multi-question AAAA (rare): the PreferIPv4 filter still applies.
		if resp := dns4Response(payload); resp != nil {
			e.counters.AddRx(int64(len(payload)))
			if !writeBack(resp) {
				return
			}
			continue
		}

		// Passthrough: relay the datagram to the original resolver.
		if upstream == nil {
			var dErr error
			upstream, dErr = e.dialer.DialContext(ctx, "udp", dst.String())
			if dErr != nil {
				e.counters.Drop()
				e.logf("dns %s: relay dial refused: %v", dst, dErr)
				return
			}
		}
		if _, wErr := upstream.Write(payload); wErr != nil {
			e.counters.Drop()
			return
		}
		e.counters.AddRx(int64(len(payload)))
		upstream.SetReadDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
		reply := make([]byte, 4096)
		n, rErr := upstream.Read(reply)
		if rErr != nil || n == 0 {
			continue // dropped query: the stub retries
		}
		if !writeBack(reply[:n]) {
			return
		}
	}
}

// panicGuard converts a transport-internal panic into a logged, absorbed
// error: the gvisor/sing-box callback goroutines have no recover seam, and
// an unrecovered panic there aborts the whole app (SIGABRT via the Go
// runtime). The stack is dumped through the log seam for diagnosis.
func (e *Engine) panicGuard(where string, ret ...any) {
	if r := recover(); r != nil {
		e.logf("PANIC in %s: %v\n%s", where, r, debug.Stack())
		for _, slot := range ret {
			if p, ok := slot.(*tun.FlowVerdict); ok && p != nil {
				*p = tun.FlowVerdict{Action: tun.ActionDrop}
			}
		}
	}
}

// networkName maps an IANA protocol number onto the FlowMeta network tag.
func networkName(proto uint8) string {
	switch proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return "unknown"
	}
}

// engineLogger forwards sing/sing-tun log lines into the platform log
// callback (Java side renders them in the log screen). Trace/Debug are
// dropped on purpose: they fire on per-packet error paths and every line
// crosses the Go→Java JNI bridge, which is pure battery cost. Warn and
// above are rare and are what actually needs diagnosing.
type engineLogger struct {
	engine *Engine
}

func (l engineLogger) Trace(args ...any) {}
func (l engineLogger) Debug(args ...any) {}
func (l engineLogger) Info(args ...any)  { l.engine.logln(args...) }
func (l engineLogger) Warn(args ...any)  { l.engine.logln(args...) }
func (l engineLogger) Error(args ...any) { l.engine.logln(args...) }
func (l engineLogger) Fatal(args ...any) { l.engine.logln(args...) }
func (l engineLogger) Panic(args ...any) { l.engine.logln(args...) }
