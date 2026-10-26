//go:build !windows

package android

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

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
	if e.relay != nil {
		if rErr := e.relay.Start(ctx, e.protect, e.filesDir); rErr != nil {
			e.logf("tunnel relay start failed (TUNNEL rules will escalate): %v", rErr)
			_ = e.relay.Close()
		}
		defer e.relay.Close() //nolint:errcheck
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
func (h *flowHandler) JudgeFlow(proto uint8, source, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	meta := FlowMeta{
		Network:     networkName(proto),
		Source:      source,
		Destination: destination,
	}
	if h.engine.decide(meta) == ActionBlock {
		return tun.FlowVerdict{Action: tun.ActionDrop}
	}
	return tun.FlowVerdict{Action: tun.ActionAccept}
}

// NewDNSPacket is only invoked on ActionHijackDNS, which wave 2 never
// returns: DNS:53 is relayed like any other UDP session (ТЗ W2).
func (h *flowHandler) NewDNSPacket(payload []byte, source, destination M.Socksaddr, writer N.PacketWriter) {
}

// NewConnectionEx relays one TCP flow: netstack endpoint ↔ egress socket,
// bidirectional, byte-counted. The final action is decided here, after the
// passive ClientHello peek (SNI/ECH).
func (h *flowHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.relayTCP(ctx, conn, source, destination, onClose)
}

func (h *flowHandler) relayTCP(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	e := h.engine
	e.counters.TCPFlowOpen()
	defer e.counters.TCPFlowClose()

	dst := destination.AddrPort()
	// Pre-decision without payload: conclusive for LAN / DNS:53 / ports.
	meta := FlowMeta{Network: "tcp", Source: source.AddrPort(), Destination: dst}
	if action, final := e.decidePre(meta); final {
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
	if e.decide(FlowMeta{Network: "udp", Source: source.AddrPort(), Destination: dst}) == ActionTunnel {
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
	e := h.engine
	e.counters.TunnelDial()
	if !e.relay.Available() {
		e.logf("udp %s: tunnel unavailable (no endpoint settings)", dst)
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
// callback (Java side renders them in the log screen).
type engineLogger struct {
	engine *Engine
}

func (l engineLogger) Trace(args ...any) { l.engine.logln(args...) }
func (l engineLogger) Debug(args ...any) { l.engine.logln(args...) }
func (l engineLogger) Info(args ...any)  { l.engine.logln(args...) }
func (l engineLogger) Warn(args ...any)  { l.engine.logln(args...) }
func (l engineLogger) Error(args ...any) { l.engine.logln(args...) }
func (l engineLogger) Fatal(args ...any) { l.engine.logln(args...) }
func (l engineLogger) Panic(args ...any) { l.engine.logln(args...) }
