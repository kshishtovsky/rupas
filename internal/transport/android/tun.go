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
	}
	device, err := tun.New(opts)
	if err != nil {
		return fmt.Errorf("create tun from fd %d: %w", fd, err)
	}
	defer device.Close()
	if err := device.Start(); err != nil {
		return fmt.Errorf("start tun: %w", err)
	}
	e.logf("tun up: fd=%d addr=%s mtu=%d stack=gvisor", fd, DefaultTUNAddress, DefaultMTU)

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
func (h *flowHandler) JudgeFlow(proto uint8, source, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	meta := FlowMeta{
		Network:     networkName(proto),
		Source:      source,
		Destination: destination,
	}
	if h.engine.verdict(meta) == ActionBlock {
		return tun.FlowVerdict{Action: tun.ActionDrop}
	}
	return tun.FlowVerdict{Action: tun.ActionAccept}
}

// NewDNSPacket is only invoked on ActionHijackDNS, which wave 2 never
// returns: DNS:53 is relayed like any other UDP session (ТЗ W2).
func (h *flowHandler) NewDNSPacket(payload []byte, source, destination M.Socksaddr, writer N.PacketWriter) {
}

// NewConnectionEx relays one TCP flow: netstack endpoint ↔ protected
// egress socket, bidirectional, byte-counted.
func (h *flowHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.relayTCP(ctx, conn, destination, onClose)
}

func (h *flowHandler) relayTCP(ctx context.Context, conn net.Conn, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	e := h.engine
	e.counters.TCPFlowOpen()
	defer e.counters.TCPFlowClose()

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

// NewPacketConnectionEx relays one UDP pseudo-session through a protected
// connected UDP socket (SYSTEM_DESIGN §5: "UDP-сокеты тоже защищать").
func (h *flowHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	go h.relayUDP(ctx, conn, destination, onClose)
}

func (h *flowHandler) relayUDP(ctx context.Context, conn N.PacketConn, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	e := h.engine
	e.counters.UDPSessionOpen()
	defer e.counters.UDPSessionClose()
	closeOnce := sync.OnceFunc(func() {
		conn.Close()
	})
	defer closeOnce()

	remote, err := e.dialer.DialContext(ctx, "udp", destination.String())
	if err != nil {
		e.counters.Drop()
		e.logf("udp %s: dial refused: %v", destination, err)
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
	e.logf("udp session: %v -> %s", conn.LocalAddr(), destination)

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
