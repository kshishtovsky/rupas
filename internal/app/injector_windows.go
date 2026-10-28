//go:build windows

package app

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/kshishtovsky/rupas/internal/prober"
	"github.com/kshishtovsky/rupas/pkg/windivert"
)

// Injector budget: TCP dial + TLS handshake deadlines plus slack for the
// pass-through pump to drain.
const (
	injectDialTimeout    = 4 * time.Second
	injectHSDeadline     = 6 * time.Second
	injectTotalBudget    = 12 * time.Second
	injectPumpStopWait   = 2 * time.Second
	injectMaxPacketBytes = 65540
)

// winInjector implements prober.FakeInjector with the same WinDivert
// mechanics the capture engine uses for InjectFake (capture/ops.go):
//
//  1. open a NETWORK-layer handle filtered to outbound TCP/443 towards
//     the calibration target (the only handle alive — the capture engine
//     is suspended during probe cycles);
//  2. net.Dial the target so the kernel picks a fresh flow; every matched
//     packet is passed through by the pump goroutine, so the handshake
//     progresses normally;
//  3. when the FIRST outbound ClientHello segment of that flow passes
//     (payload starts with a TLS handshake record), clone its IP+TCP
//     headers, swap in the fake template, drop the TTL to the candidate
//     value and set seq-1 — exactly like capture's injectFake — and send
//     it BEFORE releasing the real segment;
//  4. run a browser-like uTLS handshake (ADR-7) on the same flow and
//     report whether it completed.
//
// ok therefore means: a fake ClientHello with fakeTTL died harmlessly
// (before it could poison the flow) and the real handshake survived.
type winInjector struct {
	tpl      []byte
	log      *log.Logger
	attempts atomic.Int64
	injected atomic.Int64
}

var _ prober.FakeInjector = (*winInjector)(nil)

// newFakeInjector returns the platform FakeInjector (nil where WinDivert
// is unavailable — prober.UnwiredInjector is never used in production).
func newFakeInjector(tpl []byte, logger *log.Logger) prober.FakeInjector {
	if logger == nil {
		logger = log.Default()
	}
	return &winInjector{tpl: tpl, log: logger}
}

// Injected reports how many fake ClientHellos were sent (diagnostics).
func (w *winInjector) Injected() int64 { return w.injected.Load() }

func (w *winInjector) InjectAndHandshake(ip, sni string, fakeTTL uint8) (bool, error) {
	w.attempts.Add(1)
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() {
		return false, fmt.Errorf("app: injector: need an IPv4 target, got %q", ip)
	}
	filter := fmt.Sprintf("outbound and tcp and ip.DstAddr == %s and tcp.DstPort == 443", addr.String())
	h, err := windivert.Open(filter, windivert.LayerNetwork, 0)
	if err != nil {
		return false, fmt.Errorf("app: injector: open: %w", err)
	}
	defer h.Close()

	ctx, cancel := context.WithTimeout(context.Background(), injectTotalBudget)
	defer cancel()

	var localPort atomic.Uint32
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		w.pump(h, &localPort, fakeTTL, ctx)
	}()

	d := net.Dialer{Timeout: injectDialTimeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		w.stopPump(h, loopDone)
		return false, fmt.Errorf("app: injector: dial: %w", err)
	}
	defer conn.Close()
	if ta, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		localPort.Store(uint32(ta.Port))
	}

	// ADR-7: probes speak a browser-like ClientHello; a thin Go CH gives
	// false calibration results. InsecureSkipVerify: calibration
	// classifies the path, not the server.
	tlsConn := utls.UClient(conn, &utls.Config{ServerName: sni, InsecureSkipVerify: true}, utls.HelloChrome_Auto)
	_ = tlsConn.SetDeadline(time.Now().Add(injectHSDeadline))
	hsErr := tlsConn.HandshakeContext(ctx)
	ok := hsErr == nil

	w.stopPump(h, loopDone)
	if ctx.Err() != nil {
		return false, fmt.Errorf("app: injector: %w", ctx.Err())
	}
	if hsErr != nil {
		return false, fmt.Errorf("app: injector: handshake: %w", hsErr)
	}
	return ok, nil
}

// calibFakeRepeats matches the engine profile's default Repeats and the
// winws reference (--dpi-desync-repeats=6): the live channel (wave 4A)
// only latches onto the fake stream when it sees the duplicate ClientHello
// repeated — a single fake left the real CH unprotected (live-measured).
const calibFakeRepeats = 6

// pump is the pass-through receive loop: the handle intercepts matched
// packets, so everything must be re-injected for the flow to live. The
// fakes (calibFakeRepeats identical copies, engine parity) are injected
// in front of the first ClientHello segment of the calibrated flow.
func (w *winInjector) pump(h *windivert.Handle, localPort *atomic.Uint32, ttl uint8, ctx context.Context) {
	buf := make([]byte, injectMaxPacketBytes)
	var a windivert.Address
	injected := false
	for {
		n, err := h.Recv(buf, &a)
		if err != nil {
			return // shutdown / closed handle
		}
		pkt := buf[:n]
		if !injected && a.Outbound() && localPort.Load() != 0 {
			if p, ok := parseMiniTCP(pkt); ok &&
				p.srcPort == uint16(localPort.Load()) &&
				len(p.payload) >= 2 && p.payload[0] == 0x16 && p.payload[1] == 0x03 {
				if err := w.sendFake(h, pkt, p, &a, ttl); err == nil {
					injected = true
					w.injected.Add(int64(calibFakeRepeats))
				} else {
					w.log.Printf("app: injector: fake send failed: %v", err)
				}
			}
		}
		if err := h.Send(pkt, &a); err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func (w *winInjector) stopPump(h *windivert.Handle, done chan struct{}) {
	_ = h.Shutdown(windivert.ShutdownRecv)
	select {
	case <-done:
	case <-time.After(injectPumpStopWait):
	}
}

// sendFake crafts and sends one fake ClientHello packet, mirroring
// capture's injectFake (wave 4A winws parity): the FIRST real ClientHello
// segment's IP+TCP headers are cloned, payload replaced with the template,
// TTL lowered. seq/ack/window/flags/IP ID stay verbatim — the fake occupies
// the DPI's expected stream position (client ISN+1 / server ISN+1) so the
// DPI latches onto it and treats the real CH as a retransmission; a shifted
// seq (old `seq-1`) is discarded by the DPI as out-of-window. Sent with the
// captured address verbatim — NO Impostor flag (WinDivert treats impostor
// injections as forwarded packets and the stack decrements their TTL by
// one, which shifts the calibration result). Checksums recomputed.
func (w *winInjector) sendFake(h *windivert.Handle, orig []byte, p miniTCP, addr *windivert.Address, ttl uint8) error {
	hl := p.ipLen + p.tcpLen // IP + TCP headers (incl. options)
	need := hl + len(w.tpl)
	if need > injectMaxPacketBytes {
		return fmt.Errorf("fake packet %d bytes exceeds limit", need)
	}
	buf := make([]byte, need)
	copy(buf, orig[:hl])
	copy(buf[hl:], w.tpl)
	buf[8] = ttl                                       // IPv4 TTL
	binary.BigEndian.PutUint16(buf[2:4], uint16(need)) // IPv4 total length
	// seq (offset ipLen+4) and ack stay the triggering segment's own —
	// the segment IS the first CH segment, so seq = client ISN+1 and
	// ack = server ISN+1, exactly the reference behavior.
	// Synthetic send address, zapret rawsend style (capture/ops.go
	// fakeSendAddr): zeroed, Outbound, IfIdx, checksum-valid flags set —
	// the captured address's offload-pending checksum state would put an
	// uncomputed TCP checksum on the wire.
	fa := windivert.Address{}
	fa.Layer = addr.Layer
	fa.SetOutbound(true)
	fa.SetIPChecksum(true)
	fa.SetTCPChecksum(true)
	fa.SetUDPChecksum(true)
	fa.Network().IfIdx, fa.Network().SubIfIdx = addr.Network().IfIdx, addr.Network().SubIfIdx
	if err := windivert.CalcChecksums(buf, &fa); err != nil {
		return err
	}
	for i := 0; i < calibFakeRepeats; i++ {
		if err := h.Send(buf, &fa); err != nil {
			return err
		}
	}
	return nil
}

// miniTCP is the minimal IPv4+TCP header view the injector needs
// (capture's parser is package-private; this cold-path duplicate stays
// tiny on purpose).
type miniTCP struct {
	ipLen   int
	tcpLen  int // TCP header length incl. options (data offset)
	srcPort uint16
	seq     uint32
	payload []byte
}

func parseMiniTCP(pkt []byte) (miniTCP, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return miniTCP{}, false
	}
	ipLen := int(pkt[0]&0x0f) * 4
	if ipLen < 20 || len(pkt) < ipLen || pkt[9] != 6 { // proto TCP
		return miniTCP{}, false
	}
	off := ipLen
	if len(pkt) < off+20 {
		return miniTCP{}, false
	}
	dataOff := int(pkt[off+12]>>4) * 4
	if dataOff < 20 || off+dataOff > len(pkt) {
		return miniTCP{}, false
	}
	return miniTCP{
		ipLen:   ipLen,
		tcpLen:  dataOff,
		srcPort: binary.BigEndian.Uint16(pkt[off : off+2]),
		seq:     binary.BigEndian.Uint32(pkt[off+4 : off+8]),
		payload: pkt[off+dataOff:],
	}, true
}
