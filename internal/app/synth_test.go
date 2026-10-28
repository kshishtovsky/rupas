//go:build windows

package app

// Shared synthetic-packet builders and helpers for the app-package
// pipeline tests (mirrors internal/capture's test utilities; duplicated
// because test files are not importable).

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/kshishtovsky/rupas/internal/capture"
	"github.com/kshishtovsky/rupas/pkg/windivert"
)

func buildTCP4(src netip.Addr, sport uint16, dst netip.Addr, dport uint16, seq uint32, flags byte, payload []byte) []byte {
	src4, dst4 := src.As4(), dst.As4()
	total := 20 + 20 + len(payload)
	pkt := make([]byte, total)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	pkt[8] = 64
	pkt[9] = 6 // TCP
	copy(pkt[12:16], src4[:])
	copy(pkt[16:20], dst4[:])
	th := pkt[20:]
	binary.BigEndian.PutUint16(th[0:2], sport)
	binary.BigEndian.PutUint16(th[2:4], dport)
	binary.BigEndian.PutUint32(th[4:8], seq)
	th[12] = 0x50
	th[13] = flags
	copy(th[20:], payload)
	return pkt
}

func buildUDP4(src netip.Addr, sport uint16, dst netip.Addr, dport uint16, payload []byte) []byte {
	src4, dst4 := src.As4(), dst.As4()
	total := 20 + 8 + len(payload)
	pkt := make([]byte, total)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	pkt[8] = 64
	pkt[9] = 17 // UDP
	copy(pkt[12:16], src4[:])
	copy(pkt[16:20], dst4[:])
	uh := pkt[20:]
	binary.BigEndian.PutUint16(uh[0:2], sport)
	binary.BigEndian.PutUint16(uh[2:4], dport)
	binary.BigEndian.PutUint16(uh[4:6], uint16(8+len(payload)))
	copy(uh[8:], payload)
	return pkt
}

// buildClientHello serializes a minimal TLS ClientHello with a server_name
// extension (satisfies internal/inspector's parser).
func buildClientHello(sni string) []byte {
	entry := append([]byte{0x00, byte(len(sni) >> 8), byte(len(sni))}, sni...)
	exts := append([]byte{}, 0x00, 0x00, byte((len(entry)+2)>>8), byte(len(entry)+2))
	exts = append(exts, byte(len(entry)>>8), byte(len(entry)))
	exts = append(exts, entry...)
	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00)
	body = append(body, byte(len(exts)>>8), byte(len(exts)))
	body = append(body, exts...)
	out := make([]byte, 0, 5+4+len(body))
	out = append(out, 0x16, 0x03, 0x01, byte((4+len(body))>>8), byte(4+len(body)))
	out = append(out, 0x01, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	return append(out, body...)
}

func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

// freeTCPPort picks a free loopback port outside 443 and the UDP relay
// range the capture filter claims (Windows ephemeral ports live in
// [49152,65535], so "port 0" mostly returns unusable ones).
func freeTCPPort(t *testing.T) uint16 {
	t.Helper()
	for p := 20000; p < 20200; p++ {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			continue // taken: next candidate
		}
		ln.Close()
		return uint16(p)
	}
	t.Fatal("no usable free port")
	return 0
}

// ---------------------------------------------------------------------------
// Fake capture transport (mirrors internal/capture's FakeTransport, plus a
// wake-on-enqueue queue: the app tests keep feeding packets long after the
// engine's receive loops first blocked).
// ---------------------------------------------------------------------------

// not importable).
// ---------------------------------------------------------------------------

type appFakeTransport struct {
	mu       sync.Mutex
	cond     *sync.Cond
	sent     []windivert.Address
	sentData [][]byte
	queue    [][]byte
	outbound []bool
	stopped  bool
}

func newAppFakeTransport() *appFakeTransport {
	f := &appFakeTransport{}
	f.cond = sync.NewCond(&f.mu)
	return f
}

// Enqueue queues a packet for the next RecvBatch; it WAKES a blocked
// receiver (unlike a fixed queue the test keeps feeding packets long
// after the engine started polling).
func (f *appFakeTransport) Enqueue(pkt []byte, outbound bool) {
	f.mu.Lock()
	f.queue = append(f.queue, pkt)
	f.outbound = append(f.outbound, outbound)
	f.mu.Unlock()
	f.cond.Broadcast()
}

func (f *appFakeTransport) RecvBatch(packets [][]byte, addrs []windivert.Address) (int, error) {
	f.mu.Lock()
	for len(f.queue) == 0 && !f.stopped {
		f.cond.Wait()
	}
	if f.stopped && len(f.queue) == 0 {
		f.mu.Unlock()
		return 0, errors.New("capture: transport stopped")
	}
	n := len(f.queue)
	if n > len(packets) {
		n = len(packets)
	}
	for i := 0; i < n; i++ {
		copy(packets[i], f.queue[i])
		addrs[i] = windivert.Address{}
		addrs[i].SetOutbound(f.outbound[i])
	}
	f.queue = f.queue[n:]
	f.outbound = f.outbound[n:]
	f.mu.Unlock()
	return n, nil
}

func (f *appFakeTransport) Send(pkt []byte, addr *windivert.Address) error {
	f.mu.Lock()
	f.sentData = append(f.sentData, append([]byte(nil), pkt...))
	f.sent = append(f.sent, *addr)
	f.mu.Unlock()
	return nil
}

func (f *appFakeTransport) FixChecksums(pkt []byte, addr *windivert.Address) error { return nil }

func (f *appFakeTransport) Shutdown() error {
	f.mu.Lock()
	f.stopped = true
	f.mu.Unlock()
	f.cond.Broadcast()
	return nil
}

func (f *appFakeTransport) Close() error { return f.Shutdown() }

func (f *appFakeTransport) Sent() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte(nil), f.sentData...)
}

var _ capture.Transport = (*appFakeTransport)(nil)
