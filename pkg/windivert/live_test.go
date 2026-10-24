//go:build windows

package windivert

import (
	"errors"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Live driver tests. They run only when WinDivert.dll is loadable AND the
// process may open the driver device (administrator) AND the WinDivert
// service is running; otherwise they skip. All handles are SNIFF-mode
// (observe-only), so host traffic is never dropped or delayed, and every
// handle is closed immediately.

// skipIfDriverUsable skips the test when err indicates the driver is not
// usable from this process (no admin / service stopped / not installed).
func skipIfDriverUnusable(t *testing.T, err error) {
	t.Helper()
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.Errno(5): // ERROR_ACCESS_DENIED: not elevated
			t.Skipf("WinDivert driver requires administrator (access denied): %v", err)
		case syscall.Errno(2): // ERROR_FILE_NOT_FOUND: driver/service missing
			t.Skipf("WinDivert driver not installed: %v", err)
		case syscall.Errno(1062): // ERROR_SERVICE_NOT_ACTIVE
			t.Skipf("WinDivert service not running: %v", err)
		case syscall.Errno(1058): // ERROR_SERVICE_DISABLED
			t.Skipf("WinDivert service disabled: %v", err)
		}
	}
}

// TestLiveRecvOnePacket opens a sniff handle with filter "true" on the
// NETWORK layer, receives one packet with a timeout (Shutdown unblocks the
// reader on timeout), validates the address layout against live driver
// output, parses the packet and recomputes checksums.
func TestLiveRecvOnePacket(t *testing.T) {
	if !dllAvailable(t) {
		t.Skip("WinDivert.dll not loadable")
	}
	h, err := OpenWithFlags("true", LayerNetwork, 0, FlagSniff|FlagRecvOnly)
	if err != nil {
		skipIfDriverUnusable(t, err)
		t.Fatalf("Open(true, NETWORK, sniff): %v", err)
	}
	defer h.Close()

	if maj, err := h.GetParam(ParamVersionMajor); err == nil {
		minor, _ := h.GetParam(ParamVersionMinor)
		t.Logf("WinDivert driver version %d.%d", maj, minor)
	}

	buf := make([]byte, int(MTUMax))
	var addr Address
	type result struct {
		n   int
		err error
	}
	ch := make(chan result, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		n, err := h.Recv(buf, &addr)
		ch <- result{n, err}
	}()
	select {
	case r := <-ch:
		wg.Wait()
		if r.err != nil {
			t.Fatalf("Recv: %v", r.err)
		}
		if r.n < 20 {
			t.Fatalf("Recv returned %d bytes, want >= 20 (IP+TCP header)", r.n)
		}
		if addr.Layer != LayerNetwork {
			t.Errorf("addr.Layer = %d, want %d", addr.Layer, LayerNetwork)
		}
		if addr.Event != EventNetworkPacket {
			t.Errorf("addr.Event = %d, want %d", addr.Event, EventNetworkPacket)
		}
		// Timestamp units are driver-defined in windivert.h ("Packet's
		// timestamp"); compare relatively, not against wall clock. Observed
		// ~2.6e11 shortly after driver start. Assert non-zero monotonic.
		if addr.Timestamp <= 0 {
			t.Errorf("addr.Timestamp = %d, want a positive timestamp", addr.Timestamp)
		}
		pkt := buf[:r.n]
		pp, ok := ParsePacket(pkt)
		if !ok {
			t.Fatalf("ParsePacket failed on live %d-byte packet", r.n)
		}
		if pp.IPv4 == nil {
			t.Fatal("live packet is not IPv4 (this DLL build strips IPv6)")
		}
		if pp.IPv4.TotalLen() != r.n {
			t.Errorf("IP TotalLen %d != recv len %d", pp.IPv4.TotalLen(), r.n)
		}
		if pp.IPv4.HdrLenBytes() < 20 || pp.IPv4.HdrLenBytes() > r.n {
			t.Errorf("bad IP header length %d", pp.IPv4.HdrLenBytes())
		}
		t.Logf("captured %d bytes: v4 %s->%s proto %d outbound=%v",
			r.n, pp.IPv4.SrcIP(), pp.IPv4.DstIP(), pp.Protocol, addr.Outbound())
		// In-place checksum recomputation must succeed (userspace helper).
		if err := CalcChecksums(pkt, &addr); err != nil {
			t.Errorf("CalcChecksums: %v", err)
		}
	case <-time.After(15 * time.Second):
		// Unblock the reader goroutine, then give up quietly.
		if err := h.Shutdown(ShutdownRecv); err != nil {
			t.Logf("Shutdown: %v", err)
		}
		wg.Wait()
		t.Skip("no packets within 15s; host idle")
	}
}

// TestLiveRecvBatch receives a small batch through WinDivertRecvEx.
func TestLiveRecvBatch(t *testing.T) {
	if !dllAvailable(t) {
		t.Skip("WinDivert.dll not loadable")
	}
	h, err := OpenWithFlags("true", LayerNetwork, 0, FlagSniff|FlagRecvOnly)
	if err != nil {
		skipIfDriverUnusable(t, err)
		t.Fatalf("Open(true, NETWORK, sniff): %v", err)
	}
	defer h.Close()

	_, packets, addrs := NewBatch(8, 1600)
	type result struct {
		n   int
		err error
	}
	ch := make(chan result, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		n, err := h.RecvBatch(packets, addrs[:])
		ch <- result{n, err}
	}()
	select {
	case r := <-ch:
		wg.Wait()
		if r.err != nil {
			t.Fatalf("RecvBatch: %v", r.err)
		}
		if r.n < 1 || r.n > 8 {
			t.Fatalf("RecvBatch returned %d packets, want 1..8", r.n)
		}
		for i := 0; i < r.n; i++ {
			if len(packets[i]) < 20 {
				t.Errorf("packet %d: %d bytes", i, len(packets[i]))
			}
			if addrs[i].Layer != LayerNetwork {
				t.Errorf("addrs[%d].Layer = %d", i, addrs[i].Layer)
			}
		}
		t.Logf("RecvBatch got %d packet(s), first len %d", r.n, len(packets[0]))
	case <-time.After(15 * time.Second):
		if err := h.Shutdown(ShutdownRecv); err != nil {
			t.Logf("Shutdown: %v", err)
		}
		wg.Wait()
		t.Skip("no packets within 15s; host idle")
	}
}

// TestLiveRedirectLayerRejected documents the empirically verified behavior:
// the stock 2.2 DLL shipped in build/windivert has no REDIRECT support and
// rejects layer 5 with ERROR_INVALID_PARAMETER. If a fork DLL that supports
// it is dropped in, the test skips instead of failing.
func TestLiveRedirectLayerRejected(t *testing.T) {
	if !dllAvailable(t) {
		t.Skip("WinDivert.dll not loadable")
	}
	h, err := OpenWithFlags("tcp.DstPort == 1", LayerRedirect, 0, FlagSniff)
	if err == nil {
		h.Close()
		t.Skip("this DLL accepts layer 5 (REDIRECT-capable fork); stock behavior N/A")
	}
	skipIfDriverUnusable(t, err) // no admin / service down: cannot judge
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		t.Fatalf("Open(layer 5): non-errno error: %v", err)
	}
	if errno != errInvalidParameter {
		t.Errorf("Open(layer 5) errno = %d (%v), want 87 ERROR_INVALID_PARAMETER", errno, err)
	}
	// Out-of-range layers are rejected locally.
	if _, err := Open("true", 6, 0); err == nil {
		t.Error("layer 6 should be rejected locally")
	}
}

// TestLiveClosedHandle verifies error propagation on a used-after-close handle.
func TestLiveClosedHandle(t *testing.T) {
	if !dllAvailable(t) {
		t.Skip("WinDivert.dll not loadable")
	}
	h, err := OpenWithFlags("true", LayerNetwork, 0, FlagSniff|FlagRecvOnly)
	if err != nil {
		skipIfDriverUnusable(t, err)
		t.Fatalf("Open: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Errorf("second Close should be a no-op, got %v", err)
	}
	var a Address
	buf := make([]byte, 1500)
	if _, err := h.Recv(buf, &a); !errors.Is(err, ErrClosed) {
		t.Errorf("Recv after Close: err = %v, want ErrClosed", err)
	}
	if err := h.Send(buf, &a); !errors.Is(err, ErrClosed) {
		t.Errorf("Send after Close: err = %v, want ErrClosed", err)
	}
}
