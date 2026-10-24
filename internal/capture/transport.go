//go:build windows

package capture

import (
	"errors"

	"github.com/rupas/rupas/pkg/windivert"
)

// ErrStopped is returned by Transport implementations after Shutdown has
// unblocked a pending receive; the engine treats it as a graceful stop.
var ErrStopped = errors.New("capture: transport stopped")

// Transport is the driver boundary of the engine: batch receive, inject and
// checksum recomputation. The production implementation (WinTransport) wraps
// a WinDivert handle; tests substitute a fake that replays synthetic packets
// and records everything sent.
//
// All methods are called from the single goroutine owning the handle, except
// Shutdown/Close, which the engine's Stop invokes from another goroutine to
// unblock a pending RecvBatch (mirroring WinDivert's own contract).
type Transport interface {
	// RecvBatch receives up to len(packets) packets, re-slicing packets[i]
	// to the actual packet length and filling addrs[i]. It blocks until at
	// least one packet is available or the transport is shut down.
	RecvBatch(packets [][]byte, addrs []windivert.Address) (int, error)
	// Send injects pkt with the metadata in addr.
	Send(pkt []byte, addr *windivert.Address) error
	// FixChecksums recomputes all IP/TCP/UDP checksums of pkt in place and
	// updates the checksum-valid hint bits in addr.
	FixChecksums(pkt []byte, addr *windivert.Address) error
	// Shutdown unblocks a pending RecvBatch (WinDivert SHUTDOWN_RECV).
	Shutdown() error
	// Close releases the handle. Idempotent.
	Close() error
}

// WinTransport adapts a *windivert.Handle to Transport. FixChecksums is the
// driver's WinDivertHelperCalcChecksums, as required by SYSTEM_DESIGN §3.2.
type WinTransport struct {
	h *windivert.Handle
}

// NewWinTransport wraps an already-open handle.
func NewWinTransport(h *windivert.Handle) *WinTransport { return &WinTransport{h: h} }

func (w *WinTransport) RecvBatch(packets [][]byte, addrs []windivert.Address) (int, error) {
	return w.h.RecvBatch(packets, addrs)
}

func (w *WinTransport) Send(pkt []byte, addr *windivert.Address) error {
	return w.h.Send(pkt, addr)
}

func (w *WinTransport) FixChecksums(pkt []byte, addr *windivert.Address) error {
	return windivert.CalcChecksums(pkt, addr)
}

func (w *WinTransport) Shutdown() error {
	return w.h.Shutdown(windivert.ShutdownRecv)
}

func (w *WinTransport) Close() error { return w.h.Close() }

// ensure interface satisfaction.
var _ Transport = (*WinTransport)(nil)
