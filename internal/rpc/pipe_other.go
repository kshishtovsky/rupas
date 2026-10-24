//go:build !windows

package rpc

import (
	"errors"
	"io"
	"time"
)

// newPipeListener is Windows-only; on other platforms the control plane is
// not available (v1 is a Windows product, PRD §7).
func newPipeListener(name string) (listener, error) {
	return nil, errors.New("rupas/rpc: named pipes are only supported on Windows")
}

// DialPipe is Windows-only.
func DialPipe(name string, timeout time.Duration) (io.ReadWriteCloser, error) {
	return nil, errors.New("rupas/rpc: named pipes are only supported on Windows")
}

// keep io imported for the listener seam above.
var _ = io.ReadWriteCloser(nil)
var _ = time.Duration(0)
