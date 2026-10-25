//go:build windows

package android

import (
	"context"
	"errors"
)

// run is not available on Windows: the TUN comes from Android's
// VpnService, and the Windows capture path lives in internal/app (the
// desktop pipeline). This stub only keeps `go build ./...` green on the
// Windows dev host; the real implementation is tun.go (!windows).
func (e *Engine) run(ctx context.Context, fd int) error {
	return errors.New("android: TUN transport requires an Android/Linux build")
}
