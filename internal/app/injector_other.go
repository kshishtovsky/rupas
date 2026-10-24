//go:build !windows

package app

import (
	"log"

	"github.com/rupas/rupas/internal/prober"
)

// newFakeInjector returns nil off Windows: TTL calibration needs the
// WinDivert injection mechanics. A nil injector makes ProbeRunner skip
// calibration (with an honest note) instead of failing the probe cycle —
// prober.UnwiredInjector is never wired into production.
func newFakeInjector([]byte, *log.Logger) prober.FakeInjector { return nil }
