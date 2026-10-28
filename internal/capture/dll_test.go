//go:build windows

package capture

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kshishtovsky/rupas/pkg/windivert"
)

// dllAvailable tries to load WinDivert.dll, adding the repository's
// build/windivert directory to PATH if needed (same pattern as the
// pkg/windivert tests). Pure userspace helpers need no driver.
func dllAvailable(t *testing.T) bool {
	t.Helper()
	if windivert.Available() {
		return true
	}
	wd, err := os.Getwd()
	if err != nil {
		return false
	}
	for dir, up := wd, 0; up < 4; up, dir = up+1, filepath.Dir(dir) {
		cand := filepath.Join(dir, "build", "windivert", "WinDivert.dll")
		if _, err := os.Stat(cand); err == nil {
			_ = os.Setenv("PATH", filepath.Join(dir, "build", "windivert")+";"+os.Getenv("PATH"))
			break
		}
	}
	return windivert.Available()
}

// windivertValidate compiles a filter with the real DLL helper.
func windivertValidate(filter string) error {
	return windivert.ValidateFilter(filter, windivert.LayerNetwork)
}
