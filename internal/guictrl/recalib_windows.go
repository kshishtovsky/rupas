//go:build windows

// recalib_windows.go — full DPI recalibration from the GUI (Settings button):
// forget the persisted calibration profile and force the daemon to re-probe.
// The ladder then walks the generic TTL order instead of the seeded one.
package guictrl

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"unsafe"
)

// profilePath is the daemon's persisted calibration profile
// (internal/prober SaveProfile; %ProgramData%\rupas\profile.json).
func profilePath() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "rupas", "profile.json")
}

// WipeProfile removes the persisted calibration (in-memory seed inside the
// daemon survives until restart, but the ladder still walks the full TTL
// order; the wipe guarantees a cold start next time too).
func WipeProfile() error {
	p := profilePath()
	if _, err := os.Stat(p); err != nil {
		return nil // nothing to wipe
	}
	if err := os.Remove(p); err != nil {
		// ProgramData\rupas is written by the elevated daemon: a non-elevated
		// GUI may lack DELETE — retry through the elevated self-relaunch.
		return elevatedWipeProfile()
	}
	return nil
}

// Recalibrate = wipe profile + ensure daemon + RPC probe (full walk).
func (c *Controller) Recalibrate() error {
	if err := WipeProfile(); err != nil {
		return fmt.Errorf("не удалось удалить профиль калибровки: %w", err)
	}
	if err := c.EnsureDaemon(); err != nil {
		return err
	}
	resp, err := CallPipe(c.opts.Pipe, "probe", 5*time.Second)
	if err != nil {
		return fmt.Errorf("демон недоступен: %w", err)
	}
	if !resp.OK {
		return fmt.Errorf("probe: %s", resp.Error)
	}
	return nil
}

// RunWipeProfileFlag services `-wipeprofile` from the elevated relaunch.
func RunWipeProfileFlag() error {
	return os.Remove(profilePath())
}

var (
	shell32W       = windows.NewLazySystemDLL("shell32.dll")
	procShellExecW = shell32W.NewProc("ShellExecuteW")
)

// elevatedWipeProfile re-launches the GUI exe with -wipeprofile via runas.
func elevatedWipeProfile() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(self)
	params, _ := windows.UTF16PtrFromString("-wipeprofile")
	res, _, _ := procShellExecW.Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(params)),
		0,
		1, // SW_SHOWNORMAL
	)
	if res <= 32 {
		return fmt.Errorf("elevation отклонена (ShellExecute=%d)", res)
	}
	// Give the elevated copy a moment to delete the file.
	time.Sleep(1500 * time.Millisecond)
	if _, err := os.Stat(profilePath()); err == nil {
		return fmt.Errorf("профиль всё ещё на месте после elevation")
	}
	return nil
}
