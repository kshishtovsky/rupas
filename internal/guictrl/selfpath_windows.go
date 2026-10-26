//go:build windows

// selfpath_windows.go — helper for the HKCU autostart Run entry.
package guictrl

import "os"

func selfPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "rupas-gui.exe"
	}
	return exe
}
