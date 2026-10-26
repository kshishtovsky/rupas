//go:build windows

// autostart_windows.go — HKCU Run-key autostart (no admin needed).
package guictrl

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

const runKeyPath = `Software\Microsoft\Windows\CurrentVersion\Run`
const runValueName = "Rupas"

// Autostart reports whether the GUI launches at login.
func (c *Controller) Autostart() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue(runValueName)
	return err == nil
}

// SetAutostart adds or removes the GUI from the HKCU Run key.
func (c *Controller) SetAutostart(on bool) error {
	if on {
		k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE)
		if err != nil {
			return fmt.Errorf("autostart: %w", err)
		}
		defer k.Close()
		self := selfPath()
		return k.SetStringValue(runValueName, `"`+self+`"`)
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, runKeyPath, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("autostart: %w", err)
	}
	defer k.Close()
	return k.DeleteValue(runValueName)
}
