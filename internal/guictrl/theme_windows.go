package guictrl

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Theme modes, same three states as Android SettingsStore.K_THEME.
const (
	ThemeSystem = -1 // follow Windows
	ThemeLight  = 0
	ThemeDark   = 1
)

func themePath() string { return filepath.Join(stateDir(), "theme.json") }

// ThemeMode always returns a usable mode: a missing or damaged file means
// "system", which is also the first-run state.
func (c *Controller) ThemeMode() int {
	data, err := os.ReadFile(themePath())
	if err != nil {
		return ThemeSystem
	}
	var f struct {
		Mode int `json:"mode"`
	}
	if json.Unmarshal(data, &f) != nil {
		return ThemeSystem
	}
	if f.Mode != ThemeLight && f.Mode != ThemeDark {
		return ThemeSystem
	}
	return f.Mode
}

// SetThemeMode stores the mode; the frontend repaints immediately, the file only
// has to survive the restart (and pre-arm the window background on the next one).
func (c *Controller) SetThemeMode(mode int) error {
	if mode != ThemeSystem && mode != ThemeLight && mode != ThemeDark {
		return fmt.Errorf("theme mode %d: want -1, 0 or 1", mode)
	}
	if err := os.MkdirAll(stateDir(), 0o700); err != nil {
		return err
	}
	data, _ := json.Marshal(struct {
		Mode int `json:"mode"`
	}{mode})
	tmp := themePath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, themePath())
}
