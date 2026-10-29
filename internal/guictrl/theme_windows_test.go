package guictrl

import (
	"os"
	"path/filepath"
	"testing"
)

// Theme file is the only state: a bad value on disk must read back as "system",
// and an out-of-range mode must not be written at all.
func TestThemeModeRoundTrip(t *testing.T) {
	t.Setenv("LocalAppData", t.TempDir())
	var c Controller

	if got := c.ThemeMode(); got != ThemeSystem {
		t.Fatalf("no file: got %d, want %d", got, ThemeSystem)
	}
	for _, mode := range []int{ThemeLight, ThemeDark, ThemeSystem} {
		if err := c.SetThemeMode(mode); err != nil {
			t.Fatalf("set %d: %v", mode, err)
		}
		if got := c.ThemeMode(); got != mode {
			t.Fatalf("round trip %d: got %d", mode, got)
		}
	}
	if c.SetThemeMode(7) == nil {
		t.Fatal("mode 7 accepted")
	}
	if err := os.WriteFile(filepath.Join(stateDir(), "theme.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := c.ThemeMode(); got != ThemeSystem {
		t.Fatalf("garbage file: got %d, want %d", got, ThemeSystem)
	}
}
