//go:build live

package guictrl

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLiveDownloadUpdate проверяет реальную цепочку «скачать → сверить SHA256
// → распаковать» на опубликованном релизе. В тестах version.Version = "dev",
// поэтому любой релиз считается новее.
//
//	go test -tags live ./internal/guictrl -run TestLiveDownload -v
func TestLiveDownloadUpdate(t *testing.T) {
	if os.Getenv("LocalAppData") == "" {
		t.Skip("нужен LocalAppData")
	}
	c := &Controller{}
	dir, err := c.DownloadUpdate()
	if err != nil {
		t.Fatalf("DownloadUpdate: %v", err)
	}
	t.Logf("распаковано в %s", dir)
	for _, f := range []string{"rupas-gui.exe", "rupasd.exe", "rupasctl.exe", "WinDivert.dll"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("нет %s: %v", f, err)
		}
	}
}
