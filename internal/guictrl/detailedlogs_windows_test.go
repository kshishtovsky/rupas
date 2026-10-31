package guictrl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Подробный журнал в GUI читается прямо из файла демона: он должен отдавать
// хвост и переживать отсутствие файла (демон ещё не запускался).
func TestDetailedLogsReadsTail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rupasd.log")
	if err := os.WriteFile(path, []byte("one\ntwo\nthree\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &Controller{opts: Options{LogPath: path}}
	lines, err := c.DetailedLogs(2)
	if err != nil {
		t.Fatalf("DetailedLogs: %v", err)
	}
	if len(lines) != 2 || lines[0] != "two" || lines[1] != "three" {
		t.Fatalf("tail = %q", lines)
	}
}

func TestDetailedLogsMissingFileIsEmpty(t *testing.T) {
	c := &Controller{opts: Options{LogPath: filepath.Join(t.TempDir(), "nope.log")}}
	lines, err := c.DetailedLogs(10)
	if err != nil {
		t.Fatalf("missing file must not error: %v", err)
	}
	if len(lines) != 0 {
		t.Fatalf("want empty, got %q", lines)
	}
}

// Журнал событий и подробный журнал — разные источники; кнопка «Подробно»
// существует только чтобы их переключать.
func TestDefaultLogPathNamed(t *testing.T) {
	if !strings.HasSuffix(DefaultLogPath(), filepath.Join("rupas", "logs", "rupasd.log")) {
		t.Fatalf("unexpected default log path: %s", DefaultLogPath())
	}
}
