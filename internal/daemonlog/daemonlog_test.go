package daemonlog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Ротация должна держать потолок по диску и не терять последнюю строку.
func TestRotationKeepsBoundedFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rupasd.log")
	w, err := New(path, 100, 3)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	line := strings.Repeat("x", 40) + "\n" // 41 байт
	for i := 0; i < 20; i++ {
		if _, err := w.Write([]byte(line)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// main + .1 + .2 + .3, и ничего сверх keep.
	if _, err := os.Stat(path + ".4"); !os.IsNotExist(err) {
		t.Fatalf(".4 must not exist, err=%v", err)
	}
	for _, p := range []string{path, path + ".1", path + ".2", path + ".3"} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if st.Size() > 100+41 {
			t.Fatalf("%s grew to %d", p, st.Size())
		}
	}
	last, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.HasSuffix(string(last), "x\n") {
		t.Fatalf("last line lost: %q", string(last[max(0, len(last)-80):]))
	}
}
