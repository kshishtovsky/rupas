//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDaemonWorkDir verifies the daemon's working directory resolution:
// a config under <root>/configs/ must yield <root> so the daemon finds
// build/desync/* and other relative paths.
func TestDaemonWorkDir(t *testing.T) {
	root := t.TempDir()
	cfgDir := filepath.Join(root, "configs")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(cfgDir, "rupas.yaml")
	if err := os.WriteFile(cfgPath, []byte("profile: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if got := daemonWorkDir(cfgPath); got != root {
		t.Errorf("daemonWorkDir(%q) = %q, want %q", cfgPath, got, root)
	}

	// A config outside configs/ keeps its own directory.
	other := filepath.Join(root, "elsewhere", "my.yaml")
	if err := os.MkdirAll(filepath.Dir(other), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := daemonWorkDir(other); got != filepath.Dir(other) {
		t.Errorf("daemonWorkDir(%q) = %q, want %q", other, got, filepath.Dir(other))
	}
}

// TestTailLog returns the last N lines in chronological order.
func TestTailLog(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "daemon.log")
	if err := os.WriteFile(p, []byte("one\ntwo\nthree\nfour\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := tailLog(p, 2)
	if !strings.Contains(got, "three") || !strings.Contains(got, "four") {
		t.Fatalf("tailLog = %q, want the last two lines", got)
	}
	if strings.Contains(got, "one") {
		t.Fatalf("tailLog included an old line: %q", got)
	}
	// Missing file must not panic.
	if tailLog(filepath.Join(dir, "nope.log"), 3) != "" {
		t.Fatal("tailLog on a missing file should return empty")
	}
}

// TestFindDaemonMissing documents the error path when no rupasd.exe exists
// in the candidate locations.
func TestFindDaemonMissing(t *testing.T) {
	if p, err := findDaemon(); err == nil {
		// A daemon happens to be present next to the test binary or in
		// build/ — that's fine, just assert it resolved to a file.
		if st, statErr := os.Stat(p); statErr != nil || st.IsDir() {
			t.Fatalf("findDaemon returned a non-file path %q", p)
		}
		return
	}
}
