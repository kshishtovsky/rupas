package guictrl

import (
	"archive/zip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestFetchSumPicksTheAsset(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("aaa *Rupas-android-0.7.0-arm64.apk\nbbb *Rupas-win64-0.7.0.zip\n"))
	}))
	defer srv.Close()

	got, err := fetchSum(context.Background(), srv.URL, "Rupas-win64-0.7.0.zip")
	if err != nil {
		t.Fatalf("fetchSum: %v", err)
	}
	if got != "bbb" {
		t.Fatalf("sum = %q, want bbb", got)
	}
	if _, err := fetchSum(context.Background(), srv.URL, "nope.zip"); err == nil {
		t.Fatal("missing asset must be an error, not an empty sum")
	}
}

func TestUnzipRejectsPathEscape(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "evil.zip")
	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("../../escaped.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("x"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()

	out := filepath.Join(dir, "out")
	if err := os.MkdirAll(out, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unzip(zipPath, out); err != nil {
		t.Fatalf("unzip: %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "escaped.txt")); err == nil {
		t.Fatal("zip entry escaped the target directory")
	}
	if _, err := os.Stat(filepath.Join(out, "escaped.txt")); err != nil {
		t.Fatalf("clean entry missing: %v", err)
	}
}

func TestFileSHA256(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.txt")
	if err := os.WriteFile(p, []byte("rupas"), 0o600); err != nil {
		t.Fatal(err)
	}
	// printf 'rupas' | sha256sum
	const want = "bf3701878dbfb985a948778e08bbda6c4b64e617720cd01e2f484584a836afe7"
	got, err := fileSHA256(p)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("sha256 = %s, want %s", got, want)
	}
}
