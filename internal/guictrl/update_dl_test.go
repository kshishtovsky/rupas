package guictrl

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// TestDownloadRetriesAfterReset: the asset host reset the first attempt and
// the GUI left updates/<ver>/ empty (2026-10-30).
func TestDownloadRetriesAfterReset(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) == 1 {
			c, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			c.Close()
			return
		}
		_, _ = io.WriteString(w, strings.Repeat("z", 4096))
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "a.zip")
	if err := download(context.Background(), srv.URL, dst); err != nil {
		t.Fatalf("download after a reset: %v (attempts=%d)", err, atomic.LoadInt32(&n))
	}
	if fi, err := os.Stat(dst); err != nil || fi.Size() != 4096 {
		t.Fatalf("partial file: %v %v", fi, err)
	}
}

// A body that dies mid-transfer must not leave a truncated file behind.
func TestDownloadTruncatedBodyRetried(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) == 1 {
			w.Header().Set("Content-Length", "8192")
			_, _ = io.WriteString(w, strings.Repeat("y", 100))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			return // shorter than Content-Length -> unexpected EOF on the client
		}
		_, _ = io.WriteString(w, strings.Repeat("y", 8192))
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "a.zip")
	if err := download(context.Background(), srv.URL, dst); err != nil {
		t.Fatalf("download after a truncated body: %v", err)
	}
	fi, err := os.Stat(dst)
	if err != nil || fi.Size() != 8192 {
		t.Fatalf("want full 8192 bytes, got %v %v", fi, err)
	}
}
