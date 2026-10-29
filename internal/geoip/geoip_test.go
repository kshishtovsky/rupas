package geoip

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sampleList = "# comment line\n" +
	"1.2.3.0/24\n" +
	"\n" +
	"5.6.7.8/32   # trailing comment\n" +
	"2001:db8::/32\n"

func TestParse(t *testing.T) {
	pfx, err := Parse(strings.NewReader(sampleList))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pfx) != 3 {
		t.Fatalf("got %d prefixes, want 3: %v", len(pfx), pfx)
	}
	if pfx[0].String() != "1.2.3.0/24" || pfx[1].String() != "5.6.7.8/32" || pfx[2].String() != "2001:db8::/32" {
		t.Fatalf("unexpected prefixes: %v", pfx)
	}
	if _, err := Parse(strings.NewReader("not-a-cidr\n")); err == nil {
		t.Fatal("malformed line accepted")
	}
}

func TestListDownloadsAndCaches(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(sampleList))
	}))
	defer srv.Close()

	dir := t.TempDir()
	p := Params{Dir: dir, Mirrors: []string{srv.URL + "/{cc}.zone"}}

	got, err := List(p, "ru")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d prefixes, want 3", len(got))
	}
	cache := filepath.Join(dir, "geoip-ru.txt")
	if _, err := os.Stat(cache); err != nil {
		t.Fatalf("cache not written: %v", err)
	}

	// Fresh cache: server down must not matter.
	srv.Close()
	if _, err := List(p, "ru"); err != nil {
		t.Fatalf("fresh cache ignored: %v", err)
	}
}

func TestListStaleRefreshes(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "geoip-ru.txt")
	if err := os.WriteFile(cache, []byte("9.9.9.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stale := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(cache, stale, stale); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("8.8.8.0/24\n"))
	}))
	defer srv.Close()

	got, err := List(Params{Dir: dir, RefreshDays: 1, Mirrors: []string{srv.URL + "/{cc}"}}, "ru")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 1 || got[0].String() != "8.8.8.0/24" {
		t.Fatalf("stale cache not refreshed: %v", got)
	}
}

func TestListMirrorFailureKeepsStaleCache(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "geoip-ru.txt")
	if err := os.WriteFile(cache, []byte("9.9.9.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stale := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(cache, stale, stale); err != nil {
		t.Fatal(err)
	}

	got, err := List(Params{Dir: dir, RefreshDays: 1, Mirrors: []string{"http://127.0.0.1:1/{cc}"}}, "ru")
	if err != nil {
		t.Fatalf("stale cache should survive mirror failure: %v", err)
	}
	if len(got) != 1 || got[0].String() != "9.9.9.0/24" {
		t.Fatalf("unexpected prefixes: %v", got)
	}
}

func TestListBadBodyRejected(t *testing.T) {
	// An error page must NOT become the cache.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	if _, err := List(Params{Dir: dir, Mirrors: []string{srv.URL + "/{cc}"}}, "ru"); err == nil {
		t.Fatal("error-page body accepted as a list")
	}
	if _, err := os.Stat(filepath.Join(dir, "geoip-ru.txt")); err == nil {
		t.Fatal("error page poisoned the cache")
	}
}

func TestRefreshIgnoresFreshCache(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "geoip-ru.txt")
	if err := os.WriteFile(cache, []byte("9.9.9.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Fresh on purpose: List would keep it, Refresh must not.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("8.8.8.0/24\n"))
	}))
	defer srv.Close()
	p := Params{Dir: dir, Mirrors: []string{srv.URL + "/{cc}"}}

	if got, err := List(p, "ru"); err != nil || len(got) != 1 || got[0].String() != "9.9.9.0/24" {
		t.Fatalf("precondition: fresh cache must not be downloaded, got %v %v", got, err)
	}
	got, err := Refresh(p, "ru")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if len(got) != 1 || got[0].String() != "8.8.8.0/24" {
		t.Fatalf("fresh cache not re-downloaded: %v", got)
	}
}

func TestRefreshFailureKeepsCache(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "geoip-ru.txt")
	if err := os.WriteFile(cache, []byte("9.9.9.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Refresh(Params{Dir: dir, Mirrors: []string{"http://127.0.0.1:1/{cc}"}}, "ru"); err == nil {
		t.Fatal("mirror failure not reported")
	}
	if b, err := os.ReadFile(cache); err != nil || string(b) != "9.9.9.0/24\n" {
		t.Fatalf("failed refresh clobbered the cache: %q %v", b, err)
	}
	if _, err := Refresh(Params{Dir: dir}, "rus"); err == nil {
		t.Fatal("bad country code accepted")
	}
}

func TestListBadCountryCode(t *testing.T) {
	dir := t.TempDir()
	for _, cc := range []string{"", "rus", "r1"} {
		if _, err := List(Params{Dir: dir}, cc); err == nil {
			t.Errorf("country code %q accepted", cc)
		}
	}
}
