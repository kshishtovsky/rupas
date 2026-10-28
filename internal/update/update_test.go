package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func serve(t *testing.T, status int, body string, etag string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if etag != "" {
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", etag)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	old := latestURL
	latestURL = srv.URL
	t.Cleanup(func() { latestURL = old })
	return srv
}

const sample = `{
  "tag_name": "v0.7.0",
  "html_url": "https://github.com/kshishtovsky/rupas/releases/tag/v0.7.0",
  "body": "fix: ...",
  "published_at": "2026-11-01T10:00:00Z",
  "assets": [
    {"name": "Rupas-win64-0.7.0.zip", "browser_download_url": "https://x/win.zip", "size": 1},
    {"name": "Rupas-android-0.7.0-arm64.apk", "browser_download_url": "https://x/app.apk", "size": 2},
    {"name": "SHA256SUMS.txt", "browser_download_url": "https://x/sums", "size": 3}
  ]
}`

func TestLatestAndAssets(t *testing.T) {
	serve(t, http.StatusOK, sample, `"etag-1"`)

	c := &Client{}
	rel, err := c.Latest(context.Background())
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if rel.TagName != "v0.7.0" || len(rel.Assets) != 3 {
		t.Fatalf("unexpected release %+v", rel)
	}
	if !rel.Available("0.6.0") {
		t.Fatal("0.7.0 must be offered to 0.6.0")
	}
	if rel.Available("0.7.0") || rel.Available("0.8.0") {
		t.Fatal("same or newer local version must not be offered")
	}
	if a, ok := rel.Asset(AndroidAsset); !ok || a.URL != "https://x/app.apk" {
		t.Fatalf("android asset not picked: %+v", a)
	}
	if a, ok := rel.Asset(WindowsAsset); !ok || a.URL != "https://x/win.zip" {
		t.Fatalf("windows asset not picked: %+v", a)
	}

	// Second call sends If-None-Match and must report "not modified".
	if _, err := c.Latest(context.Background()); err != ErrNotModified {
		t.Fatalf("want ErrNotModified, got %v", err)
	}
}

func TestLatestErrors(t *testing.T) {
	serve(t, http.StatusForbidden, `{"message":"rate limit"}`, "")
	if _, err := (&Client{}).Latest(context.Background()); err == nil {
		t.Fatal("403 must be an error, not a silent 'no update'")
	}

	serve(t, http.StatusOK, `{"tag_name":"nightly"}`, "")
	if _, err := (&Client{}).Latest(context.Background()); err == nil {
		t.Fatal("unparsable tag must be an error")
	}
}

func TestAssetMatchers(t *testing.T) {
	cases := []struct {
		name         string
		win, android bool
	}{
		{"Rupas-win64-0.6.0.zip", true, false},
		{"Rupas-android-0.6.0-arm64.apk", false, true},
		{"SHA256SUMS.txt", false, false},
		{"Rupas-win64.zip", false, false},
	}
	for _, c := range cases {
		if got := WindowsAsset(c.name); got != c.win {
			t.Errorf("WindowsAsset(%q) = %v", c.name, got)
		}
		if got := AndroidAsset(c.name); got != c.android {
			t.Errorf("AndroidAsset(%q) = %v", c.name, got)
		}
	}
}
