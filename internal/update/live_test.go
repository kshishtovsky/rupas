//go:build live

package update

import (
	"context"
	"testing"
)

// TestLiveLatestRelease hits the real GitHub API: the release payload must
// parse into Release and must carry the assets the updaters look for.
// Run: go test -tags live ./internal/update -run Live -v
func TestLiveLatestRelease(t *testing.T) {
	rel, err := (&Client{}).Latest(context.Background())
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	t.Logf("latest=%s assets=%d url=%s", rel.TagName, len(rel.Assets), rel.HTMLURL)
	if _, ok := rel.Asset(WindowsAsset); !ok {
		t.Errorf("в релизе %s нет Windows-архива", rel.TagName)
	}
	if _, ok := rel.Asset(AndroidAsset); !ok {
		t.Errorf("в релизе %s нет Android-APK", rel.TagName)
	}
	if _, ok := rel.Asset(func(n string) bool { return n == "SHA256SUMS.txt" }); !ok {
		t.Errorf("в релизе %s нет SHA256SUMS.txt", rel.TagName)
	}
}
