// Package update talks to the public GitHub Releases API and answers one
// question: is there a version newer than the one running.
//
// The endpoint is unauthenticated (60 req/h per IP); callers must throttle to
// a couple of checks per day and may send the saved ETag to make the polite
// "not modified" round-trip cheap.
package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kshishtovsky/rupas/internal/version"
)

// Repo is the project the app updates from.
const Repo = "kshishtovsky/rupas"

// latestURL is a var so tests can point it at httptest.
var latestURL = "https://api.github.com/repos/" + Repo + "/releases/latest"

// ErrNotModified means the ETag matched: the cached answer is still valid.
var ErrNotModified = errors.New("update: not modified")

// Asset is one downloadable file of a release.
type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

// Release is the subset of the GitHub payload the apps care about.
type Release struct {
	TagName     string    `json:"tag_name"`
	HTMLURL     string    `json:"html_url"`
	Body        string    `json:"body"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []Asset   `json:"assets"`
}

// Client fetches the latest release. Zero value works.
type Client struct {
	HTTP *http.Client
	// ETag of the last successful response; reuse across calls.
	ETag string
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// Latest returns the latest published release. On 304 it returns
// ErrNotModified and the caller keeps its cached release.
func (c *Client) Latest(ctx context.Context) (Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, latestURL, nil)
	if err != nil {
		return Release{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if c.ETag != "" {
		req.Header.Set("If-None-Match", c.ETag)
	}

	// The DNS/TLS path to api.github.com is reset intermittently on an
	// RST-prone link (live 2026-10-30: wsarecv "forcibly closed" from the
	// GUI on a healthy tunnel) and the manual button used to fail on the
	// first reset. Browsers retry the same request; so do we.
	var resp *http.Response
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 250 * time.Millisecond)
		}
		if resp, err = c.http().Do(req); err == nil {
			break
		}
	}
	if err != nil {
		return Release{}, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		return Release{}, ErrNotModified
	case http.StatusOK:
	default:
		return Release{}, fmt.Errorf("update: github %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Release{}, err
	}
	var rel Release
	if err := json.Unmarshal(body, &rel); err != nil {
		return Release{}, fmt.Errorf("update: bad json: %w", err)
	}
	if _, _, _, ok := version.Parse(rel.TagName); !ok {
		return Release{}, fmt.Errorf("update: bad tag %q", rel.TagName)
	}
	c.ETag = resp.Header.Get("ETag")
	return rel, nil
}

// Available reports whether rel is strictly newer than current.
func (rel Release) Available(current string) bool { return version.Newer(rel.TagName, current) }

// Asset picks the first asset whose name satisfies match.
func (rel Release) Asset(match func(name string) bool) (Asset, bool) {
	for _, a := range rel.Assets {
		if match(a.Name) {
			return a, true
		}
	}
	return Asset{}, false
}

// WindowsAsset matches the portable Windows archive.
func WindowsAsset(name string) bool {
	return strings.HasPrefix(name, "Rupas-win64-") && strings.HasSuffix(name, ".zip")
}

// AndroidAsset matches the arm64 APK.
func AndroidAsset(name string) bool {
	return strings.HasPrefix(name, "Rupas-android-") && strings.HasSuffix(name, ".apk")
}
