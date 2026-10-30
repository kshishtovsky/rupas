// Package geoip downloads, caches and parses country CIDR lists for the
// `geoip: <cc>` routing rules (see config.Rule.GeoIP). The daemon needs no
// manual asset management: on every rules.Compile the list is checked for
// freshness and re-downloaded from the mirror chain when older than
// refresh_days. A failed refresh never destroys a working cache; a missing
// cache with all mirrors down is a hard startup error (fail loudly rather
// than silently route without the geoip table).
//
// The wire format is one CIDR per line ("1.2.3.0/24"); blank lines and
// '#' comments are ignored. This matches ipdeny.com country zones and the
// ipverse per-country aggregated lists natively, so no format conversion
// is needed anywhere in the pipeline.
package geoip

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Params controls where the cached lists live and how stale they may get.
type Params struct {
	// Dir is the cache directory (typically "build" next to the binary).
	Dir string
	// RefreshDays is the maximum age of a cached list before it is
	// re-downloaded. <= 0 means the default.
	RefreshDays int
	// Mirrors are download URL templates; "{cc}" is replaced with the
	// lower-case country code. Tried in order until one succeeds.
	Mirrors []string
}

const (
	// DefaultRefreshDays is the refresh period when unset: RU allocations
	// change on the scale of months, so a month is plenty.
	DefaultRefreshDays = 30
	// fetchTimeout bounds each mirror download.
	fetchTimeout = 30 * time.Second
)

// DefaultMirrors returns the stock mirror chain. Both serve plain CIDR
// text for "{cc}":
//   - ipdeny.com  — country zones derived from RIR delegations;
//   - ipverse     — GitHub-hosted per-country aggregated zones (raw).
func DefaultMirrors() []string {
	return []string{
		"https://www.ipdeny.com/ipblocks/data/countries/{cc}.zone",
		"https://raw.githubusercontent.com/ipverse/{cc}/ip/aggregated.zone",
	}
}

// WithDefaults returns p with unset fields filled in.
func (p Params) WithDefaults() Params {
	if p.Dir == "" {
		p.Dir = "build"
	}
	if p.RefreshDays <= 0 {
		p.RefreshDays = DefaultRefreshDays
	}
	if len(p.Mirrors) == 0 {
		p.Mirrors = DefaultMirrors()
	}
	return p
}

// List returns the parsed prefix table for country code cc (e.g. "ru"),
// refreshing the cache when missing or older than RefreshDays.
func List(p Params, cc string) ([]netip.Prefix, error) {
	p = p.WithDefaults()
	cc = strings.ToLower(strings.TrimSpace(cc))
	if cc == "" || !isCountryCode(cc) {
		return nil, fmt.Errorf("geoip: bad country code %q", cc)
	}
	path := filepath.Join(p.Dir, "geoip-"+cc+".txt")

	maxAge := time.Duration(p.RefreshDays) * 24 * time.Hour
	if fi, err := os.Stat(path); err == nil && time.Since(fi.ModTime()) <= maxAge {
		return parseFile(path)
	}
	// Stale or missing: refresh. Any mirror success wins; a failure with
	// a stale-but-parseable cache still degrades to the old list (better
	// last month's table than no table at all).
	if err := download(p, cc, path); err != nil {
		if _, statErr := os.Stat(path); statErr == nil {
			prefixes, parseErr := parseFile(path)
			if parseErr == nil {
				return prefixes, nil
			}
		}
		return nil, err
	}
	return parseFile(path)
}

// Refresh re-downloads cc regardless of how fresh the cache is (the GUI's
// «Обновить GeoIP» button). A failed download keeps the old cache untouched
// and returns the mirror errors.
func Refresh(p Params, cc string) ([]netip.Prefix, error) {
	p = p.WithDefaults()
	cc = strings.ToLower(strings.TrimSpace(cc))
	if cc == "" || !isCountryCode(cc) {
		return nil, fmt.Errorf("geoip: bad country code %q", cc)
	}
	path := filepath.Join(p.Dir, "geoip-"+cc+".txt")
	if err := download(p, cc, path); err != nil {
		return nil, err
	}
	return parseFile(path)
}

// download fetches cc from the mirror chain and atomically installs the
// body at path (temp file + rename, so a crash never leaves a truncated
// cache in place of the old one).
func download(p Params, cc, path string) error {
	client := &http.Client{Timeout: fetchTimeout}
	var errs []error
	for _, tpl := range p.Mirrors {
		url := strings.ReplaceAll(tpl, "{cc}", cc)
		// One reset must not lose the whole country: mirrors are reached
		// through whatever policy the user routed them to, and an RST-prone
		// link drops the first attempt often (live 2026-10-30: the GUI's
		// «Обновить GeoIP» failed on ipdeny 51.15.12.186, retry was clean).
		var resp *http.Response
		var err error
		for attempt := 0; attempt < 2; attempt++ {
			if attempt > 0 {
				time.Sleep(250 * time.Millisecond)
			}
			if resp, err = client.Get(url); err == nil { //nolint:gosec,noctx // url from trusted local config
				break
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", url, err))
			continue
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			errs = append(errs, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode))
			continue
		}
		if readErr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", url, readErr))
			continue
		}
		// Validate BEFORE installing: a mirror serving an error page must
		// not poison the cache.
		prefixes, err := Parse(strings.NewReader(string(body)))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", url, err))
			continue
		}
		if len(prefixes) == 0 {
			errs = append(errs, fmt.Errorf("%s: empty list", url))
			continue
		}
		if err := os.MkdirAll(p.Dir, 0o755); err != nil {
			return fmt.Errorf("geoip: mkdir %s: %w", p.Dir, err)
		}
		tmp, err := os.CreateTemp(p.Dir, "geoip-*.tmp")
		if err != nil {
			return fmt.Errorf("geoip: temp file: %w", err)
		}
		if _, err := tmp.Write(body); err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			return fmt.Errorf("geoip: write: %w", err)
		}
		if err := tmp.Close(); err != nil {
			os.Remove(tmp.Name())
			return fmt.Errorf("geoip: close: %w", err)
		}
		if err := os.Rename(tmp.Name(), path); err != nil {
			os.Remove(tmp.Name())
			return fmt.Errorf("geoip: rename: %w", err)
		}
		return nil
	}
	return errors.Join(errs...)
}

func parseFile(path string) ([]netip.Prefix, error) {
	f, err := os.Open(path) //nolint:gosec // path is constructed from validated parts
	if err != nil {
		return nil, fmt.Errorf("geoip: open %s: %w", path, err)
	}
	defer f.Close()
	return Parse(f)
}

// Parse decodes the one-CIDR-per-line wire format. It is strict: any
// malformed line is an error (a silently dropped line would silently
// misroute traffic).
func Parse(r io.Reader) ([]netip.Prefix, error) {
	var out []netip.Prefix
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 64*1024)
	for lineNo := 1; sc.Scan(); lineNo++ {
		line := strings.TrimSpace(sc.Text())
		if cut, _, had := strings.Cut(line, "#"); had {
			line = strings.TrimSpace(cut)
		}
		if line == "" {
			continue
		}
		pfx, err := netip.ParsePrefix(line)
		if err != nil {
			return nil, fmt.Errorf("geoip: line %d: %q: %v", lineNo, line, err)
		}
		out = append(out, pfx.Masked())
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("geoip: read: %w", err)
	}
	return out, nil
}

// isCountryCode accepts two-letter ISO-3166 alpha-2 codes (what the
// mirrors serve); anything else is a config typo.
func isCountryCode(s string) bool {
	if len(s) != 2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}

// ValidCountryCode reports whether s is a usable geoip country code.
func ValidCountryCode(s string) bool { return isCountryCode(s) }
