// Command adlistgen builds the built-in adblock lists shipped in the AAR.
//
//	cd E:\rupas && go run ./cmd/adlistgen
//
// Sources are fetched through a mirror chain (raw.githubusercontent and
// cdn.jsdelivr are reset by RU ISPs — gcore.jsdelivr answers). Output is one
// bare domain per line; the loader blocks the domain and every subdomain.
//
// Lists:
//
//	ads.list      — ad networks (EasyList adservers + AdGuard adservers + AdGuard DNS filter)
//	trackers.list — tracking/telemetry hosts (AdGuard tracking servers)
//
// Only plain `||domain^` / `0.0.0.0 domain` rules survive: regex, cosmetic and
// path rules are not expressible by a hostname matcher, and `$`-modifiers are
// dropped for the safe set (third-party, popup, document, all, important).
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type src struct {
	name string
	urls []string
	// local files (already on disk) are merged after the mirrors
	local []string
}

var mirrors = []string{
	"https://gcore.jsdelivr.net/gh/%s",
	"https://jsdelivr.b-cdn.net/gh/%s",
	"https://raw.githubusercontent.com/%s",
}

func expand(paths ...string) []string {
	out := make([]string, 0, len(paths)*len(mirrors))
	for _, p := range paths {
		for _, m := range mirrors {
			out = append(out, fmt.Sprintf(m, p))
		}
	}
	return out
}

func main() {
	outDir := flag.String("out", filepath.Join("internal", "transport", "android", "lists"), "output dir")
	flag.Parse()

	ads := src{name: "ads", urls: expand(
		"easylist/easylist@master/easylist/easylist_adservers.txt",
		"AdguardTeam/AdguardFilters@master/BaseFilter/sections/adservers.txt",
		"AdguardTeam/HostlistsRegistry@main/assets/filter_1.txt",
	)}
	// локальные списки: курируемые вручную (iMe, RU-биржи mail.ru/VK/Yandex)
	ads.local = []string{
		filepath.Join("configs", "adblock-ime.list"),
		filepath.Join("configs", "adblock-ru.list"),
	}
	trackers := src{name: "trackers", urls: expand(
		"AdguardTeam/AdguardFilters@master/SpywareFilter/sections/tracking_servers.txt",
	)}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fatal(err)
	}
	for _, s := range []src{ads, trackers} {
		set, err := fetch(s)
		if err != nil {
			fatal(fmt.Errorf("%s: %w", s.name, err))
		}
		domains := make([]string, 0, len(set))
		for d := range set {
			domains = append(domains, d)
		}
		sort.Strings(domains)
		path := filepath.Join(*outDir, s.name+".list")
		if err := writeList(path, s.name, domains); err != nil {
			fatal(err)
		}
		fmt.Printf("%-9s %6d domains  %6.1f KB  %s\n", s.name, len(domains),
			float64(fileSize(path))/1024, path)
	}
}

// fetch walks the mirror chain and merges every source that answers. A single
// unreachable mirror is not fatal: the chain exists because ISPs reset some.
func fetch(s src) (map[string]struct{}, error) {
	set := make(map[string]struct{}, 1<<16)
	var errs []string
	fetched := 0
	for _, u := range s.urls {
		rules, err := get(u)
		if err != nil {
			errs = append(errs, u+": "+err.Error())
			continue
		}
		fetched++
		for _, r := range rules {
			set[r] = struct{}{}
		}
	}
	for _, p := range s.local {
		rules, err := getLocal(p)
		if err != nil {
			errs = append(errs, p+": "+err.Error())
			continue
		}
		fetched++
		for _, r := range rules {
			set[r] = struct{}{}
		}
	}
	if fetched == 0 {
		return nil, fmt.Errorf("no mirror reachable (%s)", strings.Join(errs, "; "))
	}
	return set, nil
}

func get(u string) ([]string, error) {
	c := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "rupas-adlistgen/1")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	var out []string
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		if d := parseRule(sc.Text(), false); d != "" {
			out = append(out, d)
		}
	}
	return out, sc.Err()
}

// getLocal parses a list file that is already on disk (curated seeds).
func getLocal(p string) ([]string, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		if d := parseRule(sc.Text(), true); d != "" {
			out = append(out, d)
		}
	}
	return out, sc.Err()
}

// safeMods may be dropped without changing "block this host" semantics.
var safeMods = map[string]bool{
	"third-party": true, "~third-party": true, "first-party": true,
	"popup": true, "document": true, "all": true, "important": true,
	"3p": true, "1p": true, "genericblock": true, "elemhide": true,
}

// parseRule returns a bare hostname for a blocking rule, or "".
func parseRule(line string, allowBare bool) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") ||
		strings.HasPrefix(line, "#") || strings.HasPrefix(line, "@@") {
		return ""
	}
	// hosts format: "0.0.0.0 ads.example.com"
	if f := strings.Fields(line); len(f) == 2 && (f[0] == "0.0.0.0" || f[0] == "127.0.0.1") {
		return validHost(f[1])
	}
	if !strings.HasPrefix(line, "||") {
		if allowBare && !strings.ContainsAny(line, " 	") {
			return validHost(line) // curated seed: bare hostname per line
		}
		return ""
	}
	d := strings.TrimPrefix(line, "||")
	if i := strings.IndexByte(d, '$'); i >= 0 {
		mods := d[i+1:]
		d = d[:i]
		for _, m := range strings.Split(mods, ",") {
			m = strings.TrimSpace(m)
			if !safeMods[m] {
				return "" // domain=/denyallow=/method= need a real engine
			}
		}
	}
	return validHost(strings.TrimSuffix(d, "^"))
}

func validHost(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	if d == "" || len(d) > 253 || strings.ContainsAny(d, "/|*^$@, \t") {
		return ""
	}
	if !strings.Contains(d, ".") || strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") {
		return ""
	}
	for _, c := range d {
		if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '.' && c != '-' && c != '_' {
			return ""
		}
	}
	return d
}

func writeList(path, name string, domains []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriterSize(f, 1<<16)
	fmt.Fprintf(w, "# rupas adblock %s list — generated by cmd/adlistgen, do not edit\n", name)
	fmt.Fprintf(w, "# %s · %d domains · one hostname per line, subdomains included\n\n", time.Now().UTC().Format("2006-01-02"), len(domains))
	for _, d := range domains {
		w.WriteString(d)
		w.WriteByte('\n')
	}
	return w.Flush()
}

func fileSize(p string) int64 {
	st, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return st.Size()
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "adlistgen:", err)
	os.Exit(1)
}
