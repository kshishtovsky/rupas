package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kshishtovsky/rupas/internal/config"
)

// TestCompileGeoIP: a `geoip: <cc>` rule expands the cached country table
// into CIDR entries; first-wins keeps an earlier rule on a shared prefix.
func TestCompileGeoIP(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "geoip-xx.txt")
	list := "203.0.113.0/24\n" + // broad country prefix
		"198.51.100.7/32\n" // narrow prefix inside it
	if err := os.WriteFile(cache, []byte(list), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Profile: "test",
		Rules: []config.Rule{
			{CIDR: "203.0.113.10/32", Action: config.ActionTunnel}, // earlier rule wins on its prefix
			{GeoIP: "xx", Action: config.ActionDirect},
		},
		GeoIP: &config.GeoIP{Dir: dir},
	}
	tbl, err := Compile(cfg)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	cases := []struct {
		ip   string
		want config.Action
	}{
		{"203.0.113.1", config.ActionDirect},  // country table
		{"203.0.113.10", config.ActionTunnel}, // earlier rule wins (first-wins)
		{"203.0.113.11", config.ActionDirect}, // country table
		{"198.51.100.7", config.ActionDirect}, // narrow entry
		{"198.51.100.8", config.ActionDirect}, // outside the table → default (direct here)
	}
	for _, c := range cases {
		got := tbl.MatchProto(v4Mapped(c.ip), "", 443, config.ProtoTCP)
		if got != c.want {
			t.Errorf("%s: got %v, want %v", c.ip, got, c.want)
		}
	}
}

// v4Mapped encodes a dotted-quad IPv4 address as a v4-in-v6 [16]byte, the
// form the table API takes (see internal/capture pkt handling).
func v4Mapped(dotted string) [16]byte {
	var b [4]byte
	for i, p := range strings.Split(dotted, ".") {
		n := 0
		for _, d := range p {
			n = n*10 + int(d-'0')
		}
		b[i] = byte(n)
	}
	var out [16]byte
	out[10], out[11] = 0xff, 0xff
	copy(out[12:], b[:])
	return out
}

func TestCompileGeoIPMissingCache(t *testing.T) {
	cfg := &config.Config{
		Profile: "test",
		Rules:   []config.Rule{{GeoIP: "zz", Action: config.ActionDirect}},
		GeoIP:   &config.GeoIP{Dir: filepath.Join(t.TempDir(), "nope"), Mirrors: []string{"http://127.0.0.1:1/{cc}"}},
	}
	if _, err := Compile(cfg); err == nil {
		t.Fatal("missing cache + dead mirrors must fail compilation loudly")
	}
}
