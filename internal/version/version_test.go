package version

import "testing"

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.6.0", "0.6.0", 0},
		{"v0.6.0", "0.6.0", 0},
		{"0.6.1", "0.6.0", 1},
		{"0.6.0", "0.6.1", -1},
		{"0.10.0", "0.9.9", 1},
		{"1.0.0", "0.99.99", 1},
		{"0.6", "0.6.0", -1},  // malformed sorts first
		{"dev", "0.0.1", -1},  // unstamped build is always outdated
		{"0.6.0.1", "0.6.0", -1},
		{"", "0.6.0", -1},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestParse(t *testing.T) {
	maj, min, pat, ok := Parse("v12.34.567")
	if !ok || maj != 12 || min != 34 || pat != 567 {
		t.Fatalf("Parse(v12.34.567) = %d.%d.%d,%v", maj, min, pat, ok)
	}
	for _, bad := range []string{"", "1.2", "1.2.3.4", "1..3", "a.b.c", "1.2.-3"} {
		if _, _, _, ok := Parse(bad); ok {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
}

func TestNewer(t *testing.T) {
	if !Newer("0.7.0", "0.6.0") {
		t.Fatal("0.7.0 should be newer than 0.6.0")
	}
	if Newer("0.6.0", "0.6.0") {
		t.Fatal("equal versions must not report an update")
	}
}
