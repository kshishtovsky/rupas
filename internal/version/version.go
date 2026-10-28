// Package version carries the build stamp and the semver logic shared by the
// update checker (Android/Windows) and CI tooling.
//
// The stamp is injected by the linker from the repo-root VERSION file:
//
//	go build -ldflags "-X github.com/kshishtovsky/rupas/internal/version.Version=0.6.0"
package version

import "strconv"

// Version is "dev" for unstamped builds (plain `go build`), semver otherwise.
var Version = "dev"

// Parse accepts "1.2.3" and "v1.2.3". ok is false for anything else.
func Parse(s string) (major, minor, patch int, ok bool) {
	if len(s) > 0 && s[0] == 'v' {
		s = s[1:]
	}
	parts := [3]int{}
	field, n := 0, 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			if i == n || field > 2 { // empty field or too many dots
				return 0, 0, 0, false
			}
			v, err := strconv.Atoi(s[n:i])
			if err != nil || v < 0 {
				return 0, 0, 0, false
			}
			parts[field] = v
			field++
			n = i + 1
		}
	}
	if field != 3 {
		return 0, 0, 0, false
	}
	return parts[0], parts[1], parts[2], true
}

// Compare returns -1 if a < b, 0 if equal, 1 if a > b. Unparsable versions
// compare as smaller than any valid one, so a broken stamp never hides an update.
func Compare(a, b string) int {
	am, ai, ap, aok := Parse(a)
	bm, bi, bp, bok := Parse(b)
	switch {
	case !aok && !bok:
		return 0
	case !aok:
		return -1
	case !bok:
		return 1
	}
	if am != bm {
		return sign(am - bm)
	}
	if ai != bi {
		return sign(ai - bi)
	}
	return sign(ap - bp)
}

// Newer reports whether latest is a strictly greater version than current.
func Newer(latest, current string) bool { return Compare(latest, current) > 0 }

func sign(v int) int {
	switch {
	case v < 0:
		return -1
	case v > 0:
		return 1
	}
	return 0
}
