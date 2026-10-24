package config

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// PortRange is an inclusive port range; Lo <= Hi.
type PortRange struct {
	Lo, Hi uint16
}

// ParsePortSpec parses a port specification: a single port ("443"), a
// range ("50000-65535") or a comma-separated list of those ("53,123").
// The result is sorted by Lo; overlapping ranges are rejected.
func ParsePortSpec(spec string) ([]PortRange, error) {
	parts := strings.Split(spec, ",")
	out := make([]PortRange, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		loS, hiS, isRange := strings.Cut(p, "-")
		lo, err := parsePort(loS)
		if err != nil {
			return nil, fmt.Errorf("bad port spec %q: %v", p, err)
		}
		hi := lo
		if isRange {
			hi, err = parsePort(hiS)
			if err != nil {
				return nil, fmt.Errorf("bad port spec %q: %v", p, err)
			}
			if hi < lo {
				return nil, fmt.Errorf("bad port spec %q: hi < lo", p)
			}
		}
		out = append(out, PortRange{Lo: lo, Hi: hi})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Lo < out[j].Lo })
	for i := 1; i < len(out); i++ {
		if out[i].Lo <= out[i-1].Hi {
			return nil, fmt.Errorf("bad port spec %q: overlapping ranges", spec)
		}
	}
	return out, nil
}

func parsePort(s string) (uint16, error) {
	s = strings.TrimSpace(s)
	v, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("port %q: %v", s, err)
	}
	if v == 0 {
		return 0, fmt.Errorf("port %q: zero is not allowed", s)
	}
	return uint16(v), nil
}
