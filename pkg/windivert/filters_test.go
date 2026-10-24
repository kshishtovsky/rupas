//go:build windows

package windivert

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// dllAvailable tries to load WinDivert.dll, adding the repository's
// build/windivert directory to PATH if needed. Tests that need the (pure
// userspace) helper functions skip when it cannot be loaded.
func dllAvailable(t *testing.T) bool {
	t.Helper()
	if modWindivert.Load() == nil {
		return true
	}
	wd, err := os.Getwd()
	if err != nil {
		return false
	}
	for dir, up := wd, 0; up < 4; up, dir = up+1, filepath.Dir(dir) {
		cand := filepath.Join(dir, "build", "windivert", "WinDivert.dll")
		if _, err := os.Stat(cand); err == nil {
			os.Setenv("PATH", filepath.Join(dir, "build", "windivert")+";"+os.Getenv("PATH"))
			break
		}
	}
	return modWindivert.Load() == nil
}

func TestFilterBuilderGolden(t *testing.T) {
	golden := []struct {
		name string
		b    *FilterBuilder
		want string
	}{
		{
			"design 3.1 NETWORK desync filter",
			NewFilter().Outbound().TCP().DstPorts(443),
			"outbound and tcp and tcp.DstPort == 443",
		},
		{
			"multi-port",
			NewFilter().Outbound().TCP().DstPorts(443, 8443),
			"outbound and tcp and (tcp.DstPort == 443 or tcp.DstPort == 8443)",
		},
		{
			"cidr range (telegram dc)",
			NewFilter().Outbound().TCP().DstPorts(443).DstCIDRs("149.154.160.0/20"),
			"outbound and tcp and tcp.DstPort == 443 and (ip.DstAddr >= 149.154.160.0 and ip.DstAddr <= 149.154.175.255)",
		},
		{
			"host cidr becomes equality",
			NewFilter().Inbound().UDP().SrcCIDRs("95.161.76.100/32"),
			"inbound and udp and ip.SrcAddr == 95.161.76.100",
		},
		{
			"multi cidr or-chain",
			NewFilter().Outbound().TCP().DstCIDRs("149.154.160.0/20", "91.108.0.0/16", "95.161.76.100/32"),
			"outbound and tcp and ((ip.DstAddr >= 149.154.160.0 and ip.DstAddr <= 149.154.175.255) or (ip.DstAddr >= 91.108.0.0 and ip.DstAddr <= 91.108.255.255) or ip.DstAddr == 95.161.76.100)",
		},
		{
			"src+dst mix",
			NewFilter().TCP().SrcPorts(123).DstPorts(456),
			"tcp and tcp.DstPort == 456 and tcp.SrcPort == 123",
		},
		{
			"empty builder",
			NewFilter(),
			"true",
		},
	}
	for _, g := range golden {
		got, err := g.b.Build()
		if err != nil {
			t.Errorf("%s: Build: %v", g.name, err)
			continue
		}
		if got != g.want {
			t.Errorf("%s:\n got %q\nwant %q", g.name, got, g.want)
		}
	}
	// Every golden filter must compile with the real DLL when available.
	if dllAvailable(t) {
		for _, g := range golden {
			if err := ValidateFilter(g.want, LayerNetwork); err != nil {
				t.Errorf("%s: ValidateFilter(%q): %v", g.name, g.want, err)
			}
		}
	} else {
		t.Log("WinDivert.dll not loadable; skipping ValidateFilter cross-check")
	}
}

func TestFilterBuilderErrors(t *testing.T) {
	if _, err := NewFilter().TCP().DstCIDRs("not-a-cidr").Build(); err == nil {
		t.Error("invalid CIDR should fail Build")
	}
	_, err := NewFilter().TCP().DstCIDRs("2a03:2880::/29").Build()
	if !errors.Is(err, ErrIPv6FiltersUnsupported) {
		t.Errorf("IPv6 CIDR: err = %v, want ErrIPv6FiltersUnsupported", err)
	}
	if _, err := NewFilter().Outbound().DstPorts(443).Build(); err == nil {
		t.Error("ports without TCP()/UDP() should fail")
	}
	// ~200 CIDR clauses exceed the DLL limit (~8K chars).
	cidrs := make([]string, 200)
	for i := range cidrs {
		cidrs[i] = fmt.Sprintf("10.%d.0.0/16", i)
	}
	if got, err := NewFilter().TCP().DstCIDRs(cidrs...).Build(); err == nil {
		t.Errorf("200-CIDR filter (len %d) should be rejected as too long", len(got))
	} else if !errors.Is(err, ErrFilterTooLong) {
		t.Errorf("err = %v, want ErrFilterTooLong", err)
	}
}

func TestValidateFilter(t *testing.T) {
	if !dllAvailable(t) {
		t.Skip("WinDivert.dll not loadable")
	}
	if err := ValidateFilter("outbound and tcp and tcp.DstPort == 443", LayerNetwork); err != nil {
		t.Errorf("valid filter rejected: %v", err)
	}
	err := ValidateFilter("garbage !!!", LayerNetwork)
	if err == nil {
		t.Fatal("invalid filter accepted")
	}
	if !strings.Contains(err.Error(), "invalid filter") {
		t.Errorf("error message = %q, want it to mention invalid filter", err)
	}
	// Syntax the shipped DLL rejects (verified via export/compiler probe).
	for _, f := range []string{
		"ip.DstAddr == 149.154.160.0/20",   // CIDR mask literal
		"ip.DstAddr in {149.154.160.0/20}", // set syntax
		"ip6.DstAddr == ::1",               // IPv6 literal (stripped build)
	} {
		if err := ValidateFilter(f, LayerNetwork); err == nil {
			t.Errorf("filter %q unexpectedly accepted by this DLL", f)
		}
	}
}
