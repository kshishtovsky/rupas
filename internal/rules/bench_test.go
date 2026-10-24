package rules

import (
	"testing"

	"github.com/rupas/rupas/internal/config"
)

// benchmarkTable is the default RU-ISP profile plus a v6 prefix so all
// code paths are exercised.
func benchmarkTable(b *testing.B) *Table {
	cfg := config.Default()
	cfg.Rules = append(cfg.Rules[:0:0], cfg.Rules...)
	cfg.Rules = append(cfg.Rules, config.Rule{CIDR: "2a03:2880::/29", Action: config.ActionTunnel})
	tbl, err := Compile(cfg)
	if err != nil {
		b.Fatalf("Compile: %v", err)
	}
	return tbl
}

func BenchmarkMatchIPv4CIDRHit(b *testing.B) {
	tbl := benchmarkTable(b)
	ip := v4(149, 154, 167, 51) // inside 149.154.160.0/20
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tbl.Match(ip, "", 443)
	}
}

func BenchmarkMatchIPv4CIDRMiss(b *testing.B) {
	tbl := benchmarkTable(b)
	ip := v4(77, 88, 8, 8) // no CIDR match -> falls through to default
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tbl.Match(ip, "", 53)
	}
}

func BenchmarkMatchIPv6CIDRHit(b *testing.B) {
	tbl := benchmarkTable(b)
	ip := v6("2a03:2880:f123::1")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tbl.Match(ip, "", 443)
	}
}

func BenchmarkMatchSNIExact(b *testing.B) {
	tbl := benchmarkTable(b)
	ip := v4(142, 250, 185, 78)
	sni := "www.youtube.com"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tbl.Match(ip, sni, 443)
	}
}

func BenchmarkMatchSNIWildcard(b *testing.B) {
	tbl := benchmarkTable(b)
	ip := v4(142, 250, 185, 78)
	sni := wildcardBuf[13:44] // r4.sn-nx57nss9.googlevideo.com
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tbl.Match(ip, sni, 443)
	}
}

func BenchmarkMatchPortTable(b *testing.B) {
	tbl := benchmarkTable(b)
	ip := v4(66, 22, 224, 1)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tbl.Match(ip, "", 61234)
	}
}
