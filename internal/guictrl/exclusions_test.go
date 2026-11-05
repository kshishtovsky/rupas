package guictrl

import (
	"testing"

	"github.com/kshishtovsky/rupas/internal/config"
)

// The carrier's own dial must never be captured into the tunnel it is trying to
// bring up: excluded for every kind, not just TMN. Live 2026-11-06: a vless-tls
// channel to 3x-ui got verdict=TUNNEL on its own CH, was reset, and the tunnel
// stayed down until HOLD — everything escalated to direct (real IP leaks).
func TestExcludeCarrierEndpoints(t *testing.T) {
	ex := config.Exclusions{Domains: []string{"keep.example"}, CIDRs: []string{"10.0.0.0/8"}}
	ip := config.Endpoint{Kind: "vless_tcp", Host: "82.148.252.248", Port: 443, SNI: "atsm.digital"}
	byName := config.Endpoint{Kind: "hysteria2", Host: "vpn.example", Port: 53552, SNI: "vpn.example"}
	tmn := config.Endpoint{Kind: "tmn", Host: "203.0.113.10", Port: 18443, SNI: "cover.example"}

	got := excludeCarrierEndpoints(ex, &ip, &byName, nil, &tmn)

	wantCIDR := map[string]bool{"10.0.0.0/8": true, "82.148.252.248/32": true, "203.0.113.10/32": true}
	for _, c := range got.CIDRs {
		delete(wantCIDR, c)
	}
	if len(wantCIDR) != 0 {
		t.Fatalf("missing cidrs %v in %v", wantCIDR, got.CIDRs)
	}
	wantDomain := map[string]bool{"keep.example": true, "atsm.digital": true, "vpn.example": true, "cover.example": true}
	for _, d := range got.Domains {
		delete(wantDomain, d)
	}
	if len(wantDomain) != 0 {
		t.Fatalf("missing domains %v in %v", wantDomain, got.Domains)
	}
	// Idempotent: a second pass must not duplicate entries.
	again := excludeCarrierEndpoints(got, &ip, &byName, &tmn)
	if len(again.CIDRs) != len(got.CIDRs) || len(again.Domains) != len(got.Domains) {
		t.Fatalf("not idempotent: %v/%v -> %v/%v", got.CIDRs, got.Domains, again.CIDRs, again.Domains)
	}
}
