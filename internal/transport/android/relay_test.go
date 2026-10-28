package android

// buildTLS ALPN tests: hysteria2 must hand sing-quic an EMPTY ALPN list so
// its http/3 substitution fires (the hysteria2 inbound refuses h2), while
// plain VLESS/Trojan TLS keeps the desktop's h2+http/1.1 profile.

import "testing"

func TestBuildTLSHysteria2ALPN(t *testing.T) {
	hy := buildTLS(Endpoint{Kind: KindHysteria2, Security: secTLS, Host: "hy.example.com"})
	if hy == nil {
		t.Fatal("hysteria2 TLS options nil")
	}
	if len(hy.ALPN) != 0 {
		t.Fatalf("hysteria2 default ALPN = %v, want empty (sing-quic then picks h3)", hy.ALPN)
	}
	explicit := buildTLS(Endpoint{Kind: KindHysteria2, Security: secTLS, Host: "hy.example.com",
		ALPN: []string{"h3"}})
	if len(explicit.ALPN) != 1 || explicit.ALPN[0] != "h3" {
		t.Fatalf("hysteria2 explicit ALPN = %v, want [h3]", explicit.ALPN)
	}
	// Guard the other branch: vless TLS still defaults to h2 + http/1.1.
	vless := buildTLS(Endpoint{Kind: KindVLESS, Security: secTLS, Host: "v.example.com"})
	if len(vless.ALPN) != 2 || vless.ALPN[0] != "h2" || vless.ALPN[1] != "http/1.1" {
		t.Fatalf("vless default ALPN = %v, want [h2 http/1.1]", vless.ALPN)
	}
}
