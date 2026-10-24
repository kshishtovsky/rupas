package inspector

import (
	"testing"
)

// BenchmarkFeedSingleSegment measures the fast path: a complete real
// ClientHello (~320 bytes, TLS 1.3) parsed in place in one Feed call.
func BenchmarkFeedSingleSegment(b *testing.B) {
	ch := captureClientHello(b, tls13Config())
	s := NewStream()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Reset()
		if _, err := s.Feed(ch); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkFeedFourSegments measures reassembly: the same ClientHello cut
// into four segments (post-quantum fragmentation shape).
func BenchmarkFeedFourSegments(b *testing.B) {
	ch := captureClientHello(b, tls13Config())
	parts := splitEvenly(ch, 4)
	s := NewStream()
	// Warm up: one-time allocation of the reassembly buffer.
	for _, p := range parts {
		if _, err := s.Feed(p); err != nil && err != ErrNeedMore {
			b.Fatal(err)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Reset()
		for _, p := range parts {
			if _, err := s.Feed(p); err != nil && err != ErrNeedMore {
				b.Fatal(err)
			}
		}
	}
}

// BenchmarkFeed8KBFourSegments measures worst-case reassembly: the largest
// accepted ClientHello (8192 bytes) in four 2 KB segments.
func BenchmarkFeed8KBFourSegments(b *testing.B) {
	sni := extBytes(extServerName, sniListData("big.example"))
	filler := extBytes(0x9999, make([]byte, 8114)) // fixed body(45)+20+4+8114 = 8183; +9 = 8192
	ch := synthCH{exts: concat(sni, filler)}.build()
	parts := splitEvenly(ch, 4)
	s := NewStream()
	for _, p := range parts {
		if _, err := s.Feed(p); err != nil && err != ErrNeedMore {
			b.Fatal(err)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Reset()
		for _, p := range parts {
			if _, err := s.Feed(p); err != nil && err != ErrNeedMore {
				b.Fatal(err)
			}
		}
	}
}
