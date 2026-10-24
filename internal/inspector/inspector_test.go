package inspector

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"testing"
	"time"
	"unsafe"
)

// ---------------------------------------------------------------------------
// Helpers: real ClientHello capture and synthetic ClientHello construction.
// ---------------------------------------------------------------------------

func tls13Config() *tls.Config {
	return &tls.Config{
		ServerName: "www.youtube.com",
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}
}

func tls12Config() *tls.Config {
	return &tls.Config{
		ServerName: "www.youtube.com",
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
	}
}

// captureClientHello drives a real crypto/tls client over an in-memory
// pipe and returns the exact bytes of its first flight: one TLS record
// containing the ClientHello. No network is involved.
func captureClientHello(t testing.TB, cfg *tls.Config) []byte {
	t.Helper()
	client, wire := net.Pipe()
	defer client.Close()
	defer wire.Close()

	out := make(chan []byte, 1)
	go func() {
		defer close(out)
		hdr := make([]byte, recordHeaderLen)
		if _, err := io.ReadFull(wire, hdr); err != nil {
			return
		}
		n := int(hdr[3])<<8 | int(hdr[4])
		if n == 0 || n > 16384 {
			out <- hdr
			return
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(wire, payload); err != nil {
			out <- hdr
			return
		}
		full := make([]byte, 0, recordHeaderLen+n)
		full = append(full, hdr...)
		full = append(full, payload...)
		out <- full
	}()

	tlsConn := tls.Client(client, cfg)
	go func() { _ = tlsConn.Handshake() }() // fails after capture; ignored

	select {
	case b := <-out:
		if len(b) < recordHeaderLen {
			t.Fatal("failed to capture a ClientHello record")
		}
		return b
	case <-time.After(5 * time.Second):
		t.Fatal("timeout capturing ClientHello")
	}
	return nil
}

// synthCH builds a synthetic ClientHello record for edge-case tests.
// Force fields override the computed length fields to craft malformed
// messages; they are documented per test.
type synthCH struct {
	recordVersion uint16 // TLS record version, 0 = 0x0301
	legacyVersion uint16 // ClientHello legacy_version, 0 = 0x0303
	sessionID     []byte
	cipherSuites  []byte
	compression   []byte
	exts          []byte // pre-serialized extensions, without the 2-byte block length
	omitExtBlock  bool   // omit the extensions block entirely
	recLenForce   int    // 0 = computed, else force the record length field
	hsLenForce    int    // 0 = computed, else force the 24-bit handshake length
}

func (c synthCH) build() []byte {
	rv := c.recordVersion
	if rv == 0 {
		rv = 0x0301
	}
	lv := c.legacyVersion
	if lv == 0 {
		lv = 0x0303
	}
	cs := c.cipherSuites
	if cs == nil {
		cs = []byte{0x13, 0x01, 0xc0, 0x2c} // TLS 1.3 + ECDHE suite
	}
	comp := c.compression
	if comp == nil {
		comp = []byte{0x00}
	}

	body := make([]byte, 0, 256+len(c.exts))
	body = append(body, byte(lv>>8), byte(lv))
	body = append(body, make([]byte, 32)...) // zero random is fine
	body = append(body, byte(len(c.sessionID)))
	body = append(body, c.sessionID...)
	body = append(body, byte(len(cs)>>8), byte(len(cs)))
	body = append(body, cs...)
	body = append(body, byte(len(comp)))
	body = append(body, comp...)
	if !c.omitExtBlock {
		body = append(body, byte(len(c.exts)>>8), byte(len(c.exts)))
		body = append(body, c.exts...)
	}

	recLen := handshakeHeaderLen + len(body)
	hsLen := len(body)
	if c.recLenForce != 0 {
		recLen = c.recLenForce
	}
	if c.hsLenForce != 0 {
		hsLen = c.hsLenForce
	}

	out := make([]byte, 0, recordHeaderLen+handshakeHeaderLen+len(body))
	out = append(out, contentTypeHandshake, byte(rv>>8), byte(rv))
	out = append(out, byte(recLen>>8), byte(recLen))
	out = append(out, handshakeTypeClientHello, byte(hsLen>>16), byte(hsLen>>8), byte(hsLen))
	return append(out, body...)
}

// extBytes serializes one TLS extension.
func extBytes(typ uint16, data []byte) []byte {
	b := make([]byte, 0, 4+len(data))
	b = append(b, byte(typ>>8), byte(typ))
	b = append(b, byte(len(data)>>8), byte(len(data)))
	return append(b, data...)
}

// sniListData builds a server_name extension payload with one host entry.
func sniListData(name string) []byte {
	list := []byte{0x00, byte(len(name) >> 8), byte(len(name))}
	list = append(list, name...)
	d := make([]byte, 2, 2+len(list))
	d = append(d, list...)
	d[0], d[1] = byte(len(list)>>8), byte(len(list))
	return d
}

// alpnListData builds an ALPN extension payload.
func alpnListData(names ...string) []byte {
	var list []byte
	for _, n := range names {
		list = append(list, byte(len(n)))
		list = append(list, n...)
	}
	d := make([]byte, 2, 2+len(list))
	d = append(d, list...)
	d[0], d[1] = byte(len(list)>>8), byte(len(list))
	return d
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// splitAt cuts b into segments at the given byte offsets.
func splitAt(b []byte, at ...int) [][]byte {
	parts := make([][]byte, 0, len(at)+1)
	prev := 0
	for _, off := range at {
		parts = append(parts, b[prev:off])
		prev = off
	}
	return append(parts, b[prev:])
}

// splitEvenly cuts b into n similarly sized segments.
func splitEvenly(b []byte, n int) [][]byte {
	size := (len(b) + n - 1) / n
	var parts [][]byte
	for lo := 0; lo < len(b); lo += size {
		hi := lo + size
		if hi > len(b) {
			hi = len(b)
		}
		parts = append(parts, b[lo:hi])
	}
	return parts
}

// inSpan reports whether sub is a subslice of full by pointer identity:
// proves that no copy was made.
func inSpan(sub, full []byte) bool {
	if len(sub) == 0 || len(full) == 0 {
		return len(sub) == 0
	}
	lo := uintptr(unsafe.Pointer(&full[0]))
	hi := uintptr(unsafe.Pointer(&full[len(full)-1]))
	p := uintptr(unsafe.Pointer(&sub[0]))
	q := uintptr(unsafe.Pointer(&sub[len(sub)-1]))
	return p >= lo && p <= hi && q >= lo && q <= hi
}

func indexOf(hay, needle []byte) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		match := true
		for j := range needle {
			if hay[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// ---------------------------------------------------------------------------
// Real crypto/tls ClientHellos, whole and segmented.
// ---------------------------------------------------------------------------

func validateYouTubeResult(t *testing.T, res Result) {
	t.Helper()
	if !res.IsTLS || res.NeedMore {
		t.Fatalf("res = %+v, want completed TLS result", res)
	}
	if !res.SNIFound || string(res.SNI) != "www.youtube.com" {
		t.Errorf("SNI = %q (found=%v), want www.youtube.com", res.SNI, res.SNIFound)
	}
	if string(res.ALPN) != "h2" {
		t.Errorf("ALPN = %q, want h2", res.ALPN)
	}
	if res.ECH {
		t.Errorf("ECH = true, want false")
	}
}

func TestFeedRealClientHelloSegmented(t *testing.T) {
	cases := []struct {
		name string
		cfg  *tls.Config
	}{
		{"tls13", tls13Config()},
		{"tls12", tls12Config()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ch := captureClientHello(t, tc.cfg)
			for _, nseg := range []int{1, 2, 3, 4} {
				t.Run(fmt.Sprintf("%dsegments", nseg), func(t *testing.T) {
					parts := splitEvenly(ch, nseg)
					s := NewStream()
					for i, p := range parts {
						res, err := s.Feed(p)
						if i < len(parts)-1 {
							if !errors.Is(err, ErrNeedMore) {
								t.Fatalf("segment %d: err = %v, want ErrNeedMore", i, err)
							}
							if !res.NeedMore || !res.IsTLS {
								t.Fatalf("segment %d: res = %+v, want NeedMore&&IsTLS", i, res)
							}
							continue
						}
						if err != nil {
							t.Fatalf("last segment: err = %v", err)
						}
						validateYouTubeResult(t, res)
					}
				})
			}

			// Fast path: single-segment SNI/ALPN must alias the input.
			s := NewStream()
			res, err := s.Feed(ch)
			if err != nil {
				t.Fatalf("Feed: %v", err)
			}
			validateYouTubeResult(t, res)
			if !inSpan(res.SNI, ch) {
				t.Errorf("SNI is not a subslice of the input segment (copy made)")
			}
			if !inSpan(res.ALPN, ch) {
				t.Errorf("ALPN is not a subslice of the input segment (copy made)")
			}
		})
	}
}

// TestFeedEverySplitPoint feeds every possible two-segment split of a real
// ClientHello: any true prefix must yield ErrNeedMore, and the completed
// stream must always produce the right SNI aliasing the reassembly buffer.
func TestFeedEverySplitPoint(t *testing.T) {
	ch := captureClientHello(t, tls13Config())
	for i := 1; i < len(ch); i++ {
		s := NewStream()
		_, err := s.Feed(ch[:i])
		if !errors.Is(err, ErrNeedMore) {
			t.Fatalf("prefix len %d: err = %v, want ErrNeedMore", i, err)
		}
		res, err := s.Feed(ch[i:])
		if err != nil {
			t.Fatalf("split at %d: completion err = %v", i, err)
		}
		if !res.SNIFound || string(res.SNI) != "www.youtube.com" {
			t.Fatalf("split at %d: SNI = %q", i, res.SNI)
		}
		if !inSpan(res.SNI, s.acc) {
			t.Fatalf("split at %d: SNI does not alias the reassembly buffer", i)
		}
	}
}

// TestFeedPathologicalSplits cuts the ClientHello exactly at protocol
// boundaries and in the middle of the SNI name.
func TestFeedPathologicalSplits(t *testing.T) {
	ch := captureClientHello(t, tls13Config())
	sniAt := indexOf(ch, []byte("www.youtube.com"))
	if sniAt < 0 {
		t.Fatal("SNI bytes not found in captured ClientHello")
	}
	splits := [][]int{
		{1},                            // inside record header
		{5},                            // after record header
		{9},                            // after handshake header
		{5, 9},                         // headers alone, then body
		{sniAt + 7},                    // middle of the SNI name
		{1, 5, 9, sniAt + 7},           // four pieces
		{0, len(ch)},                   // empty first segment
		{len(ch) / 2},                  // even halves
		{len(ch) / 3, 2 * len(ch) / 3}, // thirds
	}
	for _, at := range splits {
		s := NewStream()
		var res Result
		var err error
		for _, p := range splitAt(ch, at...) {
			res, err = s.Feed(p)
			if errors.Is(err, ErrNeedMore) {
				continue
			}
			if err != nil {
				t.Fatalf("split %v: %v", at, err)
			}
		}
		if err != nil || !res.SNIFound || string(res.SNI) != "www.youtube.com" {
			t.Fatalf("split %v: err=%v SNI=%q found=%v", at, err, res.SNI, res.SNIFound)
		}
	}
}

// ---------------------------------------------------------------------------
// Synthetic ClientHellos: extensions, ECH, absence of fields.
// ---------------------------------------------------------------------------

func TestFeedSynthetic(t *testing.T) {
	cases := []struct {
		name     string
		ch       []byte
		wantSNI  string // "" => not found
		wantALPN string // "" => nil
		wantECH  bool
	}{
		{
			name: "sni_alpn_ech_with_grease_and_unknown",
			ch: synthCH{exts: concat(
				extBytes(0x0a0a, nil), // GREASE, zero length
				extBytes(extServerName, sniListData("example.org")),
				extBytes(0x0017, []byte{0x00, 0x00}), // unknown to us
				extBytes(extECH, []byte{0xdb, 0x00, 0x01}),
				extBytes(extALPN, alpnListData("h2", "http/1.1")),
			)}.build(),
			wantSNI:  "example.org",
			wantALPN: "h2",
			wantECH:  true,
		},
		{
			name:    "ech_legacy_ff0d",
			ch:      synthCH{exts: extBytes(extECHLegacy, []byte{0})}.build(),
			wantECH: true,
		},
		{
			name: "both_ech_codepoints",
			ch: synthCH{exts: concat(
				extBytes(extECH, []byte{0}),
				extBytes(extECHLegacy, []byte{0}),
			)}.build(),
			wantECH: true,
		},
		{
			name: "no_extensions_block",
			ch:   synthCH{omitExtBlock: true}.build(),
		},
		{
			name: "empty_extensions_block",
			ch:   synthCH{}.build(),
		},
		{
			name:    "duplicate_sni_extensions_first_wins",
			ch:      synthCH{exts: concat(extBytes(extServerName, sniListData("first.example")), extBytes(extServerName, sniListData("second.example")))}.build(),
			wantSNI: "first.example",
		},
		{
			name: "empty_sni_list",
			ch:   synthCH{exts: extBytes(extServerName, []byte{0, 0})}.build(),
		},
		{
			name: "zero_length_hostname",
			ch:   synthCH{exts: extBytes(extServerName, []byte{0, 3, 0x00, 0x00, 0x00})}.build(),
		},
		{
			name: "sni_list_len_overrun",
			ch:   synthCH{exts: extBytes(extServerName, []byte{0, 16, 0x00, 0x00, 0x01, 'x'})}.build(),
		},
		{
			name:     "alpn_http1_only",
			ch:       synthCH{exts: extBytes(extALPN, alpnListData("http/1.1"))}.build(),
			wantALPN: "http/1.1",
		},
		{
			name: "empty_alpn_list",
			ch:   synthCH{exts: extBytes(extALPN, []byte{0, 0})}.build(),
		},
		{
			name:    "session_id_32_tls13_style",
			ch:      synthCH{sessionID: make([]byte, 32), exts: extBytes(extServerName, sniListData("sid.example"))}.build(),
			wantSNI: "sid.example",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewStream()
			res, err := s.Feed(tc.ch)
			if err != nil {
				t.Fatalf("Feed: %v", err)
			}
			if !res.IsTLS || res.NeedMore {
				t.Fatalf("res = %+v, want completed", res)
			}
			if tc.wantSNI == "" {
				if res.SNIFound {
					t.Errorf("SNIFound = true, SNI = %q, want none", res.SNI)
				}
			} else if !res.SNIFound || string(res.SNI) != tc.wantSNI {
				t.Errorf("SNI = %q (found %v), want %q", res.SNI, res.SNIFound, tc.wantSNI)
			}
			if tc.wantALPN == "" {
				if res.ALPN != nil {
					t.Errorf("ALPN = %q, want nil", res.ALPN)
				}
			} else if string(res.ALPN) != tc.wantALPN {
				t.Errorf("ALPN = %q, want %q", res.ALPN, tc.wantALPN)
			}
			if res.ECH != tc.wantECH {
				t.Errorf("ECH = %v, want %v", res.ECH, tc.wantECH)
			}
		})
	}
}

// TestFeedSNIMixedEntryTypes: the server_name list carries a non-host
// entry before the host_name entry; the parser must skip to the host one.
func TestFeedSNIMixedEntryTypes(t *testing.T) {
	// list: [type=2, len=3, "abc"], [type=0, len=11, "example.org"]
	list := []byte{
		0x02, 0x00, 0x03, 'a', 'b', 'c',
		0x00, 0x00, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'o', 'r', 'g',
	}
	data := append([]byte{byte(len(list) >> 8), byte(len(list))}, list...)
	ch := synthCH{exts: extBytes(extServerName, data)}.build()

	s := NewStream()
	res, err := s.Feed(ch)
	if err != nil {
		t.Fatalf("Feed: %v", err)
	}
	if !res.SNIFound || string(res.SNI) != "example.org" {
		t.Fatalf("SNI = %q (found %v), want example.org", res.SNI, res.SNIFound)
	}
}

// TestFeedMaxSizeCH builds the largest ClientHello the inspector accepts
// (exactly 8192 bytes including the record header) and feeds it in four
// 2 KB segments.
func TestFeedMaxSizeCH(t *testing.T) {
	sni := extBytes(extServerName, sniListData("big.example"))
	filler := extBytes(0x9999, make([]byte, 8114)) // fixed body(45)+20+4+8114 = 8183; +9 = 8192
	ch := synthCH{exts: concat(sni, filler)}.build()
	if len(ch) != maxAccumulate {
		t.Fatalf("synthetic CH length = %d, want %d", len(ch), maxAccumulate)
	}

	s := NewStream()
	parts := splitEvenly(ch, 4)
	for i, p := range parts {
		res, err := s.Feed(p)
		if i < 3 {
			if !errors.Is(err, ErrNeedMore) {
				t.Fatalf("segment %d: err = %v, want ErrNeedMore", i, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("last segment: %v", err)
		}
		if !res.SNIFound || string(res.SNI) != "big.example" {
			t.Fatalf("SNI = %q", res.SNI)
		}
	}
	if len(s.acc) != maxAccumulate {
		t.Errorf("reassembly buffer = %d bytes, want %d", len(s.acc), maxAccumulate)
	}
	if cap(s.acc) != maxAccumulate {
		t.Errorf("reassembly buffer cap = %d, want %d (one-time growth)", cap(s.acc), maxAccumulate)
	}
}

// ---------------------------------------------------------------------------
// Rejections: not TLS, malformed.
// ---------------------------------------------------------------------------

func TestFeedNotTLS(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"http_get", []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")},
		{"app_data_record", []byte{0x17, 0x03, 0x03, 0x00, 0x10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}},
		{"alert_record", []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00}},
		{"change_cipher_spec", []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}},
		{"binary_junk", []byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewStream()
			_, err := s.Feed(tc.data)
			if !errors.Is(err, ErrNotTLS) {
				t.Fatalf("err = %v, want ErrNotTLS", err)
			}
			// Terminal: further feeds keep returning the rejection.
			if _, err := s.Feed([]byte{0x16}); !errors.Is(err, ErrNotTLS) {
				t.Fatalf("after rejection err = %v, want ErrNotTLS", err)
			}
			if !s.Done() {
				t.Error("Done() = false after rejection")
			}
		})
	}

	// A handshake record whose message is a ServerHello, not ClientHello.
	sh := synthCH{}.build()
	sh[5] = 0x02
	s := NewStream()
	if _, err := s.Feed(sh); !errors.Is(err, ErrNotTLS) {
		t.Fatalf("ServerHello: err = %v, want ErrNotTLS", err)
	}
}

func TestFeedMalformed(t *testing.T) {
	tmpl := synthCH{exts: extBytes(extServerName, sniListData("ok.example"))}
	valid := tmpl.build()

	// Field-level overruns patched on the valid template.
	withSidLen := func(v byte) []byte {
		b := append([]byte(nil), valid...)
		b[recordHeaderLen+handshakeHeaderLen+34] = v // session_id length byte
		return b
	}
	withCipherLen := func(hi, lo byte) []byte {
		b := append([]byte(nil), valid...)
		off := recordHeaderLen + handshakeHeaderLen + 34 + 1 // after sid len byte (synth sid is empty)
		b[off], b[off+1] = hi, lo
		return b
	}
	withCompLen := func(v byte) []byte {
		b := append([]byte(nil), valid...)
		off := recordHeaderLen + handshakeHeaderLen + 34 + 1 + 2 + 4 // sid(1)+cslen(2)+cs(4)
		b[off] = v
		return b
	}
	withExtBlockLen := func(hi, lo byte) []byte {
		b := append([]byte(nil), valid...)
		off := len(b) - (4 + 2 + 3 + len("ok.example")) - 2 // extensions block length field
		b[off], b[off+1] = hi, lo
		return b
	}
	withHsLen := func(v int) []byte {
		b := append([]byte(nil), valid...)
		b[6], b[7], b[8] = byte(v>>16), byte(v>>8), byte(v)
		return b
	}

	csOdd := tmpl
	csOdd.cipherSuites = []byte{0x13, 0x01, 0x00} // odd byte count

	cases := []struct {
		name string
		data []byte
	}{
		{"record_len_zero", []byte{0x16, 0x03, 0x01, 0x00, 0x00}},
		{"record_len_65535", []byte{0x16, 0x03, 0x01, 0xff, 0xff, 0x01, 0x00, 0x00, 0x30}},
		{"record_len_over_cap", []byte{0x16, 0x03, 0x03, 0x1f, 0xfc, 0x01}}, // 8188 > 8187
		{"version_major_2", []byte{0x16, 0x02, 0x01, 0x00, 0x30, 0x01}},
		{"version_major_4", []byte{0x16, 0x04, 0x03, 0x00, 0x30, 0x01}},
		{"hs_len_spans_records", synthCH{recLenForce: 64, hsLenForce: 200}.build()},
		{"hs_len_zero_empty_body", withHsLen(0)},
		{"body_too_short", synthCH{hsLenForce: 10}.build()},
		{"session_id_len_255_no_payload", withSidLen(0xff)},
		{"cipher_suites_len_zero", withCipherLen(0, 0)},
		{"cipher_suites_odd_count", csOdd.build()},
		{"cipher_suites_len_overrun", withCipherLen(0x7f, 0xff)},
		{"compression_len_zero", withCompLen(0)},
		{"compression_len_overrun", withCompLen(0xff)},
		{"ext_block_len_overrun", withExtBlockLen(0xff, 0xf0)},
		{"ext_entry_len_overrun", func() []byte {
			ch := synthCH{exts: extBytes(0x9999, []byte{1, 2, 3, 4})}.build()
			eo := recordHeaderLen + handshakeHeaderLen + 34 + 1 + 2 + 4 + 1 + 1 + 2
			ch[eo+2], ch[eo+3] = 0xff, 0xff // entry length 65535
			return ch
		}()},
		{"ext_trailing_bytes", func() []byte {
			exts := concat(extBytes(0x1234, []byte{0xaa, 0xbb}), []byte{0xcc, 0xdd})
			return synthCH{exts: exts}.build()
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewStream()
			_, err := s.Feed(tc.data)
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}

	// Malformed CH discovered only in the second segment.
	s := NewStream()
	if _, err := s.Feed(valid[:10]); !errors.Is(err, ErrNeedMore) {
		t.Fatalf("first segment: err = %v, want ErrNeedMore", err)
	}
	bad := withSidLen(0xff)
	if _, err := s.Feed(bad[10:]); !errors.Is(err, ErrMalformed) {
		t.Fatalf("second segment: err = %v, want ErrMalformed", err)
	}
}

// TestFeedOversizedJunkStream feeds far more than 8 KB behind a
// valid-looking record header: the reassembly buffer must stay bounded and
// the stream rejected as malformed once the declared message completes.
func TestFeedOversizedJunkStream(t *testing.T) {
	s := NewStream()
	header := []byte{0x16, 0x03, 0x03, byte(maxRecordLen >> 8), byte(maxRecordLen & 0xff), 0x01, 0x00, 0x1f, 0xe7} // recLen=8187, hsLen=8183
	junk := make([]byte, 16384)
	for i := range junk {
		junk[i] = 0x41
	}
	copy(junk, header[5:])

	if _, err := s.Feed(header); !errors.Is(err, ErrNeedMore) {
		t.Fatalf("header: err = %v, want ErrNeedMore", err)
	}
	if _, err := s.Feed(junk); !errors.Is(err, ErrMalformed) {
		t.Fatalf("junk body: err = %v, want ErrMalformed", err)
	}
	if len(s.acc) > maxAccumulate {
		t.Fatalf("reassembly buffer grew to %d, cap %d", len(s.acc), maxAccumulate)
	}
	if !s.Done() {
		t.Error("stream not terminal after malformed payload")
	}
}

// ---------------------------------------------------------------------------
// State machine behavior.
// ---------------------------------------------------------------------------

func TestFeedTerminalIdempotent(t *testing.T) {
	ch := captureClientHello(t, tls13Config())
	s := NewStream()
	res1, err := s.Feed(ch)
	if err != nil {
		t.Fatalf("Feed: %v", err)
	}
	res2, err := s.Feed([]byte{0xde, 0xad})
	if err != nil {
		t.Fatalf("second Feed after done: %v", err)
	}
	if string(res1.SNI) != string(res2.SNI) || res1.SNIFound != res2.SNIFound {
		t.Errorf("cached result changed: %+v vs %+v", res1, res2)
	}
	if !s.Done() {
		t.Error("Done() = false after success")
	}

	s2 := NewStream()
	if _, err := s2.Feed([]byte("GET /")); !errors.Is(err, ErrNotTLS) {
		t.Fatalf("reject: %v", err)
	}
	if _, err := s2.Feed(ch); !errors.Is(err, ErrNotTLS) {
		t.Fatalf("cached reject: %v", err)
	}
}

func TestStreamReset(t *testing.T) {
	ch := captureClientHello(t, tls13Config())
	s := NewStream()
	if _, err := s.Feed(ch[:40]); !errors.Is(err, ErrNeedMore) {
		t.Fatalf("partial: %v", err)
	}
	s.Reset()
	if s.Done() {
		t.Error("Done() after Reset")
	}
	res, err := s.Feed(ch)
	if err != nil {
		t.Fatalf("Feed after Reset: %v", err)
	}
	if string(res.SNI) != "www.youtube.com" {
		t.Fatalf("SNI after Reset = %q", res.SNI)
	}
}

func TestIndependentStreams(t *testing.T) {
	chA := captureClientHello(t, tls13Config())
	chB := synthCH{exts: extBytes(extServerName, sniListData("other.example"))}.build()

	sa, sb := NewStream(), NewStream()
	if _, err := sa.Feed(chA[:20]); !errors.Is(err, ErrNeedMore) {
		t.Fatalf("a partial: %v", err)
	}
	resB, err := sb.Feed(chB)
	if err != nil {
		t.Fatalf("b full: %v", err)
	}
	if string(resB.SNI) != "other.example" {
		t.Fatalf("b SNI = %q", resB.SNI)
	}
	resA, err := sa.Feed(chA[20:])
	if err != nil {
		t.Fatalf("a complete: %v", err)
	}
	if string(resA.SNI) != "www.youtube.com" {
		t.Fatalf("a SNI = %q", resA.SNI)
	}
}

func TestFeedEmptySegments(t *testing.T) {
	ch := captureClientHello(t, tls13Config())
	s := NewStream()
	if _, err := s.Feed(nil); !errors.Is(err, ErrNeedMore) {
		t.Fatalf("nil first: %v", err)
	}
	if _, err := s.Feed([]byte{}); !errors.Is(err, ErrNeedMore) {
		t.Fatalf("empty first: %v", err)
	}
	if s.Done() {
		t.Error("empty feeds must not terminate the stream")
	}
	if res, err := s.Feed(ch); err != nil || !res.SNIFound {
		t.Fatalf("full after empties: res=%+v err=%v", res, err)
	}
}

// ---------------------------------------------------------------------------
// Allocation guarantees.
// ---------------------------------------------------------------------------

func TestFeedFastPathZeroAllocs(t *testing.T) {
	ch := captureClientHello(t, tls13Config())
	s := NewStream()
	if _, err := s.Feed(ch); err != nil {
		t.Fatalf("warm-up: %v", err)
	}
	var ferr error
	n := testing.AllocsPerRun(200, func() {
		s.Reset()
		if _, err := s.Feed(ch); err != nil {
			ferr = err
		}
	})
	if ferr != nil {
		t.Fatalf("Feed: %v", ferr)
	}
	if n != 0 {
		t.Fatalf("AllocsPerRun(Feed, warm full ClientHello) = %v, want 0", n)
	}
}

func TestFeedSegmentedWarmZeroAllocs(t *testing.T) {
	ch := captureClientHello(t, tls13Config())
	parts := splitEvenly(ch, 4)
	s := NewStream()
	for _, p := range parts {
		if _, err := s.Feed(p); err != nil && !errors.Is(err, ErrNeedMore) {
			t.Fatalf("warm-up: %v", err)
		}
	}
	var ferr error
	n := testing.AllocsPerRun(200, func() {
		s.Reset()
		for _, p := range parts {
			if _, err := s.Feed(p); err != nil && !errors.Is(err, ErrNeedMore) {
				ferr = err
			}
		}
	})
	if ferr != nil {
		t.Fatalf("Feed: %v", ferr)
	}
	if n != 0 {
		t.Fatalf("AllocsPerRun(Feed, warm 4-segment ClientHello) = %v, want 0", n)
	}
}

// ---------------------------------------------------------------------------
// Fuzz-style robustness: random mutations and random segmentation must
// never panic, never exceed the buffer cap, and only ever return the three
// sentinel errors (or success).
// ---------------------------------------------------------------------------

func TestFeedMutationRobustness(t *testing.T) {
	base := captureClientHello(t, tls13Config())
	rng := rand.New(rand.NewSource(20261025))

	for iter := 0; iter < 3000; iter++ {
		buf := append([]byte(nil), base...)
		mutated := true
		switch rng.Intn(6) {
		case 0: // truncate anywhere
			buf = buf[:rng.Intn(len(buf)+1)]
		case 1: // flip 1..8 random bytes
			for j := 0; j < 1+rng.Intn(8); j++ {
				buf[rng.Intn(len(buf))] ^= byte(1 + rng.Intn(255))
			}
		case 2: // overwrite a random byte
			buf[rng.Intn(len(buf))] = byte(rng.Intn(256))
		case 3: // append random junk
			junk := make([]byte, rng.Intn(64))
			_, _ = rng.Read(junk)
			buf = append(buf, junk...)
		case 4: // random length-field torture
			pos := rng.Intn(len(buf))
			buf[pos] = byte(rng.Intn(256))
			if pos+1 < len(buf) {
				buf[pos+1] = byte(rng.Intn(256))
			}
		case 5: // unmutated: exercises random chunking of a valid CH
			mutated = false
		}

		s := NewStream()
		for len(buf) > 0 {
			n := 1 + rng.Intn(len(buf))
			res, err := s.Feed(buf[:n])
			buf = buf[n:]

			if err == nil {
				if !res.IsTLS || res.NeedMore {
					t.Fatalf("iter %d: success with res = %+v", iter, res)
				}
				if !mutated && (!res.SNIFound || string(res.SNI) != "www.youtube.com") {
					t.Fatalf("iter %d: valid CH lost its SNI: %+v", iter, res)
				}
				break
			}
			if !errors.Is(err, ErrNeedMore) && !errors.Is(err, ErrNotTLS) && !errors.Is(err, ErrMalformed) {
				t.Fatalf("iter %d: unexpected error %v", iter, err)
			}
			if errors.Is(err, ErrNeedMore) != res.NeedMore {
				t.Fatalf("iter %d: err/NeedMore mismatch: %v %+v", iter, err, res)
			}
			if len(s.acc) > maxAccumulate {
				t.Fatalf("iter %d: reassembly buffer %d > %d", iter, len(s.acc), maxAccumulate)
			}
			if !errors.Is(err, ErrNeedMore) {
				break // terminal
			}
		}
	}
}
