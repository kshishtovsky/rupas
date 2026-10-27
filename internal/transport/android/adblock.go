package android

// Adblock (v0.4.0): the built-in ads/trackers filter. Two seams use the same
// compiled matcher — the DNS hijack in serveDNS53 (tun.go) and the SNI check
// in Engine.decide. Matching is a sorted []uint64 of FNV-1a hashes with a
// binary search: 184k domains cost 3.2 MB of rodata and lookups allocate
// nothing (a map[uint64]struct{} costs 19 MB for the same list).
//
// A name matches when it, or any parent suffix on a label boundary, is in a
// list: "ads.example.com" matches the entry "example.com" but "notexample.com"
// does not. The whitelist is matched the same way and vetoes both seams.

import (
	"bytes"
	"embed"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

//go:embed lists/ads.list lists/trackers.list
var adblockLists embed.FS

const (
	fnvOffset64 = 14695981039346656037
	fnvPrime64  = 1099511628211
	// adblockTTL is short on purpose: a wrong verdict must not outlive the
	// list for long on a device that changes settings often.
	adblockTTL       = 60
	dnsRcodeNoError  = 0
	dnsRcodeNXDomain = 3
)

// AdblockSettings is the optional "adblock" object of the SetSettings JSON:
//
//	{"adblock":{"ads":true,"trackers":false,"whitelist":["example.com"]}}
//
// ads defaults to true, trackers to false; whitelist is optional and exempts a
// domain plus all its subdomains in both DNS and SNI.
type AdblockSettings struct {
	Ads       *bool    `json:"ads,omitempty"`
	Trackers  *bool    `json:"trackers,omitempty"`
	Whitelist []string `json:"whitelist,omitempty"`
}

func (s *AdblockSettings) adsOn() bool {
	return s != nil && (s.Ads == nil || *s.Ads)
}

func (s *AdblockSettings) trackersOn() bool {
	return s != nil && s.Trackers != nil && *s.Trackers
}

// validate refuses a broken whitelist entry by index: the screen edits a list,
// and "whitelist 2 is broken" is what the owner can act on.
func (s *AdblockSettings) validate() error {
	for i, w := range s.Whitelist {
		if err := validateDomain(w); err != nil {
			return fmt.Errorf("android: settings: adblock.whitelist[%d]: %w", i, err)
		}
	}
	return nil
}

// validateDomain accepts a bare lowercase-able hostname (no scheme, port or
// wildcard): labels of 1..63 chars of [a-z0-9-_], total at most 253.
func validateDomain(d string) error {
	d = strings.TrimSpace(d)
	if d == "" {
		return fmt.Errorf("empty domain")
	}
	if len(d) > 253 {
		return fmt.Errorf("domain longer than 253 bytes")
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" {
			return fmt.Errorf("empty label in %q", d)
		}
		if len(label) > 63 {
			return fmt.Errorf("label longer than 63 bytes in %q", d)
		}
		for j := 0; j < len(label); j++ {
			c := label[j] | 0x20 // ASCII fold: A-Z → a-z
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
				return fmt.Errorf("bad character %q in %q", label[j], d)
			}
		}
	}
	return nil
}

// Adblock is the compiled matcher. Immutable once built: safe for concurrent
// use by every flow goroutine.
type Adblock struct {
	ads, trackers, white []uint64
	adsOn, trackersOn    bool
}

// AdsCount/TrackersCount report the compiled list sizes for Status().
func (a *Adblock) AdsCount() int       { return len(a.ads) }
func (a *Adblock) TrackersCount() int  { return len(a.trackers) }
func (a *Adblock) WhitelistCount() int { return len(a.white) }

// EnabledNames is the "enabled=" part of the start log line.
func (a *Adblock) EnabledNames() string {
	switch {
	case a.adsOn && a.trackersOn:
		return "ads+trackers"
	case a.trackersOn:
		return "trackers"
	default:
		return "ads"
	}
}

// compileAdblock builds the matcher from the embedded lists. nil (no error)
// means both lists are disabled — the caller logs "off" and blocks nothing. A
// list that fails to embed, or compiles empty, is an error: status must say
// "failed", never a silent "on".
func compileAdblock(s *AdblockSettings) (*Adblock, error) {
	a := &Adblock{adsOn: s.adsOn(), trackersOn: s.trackersOn()}
	if !a.adsOn && !a.trackersOn {
		return nil, nil
	}
	if a.adsOn {
		data, err := adblockLists.ReadFile("lists/ads.list")
		if err != nil {
			return nil, fmt.Errorf("ads list: %w", err)
		}
		if a.ads = compileList(data); len(a.ads) == 0 {
			return nil, fmt.Errorf("ads list: compiled empty")
		}
	}
	if a.trackersOn {
		data, err := adblockLists.ReadFile("lists/trackers.list")
		if err != nil {
			return nil, fmt.Errorf("trackers list: %w", err)
		}
		if a.trackers = compileList(data); len(a.trackers) == 0 {
			return nil, fmt.Errorf("trackers list: compiled empty")
		}
	}
	if len(s.Whitelist) > 0 {
		a.white = make([]uint64, 0, len(s.Whitelist))
		for _, w := range s.Whitelist {
			a.white = append(a.white, fnvName(strings.ToLower(strings.TrimSpace(w))))
		}
		sortKeys(a.white)
	}
	return a, nil
}

// compileList hashes every domain line of a list file (one hostname per line,
// '#' starts a comment) into a sorted, deduplicated key slice.
func compileList(data []byte) []uint64 {
	keys := make([]uint64, 0, len(data)/16)
	for len(data) > 0 {
		var line []byte
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			line, data = data[:i], data[i+1:]
		} else {
			line, data = data, nil
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		keys = append(keys, fnvName(line))
	}
	return sortKeys(keys)
}

// sortKeys sorts and dedupes (the lists carry a few duplicates).
func sortKeys(k []uint64) []uint64 {
	sort.Slice(k, func(i, j int) bool { return k[i] < k[j] })
	n := 0
	for i, v := range k {
		if i == 0 || v != k[n-1] {
			k[n] = v
			n++
		}
	}
	return k[:n]
}

// domainText is the two shapes a hostname arrives in: a string from the
// ClientHello peek, a []byte from the DNS wire. One matcher serves both, so
// the DNS path never builds a string.
type domainText interface{ ~string | ~[]byte }

// fnvName is FNV-1a 64 over the ASCII-lowercased bytes.
func fnvName[T domainText](b T) uint64 {
	h := uint64(fnvOffset64)
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		h = (h ^ uint64(c)) * fnvPrime64
	}
	return h
}

// Match reports the list that blocks a lowercase SNI name ("ads"|"trackers"),
// or ok=false when it is unknown or whitelisted. Zero allocations.
func (a *Adblock) Match(name string) (string, bool) { return adMatch(a, name) }

// adMatch checks the whitelist first: an exempt domain exempts its subdomains
// in both the DNS and the SNI seam.
func adMatch[T domainText](a *Adblock, name T) (string, bool) {
	if a == nil || len(name) == 0 {
		return "", false
	}
	if adHasName(a.white, name) {
		return "", false
	}
	if a.adsOn && adHasName(a.ads, name) {
		return "ads", true
	}
	if a.trackersOn && adHasName(a.trackers, name) {
		return "trackers", true
	}
	return "", false
}

// adHasName probes the name and every parent suffix on a label boundary.
func adHasName[T domainText](keys []uint64, name T) bool {
	if len(keys) == 0 {
		return false
	}
	for {
		if adHas(keys, fnvName(name)) {
			return true
		}
		dot := -1
		for i := 0; i < len(name); i++ {
			if name[i] == '.' {
				dot = i
				break
			}
		}
		if dot < 0 {
			return false
		}
		name = name[dot+1:]
	}
}

// adHas is a branch-predictable binary search over the sorted key slice.
func adHas(keys []uint64, h uint64) bool {
	lo, hi := 0, len(keys)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		switch {
		case keys[mid] < h:
			lo = mid + 1
		case keys[mid] > h:
			hi = mid
		default:
			return true
		}
	}
	return false
}

// dnsQuestion decodes the single question of a query: the name is dot-joined
// into caller stack memory (never a string), off is the offset after the
// question, so header+question can be echoed verbatim.
func dnsQuestion(q []byte, buf *[256]byte) (name []byte, off int, qtype uint16, ok bool) {
	if len(q) < 12 || q[2]&0x80 != 0 { // short, or QR=1 (a response)
		return nil, 0, 0, false
	}
	if binary.BigEndian.Uint16(q[4:6]) != 1 { // one question only
		return nil, 0, 0, false
	}
	if q[6]|q[7]|q[8]|q[9] != 0 { // AN/NS must be empty for the echo to line up
		return nil, 0, 0, false
	}
	p, n := 12, 0
	for {
		if p >= len(q) {
			return nil, 0, 0, false
		}
		l := int(q[p])
		p++
		if l == 0 {
			break
		}
		if l&0xC0 != 0 || p+l > len(q) { // compression pointers never appear here
			return nil, 0, 0, false
		}
		if n > 0 {
			buf[n] = '.'
			n++
		}
		if n+l > len(buf) {
			return nil, 0, 0, false
		}
		copy(buf[n:], q[p:p+l])
		n += l
		p += l
	}
	if n == 0 || p+4 > len(q) {
		return nil, 0, 0, false
	}
	return buf[:n], p + 4, binary.BigEndian.Uint16(q[p : p+2]), true
}

// dnsAnswer synthesizes the reply for one query datagram into buf (reused by
// the session across datagrams), reporting the list that blocked the name.
// resp==nil means "relay upstream unchanged".
func dnsAnswer(a *Adblock, preferIPv4 bool, q, buf []byte) (resp []byte, tag string) {
	var name [256]byte
	qn, off, qtype, ok := dnsQuestion(q, &name)
	if !ok {
		return nil, ""
	}
	var zero4 [4]byte
	var zero16 [16]byte
	if a != nil {
		if list, blocked := adMatch(a, qn); blocked {
			switch qtype {
			case dnsTypeA:
				return dnsBuild(q, off, dnsRcodeNoError, dnsTypeA, zero4[:], buf), list
			case dnsTypeAAAA:
				return dnsBuild(q, off, dnsRcodeNoError, dnsTypeAAAA, zero16[:], buf), list
			default: // HTTPS/SVCB/MX/TXT: no such name rather than a fake record
				return dnsBuild(q, off, dnsRcodeNXDomain, 0, nil, buf), list
			}
		}
	}
	// PreferIPv4: AAAA answered empty, so every app lands on IPv4.
	if preferIPv4 && qtype == dnsTypeAAAA {
		return dnsBuild(q, off, dnsRcodeNoError, 0, nil, buf), ""
	}
	return nil, ""
}

// dnsQName extracts the question name for the single log line of a blocked
// query. It allocates on purpose: the line already crosses the JNI bridge, and
// copying a stack buffer out only on a block keeps the hot path clean.
func dnsQName(q []byte) string {
	var buf [256]byte
	name, _, _, ok := dnsQuestion(q, &buf)
	if !ok {
		return "?"
	}
	return string(name)
}

// dnsBuild assembles a reply into buf: header and question echoed verbatim,
// QR=1, RA=1, the given RCODE, one IN answer (TTL 60) when rdata is non-nil,
// and the query's EDNS OPT record echoed so EDNS clients keep their shape.
func dnsBuild(q []byte, off int, rcode byte, rtype uint16, rdata, buf []byte) []byte {
	ar := binary.BigEndian.Uint16(q[10:12])
	buf = append(buf[:0], q[:off]...)
	ans := uint16(0)
	if len(rdata) > 0 {
		ans = 1
		buf = append(buf, 0xC0, 12) // name: pointer to the question
		buf = binary.BigEndian.AppendUint16(buf, rtype)
		buf = binary.BigEndian.AppendUint16(buf, 1) // class IN
		buf = binary.BigEndian.AppendUint32(buf, adblockTTL)
		buf = binary.BigEndian.AppendUint16(buf, uint16(len(rdata)))
		buf = append(buf, rdata...)
	}
	if ar > 0 {
		buf = append(buf, q[off:]...)
	}
	buf[2] = q[2] | 0x80              // QR=1, opcode/RD preserved
	buf[3] = q[3]&0x70 | 0x80 | rcode // RA=1, AD/CD preserved
	binary.BigEndian.PutUint16(buf[6:8], ans)
	binary.BigEndian.PutUint16(buf[8:10], 0)
	binary.BigEndian.PutUint16(buf[10:12], ar)
	return buf
}
