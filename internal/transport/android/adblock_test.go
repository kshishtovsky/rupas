package android

import (
	"encoding/binary"
	"strings"
	"testing"
)

// ---------- helpers ----------

func boolPtr(b bool) *bool { return &b }

// keysOf compiles an ad-hoc list of domains into the sorted key slice the
// matcher expects.
func keysOf(names ...string) []uint64 {
	k := make([]uint64, 0, len(names))
	for _, n := range names {
		k = append(k, fnvName(n))
	}
	return sortKeys(k)
}

// testAdblock builds a matcher over explicit lists (no embedded data).
func testAdblock(ads, trackers, white []string) *Adblock {
	a := &Adblock{
		ads:      keysOf(ads...),
		trackers: keysOf(trackers...),
		white:    keysOf(white...),
	}
	a.adsOn = len(ads) > 0
	a.trackersOn = len(trackers) > 0
	return a
}

// dnsTestQuery builds a wire query for name/qtype, optionally with an EDNS OPT
// record in the additional section.
func dnsTestQuery(name string, qtype uint16, edns bool) []byte {
	q := make([]byte, 12)
	q[0], q[1] = 0xbe, 0xef
	q[2] = 0x01 // RD
	for _, label := range strings.Split(name, ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0)
	q = binary.BigEndian.AppendUint16(q, qtype)
	q = binary.BigEndian.AppendUint16(q, 1) // IN
	if edns {
		q = append(q, 0)                           // root name
		q = binary.BigEndian.AppendUint16(q, 41)   // OPT
		q = binary.BigEndian.AppendUint16(q, 1232) // UDP payload
		q = binary.BigEndian.AppendUint32(q, 0)    // ext rcode/version/flags
		q = binary.BigEndian.AppendUint16(q, 0)    // RDLEN
	}
	binary.BigEndian.PutUint16(q[4:6], 1) // QDCOUNT
	if edns {
		binary.BigEndian.PutUint16(q[10:12], 1) // ARCOUNT
	}
	return q
}

// dnsQuestionEnd returns the offset right after the single question.
func dnsQuestionEnd(t *testing.T, q []byte) int {
	t.Helper()
	off := 12
	for q[off] != 0 {
		off += int(q[off]) + 1
	}
	return off + 1 + 4
}

// dnsFirstAnswer decodes the first answer RR that starts at off.
func dnsFirstAnswer(t *testing.T, resp []byte, off int) (rtype uint16, ttl uint32, rdata []byte) {
	t.Helper()
	if len(resp) < off+12 {
		t.Fatalf("response too short: %d bytes", len(resp))
	}
	if resp[off] != 0xC0 || resp[off+1] != 12 {
		t.Fatalf("answer name is not a pointer to the question: % x", resp[off:off+2])
	}
	rtype = binary.BigEndian.Uint16(resp[off+2 : off+4])
	if cl := binary.BigEndian.Uint16(resp[off+4 : off+6]); cl != 1 {
		t.Fatalf("answer class = %d, want IN(1)", cl)
	}
	ttl = binary.BigEndian.Uint32(resp[off+6 : off+10])
	rdlen := int(binary.BigEndian.Uint16(resp[off+10 : off+12]))
	start := off + 12
	if len(resp) < start+rdlen {
		t.Fatalf("rdata truncated: need %d bytes at %d of %d", rdlen, start, len(resp))
	}
	return rtype, ttl, resp[start : start+rdlen]
}

// ---------- 1: label boundaries ----------

func TestAdblockLabelBoundary(t *testing.T) {
	a := testAdblock([]string{"example.com"}, nil, nil)
	cases := []struct {
		name string
		want bool
	}{
		{"example.com", true},
		{"ads.example.com", true},
		{"a.b.example.com", true},
		{"notexample.com", false},
		{"badexample.com", false},
		{"example.com.evil.net", false},
		{"com", false},
	}
	for _, c := range cases {
		_, got := a.Match(c.name)
		if got != c.want {
			t.Errorf("Match(%q) blocked = %v, want %v", c.name, got, c.want)
		}
	}
}

// ---------- 2: ads/trackers switches ----------

func TestAdblockSwitches(t *testing.T) {
	adsOff, trkOff := false, false
	adsOn, trkOn := true, true

	// ads=false: neither list is compiled, nothing is blocked.
	a, err := compileAdblock(&AdblockSettings{Ads: &adsOff, Trackers: &trkOff})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if a != nil {
		t.Fatalf("both lists disabled must compile to nil, got %+v", a)
	}

	// ads=false, trackers=false → engine blocks nothing.
	if got := newAdblockEngine(&AdblockSettings{Ads: &adsOff, Trackers: &trkOff}).decide(FlowMeta{Network: "tcp", SNI: "googleads.g.doubleclick.net"}); got == ActionBlock {
		t.Fatal("ads=false must not block an ads domain")
	}

	// trackers=true → tracker blocked, ads list not compiled.
	trackers := newAdblockEngine(&AdblockSettings{Ads: &adsOff, Trackers: &trkOn})
	if got := trackers.decide(FlowMeta{Network: "tcp", SNI: "api.adjust.com"}); got != ActionBlock {
		t.Fatalf("trackers=true: decide(api.adjust.com) = %v, want BLOCK", got)
	}
	if got := trackers.decide(FlowMeta{Network: "tcp", SNI: "googleads.g.doubleclick.net"}); got == ActionBlock {
		t.Fatal("trackers=true, ads=false must not block an ads-only domain")
	}

	// trackers=false → nothing blocked.
	off := newAdblockEngine(&AdblockSettings{Ads: &adsOn, Trackers: &trkOff})
	if got := off.decide(FlowMeta{Network: "tcp", SNI: "api.adjust.com"}); got == ActionBlock {
		t.Fatal("trackers=false must not block a tracker")
	}
	if got := off.decide(FlowMeta{Network: "tcp", SNI: "googleads.g.doubleclick.net"}); got != ActionBlock {
		t.Fatalf("ads=true: decide(googleads.g.doubleclick.net) = %v, want BLOCK", got)
	}
}

// ---------- 3: whitelist (DNS + SNI) ----------

func TestAdblockWhitelist(t *testing.T) {
	a := testAdblock([]string{"example.com"}, nil, []string{"example.com"})
	if _, blocked := a.Match("ads.example.com"); blocked {
		t.Fatal("whitelist must exempt the domain and its subdomains in the matcher (SNI seam)")
	}
	var buf [512]byte
	if resp, _ := dnsAnswer(a, false, dnsTestQuery("ads.example.com", dnsTypeA, false), buf[:0]); resp != nil {
		t.Fatal("whitelist must exempt the domain in the DNS seam too")
	}

	// Real lists, through the SNI decision: whitelisting doubleclick.net
	// unblocks googleads.g.doubleclick.net.
	open := newAdblockEngine(&AdblockSettings{Ads: boolPtr(true), Whitelist: []string{"doubleclick.net"}})
	if got := open.decide(FlowMeta{Network: "tcp", SNI: "googleads.g.doubleclick.net"}); got == ActionBlock {
		t.Fatal("whitelisted parent must unblock the subdomain on SNI")
	}
	closed := newAdblockEngine(&AdblockSettings{Ads: boolPtr(true)})
	if got := closed.decide(FlowMeta{Network: "tcp", SNI: "googleads.g.doubleclick.net"}); got != ActionBlock {
		t.Fatalf("without whitelist decide = %v, want BLOCK", got)
	}
}

// ---------- 4: DNS synthesis ----------

func TestAdblockDNSSynthesis(t *testing.T) {
	a := testAdblock([]string{"ads.example.com"}, nil, nil)
	var buf [512]byte

	// A → 0.0.0.0, TTL 60, RCODE 0, question echoed.
	q := dnsTestQuery("ads.example.com", dnsTypeA, false)
	off := dnsQuestionEnd(t, q)
	resp, list := dnsAnswer(a, false, q, buf[:0])
	if resp == nil {
		t.Fatal("blocked A query must be answered locally")
	}
	if list != "ads" {
		t.Fatalf("list = %q, want ads", list)
	}
	if resp[2]&0x80 == 0 {
		t.Error("QR bit not set on the synthesized answer")
	}
	if resp[3]&0x80 == 0 {
		t.Error("RA bit not set on the synthesized answer")
	}
	if rcode := resp[3] & 0x0F; rcode != dnsRcodeNoError {
		t.Errorf("rcode = %d, want 0", rcode)
	}
	if an := binary.BigEndian.Uint16(resp[6:8]); an != 1 {
		t.Errorf("ANCOUNT = %d, want 1", an)
	}
	if string(resp[12:off]) != string(q[12:off]) {
		t.Errorf("question section not echoed verbatim: %q vs %q", resp[12:off], q[12:off])
	}
	rtype, ttl, rdata := dnsFirstAnswer(t, resp, off)
	if rtype != dnsTypeA || ttl != adblockTTL {
		t.Errorf("answer type/ttl = %d/%d, want A/%d", rtype, ttl, adblockTTL)
	}
	if len(rdata) != 4 || rdata[0]|rdata[1]|rdata[2]|rdata[3] != 0 {
		t.Errorf("A rdata = % x, want 0.0.0.0", rdata)
	}

	// AAAA → ::.
	q6 := dnsTestQuery("ads.example.com", dnsTypeAAAA, false)
	off6 := dnsQuestionEnd(t, q6)
	resp6, _ := dnsAnswer(a, false, q6, buf[:0])
	if resp6 == nil {
		t.Fatal("blocked AAAA query must be answered locally")
	}
	rtype6, _, rdata6 := dnsFirstAnswer(t, resp6, off6)
	if rtype6 != dnsTypeAAAA || len(rdata6) != 16 {
		t.Fatalf("AAAA answer type/len = %d/%d", rtype6, len(rdata6))
	}
	for _, b := range rdata6 {
		if b != 0 {
			t.Fatalf("AAAA rdata = % x, want ::", rdata6)
		}
	}

	// HTTPS (65) → NXDOMAIN, no answers.
	qh := dnsTestQuery("ads.example.com", 65, false)
	resph, _ := dnsAnswer(a, false, qh, buf[:0])
	if resph == nil {
		t.Fatal("blocked HTTPS query must be answered locally")
	}
	if rcode := resph[3] & 0x0F; rcode != dnsRcodeNXDomain {
		t.Errorf("HTTPS rcode = %d, want NXDOMAIN(3)", rcode)
	}
	if an := binary.BigEndian.Uint16(resph[6:8]); an != 0 {
		t.Errorf("HTTPS ANCOUNT = %d, want 0", an)
	}

	// EDNS: the OPT record survives the synthesized answer.
	qe := dnsTestQuery("ads.example.com", dnsTypeA, true)
	offe := dnsQuestionEnd(t, qe)
	respe, _ := dnsAnswer(a, false, qe, buf[:0])
	if respe == nil {
		t.Fatal("EDNS query must still be answered")
	}
	if ar := binary.BigEndian.Uint16(respe[10:12]); ar != 1 {
		t.Errorf("ARCOUNT = %d, want 1 (OPT echoed)", ar)
	}
	if tail := respe[offe+16:]; string(tail) != string(qe[offe:]) {
		t.Errorf("OPT record not echoed after the answer: % x vs % x", tail, qe[offe:])
	}

	// Not blocked → relay (nil).
	if resp, _ := dnsAnswer(a, false, dnsTestQuery("ok.example.com", dnsTypeA, false), buf[:0]); resp != nil {
		t.Fatal("unblocked name must be relayed, not answered")
	}
	// PreferIPv4 keeps its AAAA→empty-NOERROR behaviour with no adblock.
	if resp, _ := dnsAnswer(nil, true, dnsTestQuery("ok.example.com", dnsTypeAAAA, false), buf[:0]); resp == nil {
		t.Fatal("PreferIPv4 must still answer AAAA with an empty NOERROR")
	}
}

// ---------- 5: zero allocations on the hot path ----------

func TestAdblockMatchNoAlloc(t *testing.T) {
	a, err := compileAdblock(&AdblockSettings{Ads: boolPtr(true), Trackers: boolPtr(true)})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	names := []string{"googleads.g.doubleclick.net", "rt.applovin.com", "api.telegram.org", "www.google.com"}
	i := 0
	avg := testing.AllocsPerRun(1000, func() {
		a.Match(names[i%len(names)])
		i++
	})
	if avg != 0 {
		t.Fatalf("Match allocates %.1f objects per call, want 0", avg)
	}
	// The DNS seam writes into the caller's buffer: no allocation per datagram.
	q := dnsTestQuery("googleads.g.doubleclick.net", dnsTypeA, true)
	buf := make([]byte, 0, 512)
	avg = testing.AllocsPerRun(1000, func() {
		var resp []byte
		if resp, _ = dnsAnswer(a, true, q, buf); resp != nil {
			buf = resp
		}
	})
	if avg != 0 {
		t.Fatalf("dnsAnswer allocates %.1f objects per call, want 0", avg)
	}
}

// ---------- 6: settings JSON ----------

func TestAdblockSettingsJSON(t *testing.T) {
	base := `"uuid":"u","server":"s","port":443`

	// Absent key → no filter configured; a present object defaults to
	// ads=true, trackers=false.
	s, err := ParseSettings(`{` + base + `}`)
	if err != nil {
		t.Fatalf("parse without adblock: %v", err)
	}
	if s.Adblock != nil {
		t.Fatal("absent adblock must leave the field nil")
	}
	s, err = ParseSettings(`{` + base + `,"adblock":{}}`)
	if err != nil {
		t.Fatalf("parse empty adblock: %v", err)
	}
	if !s.Adblock.adsOn() || s.Adblock.trackersOn() {
		t.Fatalf("defaults = ads %v trackers %v, want true/false", s.Adblock.adsOn(), s.Adblock.trackersOn())
	}

	// Explicit values apply.
	s, err = ParseSettings(`{` + base + `,"adblock":{"ads":false,"trackers":true,"whitelist":["Example.COM"]}}`)
	if err != nil {
		t.Fatalf("parse explicit adblock: %v", err)
	}
	if s.Adblock.adsOn() || !s.Adblock.trackersOn() {
		t.Fatalf("explicit values ignored: ads %v trackers %v", s.Adblock.adsOn(), s.Adblock.trackersOn())
	}

	// Broken whitelist entry → error naming the index.
	for _, bad := range []string{"exa mple.com", "bad..com", "*", "http://example.com"} {
		_, err := ParseSettings(`{` + base + `,"adblock":{"whitelist":["ok.com","` + bad + `"]}}`)
		if err == nil {
			t.Fatalf("whitelist %q accepted", bad)
		}
		if !strings.Contains(err.Error(), "whitelist[1]") {
			t.Fatalf("error for %q does not name the index: %v", bad, err)
		}
	}
}

// ---------- 7: the shipped lists ----------

func TestAdblockRealLists(t *testing.T) {
	a, err := compileAdblock(&AdblockSettings{Ads: boolPtr(true), Trackers: boolPtr(true)})
	if err != nil {
		t.Fatalf("compile the shipped lists: %v", err)
	}
	if a == nil {
		t.Fatal("both lists enabled but matcher is nil")
	}
	t.Logf("compiled ads=%d trackers=%d", a.AdsCount(), a.TrackersCount())

	for _, name := range []string{
		"googleads.g.doubleclick.net",
		"rt.applovin.com",
		"rtb.ads.vungle.com",
		// mail.ru: реклама отдаётся с собственных доменов холдинга и с биржи
		// MRADX. Именно эти четыре отсутствовали/лежали в трекерах, из-за чего
		// science.mail.ru показывал баннеры при включённом фильтре.
		"ad.mail.ru",
		"rs.mail.ru",
		"r.mradx.net",
		"ads.adfox.ru",
	} {
		if _, blocked := a.Match(name); !blocked {
			t.Errorf("%s must be blocked", name)
		}
	}
	for _, name := range []string{
		"api.telegram.org",
		"www.google.com",
		"rr3---sn-4g5e6nez.googlevideo.com",
		"imem.app",
		"alfabank.ru",
		// Сам сайт mail.ru и его картинки обязаны открываться.
		"science.mail.ru",
		"mail.ru",
		"resizer.mail.ru",
	} {
		if list, blocked := a.Match(name); blocked {
			t.Errorf("%s must NOT be blocked (matched %s list)", name, list)
		}
	}
}

// ---------- benchmark ----------

// newAdblockEngine builds a W3 engine carrying the given adblock settings —
// the SNI seam exactly as Status()/decide see it.
func newAdblockEngine(cfg *AdblockSettings) *Engine {
	return NewW3EngineWithRules(&Settings{Adblock: cfg}, nil, nil, "", nil)
}

func BenchmarkAdblockMatch(b *testing.B) {
	a, err := compileAdblock(&AdblockSettings{Ads: boolPtr(true), Trackers: boolPtr(true)})
	if err != nil {
		b.Fatalf("compile: %v", err)
	}
	for _, name := range []string{"googleads.g.doubleclick.net", "api.telegram.org"} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				a.Match(name)
			}
		})
	}
}

func BenchmarkAdblockDNSSynthesis(b *testing.B) {
	a, err := compileAdblock(&AdblockSettings{Ads: boolPtr(true)})
	if err != nil {
		b.Fatalf("compile: %v", err)
	}
	q := dnsTestQuery("googleads.g.doubleclick.net", dnsTypeA, true)
	buf := make([]byte, 0, 512)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if resp, _ := dnsAnswer(a, true, q, buf); resp != nil {
			buf = resp
		}
	}
}
