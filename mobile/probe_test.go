package core

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

// decodeProbe asserts the frozen key set and returns the parsed result.
func decodeProbe(t *testing.T, raw string) probeResult {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	var r probeResult
	if err := dec.Decode(&r); err != nil {
		t.Fatalf("json %q: %v", raw, err)
	}
	if dec.More() {
		t.Fatalf("json %q: trailing data", raw)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &keys); err != nil {
		t.Fatalf("json %q: %v", raw, err)
	}
	if len(keys) != 4 {
		t.Fatalf("keys of %q: want ok/ms/stage/err, got %v", raw, keys)
	}
	return r
}

// A probe already running makes the second call answer "busy" at once.
func TestTestProfileBusy(t *testing.T) {
	probeMu.Lock()
	defer probeMu.Unlock()

	r := decodeProbe(t, TestProfile("trojan://pw@example.com:443#probe", t.TempDir()))
	if r.OK || r.Stage != "busy" || r.MS != 0 || r.Err == "" {
		t.Fatalf("want busy/no/0/err, got %+v", r)
	}
}

// A link the parser rejects fails in the start stage, and the link (which
// carries the credentials) never reaches err.
func TestTestProfileBadLinkLeaksNothing(t *testing.T) {
	// ss:// is unsupported on purpose: its parse error echoes a 48-byte
	// excerpt of the raw link, and that excerpt covers the userinfo.
	const secret = "c3VwZXItc2VjcmV0LXVzZXI"
	link := "ss://" + secret + "@example.com:8388#probe"

	r := decodeProbe(t, TestProfile(link, t.TempDir()))
	if r.OK {
		t.Fatalf("bad link must not pass: %+v", r)
	}
	if r.Stage != "start" && r.Stage != "dial" {
		t.Fatalf("stage: want start|dial, got %q", r.Stage)
	}
	if r.Err == "" {
		t.Fatal("err must explain the failure")
	}
	if r.MS != 0 {
		t.Fatalf("ms must be 0 on failure, got %d", r.MS)
	}
	if strings.Contains(r.Err, secret) || strings.Contains(r.Err, link) {
		t.Fatalf("secret leaked into err: %q", r.Err)
	}
	t.Logf("stage=%s err=%q", r.Stage, r.Err)
}

// The uuid of a well-formed link is a secret too.
func TestTestProfileBadVLESSHidesUUID(t *testing.T) {
	const uuid = "11111111-2222-3333-4444-555555555555"
	link := "vless://" + uuid + "@example.com:443?type=bogus&security=tls#probe"

	r := decodeProbe(t, TestProfile(link, t.TempDir()))
	if r.OK || r.Err == "" {
		t.Fatalf("want failure with err, got %+v", r)
	}
	if strings.Contains(r.Err, uuid) {
		t.Fatalf("uuid leaked into err: %q", r.Err)
	}
}

// err is capped at 200 bytes and stays valid UTF-8.
func TestRedactTruncates(t *testing.T) {
	out := redact(strings.Repeat("a", 250), "")
	if len(out) != 200 {
		t.Fatalf("want 200 bytes, got %d", len(out))
	}
	wide := redact(strings.Repeat("й", 300), "") // 600 bytes
	if len(wide) > 200 {
		t.Fatalf("want <=200 bytes, got %d", len(wide))
	}
	if !utf8.ValidString(wide) {
		t.Fatalf("truncation split a rune: %q", wide)
	}
}
