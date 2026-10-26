package android

import (
	"encoding/binary"
	"testing"
)

// dnsQuery builds a minimal DNS query with one question.
func dnsQuery(id uint16, qtype uint16, name string) []byte {
	var q []byte
	q = binary.BigEndian.AppendUint16(q, id)
	q = binary.BigEndian.AppendUint16(q, 0x0100) // RD=1
	q = binary.BigEndian.AppendUint16(q, 1)      // QDCOUNT=1
	q = append(q, 0, 0, 0, 0, 0, 0)              // AN/NS/AR = 0
	for _, label := range []string{name, ""} {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = binary.BigEndian.AppendUint16(q, qtype)
	q = binary.BigEndian.AppendUint16(q, 1) // IN
	return q
}

func TestDNS4AAAAQueryGetsEmptyNoError(t *testing.T) {
	resp := dns4Response(dnsQuery(0x1234, dnsTypeAAAA, "www.google.com"))
	if resp == nil {
		t.Fatal("AAAA query must be answered synthetically")
	}
	if got := resp[0:2]; got[0] != 0x12 || got[1] != 0x34 {
		t.Fatalf("id not echoed: % x", got)
	}
	if resp[2]&0x80 == 0 {
		t.Fatal("QR not set")
	}
	an := binary.BigEndian.Uint16(resp[6:8])
	if an != 0 {
		t.Fatalf("answers must be empty, got %d", an)
	}
	qd := binary.BigEndian.Uint16(resp[4:6])
	if qd != 1 {
		t.Fatalf("question section must be echoed, QDCOUNT=%d", qd)
	}
}

func TestDNS4AQueryPassesThrough(t *testing.T) {
	if resp := dns4Response(dnsQuery(1, dnsTypeA, "www.google.com")); resp != nil {
		t.Fatalf("A query must be relayed upstream, not synthesized: % x", resp)
	}
}

func TestDNS4HTTPSQueryPassesThrough(t *testing.T) {
	if resp := dns4Response(dnsQuery(2, 65, "www.google.com")); resp != nil {
		t.Fatal("HTTPS/SVCB query must be relayed upstream")
	}
}

func TestDNS4GarbagePassesThrough(t *testing.T) {
	cases := [][]byte{
		nil,
		make([]byte, 6),                      // too short
		{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // QR=0 but QDCOUNT=0
	}
	for i, c := range cases {
		if resp := dns4Response(c); resp != nil {
			t.Fatalf("case %d: garbage must pass through", i)
		}
	}
	// a response (QR=1) passes through untouched
	q := dnsQuery(3, dnsTypeAAAA, "x.org")
	q[2] |= 0x80
	if resp := dns4Response(q); resp != nil {
		t.Fatal("responses must pass through")
	}
}

func TestPreferIPv4DefaultEnabled(t *testing.T) {
	s, err := ParseSettings(`{"fallback":true,"links":["vless://u@h:1?type=tcp#t"]}`)
	if err != nil {
		t.Fatalf("ParseSettings: %v", err)
	}
	if !s.PreferIPv4Enabled() {
		t.Fatal("absent prefer_ipv4 must default to enabled")
	}
	s2, err := ParseSettings(`{"fallback":true,"prefer_ipv4":false,"links":["vless://u@h:1?type=tcp#t"]}`)
	if err != nil {
		t.Fatalf("ParseSettings with prefer_ipv4: %v", err)
	}
	if s2.PreferIPv4Enabled() {
		t.Fatal("explicit false must disable PreferIPv4")
	}
}
