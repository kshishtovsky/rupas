package tunnel

import (
	"testing"
)

// Acceptance gates (go-hotpath): the forged-packet path runs at per-segment
// frequency on bulk flows — zero allocations is a hard requirement, verified
// by testing.AllocsPerRun, not by eye.

func benchTermConn() *termConn {
	return &termConn{k: termKey{
		srcIP: [4]byte{26, 26, 26, 2}, srcPort: 51000,
		dstIP: [4]byte{142, 250, 74, 136}, dstPort: 443,
	}}
}

func TestCraftZeroAlloc(t *testing.T) {
	c := benchTermConn()
	payload := make([]byte, 1200)
	f := func() {
		pkt := c.craft(1000, 2000, termACK|termPSH, payload, 65535)
		putCraftBuf(pkt)
	}
	f() // warm the pool — first rent may allocate, documented
	if n := testing.AllocsPerRun(200, f); n != 0 {
		t.Fatalf("craft+put: got %v allocs/op, want 0", n)
	}
	// SYN path (MSS option appended)
	fsyn := func() {
		pkt := c.craft(c.serverISN, c.clientNext, termSYN|termACK, nil, termWindow)
		putCraftBuf(pkt)
	}
	fsyn()
	if n := testing.AllocsPerRun(200, fsyn); n != 0 {
		t.Fatalf("craft(SYN): got %v allocs/op, want 0", n)
	}
}

func TestIPChecksum2MatchesConcat(t *testing.T) {
	pseudo := [12]byte{142, 250, 74, 136, 26, 26, 26, 2, 0, 6, 0, 40}
	tcp := make([]byte, 40)
	for i := range tcp {
		tcp[i] = byte(i * 7)
	}
	concat := append(append(make([]byte, 0, len(pseudo)+len(tcp)), pseudo[:]...), tcp...)
	if got, want := ipChecksum2(pseudo[:], tcp), ipChecksum(concat); got != want {
		t.Fatalf("ipChecksum2 = %04x, ipChecksum(concat) = %04x", got, want)
	}
}

func TestFlowDescCached(t *testing.T) {
	c := benchTermConn()
	want := "26.26.26.2:51000 -> 142.250.74.136:443"
	if got := c.flowDesc(); got != want {
		t.Fatalf("flowDesc = %q, want %q", got, want)
	}
	f := func() { _ = c.flowDesc() }
	if n := testing.AllocsPerRun(200, f); n != 0 {
		t.Fatalf("flowDesc (cached): got %v allocs/op, want 0", n)
	}
}

func BenchmarkCraftDataSegment(b *testing.B) {
	c := benchTermConn()
	payload := make([]byte, 1200)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		pkt := c.craft(1000, 2000, termACK|termPSH, payload, 65535)
		putCraftBuf(pkt)
	}
}

func BenchmarkCraftWindowUpdate(b *testing.B) {
	c := benchTermConn()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		pkt := c.craft(1000, 2000, termACK, nil, 65535)
		putCraftBuf(pkt)
	}
}
