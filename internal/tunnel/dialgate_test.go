package tunnel

import (
	"testing"
	"time"
)

// TestDialGateAdmitsBurstWhileHealthy pins the behaviour that broke Telegram
// media: a burst of parallel client flows must all get a carrier dial slot at
// once. The old gate allowed 1 dial/s with 2 concurrent, so the 8th parallel
// flow waited seconds and most of a media burst failed its connect timeout.
func TestDialGateAdmitsBurstWhileHealthy(t *testing.T) {
	g := newDialGate()
	const burst = 8
	admitted := 0
	for i := 0; i < burst; i++ {
		if g.allow() {
			admitted++
		}
	}
	if admitted < burst {
		t.Fatalf("healthy gate admitted %d/%d parallel dials; a media burst needs all of them", admitted, burst)
	}
	for i := 0; i < admitted; i++ {
		g.done()
	}
}

// TestDialGateBacksOffAfterFailure keeps the storm control honest: a refused
// carrier dial must still clamp the next dial, or the VPS gets hammered.
func TestDialGateBacksOffAfterFailure(t *testing.T) {
	g := newDialGate()
	if !g.allow() {
		t.Fatal("first dial refused on a healthy gate")
	}
	g.failure()
	g.done()
	if g.allow() {
		t.Fatal("dial admitted during the post-failure cooldown")
	}
	// success() clears the cooldown, so the next dial goes through.
	g.success()
	if !g.allow() {
		t.Fatal("dial refused after success() cleared the cooldown")
	}
	g.done()
}

// TestDialGateSuccessRestoresThroughput: one healthy dial must not leave the
// gate throttled from an earlier failure burst.
func TestDialGateSuccessRestoresThroughput(t *testing.T) {
	g := newDialGate()
	for i := 0; i < 4; i++ {
		g.failure()
	}
	g.success()
	admitted := 0
	for i := 0; i < 8; i++ {
		if g.allow() {
			admitted++
		}
	}
	if admitted < 8 {
		t.Fatalf("after recovery admitted %d/8 dials; the gate stayed throttled", admitted)
	}
	for i := 0; i < admitted; i++ {
		g.done()
	}
	if time.Since(time.Now()) > time.Second { // keep the import honest
		t.Fatal("unreachable")
	}
}
