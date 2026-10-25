package tunnel

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Wave 9 regression tests: the terminator path runs on the SINGLE capture
// receive goroutine (recvLoop → processPacket → relayTunnelTCP → FeedTCP →
// Feed → feed), so any blocking call here froze the whole machine's
// networking, DIRECT flows included. These tests pin the non-blocking
// contract with hard deadlines.
// ---------------------------------------------------------------------------

// testLogger discards output so hot-path warnings do not pollute the test
// log.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestEnqueueLockedFullQueueNeverBlocks: with writeCh saturated and the
// connection ALIVE, enqueueLocked must return immediately and report the
// payloads that did not fit — never park the caller (the old select had no
// default and blocked forever on a full queue).
func TestEnqueueLockedFullQueueNeverBlocks(t *testing.T) {
	c := &termConn{
		tm:      &Terminator{log: testLogger()},
		writeCh: make(chan []byte, 4),
		closed:  make(chan struct{}),
	}
	// Fill the queue to capacity; nothing drains it (no pumpWrites).
	filler := make([][]byte, cap(c.writeCh))
	for i := range filler {
		filler[i] = make([]byte, 10)
	}
	if left := c.enqueueLocked(filler); left != 0 {
		t.Fatalf("enqueue into an empty queue dropped %d payloads", left)
	}
	if len(c.writeCh) != cap(c.writeCh) {
		t.Fatalf("queue len %d, want full %d", len(c.writeCh), cap(c.writeCh))
	}
	if got, want := c.queuedBytes.Load(), int64(len(filler)*10); got != want {
		t.Fatalf("queuedBytes = %d, want %d", got, want)
	}

	// Enqueue MORE onto the full queue: must return at once and report
	// every rejected payload.
	extra := [][]byte{make([]byte, 10), make([]byte, 10), make([]byte, 10)}
	done := make(chan int, 1)
	go func() { done <- c.enqueueLocked(extra) }()
	select {
	case left := <-done:
		if left != len(extra) {
			t.Fatalf("enqueueLocked reported %d rejected, want %d", left, len(extra))
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("enqueueLocked BLOCKED on a full queue: the capture recv goroutine would hang")
	}

	// Partial room: exactly the free slot is taken, the rest reported.
	<-c.writeCh
	partial := [][]byte{make([]byte, 5), make([]byte, 5), make([]byte, 5)}
	done2 := make(chan int, 1)
	go func() { done2 <- c.enqueueLocked(partial) }()
	select {
	case left := <-done2:
		if left != len(partial)-1 {
			t.Fatalf("partial enqueue reported %d rejected, want %d", left, len(partial)-1)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("enqueueLocked blocked with one free slot")
	}
	if got, want := c.queuedBytes.Load(), int64(len(filler)*10+len(partial[0])); got != want {
		t.Fatalf("queuedBytes = %d, want %d (every queued byte must stay charged)", got, want)
	}
}

// blockingConn is a carrier that accepts a dial and then wedges: the first
// Write parks until Close. It models the "carrier stalled" case in which the
// relay queue fills up and stays full.
type blockingConn struct {
	closeOnce sync.Once
	done      chan struct{}
}

func newBlockingConn() *blockingConn { return &blockingConn{done: make(chan struct{})} }

func (b *blockingConn) Read([]byte) (int, error) {
	<-b.done
	return 0, io.EOF
}

func (b *blockingConn) Write(p []byte) (int, error) {
	<-b.done
	return 0, io.ErrClosedPipe
}

func (b *blockingConn) Close() error {
	b.closeOnce.Do(func() { close(b.done) })
	return nil
}

func (b *blockingConn) LocalAddr() net.Addr              { return blockingAddr{} }
func (b *blockingConn) RemoteAddr() net.Addr             { return blockingAddr{} }
func (b *blockingConn) SetDeadline(time.Time) error      { return nil }
func (b *blockingConn) SetReadDeadline(time.Time) error  { return nil }
func (b *blockingConn) SetWriteDeadline(time.Time) error { return nil }

type blockingAddr struct{}

func (blockingAddr) Network() string { return "blocking" }
func (blockingAddr) String() string  { return "blocking" }

// TestFeedFullQueueReturnsImmediatelyWithDupAck: the in-order branch must
// treat a full relay queue as backpressure — return at once, not consume the
// segment (clientNext unchanged) and answer with a dup-ACK so the client
// fast-retransmits.
func TestFeedFullQueueReturnsImmediatelyWithDupAck(t *testing.T) {
	sender := &fakeTermSender{}
	// A carrier that accepts the dial and then wedges in Write: the relay
	// queue fills and never drains, exactly like a stalled tunnel.
	carrier := newBlockingConn()
	tm := NewTerminator(sender, func(ctx context.Context, dst string) (net.Conn, error) {
		return carrier, nil
	}, testLogger())
	defer tm.Close()

	termFeed(tm, termSYN, 1000, 0, nil)
	time.Sleep(50 * time.Millisecond)
	c := termConnOf(tm)
	if c == nil {
		t.Fatal("no terminator connection after SYN")
	}

	// Saturate the relay queue (pumpWrites is parked in Write).
	for i := 0; i < 4*cap(c.writeCh) && len(c.writeCh) < cap(c.writeCh); i++ {
		c.mu.Lock()
		c.enqueueLocked([][]byte{make([]byte, 8)})
		c.mu.Unlock()
	}
	c.mu.Lock()
	base := c.clientNext
	c.mu.Unlock()
	if len(c.writeCh) != cap(c.writeCh) {
		t.Fatalf("queue not full: %d/%d", len(c.writeCh), cap(c.writeCh))
	}
	before := len(sender.sent())

	// One in-order data segment: must return immediately.
	done := make(chan struct{})
	go func() {
		termFeed(tm, termACK|termPSH, base, 1001, make([]byte, 16))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Feed BLOCKED with a full relay queue: the capture recv goroutine would hang")
	}

	c.mu.Lock()
	next := c.clientNext
	c.mu.Unlock()
	if next != base {
		t.Fatalf("clientNext advanced %d → %d: the deferred segment was consumed", base, next)
	}
	if got := c.qFullN.Load(); got == 0 {
		t.Fatal("qFullN = 0: the deferral was not counted")
	}
	// A dup-ACK (pure ACK with ack == clientNext) must have been injected.
	var dup bool
	for _, p := range sender.sent()[before:] {
		pp := parseTerm(t, p)
		if pp.flags == termACK && pp.ack == base {
			dup = true
		}
	}
	if !dup {
		t.Fatal("no dup-ACK after the deferred segment: the client would wait out its RTO")
	}
}

// TestWaitWindowSingleTimer: the window wait allocates its timer ONCE per
// call, not once per loop iteration (the old time.After-in-a-loop). The test
// compares a call that times out immediately (one iteration) against one
// that keeps looping on ACKs: any per-iteration timer makes the busy case
// allocate proportionally more.
func TestWaitWindowSingleTimer(t *testing.T) {
	newConn := func() *termConn {
		return &termConn{
			tm:        &Terminator{log: testLogger(), send: &fakeTermSender{}},
			closed:    make(chan struct{}),
			ackSignal: make(chan struct{}, 1),
			clientWin: 0, // window shut: every wake loops
		}
	}
	const stall = 20 * time.Millisecond

	// Idle: no ACK arrives, the timer fires on the first select.
	idle := newConn()
	idleAllocs := testing.AllocsPerRun(10, func() {
		_ = idle.waitWindowFor(1, stall)
	})

	// Busy: an ACK every 50 µs → many iterations per call.
	busy := newConn()
	stop := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		tick := time.NewTicker(50 * time.Microsecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				select {
				case busy.ackSignal <- struct{}{}:
				default:
				}
			}
		}
	}()
	busyAllocs := testing.AllocsPerRun(10, func() {
		_ = busy.waitWindowFor(1, stall)
	})
	close(stop)
	<-stopped

	// A per-iteration time.After adds ≥ 1 object per iteration; hundreds of
	// iterations in the busy call would show up as a large delta.
	t.Logf("allocs per call: idle %.2f, busy %.2f", idleAllocs, busyAllocs)
	if busyAllocs-idleAllocs > 1 {
		t.Fatalf("window wait allocates per iteration: idle %.1f, busy %.1f objects per call", idleAllocs, busyAllocs)
	}
}

// TestWaitWindowWakesOnACK: the timer rewrite must not lose the wakeup — an
// ACK that opens the window unblocks the pump at once.
func TestWaitWindowWakesOnACK(t *testing.T) {
	c := &termConn{
		tm:        &Terminator{log: testLogger()},
		closed:    make(chan struct{}),
		ackSignal: make(chan struct{}, 1),
		clientWin: 0,
	}
	c.serverNext, c.serverUna = 1000, 1000
	got := make(chan bool, 1)
	go func() { got <- c.waitWindow(100) }()
	time.Sleep(20 * time.Millisecond)
	c.mu.Lock()
	c.clientWin = 0xFFFF
	c.mu.Unlock()
	select {
	case c.ackSignal <- struct{}{}:
	default:
	}
	select {
	case ok := <-got:
		if !ok {
			t.Fatal("waitWindow returned false after the window opened")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waitWindow did not wake on ackSignal")
	}
}

// TestWaitWindowDeadConnReturns: a killed connection must release a waiting
// pump immediately (no stall).
func TestWaitWindowDeadConnReturns(t *testing.T) {
	c := &termConn{
		tm:        &Terminator{log: testLogger()},
		closed:    make(chan struct{}),
		ackSignal: make(chan struct{}, 1),
		clientWin: 0,
		dead:      true,
	}
	done := make(chan bool, 1)
	go func() { done <- c.waitWindow(100) }()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("waitWindow returned true for a dead connection")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("waitWindow hung on a dead connection")
	}
}

// TestWaitWindowProgressKeepsWaiting: a peer that keeps making progress (its
// ACK advances our unacked point) must NOT be reset — only a peer with zero
// progress for the whole stall budget is wedged. Two calls with a 40 ms
// budget and a progress tick every 10 ms must both return false only after
// the connection is closed, not by the stall path.
func TestWaitWindowProgressKeepsWaiting(t *testing.T) {
	sender := &fakeTermSender{}
	tm := NewTerminator(sender, func(ctx context.Context, dst string) (net.Conn, error) {
		return nil, errors.New("no carrier")
	}, testLogger())
	defer tm.Close()

	c := &termConn{
		tm:        tm,
		closed:    make(chan struct{}),
		ackSignal: make(chan struct{}, 1),
		clientWin: 0,
	}
	c.serverNext, c.serverUna = 5000, 5000

	// 300 ms of progress at a 40 ms stall budget: the reset path must never
	// fire (it would kill the flow and send a RST).
	stop := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for i := 0; i < 30; i++ {
			time.Sleep(10 * time.Millisecond)
			c.mu.Lock()
			c.serverUna++ // the client ACKed one of our bytes
			c.mu.Unlock()
			select {
			case c.ackSignal <- struct{}{}:
			default:
			}
		}
		close(stop)
	}()
	got := make(chan bool, 1)
	go func() { got <- c.waitWindowFor(1, 40*time.Millisecond) }()
	select {
	case ok := <-got:
		if !ok {
			t.Fatal("waitWindow gave up on a peer that was making progress")
		}
	case <-stopped:
		t.Fatal("window wait timed out despite continuous ACK progress (would have reset a healthy flow)")
	case <-time.After(5 * time.Second):
		t.Fatal("test did not finish")
	}
	close(c.closed)
}
