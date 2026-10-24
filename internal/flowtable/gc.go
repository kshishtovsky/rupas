package flowtable

import (
	"sync"
	"sync/atomic"
	"time"
)

// processStart anchors the monotonic clock used for all Flow timestamps.
// time.Since carries a monotonic reading, so timestamps are immune to wall
// clock jumps (NTP steps, sleep/resume).
var processStart = time.Now()

// nowNanos returns monotonic nanoseconds since process start (negative never
// happens; it starts near 0). Zero allocations.
func nowNanos() int64 {
	return int64(time.Since(processStart))
}

// TouchSyn records "SYN seen now". Atomic: the GC goroutine reads timestamps.
func (f *Flow) TouchSyn() { atomic.StoreInt64(&f.SynT, nowNanos()) }

// TouchData records "data segment seen now" (also refreshes idle state).
func (f *Flow) TouchData() { atomic.StoreInt64(&f.DataT, nowNanos()) }

// TouchEst records "handshake established now".
func (f *Flow) TouchEst() { atomic.StoreInt64(&f.EstT, nowNanos()) }

// lastActivityNanos returns the most recent timestamp across SynT/DataT/EstT.
// Reads are atomic because capture goroutines write without holding the
// shard lock. A flow that was never touched (all zeros) counts as idle since
// process start, so it expires on the first GC pass.
func (f *Flow) lastActivityNanos() int64 {
	last := atomic.LoadInt64(&f.SynT)
	if v := atomic.LoadInt64(&f.DataT); v > last {
		last = v
	}
	if v := atomic.LoadInt64(&f.EstT); v > last {
		last = v
	}
	return last
}

// gcSweep scans the next shard in the ring and removes flows idle for longer
// than idleTTL, returning them to the pool. One shard per call keeps the
// critical section bounded (SYSTEM_DESIGN §4.1: ring scan, 1 shard per tick).
// The caller must serialize gcSweep calls (the background GC goroutine does).
func (ft *FlowTable) gcSweep(idleTTL time.Duration) int {
	sh := &ft.shards[ft.gcNext&ft.mask]
	ft.gcNext++
	cutoff := nowNanos() - int64(idleTTL)
	removed := 0
	sh.mu.Lock()
	for k, f := range sh.m {
		if f.lastActivityNanos() <= cutoff {
			delete(sh.m, k)
			ft.pool.Put(f)
			removed++
		}
	}
	sh.mu.Unlock()
	return removed
}

// GC starts a background goroutine that scans one shard per tick and deletes
// flows idle for longer than idleTTL. It returns a stop function that
// terminates the goroutine; calling it more than once is safe. Starting GC
// twice is a no-op: the second call returns a no-op stop function.
//
// Deleted flows are recycled into the pool; the single-owner discipline
// documented on Delete applies to the GC as well.
func (ft *FlowTable) GC(idleTTL, tick time.Duration) (stop func()) {
	if !ft.gcOn.CompareAndSwap(false, true) {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		defer ft.gcOn.Store(false)
		t := time.NewTicker(tick)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				ft.gcSweep(idleTTL)
			case <-done:
				return
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(done) }) }
}
