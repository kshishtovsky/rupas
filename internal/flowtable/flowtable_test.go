package flowtable

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"
)

// splitmix64: deterministic PRNG for test/bench key generation.
func splitmix64(x uint64) uint64 {
	x += 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}

// genKey builds a deterministic, well-spread key from an integer id.
func genKey(i uint64) FlowKey {
	a, b, c, d := splitmix64(i), splitmix64(i+1), splitmix64(i+2), splitmix64(i+3)
	var k FlowKey
	binary.LittleEndian.PutUint64(k.SrcIP[0:8], a)
	binary.LittleEndian.PutUint64(k.SrcIP[8:16], b)
	binary.LittleEndian.PutUint64(k.DstIP[0:8], c)
	binary.LittleEndian.PutUint64(k.DstIP[8:16], d)
	k.SrcPort = uint16(a >> 48)
	k.DstPort = uint16(b >> 32)
	k.Proto = 6 // TCP
	return k
}

func TestStateConstants(t *testing.T) {
	states := []struct {
		name string
		val  uint32
	}{
		{"FlowNew", FlowNew},
		{"FlowDirect", FlowDirect},
		{"FlowDesynced", FlowDesynced},
		{"FlowEstablished", FlowEstablished},
		{"FlowTunnel", FlowTunnel},
	}
	for i, s := range states {
		if uint32(i) != s.val {
			t.Errorf("%s = %d, want %d (order per SYSTEM_DESIGN 4.1)", s.name, s.val, i)
		}
	}
}

func TestHashStableAndPaddingIndependent(t *testing.T) {
	keys := []FlowKey{
		{},                    // zero key
		genKey(1), genKey(42), // pseudo-random
		genKey(1 << 40), // high ids
		{Proto: 17},     // only proto set
		func() FlowKey { // realistic IPv4-mapped TCP:443
			var k FlowKey
			k.SrcIP[10], k.SrcIP[11] = 0xff, 0xff
			k.DstIP[10], k.DstIP[11] = 0xff, 0xff
			binary.BigEndian.PutUint32(k.SrcIP[12:16], 192<<24|168<<16|1)
			binary.BigEndian.PutUint32(k.DstIP[12:16], 142<<24|250<<16|185)
			k.SrcPort, k.DstPort, k.Proto = 51724, 443, 6
			return k
		}(),
	}
	for i, k := range keys {
		first := k.Hash()
		if second := k.Hash(); second != first {
			t.Errorf("key %d: hash not deterministic: %d != %d", i, first, second)
		}
		// A copy of the key (fresh stack slot, dirty padding) must hash equal.
		var k2 FlowKey = k
		if got := k2.Hash(); got != first {
			t.Errorf("key %d: equal keys hash differently: %d != %d", i, got, first)
		}
	}
}

func TestHashSeparatesEveryField(t *testing.T) {
	base := genKey(7)
	mutations := []struct {
		name string
		mut  func(*FlowKey)
	}{
		{"SrcIP", func(k *FlowKey) { k.SrcIP[0] ^= 1 }},
		{"DstIP", func(k *FlowKey) { k.DstIP[15] ^= 1 }},
		{"SrcPort", func(k *FlowKey) { k.SrcPort++ }},
		{"DstPort", func(k *FlowKey) { k.DstPort++ }},
		{"Proto", func(k *FlowKey) { k.Proto++ }},
	}
	baseline := base.Hash()
	for _, m := range mutations {
		k := base
		m.mut(&k)
		if k.Hash() == baseline {
			t.Errorf("%s mutation does not change the hash", m.name)
		}
	}
}

func TestHashDistribution(t *testing.T) {
	const n = 1 << 16
	seen := make(map[uint64]struct{}, n)
	shards := 8
	counts := make([]int, shards)
	for i := uint64(0); i < n; i++ {
		k := genKey(i)
		h := k.Hash()
		seen[h] = struct{}{}
		counts[int(h&uint64(shards-1))]++
	}
	if len(seen) != n {
		t.Errorf("full 64-bit hash collisions: %d distinct hashes for %d keys", len(seen), n)
	}
	want := n / shards
	for s, c := range counts {
		if c < want/2 || c > want*2 {
			t.Errorf("shard %d of %d: %d keys, uniform expectation %d (outside [0.5x, 2x])", s, shards, c, want)
		}
	}
}

func TestShardCount(t *testing.T) {
	ft := New()
	if ft.Shards() < 1 || ft.Shards()&(ft.Shards()-1) != 0 {
		t.Fatalf("shard count %d is not a power of two >= 1", ft.Shards())
	}
	// Must follow k = round(log2(GOMAXPROCS)) clamped to [0,12].
	gomax := runtime.GOMAXPROCS(0)
	k := 0
	for 1<<(k+1) <= gomax {
		k++ // k = floor(log2(gomax))
	}
	// Round to nearest: gomax^2 > 2^k * 2^(k+1) means nearer to k+1.
	if gomax > 1 && gomax*gomax > (1<<k)*(1<<(k+1)) {
		k++
	}
	if k > 12 {
		k = 12
	}
	if ft.Shards() != 1<<k {
		t.Errorf("Shards() = %d, want %d (GOMAXPROCS=%d)", ft.Shards(), 1<<k, gomax)
	}
	if got := NewWithShardBits(0).Shards(); got != 1 {
		t.Errorf("NewWithShardBits(0).Shards() = %d, want 1", got)
	}
}

func TestLifecycle(t *testing.T) {
	keys := []FlowKey{
		genKey(1),
		func() FlowKey { // IPv6
			k := genKey(2)
			k.SrcIP[0] = 0x20
			k.DstIP[0] = 0x20
			return k
		}(),
		func() FlowKey { // UDP
			k := genKey(3)
			k.Proto = 17
			return k
		}(),
	}
	for i, k := range keys {
		t.Run(fmt.Sprintf("key%d", i), func(t *testing.T) {
			ft := NewWithShardBits(3)
			if _, ok := ft.Get(k); ok {
				t.Fatal("empty table returned a flow")
			}
			f1 := ft.GetOrCreate(k)
			if f1 == nil {
				t.Fatal("GetOrCreate returned nil")
			}
			if f1.State.Load() != FlowNew {
				t.Errorf("fresh flow State = %d, want FlowNew", f1.State.Load())
			}
			f2 := ft.GetOrCreate(k)
			if f1 != f2 {
				t.Error("GetOrCreate returned a different pointer for the same key")
			}
			if got, ok := ft.Get(k); !ok || got != f1 {
				t.Error("Get did not return the live flow")
			}
			if ft.Len() != 1 {
				t.Errorf("Len() = %d, want 1", ft.Len())
			}
			ft.Delete(k)
			if _, ok := ft.Get(k); ok {
				t.Error("Delete did not remove the flow")
			}
			if ft.Len() != 0 {
				t.Errorf("Len() = %d, want 0", ft.Len())
			}
			ft.Delete(k) // no-op, must not panic
		})
	}
	// Multi-key accumulation across shards.
	ft := NewWithShardBits(3)
	for i, k := range keys {
		ft.GetOrCreate(k)
		if ft.Len() != i+1 {
			t.Errorf("Len() = %d after %d inserts", ft.Len(), i+1)
		}
	}
}

func TestGetOrCreateResetsRecycledFlow(t *testing.T) {
	ft := NewWithShardBits(2)
	k1, k2 := genKey(11), genKey(12)

	f := ft.GetOrCreate(k1)
	f.State.Store(FlowTunnel)
	f.CHSeen, f.ECH = true, true
	f.Strategy = 9
	f.OrigDst = k1.DstIP
	f.OrigPort = 443
	f.SynT, f.DataT, f.EstT = 1, 2, 3
	f.Fails = 5
	ft.Delete(k1)

	// Next insert very likely reuses the pooled object; it must look new.
	for _, k := range []FlowKey{k2, k1} {
		nf := ft.GetOrCreate(k)
		if nf.State.Load() != FlowNew {
			t.Errorf("State = %d, want FlowNew", nf.State.Load())
		}
		if nf.CHSeen || nf.ECH || nf.Strategy != 0 || nf.OrigPort != 0 || nf.Fails != 0 {
			t.Errorf("recycled flow not zeroed: CHSeen=%v ECH=%v Strategy=%d OrigPort=%d Fails=%d",
				nf.CHSeen, nf.ECH, nf.Strategy, nf.OrigPort, nf.Fails)
		}
		if nf.SynT != 0 || nf.DataT != 0 || nf.EstT != 0 {
			t.Errorf("recycled flow timestamps not zeroed: %d %d %d", nf.SynT, nf.DataT, nf.EstT)
		}
		if nf.OrigDst != ([16]byte{}) {
			t.Error("recycled flow OrigDst not zeroed")
		}
		ft.Delete(k)
	}
}

func TestZeroAllocsWarm(t *testing.T) {
	ft := New()
	key := genKey(99)
	ft.GetOrCreate(key) // warm-up: insert outside measurement
	if allocs := testing.AllocsPerRun(1000, func() { ft.GetOrCreate(key) }); allocs != 0 {
		t.Errorf("GetOrCreate(warm) allocs = %v, want 0", allocs)
	}
	if allocs := testing.AllocsPerRun(1000, func() { ft.Get(key) }); allocs != 0 {
		t.Errorf("Get allocs = %v, want 0", allocs)
	}
	if allocs := testing.AllocsPerRun(1000, func() { ft.Len() }); allocs != 0 {
		t.Errorf("Len allocs = %v, want 0", allocs)
	}
}

func TestNowNanosMonotonic(t *testing.T) {
	prev := nowNanos()
	for i := 0; i < 1000; i++ {
		next := nowNanos()
		if next < prev {
			t.Fatalf("monotonic clock went backwards: %d < %d", next, prev)
		}
		prev = next
	}
}

func TestTouchTimestamps(t *testing.T) {
	f := &Flow{}
	before := nowNanos()
	f.TouchSyn()
	if f.SynT < before || f.SynT > nowNanos()+time.Millisecond.Nanoseconds() {
		t.Errorf("SynT = %d, want within [%d, now]", f.SynT, before)
	}
	f.TouchData()
	f.TouchEst()
	if f.lastActivityNanos() < f.SynT {
		t.Errorf("lastActivity = %d, want >= SynT %d", f.lastActivityNanos(), f.SynT)
	}
}

func TestGCSweep(t *testing.T) {
	ft := NewWithShardBits(2) // 4 shards: exercise the ring over all of them
	const idle = 10 * time.Millisecond
	// Make sure process uptime exceeds the TTL so cutoff arithmetic is
	// unambiguous (timestamps are monotonic-since-start and are >= 0 in
	// production; only a test started microseconds ago can see negatives).
	for nowNanos() < 2*int64(idle) {
		time.Sleep(idle / 2)
	}

	type entry struct {
		name  string
		touch func(f *Flow)
		keep  bool
	}
	entries := []entry{
		{"fresh-syn", func(f *Flow) { f.TouchSyn() }, true},
		{"fresh-data", func(f *Flow) { f.TouchData() }, true},
		{"fresh-est", func(f *Flow) { f.TouchEst() }, true},
		{"idle", func(f *Flow) {
			old := nowNanos() - 3*idle.Nanoseconds()
			f.SynT, f.DataT, f.EstT = old, old, old
		}, false},
		{"never-touched", func(f *Flow) {}, false},
	}
	for i, e := range entries {
		f := ft.GetOrCreate(genKey(uint64(1000 + i)))
		e.touch(f)
	}

	// One full ring pass over all 4 shards.
	removed := ft.gcSweep(idle) // shard 0
	removed += ft.gcSweep(idle) // shard 1
	removed += ft.gcSweep(idle) // shard 2
	removed += ft.gcSweep(idle) // shard 3
	if removed != 2 {
		t.Errorf("gcSweep removed %d flows, want 2 (idle + never-touched)", removed)
	}
	if ft.Len() != len(entries)-2 {
		t.Errorf("Len() = %d, want %d", ft.Len(), len(entries)-2)
	}
	for i, e := range entries {
		_, ok := ft.Get(genKey(uint64(1000 + i)))
		if ok != e.keep {
			t.Errorf("%s: present = %v, want %v", e.name, ok, e.keep)
		}
	}
}

// TestGCTunnelFlowsSurvive verifies the wave-7 exemption: a TUNNEL flow
// that has gone idle is NOT collected by gcSweep (it must live until
// FIN/RST teardown or the terminator clears it), while idle DIRECT and
// never-touched flows are reaped exactly as before.
func TestGCTunnelFlowsSurvive(t *testing.T) {
	ft := NewWithShardBits(2) // 4 shards: full ring pass like TestGCSweep
	const idle = 10 * time.Millisecond
	for nowNanos() < 2*int64(idle) {
		time.Sleep(idle / 2)
	}

	tunnel := ft.GetOrCreate(genKey(21)) // idle TUNNEL — must survive
	tunnel.State.Store(FlowTunnel)
	old := nowNanos() - 3*idle.Nanoseconds()
	tunnel.SynT, tunnel.DataT, tunnel.EstT = old, old, old

	idleDirect := ft.GetOrCreate(genKey(22)) // idle DIRECT — reaped
	idleDirect.State.Store(FlowDirect)

	ft.GetOrCreate(genKey(23)) // never-touched — reaped

	removed := ft.gcSweep(idle) // full ring pass over all 4 shards
	removed += ft.gcSweep(idle) // shard 1
	removed += ft.gcSweep(idle) // shard 2
	removed += ft.gcSweep(idle) // shard 3
	if removed != 2 {
		t.Errorf("gcSweep removed %d flows, want 2 (idle-direct + never-touched)", removed)
	}
	if _, ok := ft.Get(genKey(21)); !ok {
		t.Error("idle TUNNEL flow was collected — wave-7 GC exemption missing")
	}
	if _, ok := ft.Get(genKey(22)); ok {
		t.Error("idle DIRECT flow survived GC")
	}
	if _, ok := ft.Get(genKey(23)); ok {
		t.Error("never-touched flow survived GC")
	}
}

func TestGCBackground(t *testing.T) {
	ft := NewWithShardBits(1)
	const idle = 20 * time.Millisecond

	live := ft.GetOrCreate(genKey(1))
	live.TouchSyn()
	stale := ft.GetOrCreate(genKey(2))
	stale.SynT = nowNanos() - time.Hour.Nanoseconds()

	stop := ft.GC(idle, 2*time.Millisecond)
	defer stop()

	deadline := time.Now().Add(2 * time.Second)
	for ft.Len() != 1 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if ft.Len() != 1 {
		t.Fatalf("Len() = %d, want 1 after GC deadline", ft.Len())
	}
	if _, ok := ft.Get(genKey(1)); !ok {
		t.Error("live flow was collected")
	}
	if _, ok := ft.Get(genKey(2)); ok {
		t.Error("stale flow survived GC")
	}

	stop()
	// The goroutine exits asynchronously: wait for the flag to clear.
	deadline = time.Now().Add(2 * time.Second)
	for ft.gcOn.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if ft.gcOn.Load() {
		t.Fatal("GC goroutine did not stop after stop()")
	}
	// Restart must work, and a second concurrent start must be a no-op.
	stop2 := ft.GC(idle, time.Hour)
	noop := ft.GC(idle, time.Hour) // must not start a second goroutine
	noop()
	stop2()
	deadline = time.Now().Add(2 * time.Second)
	for ft.gcOn.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if ft.gcOn.Load() {
		t.Fatal("restarted GC goroutine did not stop after stop()")
	}
}

func TestConcurrentMixed(t *testing.T) {
	ft := New()
	stop := ft.GC(time.Hour, time.Millisecond) // exercises GC vs writers under -race
	defer stop()

	const goroutines = 8
	const ops = 100000

	var hot [64]FlowKey
	for i := range hot {
		hot[i] = genKey(uint64(i))
		ft.GetOrCreate(hot[i])
	}

	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < ops; i++ {
				// Contended hit path on shared keys.
				k := hot[i%len(hot)]
				f := ft.GetOrCreate(k)
				f.State.CompareAndSwap(FlowNew, FlowEstablished)
				if s := f.State.Load(); s != FlowEstablished && s != FlowNew {
					errs <- fmt.Errorf("goroutine %d: unexpected state %d", g, s)
					return
				}
				if _, ok := ft.Get(k); !ok {
					errs <- fmt.Errorf("goroutine %d: hot key disappeared", g)
					return
				}
				// Private key churn: insert, atomic-only mutation, delete.
				// Key space (>= 2^48) is disjoint from the hot set (ids 0..63).
				pk := genKey((uint64(g)+1)<<48 + uint64(i))
				pf := ft.GetOrCreate(pk)
				pf.State.Store(FlowTunnel)
				pf.TouchData()
				ft.Delete(pk)
				if i%1024 == 0 {
					if n := ft.Len(); n < len(hot) {
						errs <- fmt.Errorf("goroutine %d: Len() = %d below hot set size", g, n)
						return
					}
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	if ft.Len() != len(hot) {
		t.Errorf("Len() = %d after test, want %d", ft.Len(), len(hot))
	}
}

func TestConcurrentSameKeySingleFlow(t *testing.T) {
	ft := NewWithShardBits(2)
	key := genKey(500)
	const goroutines = 8
	var wg sync.WaitGroup
	ptrs := make([]*Flow, goroutines)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				f := ft.GetOrCreate(key)
				if f != nil {
					ptrs[g] = f
				}
			}
		}(g)
	}
	wg.Wait()
	for g := 1; g < goroutines; g++ {
		if ptrs[g] != ptrs[0] {
			t.Fatalf("goroutine %d got pointer %p, goroutine 0 got %p — duplicate flows for one key", g, ptrs[g], ptrs[0])
		}
	}
	if ft.Len() != 1 {
		t.Errorf("Len() = %d, want 1", ft.Len())
	}
}
