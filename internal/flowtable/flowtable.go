// Package flowtable provides a sharded, conntrack-style flow table for the
// Rupas packet hot path.
//
// Design (docs/SYSTEM_DESIGN.md §4.1, ADR-6):
//   - 2^k shards (k = round(log2(GOMAXPROCS))), one RWMutex per shard, so
//     capture goroutines do not contend on a single map;
//   - map[FlowKey]*Flow: fixed-size struct keys stored inline by the runtime,
//     no interface boxing, no per-lookup key allocation;
//   - GetOrCreate on an existing key performs ZERO heap allocations after
//     warm-up; Flow objects are recycled through a sync.Pool;
//   - background ring GC: one shard is scanned per tick, idle > TTL flows are
//     deleted and returned to the pool.
package flowtable

import (
	"math"
	"runtime"
	"sync"
	"sync/atomic"
)

// FlowKey identifies a flow (5-tuple). IPs are 16-byte IPv4-mapped or native
// IPv6 addresses. The struct is comparable and used directly as a map key:
// no boxing, no hashing to strings, no allocations on lookup.
type FlowKey struct {
	SrcIP   [16]byte
	DstIP   [16]byte
	SrcPort uint16
	DstPort uint16
	Proto   uint8
}

// Flow states, stored in Flow.State (atomic.Uint32).
const (
	FlowNew    uint32 = iota // SYN seen, no ClientHello yet
	FlowDirect               // matched DIRECT: re-inject as is, never inspected again
	FlowDesynced
	FlowEstablished
	FlowTunnel
)

// Flow is a per-connection entry.
//
// State is safe for concurrent use (atomic). Timestamps (SynT/DataT/EstT)
// must be written via the Touch* methods (atomic stores) because the GC
// goroutine reads them; all remaining fields are owned by the capture
// goroutine that won the GetOrCreate race (single-writer per layer,
// SYSTEM_DESIGN §3.2 invariant).
type Flow struct {
	State    atomic.Uint32
	CHSeen   bool     // ClientHello inspected
	ECH      bool     // encrypted_client_hello extension seen
	Strategy uint8    // index of the applied desync strategy
	OrigDst  [16]byte // original destination (for redirect)
	OrigPort uint16
	SynT     int64 // ns, monotonic since process start
	DataT    int64 // last data segment, ns monotonic
	EstT     int64 // handshake completed, ns monotonic
	Fails    uint8 // handshake retries, drives degradation
}

// shard is one lock domain of the table.
type shard struct {
	mu sync.RWMutex
	m  map[FlowKey]*Flow
}

// FlowTable is a sharded flow table. It is safe for concurrent use.
type FlowTable struct {
	shards []shard
	mask   uint64 // len(shards)-1, power-of-two mask
	pool   sync.Pool
	gcNext uint64 // ring-scan cursor; owned by the GC goroutine / gcSweep caller
	gcOn   atomic.Bool
}

// New creates a FlowTable with 2^k shards, where k = round(log2(GOMAXPROCS)),
// clamped to [0, 12].
func New() *FlowTable {
	k := int(math.Round(math.Log2(float64(runtime.GOMAXPROCS(0)))))
	if k < 0 {
		k = 0
	}
	if k > 12 {
		k = 12
	}
	return NewWithShardBits(uint(k))
}

// NewWithShardBits creates a table with exactly 1<<k shards (k clamped to
// [0, 15]); intended for tests and diagnostics.
func NewWithShardBits(k uint) *FlowTable {
	if k > 15 {
		k = 15
	}
	n := uint64(1) << k
	ft := &FlowTable{
		shards: make([]shard, n),
		mask:   n - 1,
	}
	for i := range ft.shards {
		ft.shards[i].m = make(map[FlowKey]*Flow)
	}
	ft.pool.New = func() any { return new(Flow) }
	return ft
}

// Shards returns the number of shards (a power of two).
func (ft *FlowTable) Shards() int { return len(ft.shards) }

// shardOf returns the shard for the key. Zero-copy: only the hash is computed.
func (ft *FlowTable) shardOf(k *FlowKey) *shard {
	return &ft.shards[k.Hash()&ft.mask]
}

// Get returns the flow for the key, or (nil, false) if unknown.
// Zero allocations on any path.
func (ft *FlowTable) Get(k FlowKey) (*Flow, bool) {
	sh := ft.shardOf(&k)
	sh.mu.RLock()
	f, ok := sh.m[k]
	sh.mu.RUnlock()
	return f, ok
}

// GetOrCreate returns the flow for the key, inserting a fresh one (zeroed,
// State == FlowNew) if absent.
//
// Hot path: on a hit it takes only an RLock, one custom-hash computation and
// one map lookup — ZERO heap allocations after warm-up. Flow objects come
// from a sync.Pool and are recycled by Delete and the GC.
func (ft *FlowTable) GetOrCreate(k FlowKey) *Flow {
	sh := ft.shardOf(&k)
	// Fast path: shared read lock, no pool traffic, no allocation.
	sh.mu.RLock()
	f, ok := sh.m[k]
	sh.mu.RUnlock()
	if ok {
		return f
	}
	// Slow path: exclusive lock, re-check to avoid duplicate inserts
	// (only the goroutine that confirms the miss pays pool.Get).
	sh.mu.Lock()
	if f, ok = sh.m[k]; ok {
		sh.mu.Unlock()
		return f
	}
	f = ft.pool.Get().(*Flow)
	*f = Flow{} // recycled object must look brand new
	sh.m[k] = f
	sh.mu.Unlock()
	return f
}

// Delete removes the flow for the key and recycles it into the pool.
// It is a no-op for unknown keys.
//
// The caller must guarantee that no other goroutine still dereferences the
// *Flow obtained earlier for this key (single-owner discipline of the
// capture layer); the table cannot detect stale pointers.
func (ft *FlowTable) Delete(k FlowKey) {
	sh := ft.shardOf(&k)
	sh.mu.Lock()
	if f, ok := sh.m[k]; ok {
		delete(sh.m, k)
		sh.mu.Unlock()
		ft.pool.Put(f)
		return
	}
	sh.mu.Unlock()
}

// Len returns the total number of live flows across all shards.
func (ft *FlowTable) Len() int {
	n := 0
	for i := range ft.shards {
		sh := &ft.shards[i]
		sh.mu.RLock()
		n += len(sh.m)
		sh.mu.RUnlock()
	}
	return n
}
