package flowtable

import "testing"

// benchKeys returns a deterministic, power-of-two-length key set.
func benchKeys(n int) []FlowKey {
	keys := make([]FlowKey, n)
	for i := range keys {
		keys[i] = genKey(uint64(i))
	}
	return keys
}

func benchTable(b *testing.B, logFlows int) (*FlowTable, []FlowKey) {
	b.Helper()
	n := 1 << uint(logFlows)
	ft := New()
	keys := benchKeys(n)
	for i := range keys {
		ft.GetOrCreate(keys[i])
	}
	if ft.Len() != n {
		b.Fatalf("setup: Len() = %d, want %d", ft.Len(), n)
	}
	b.ReportAllocs()
	b.ResetTimer()
	return ft, keys
}

// BenchmarkGet measures the pure lookup path at 1M flows.
func BenchmarkGet1M(b *testing.B) {
	ft, keys := benchTable(b, 20)
	mask := uint32(len(keys) - 1)
	var sink bool
	for i := uint32(0); i < uint32(b.N); i++ {
		_, sink = ft.Get(keys[i&mask])
	}
	_ = sink
}

func BenchmarkGet1MParallel(b *testing.B) {
	ft, keys := benchTable(b, 20)
	mask := uint32(len(keys) - 1)
	b.RunParallel(func(pb *testing.PB) {
		var sink bool
		for i := uint32(0); pb.Next(); i++ {
			_, sink = ft.Get(keys[i&mask])
		}
		_ = sink
	})
}

// BenchmarkGetOrCreate1M measures the hot path on an existing table:
// RLock + custom hash + map hit. Must be 0 allocs/op.
func BenchmarkGetOrCreate1M(b *testing.B) {
	ft, keys := benchTable(b, 20)
	mask := uint32(len(keys) - 1)
	for i := uint32(0); i < uint32(b.N); i++ {
		ft.GetOrCreate(keys[i&mask])
	}
}

func BenchmarkGetOrCreate1MParallel(b *testing.B) {
	ft, keys := benchTable(b, 20)
	mask := uint32(len(keys) - 1)
	b.RunParallel(func(pb *testing.PB) {
		for i := uint32(0); pb.Next(); i++ {
			ft.GetOrCreate(keys[i&mask])
		}
	})
}

// BenchmarkInsertDelete1M exercises the cold path: pool recycle +
// map insert/delete under the write lock.
func BenchmarkInsertDelete1M(b *testing.B) {
	ft, _ := benchTable(b, 20)
	k := genKey(1 << 62)
	for i := 0; i < b.N; i++ {
		ft.GetOrCreate(k)
		ft.Delete(k)
	}
}

// BenchmarkHash isolates the custom zero-copy hash.
func BenchmarkHash(b *testing.B) {
	k := genKey(31337)
	var sink uint64
	for i := 0; i < b.N; i++ {
		sink = k.Hash()
	}
	_ = sink
}
