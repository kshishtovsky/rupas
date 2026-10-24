package flowtable

import (
	"encoding/binary"
	"math/bits"
)

// xxhash-inspired 64-bit mixing constants (no external dependencies).
const (
	prime1 uint64 = 11400714785074694791
	prime2 uint64 = 14029467366897019727
	prime3 uint64 = 1609587929392839161
	prime4 uint64 = 9650029242287828579
	prime5 uint64 = 2870177450012600261
)

// flowKeySigBytes is the number of significant bytes hashed: SrcIP(16) +
// DstIP(16) + SrcPort(2) + DstPort(2) + Proto(1). Struct padding is never
// hashed, so two equal keys always hash equally regardless of how they were
// built.
const flowKeySigBytes = 37

func mixRound(acc, val uint64) uint64 {
	acc += val * prime2
	acc = bits.RotateLeft64(acc, 31)
	return acc * prime1
}

func mergeRound(acc, val uint64) uint64 {
	val = mixRound(0, val)
	acc ^= val
	return acc*prime1 + prime4
}

// Hash returns the 64-bit hash of the key.
//
// It is a self-contained xxhash-like construction over the 37 significant
// bytes of FlowKey: the 32 address bytes feed four parallel mix rounds and
// the port/proto tail is packed into one lane, followed by the standard
// avalanche. Zero-copy: bytes are read in place from the caller's key, no
// slices escape, nothing is boxed — the function performs no allocations.
func (k *FlowKey) Hash() uint64 {
	// Lane seeds mirror xxhash with seed = prime5; the additions wrap at
	// runtime (uint64 arithmetic), unlike untyped constants.
	v1 := prime5
	v1 += prime1
	v1 += prime2
	v2 := prime5
	v3 := prime5
	v3 -= prime1
	v4 := prime5
	v4 -= prime2
	// Four 8-byte lanes over SrcIP || DstIP.
	v1 = mixRound(v1, binary.LittleEndian.Uint64(k.SrcIP[0:8]))
	v2 = mixRound(v2, binary.LittleEndian.Uint64(k.SrcIP[8:16]))
	v3 = mixRound(v3, binary.LittleEndian.Uint64(k.DstIP[0:8]))
	v4 = mixRound(v4, binary.LittleEndian.Uint64(k.DstIP[8:16]))

	h := bits.RotateLeft64(v1, 1) + bits.RotateLeft64(v2, 7) +
		bits.RotateLeft64(v3, 12) + bits.RotateLeft64(v4, 18)
	h = mergeRound(h, v1)
	h = mergeRound(h, v2)
	h = mergeRound(h, v3)
	h = mergeRound(h, v4)

	h += flowKeySigBytes

	// Tail lane: SrcPort || DstPort || Proto packed little-endian.
	tail := uint64(k.SrcPort) | uint64(k.DstPort)<<16 | uint64(k.Proto)<<32
	h ^= mixRound(0, tail)
	h = bits.RotateLeft64(h, 27)*prime1 + prime4

	// Final avalanche so that low bits (used for shard masking) are uniform.
	h ^= h >> 33
	h *= prime2
	h ^= h >> 29
	h *= prime3
	h ^= h >> 32
	return h
}
