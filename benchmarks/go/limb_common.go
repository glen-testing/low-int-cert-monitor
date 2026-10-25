package main

import (
	"math/big"
	"math/bits"
)

// ---------------------------------------------------------------------
// Shared, curve-agnostic uint64-limb helpers for the hand-rolled fast
// field implementations (variant 3). All limb arrays are little-endian
// (limb[0] holds bits 0..63).
//
// mulSchoolbook uses a carry-ripple accumulation rather than a single
// scalar "carry" variable: bits.Mul64's high word is bounded by 2^64-2,
// but hi+carry-in+carry-in can theoretically reach exactly 2^64 with a
// naive 3-term add, silently dropping a carry. Propagating each partial
// product one bit-carry at a time (rippleAdd) is slightly more verbose
// but mechanically provably correct, which matters more here than a
// few saved cycles in the schoolbook multiply.
// ---------------------------------------------------------------------

func rippleAdd(buf []uint64, pos int, val uint64) {
	for val != 0 {
		if pos >= len(buf) {
			panic("rippleAdd: carry overflowed destination buffer")
		}
		sum, carry := bits.Add64(buf[pos], val, 0)
		buf[pos] = sum
		val = carry
		pos++
	}
}

// mulSchoolbookInto multiplies two equal-length limb arrays into a
// caller-provided dst (len(dst) == 2*len(x), zeroed first). Avoiding
// an allocation per call matters a lot here: this is called on every
// single field multiplication, and on a single-core-pinned box (this
// task's mandatory safety rule) GC competes with the mutator for that
// same one core, so allocation-heavy code pays a disproportionate
// price. An earlier allocating version (mulSchoolbook, kept below for
// the validate tests) measured point-additions no faster than the
// generic math/big backend — entirely explained by this.
func mulSchoolbookInto(dst, x, y []uint64) {
	for i := range dst {
		dst[i] = 0
	}
	n := len(x)
	for i := 0; i < n; i++ {
		if x[i] == 0 {
			continue
		}
		for j := 0; j < n; j++ {
			hi, lo := bits.Mul64(x[i], y[j])
			rippleAdd(dst, i+j, lo)
			rippleAdd(dst, i+j+1, hi)
		}
	}
}

// mulSchoolbook is the allocating convenience wrapper, kept for tests
// and one-off/init-time call sites where allocation cost is moot.
func mulSchoolbook(x, y []uint64) []uint64 {
	result := make([]uint64, 2*len(x))
	mulSchoolbookInto(result, x, y)
	return result
}

func addLimbsRaw(z, x, y []uint64) uint64 {
	var c uint64
	for i := range z {
		z[i], c = bits.Add64(x[i], y[i], c)
	}
	return c
}

func subLimbsRaw(z, x, y []uint64) uint64 {
	var b uint64
	for i := range z {
		z[i], b = bits.Sub64(x[i], y[i], b)
	}
	return b
}

// cmpLimbs returns -1, 0, +1 as x <,==,> y (same length, little-endian).
func cmpLimbs(x, y []uint64) int {
	for i := len(x) - 1; i >= 0; i-- {
		if x[i] != y[i] {
			if x[i] < y[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func isZeroLimbs(x []uint64) bool {
	for _, v := range x {
		if v != 0 {
			return false
		}
	}
	return true
}

func bigToLimbs(v *big.Int, n int) []uint64 {
	out := make([]uint64, n)
	tmp := new(big.Int).Set(v)
	mask := new(big.Int).SetUint64(^uint64(0))
	for i := 0; i < n; i++ {
		w := new(big.Int).And(tmp, mask)
		out[i] = w.Uint64()
		tmp.Rsh(tmp, 64)
	}
	if tmp.Sign() != 0 {
		panic("bigToLimbs: value does not fit in n limbs")
	}
	return out
}

func limbsToBig(limbs []uint64) *big.Int {
	out := new(big.Int)
	for i := len(limbs) - 1; i >= 0; i-- {
		out.Lsh(out, 64)
		out.Or(out, new(big.Int).SetUint64(limbs[i]))
	}
	return out
}
