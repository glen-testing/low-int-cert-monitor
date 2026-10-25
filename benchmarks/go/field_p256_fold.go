package main

import "math/big"

// ---------------------------------------------------------------------
// P-256 generalized-Mersenne ("Solinas-style") fast reduction for
// p256 = 2^256 - 2^224 + 2^192 + 2^96 - 1, i.e.
// 2^256 == 2^224-2^192-2^96+1 (mod p256).
//
// This is a SEPARATE type (Elt256Plain, plain/non-Montgomery
// representation) from the production Elt256 in field_p256.go, kept
// alive purely as the other half of the "Fast NIST reduction vs
// generic Montgomery multiplication — compare both" benchmark
// datapoint (see field_p256.go's header for why Montgomery won the
// production slot). Keeping it a distinct type makes it impossible to
// accidentally mix a Montgomery-form and plain-form Elt256 in an
// arithmetic op.
//
// NOTE on method: an earlier attempt transcribed the classic FIPS
// 186-4 Appendix D.2 32-bit-word S1..S9 reduction formula from memory.
// It FAILED random-vector validation against math/big (caught by
// field_validate_test.go before anything downstream ever trusted it —
// exactly the gate this task requires). Rather than keep debugging a
// memorized word table with no reference to check against, this
// re-derives the same mathematical identity directly from the prime's
// structure and implements it as a small bounded loop of shifts/adds,
// which is mechanically simpler to get right and to verify:
//
//   T = Vlo + Vhi*2^256         (Vlo, Vhi: 256-bit halves of the 512-bit product)
//   T mod p = Vlo + Vhi*2^224 - Vhi*2^192 - Vhi*2^96 + Vhi   (mod p)
//
// The right-hand side can still exceed 256 bits (Vhi*2^224 is up to 480
// bits), so this fold is applied repeatedly — each application shrinks
// the bit length by roughly 32 bits — until the value fits in 256 bits,
// tracking sign explicitly (the pos/neg terms can cross), then a final
// bounded conditional-subtract brings it into [0,p). Validated against
// math/big over tens of thousands of random vectors in
// field_validate_test.go.
// ---------------------------------------------------------------------

type Elt256Plain struct{ l [p256Limbs]uint64 }

func p256FromBigPlain(v *big.Int) Elt256Plain {
	var e Elt256Plain
	copy(e.l[:], bigToLimbs(v, p256Limbs))
	return e
}
func (e Elt256Plain) ToBig() *big.Int { return limbsToBig(e.l[:]) }

func p256MulFold(x, y Elt256Plain) Elt256Plain {
	var prod [8]uint64 // 512 bits; local fixed array, no heap allocation
	mulSchoolbookInto(prod[:], x.l[:], y.l[:])
	return p256ReduceWideFold(prod[:])
}

// trimLen returns the number of significant limbs (dropping high
// all-zero ones) without allocating.
func trimLen(x []uint64) int {
	n := len(x)
	for n > 0 && x[n-1] == 0 {
		n--
	}
	return n
}

// p256ScratchLimbs is a generous fixed width for every intermediate
// value in the fold below: mag never exceeds 512 bits (8 limbs) at the
// start of an iteration (see the file comment's shrinkage argument),
// and within one iteration the widest term is bounded by
// mag_bits+224 <= 736 bits (11.5 limbs) — 16 limbs (1024 bits) is
// ample headroom. Fixed-size local arrays (not make()) keep the whole
// reduction allocation-free.
const p256ScratchLimbs = 16

// shiftLeftFixed writes src<<bits into dst (zeroing it first).
func shiftLeftFixed(dst *[p256ScratchLimbs]uint64, src []uint64, bits int) {
	for i := range dst {
		dst[i] = 0
	}
	wordShift := bits / 64
	bitShift := uint(bits % 64)
	for i, v := range src {
		if v == 0 {
			continue
		}
		if bitShift == 0 {
			rippleAdd(dst[:], i+wordShift, v)
		} else {
			rippleAdd(dst[:], i+wordShift, v<<bitShift)
			rippleAdd(dst[:], i+wordShift+1, v>>(64-bitShift))
		}
	}
}

func addIntoFixed(dst *[p256ScratchLimbs]uint64, src []uint64) {
	for i, v := range src {
		if v != 0 {
			rippleAdd(dst[:], i, v)
		}
	}
}

// p256ReduceWideFold reduces an arbitrary-width non-negative value (as
// produced by mulSchoolbook) modulo p256, by repeatedly folding the
// part at or above bit 256 down using 2^256 == 2^224-2^192-2^96+1.
func p256ReduceWideFold(v []uint64) Elt256Plain {
	var mag [p256ScratchLimbs]uint64
	copy(mag[:], v)
	n := trimLen(mag[:])
	neg := false

	var vlo, t224, t192, t96, pos, negPart, diff [p256ScratchLimbs]uint64
	for n > 4 {
		for i := range vlo {
			vlo[i] = 0
		}
		copy(vlo[:4], mag[:4])
		vhi := mag[4:n]

		shiftLeftFixed(&t224, vhi, 224)
		shiftLeftFixed(&t192, vhi, 192)
		shiftLeftFixed(&t96, vhi, 96)

		for i := range pos {
			pos[i] = 0
		}
		addIntoFixed(&pos, vlo[:])
		addIntoFixed(&pos, t224[:])
		addIntoFixed(&pos, vhi)

		for i := range negPart {
			negPart[i] = 0
		}
		addIntoFixed(&negPart, t192[:])
		addIntoFixed(&negPart, t96[:])

		var newNeg bool
		if cmpLimbs(pos[:], negPart[:]) >= 0 {
			subLimbsRaw(diff[:], pos[:], negPart[:])
			newNeg = false
		} else {
			subLimbsRaw(diff[:], negPart[:], pos[:])
			newNeg = true
		}
		neg = neg != newNeg // sign composes by XOR each fold
		mag = diff
		n = trimLen(mag[:])
	}

	var m4 [4]uint64
	copy(m4[:], mag[:4])
	for iter := 0; cmpLimbs(m4[:], p256Mod.l[:]) >= 0; iter++ {
		if iter > 16 {
			panic("p256ReduceWideFold: final normalization did not converge")
		}
		var r [4]uint64
		subLimbsRaw(r[:], m4[:], p256Mod.l[:])
		m4 = r
	}
	if neg && !isZeroLimbs(m4[:]) {
		var r [4]uint64
		subLimbsRaw(r[:], p256Mod.l[:], m4[:])
		m4 = r
	}
	return Elt256Plain{l: m4}
}
