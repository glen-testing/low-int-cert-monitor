package main

import (
	"math/big"
	"math/bits"
)

// ---------------------------------------------------------------------
// Variant 3 (P-384): hand-rolled uint64-limb field arithmetic using
// generic Montgomery multiplication (SOS method) instead of a
// curve-specific Solinas word formula.
//
// Rationale: P-384's NIST reduction constants (FIPS 186-4 App. D.2)
// are long and, unlike P-256's, not something this implementation can
// recite with full confidence from memory; getting a hand-transcribed
// Solinas formula subtly wrong would silently corrupt the fast path of
// a tool whose whole job is to not miss weak keys. Montgomery
// multiplication is prime-agnostic (same code for every modulus, only
// n0inv and R^2 mod n differ, both computed once at init via
// math/big, off the hot path) and is the standard fallback this task's
// own instructions allow ("generic big.Int path... fix or fall back").
// It is still pure uint64/math/bits arithmetic in the hot path, no
// math/big — just not curve-specific-formula "fast NIST reduction".
// Elements are stored internally in Montgomery form (v*R mod p,
// R=2^384); Add/Sub/Double are unaffected by the R scaling (it factors
// out), only Mul/FromBig/ToBig need the Montgomery-specific handling.
// ---------------------------------------------------------------------

const p384Limbs = 6

type Elt384 struct{ l [p384Limbs]uint64 } // Montgomery form: stores v*R mod p

var (
	p384ModPlain [p384Limbs]uint64
	p384N0inv    uint64 // -p384ModPlain[0]^{-1} mod 2^64
	p384R2       [p384Limbs]uint64
)

// invMod64 computes n^{-1} mod 2^64 for odd n via Newton/Hensel
// iteration (doubles correct bits each step; 6 steps covers 64 bits).
// All arithmetic is native uint64, so overflow wraparound IS mod 2^64.
func invMod64(n uint64) uint64 {
	x := uint64(1)
	for i := 0; i < 6; i++ {
		x = x * (2 - n*x)
	}
	return x
}

func init() {
	copy(p384ModPlain[:], bigToLimbs(curveParams[P384].P, p384Limbs))
	p384N0inv = -invMod64(p384ModPlain[0])
	R := new(big.Int).Lsh(big.NewInt(1), 64*p384Limbs)
	r2 := new(big.Int).Mod(new(big.Int).Mul(R, R), curveParams[P384].P)
	copy(p384R2[:], bigToLimbs(r2, p384Limbs))
}

// p384BufLimbs is fixed (2*p384Limbs+2 = 14); using a local array
// instead of make() keeps this entirely allocation-free. See the
// mulSchoolbookInto comment: with GOMAXPROCS=1 (this task's mandatory
// single-core rule), GC competes with the mutator for the one
// available core, so allocation in the field-arithmetic hot path is
// disproportionately expensive.
const p384BufLimbs = 2*p384Limbs + 2

func p384MontMul(a, b [p384Limbs]uint64) [p384Limbs]uint64 {
	var buf [p384BufLimbs]uint64
	mulSchoolbookInto(buf[:2*p384Limbs], a[:], b[:])
	for i := 0; i < p384Limbs; i++ {
		m := buf[i] * p384N0inv
		for j := 0; j < p384Limbs; j++ {
			hi, lo := bits.Mul64(m, p384ModPlain[j])
			rippleAdd(buf[:], i+j, lo)
			rippleAdd(buf[:], i+j+1, hi)
		}
	}
	for i := 0; i < p384Limbs; i++ {
		if buf[i] != 0 {
			panic("p384MontMul: low limb not cleared by reduction (formula bug)")
		}
	}
	var wide, modPadded [p384Limbs + 2]uint64
	copy(wide[:], buf[p384Limbs:])
	copy(modPadded[:], p384ModPlain[:])
	for iter := 0; cmpLimbs(wide[:], modPadded[:]) >= 0; iter++ {
		if iter > 64 {
			panic("p384MontMul: final reduction did not converge")
		}
		var next [p384Limbs + 2]uint64
		subLimbsRaw(next[:], wide[:], modPadded[:])
		wide = next
	}
	var out [p384Limbs]uint64
	copy(out[:], wide[:p384Limbs])
	if wide[p384Limbs] != 0 || wide[p384Limbs+1] != 0 {
		panic("p384MontMul: result did not fit in the field width")
	}
	return out
}

func p384FromBig(v *big.Int) Elt384 {
	plain := [p384Limbs]uint64{}
	copy(plain[:], bigToLimbs(v, p384Limbs))
	return Elt384{l: p384MontMul(plain, p384R2)}
}

func (e Elt384) ToBig() *big.Int {
	one := [p384Limbs]uint64{1}
	plain := p384MontMul(e.l, one)
	return limbsToBig(plain[:])
}

func p384Add(x, y Elt384) Elt384 {
	var z [p384Limbs]uint64
	carry := addLimbsRaw(z[:], x.l[:], y.l[:])
	e := Elt384{l: z}
	if carry != 0 || cmpLimbs(e.l[:], p384ModPlain[:]) >= 0 {
		var r [p384Limbs]uint64
		subLimbsRaw(r[:], e.l[:], p384ModPlain[:])
		e.l = r
	}
	return e
}

func p384Sub(x, y Elt384) Elt384 {
	var z [p384Limbs]uint64
	borrow := subLimbsRaw(z[:], x.l[:], y.l[:])
	e := Elt384{l: z}
	if borrow != 0 {
		var r [p384Limbs]uint64
		addLimbsRaw(r[:], e.l[:], p384ModPlain[:])
		e.l = r
	}
	return e
}

func p384Dbl(x Elt384) Elt384 { return p384Add(x, x) }

func p384Mul(x, y Elt384) Elt384 { return Elt384{l: p384MontMul(x.l, y.l)} }
func p384Sqr(x Elt384) Elt384    { return p384Mul(x, x) }

func p384Inverse(x Elt384) Elt384 {
	inv := new(big.Int).ModInverse(x.ToBig(), curveParams[P384].P)
	if inv == nil {
		panic("p384Inverse: not invertible")
	}
	return p384FromBig(inv)
}

func p384IsZero(x Elt384) bool { return isZeroLimbs(x.l[:]) }
