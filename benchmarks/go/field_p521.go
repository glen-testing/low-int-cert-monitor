package main

import "math/big"

// ---------------------------------------------------------------------
// Variant 3 (P-521): hand-rolled uint64-limb field arithmetic with
// Mersenne reduction. p521 = 2^521 - 1, so 2^521 == 1 (mod p): folding
// the product's high half down and adding it to the low half reduces
// mod p in O(1) folds, with no curve-specific magic constants needed
// (lowest risk of the three hand-rolled reductions).
//
// Representation: value = sum limb[i]*2^(64i), i=0..8 (9 limbs, 576
// bit container). A fully-reduced element has limb[8] < 2^9 (bits
// 521..575 are always zero) and value < p.
// ---------------------------------------------------------------------

const p521Limbs = 9

type Elt521 struct{ l [p521Limbs]uint64 }

// p521Mod's limbs are derived from curveParams at init time (not
// hand-transcribed) to remove any risk of a manual hex-splitting error.
var p521Mod Elt521

func init() {
	copy(p521Mod.l[:], bigToLimbs(curveParams[P521].P, p521Limbs))
}

func p521FromBig(v *big.Int) Elt521 {
	var e Elt521
	copy(e.l[:], bigToLimbs(v, p521Limbs))
	return e
}

func (e Elt521) ToBig() *big.Int { return limbsToBig(e.l[:]) }

// p521ProdLimbs (18 = 2*p521Limbs) is fixed; fixed-size local arrays
// throughout this function keep it allocation-free (see the
// mulSchoolbookInto comment on why that matters under GOMAXPROCS=1).
const p521ProdLimbs = 2 * p521Limbs

func p521reduceToRange(v []uint64) Elt521 {
	var cur [p521ProdLimbs]uint64
	copy(cur[:], v)
	for iter := 0; ; iter++ {
		if iter > 8 {
			panic("p521reduceToRange: fold did not converge")
		}
		hasHigh := false
		for i := p521Limbs; i < p521ProdLimbs; i++ {
			if cur[i] != 0 {
				hasHigh = true
				break
			}
		}
		if !hasHigh && cur[8]>>9 == 0 {
			break
		}
		// Thi = cur >> 521, Tlo = cur & (2^521-1), both into 9-limb buffers.
		var hi, lo, sum [p521Limbs]uint64
		for k := 0; k < p521Limbs; k++ {
			var lo64, hi64 uint64
			if k+8 < p521ProdLimbs {
				lo64 = cur[k+8] >> 9
			}
			if k+9 < p521ProdLimbs {
				hi64 = cur[k+9] << 55
			}
			hi[k] = lo64 | hi64
		}
		copy(lo[:], cur[:p521Limbs])
		lo[8] &= 0x1FF
		carry := addLimbsRaw(sum[:], lo[:], hi[:])
		if carry != 0 {
			panic("p521reduceToRange: unexpected carry out of 9-limb fold")
		}
		for i := range cur {
			cur[i] = 0
		}
		copy(cur[:p521Limbs], sum[:])
	}
	var out [p521Limbs]uint64
	copy(out[:], cur[:p521Limbs])
	e := Elt521{l: out}
	for cmpLimbs(e.l[:], p521Mod.l[:]) >= 0 {
		var z [p521Limbs]uint64
		subLimbsRaw(z[:], e.l[:], p521Mod.l[:])
		e.l = z
	}
	return e
}

func p521Add(x, y Elt521) Elt521 {
	var z [p521Limbs]uint64
	carry := addLimbsRaw(z[:], x.l[:], y.l[:])
	e := Elt521{l: z}
	if carry != 0 || cmpLimbs(e.l[:], p521Mod.l[:]) >= 0 {
		var r [p521Limbs]uint64
		subLimbsRaw(r[:], e.l[:], p521Mod.l[:])
		e.l = r
	}
	return e
}

func p521Sub(x, y Elt521) Elt521 {
	var z [p521Limbs]uint64
	borrow := subLimbsRaw(z[:], x.l[:], y.l[:])
	e := Elt521{l: z}
	if borrow != 0 {
		var r [p521Limbs]uint64
		addLimbsRaw(r[:], e.l[:], p521Mod.l[:])
		e.l = r
	}
	return e
}

func p521Dbl(x Elt521) Elt521 { return p521Add(x, x) }

func p521Mul(x, y Elt521) Elt521 {
	var prod [p521ProdLimbs]uint64
	mulSchoolbookInto(prod[:], x.l[:], y.l[:])
	return p521reduceToRange(prod[:])
}

func p521Sqr(x Elt521) Elt521 { return p521Mul(x, x) }

func p521Inverse(x Elt521) Elt521 {
	// Rarely used (batch normalization only): bridge through math/big.
	inv := new(big.Int).ModInverse(x.ToBig(), curveParams[P521].P)
	if inv == nil {
		panic("p521Inverse: not invertible")
	}
	return p521FromBig(inv)
}

func p521IsZero(x Elt521) bool { return isZeroLimbs(x.l[:]) }
