package main

import "math/big"

// ---------------------------------------------------------------------
// Jacobian point arithmetic (variant 2 formula: madd-2004-hmv mixed
// addition, derived/cross-checked in bigint_engine.go) instantiated on
// the hand-rolled fast P-256 field (variant 3). Structurally identical
// to jacPointBig; kept as a separate concrete type (not a generic) so
// the ns/add benchmark measures the fast field's real cost, with zero
// interface/dispatch overhead in the hot path.
// ---------------------------------------------------------------------

type jacP256 struct{ X, Y, Z Elt256 }

var p256One Elt256

func init() { p256One = p256FromBig(big.NewInt(1)) }

func jacAffineP256(x, y Elt256) *jacP256 { return &jacP256{X: x, Y: y, Z: p256One} }
func jacInfinityP256() *jacP256          { return &jacP256{X: p256One, Y: p256One, Z: Elt256{}} }

func (p *jacP256) toAffine() (Elt256, Elt256) {
	zinv := p256Inverse(p.Z)
	zinv2 := p256Sqr(zinv)
	zinv3 := p256Mul(zinv2, zinv)
	return p256Mul(p.X, zinv2), p256Mul(p.Y, zinv3)
}

// mixedAddP256 computes p + (ax,ay) using madd-2004-hmv, falling back
// to a one-inverse affine computation (bridged through math/big) on
// the rare same-x edge cases (doubling, or point + its negation).
func mixedAddP256(p *jacP256, ax, ay Elt256) *jacP256 {
	if p256IsZero(p.Z) {
		return jacAffineP256(ax, ay)
	}
	Z1Z1 := p256Sqr(p.Z)
	Z1cubed := p256Mul(Z1Z1, p.Z)
	U2 := p256Mul(ax, Z1Z1)
	S2 := p256Mul(ay, Z1cubed)
	H := p256Sub(U2, p.X)
	if p256IsZero(H) {
		r0 := p256Sub(S2, p.Y)
		mod := curveParams[P256].P
		if p256IsZero(r0) {
			px, py := p.toAffine()
			x3, y3 := affineDoubleBig(mod, px.ToBig(), py.ToBig())
			return jacAffineP256(p256FromBig(x3), p256FromBig(y3))
		}
		return jacInfinityP256()
	}
	HH := p256Sqr(H)
	I := p256Dbl(p256Dbl(HH))
	J := p256Mul(H, I)
	diff := p256Sub(S2, p.Y)
	r := p256Dbl(diff)
	V := p256Mul(p.X, I)
	r2 := p256Sqr(r)
	X3 := p256Sub(p256Sub(r2, J), p256Dbl(V))
	T1 := p256Sub(V, X3)
	Y3 := p256Sub(p256Mul(r, T1), p256Dbl(p256Mul(p.Y, J)))
	Z3 := p256Mul(p256Dbl(p.Z), H)
	return &jacP256{X: X3, Y: Y3, Z: Z3}
}

// batchNormalizeP256 converts a slice of Jacobian points to affine
// using Montgomery's trick (one field inverse for the whole batch).
// Points at infinity normalize to ok=false.
func batchNormalizeP256(pts []*jacP256) (xs, ys []Elt256, ok []bool) {
	n := len(pts)
	xs, ys, ok = make([]Elt256, n), make([]Elt256, n), make([]bool, n)
	idx := make([]int, 0, n)
	for i, p := range pts {
		if !p256IsZero(p.Z) {
			idx = append(idx, i)
		}
	}
	if len(idx) == 0 {
		return
	}
	c := make([]Elt256, len(idx))
	acc := p256One
	for k, i := range idx {
		acc = p256Mul(acc, pts[i].Z)
		c[k] = acc
	}
	inv := p256Inverse(acc)
	for k := len(idx) - 1; k >= 0; k-- {
		i := idx[k]
		var zinv Elt256
		if k == 0 {
			zinv = inv
		} else {
			zinv = p256Mul(inv, c[k-1])
		}
		inv = p256Mul(inv, pts[i].Z)
		zinv2 := p256Sqr(zinv)
		zinv3 := p256Mul(zinv2, zinv)
		xs[i] = p256Mul(pts[i].X, zinv2)
		ys[i] = p256Mul(pts[i].Y, zinv3)
		ok[i] = true
	}
	return
}

// buildChainP256 returns Jacobian 1*gen..count*gen (index k-1 == k*gen).
func buildChainP256(params *CurveParams, genX, genY *big.Int, count int) []*jacP256 {
	out := make([]*jacP256, count)
	if count == 0 {
		return out
	}
	gx, gy := p256FromBig(genX), p256FromBig(genY)
	out[0] = jacAffineP256(gx, gy)
	if count == 1 {
		return out
	}
	x2, y2 := affineDoubleBig(params.P, genX, genY)
	out[1] = jacAffineP256(p256FromBig(x2), p256FromBig(y2))
	for k := 2; k < count; k++ {
		out[k] = mixedAddP256(out[k-1], gx, gy)
	}
	return out
}
