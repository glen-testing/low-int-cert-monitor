package main

import "math/big"

type jacP384 struct{ X, Y, Z Elt384 }

var p384One Elt384

func init() { p384One = p384FromBig(big.NewInt(1)) }

func jacAffineP384(x, y Elt384) *jacP384 { return &jacP384{X: x, Y: y, Z: p384One} }
func jacInfinityP384() *jacP384          { return &jacP384{X: p384One, Y: p384One, Z: Elt384{}} }

func (p *jacP384) toAffine() (Elt384, Elt384) {
	zinv := p384Inverse(p.Z)
	zinv2 := p384Sqr(zinv)
	zinv3 := p384Mul(zinv2, zinv)
	return p384Mul(p.X, zinv2), p384Mul(p.Y, zinv3)
}

func mixedAddP384(p *jacP384, ax, ay Elt384) *jacP384 {
	if p384IsZero(p.Z) {
		return jacAffineP384(ax, ay)
	}
	Z1Z1 := p384Sqr(p.Z)
	Z1cubed := p384Mul(Z1Z1, p.Z)
	U2 := p384Mul(ax, Z1Z1)
	S2 := p384Mul(ay, Z1cubed)
	H := p384Sub(U2, p.X)
	if p384IsZero(H) {
		r0 := p384Sub(S2, p.Y)
		mod := curveParams[P384].P
		if p384IsZero(r0) {
			px, py := p.toAffine()
			x3, y3 := affineDoubleBig(mod, px.ToBig(), py.ToBig())
			return jacAffineP384(p384FromBig(x3), p384FromBig(y3))
		}
		return jacInfinityP384()
	}
	HH := p384Sqr(H)
	I := p384Dbl(p384Dbl(HH))
	J := p384Mul(H, I)
	diff := p384Sub(S2, p.Y)
	r := p384Dbl(diff)
	V := p384Mul(p.X, I)
	r2 := p384Sqr(r)
	X3 := p384Sub(p384Sub(r2, J), p384Dbl(V))
	T1 := p384Sub(V, X3)
	Y3 := p384Sub(p384Mul(r, T1), p384Dbl(p384Mul(p.Y, J)))
	Z3 := p384Mul(p384Dbl(p.Z), H)
	return &jacP384{X: X3, Y: Y3, Z: Z3}
}

func batchNormalizeP384(pts []*jacP384) (xs, ys []Elt384, ok []bool) {
	n := len(pts)
	xs, ys, ok = make([]Elt384, n), make([]Elt384, n), make([]bool, n)
	idx := make([]int, 0, n)
	for i, p := range pts {
		if !p384IsZero(p.Z) {
			idx = append(idx, i)
		}
	}
	if len(idx) == 0 {
		return
	}
	c := make([]Elt384, len(idx))
	acc := p384One
	for k, i := range idx {
		acc = p384Mul(acc, pts[i].Z)
		c[k] = acc
	}
	inv := p384Inverse(acc)
	for k := len(idx) - 1; k >= 0; k-- {
		i := idx[k]
		var zinv Elt384
		if k == 0 {
			zinv = inv
		} else {
			zinv = p384Mul(inv, c[k-1])
		}
		inv = p384Mul(inv, pts[i].Z)
		zinv2 := p384Sqr(zinv)
		zinv3 := p384Mul(zinv2, zinv)
		xs[i] = p384Mul(pts[i].X, zinv2)
		ys[i] = p384Mul(pts[i].Y, zinv3)
		ok[i] = true
	}
	return
}

func buildChainP384(params *CurveParams, genX, genY *big.Int, count int) []*jacP384 {
	out := make([]*jacP384, count)
	if count == 0 {
		return out
	}
	gx, gy := p384FromBig(genX), p384FromBig(genY)
	out[0] = jacAffineP384(gx, gy)
	if count == 1 {
		return out
	}
	x2, y2 := affineDoubleBig(params.P, genX, genY)
	out[1] = jacAffineP384(p384FromBig(x2), p384FromBig(y2))
	for k := 2; k < count; k++ {
		out[k] = mixedAddP384(out[k-1], gx, gy)
	}
	return out
}
