package main

import "math/big"

type jacP521 struct{ X, Y, Z Elt521 }

var p521One Elt521

func init() { p521One = p521FromBig(big.NewInt(1)) }

func jacAffineP521(x, y Elt521) *jacP521 { return &jacP521{X: x, Y: y, Z: p521One} }
func jacInfinityP521() *jacP521          { return &jacP521{X: p521One, Y: p521One, Z: Elt521{}} }

func (p *jacP521) toAffine() (Elt521, Elt521) {
	zinv := p521Inverse(p.Z)
	zinv2 := p521Sqr(zinv)
	zinv3 := p521Mul(zinv2, zinv)
	return p521Mul(p.X, zinv2), p521Mul(p.Y, zinv3)
}

func mixedAddP521(p *jacP521, ax, ay Elt521) *jacP521 {
	if p521IsZero(p.Z) {
		return jacAffineP521(ax, ay)
	}
	Z1Z1 := p521Sqr(p.Z)
	Z1cubed := p521Mul(Z1Z1, p.Z)
	U2 := p521Mul(ax, Z1Z1)
	S2 := p521Mul(ay, Z1cubed)
	H := p521Sub(U2, p.X)
	if p521IsZero(H) {
		r0 := p521Sub(S2, p.Y)
		mod := curveParams[P521].P
		if p521IsZero(r0) {
			px, py := p.toAffine()
			x3, y3 := affineDoubleBig(mod, px.ToBig(), py.ToBig())
			return jacAffineP521(p521FromBig(x3), p521FromBig(y3))
		}
		return jacInfinityP521()
	}
	HH := p521Sqr(H)
	I := p521Dbl(p521Dbl(HH))
	J := p521Mul(H, I)
	diff := p521Sub(S2, p.Y)
	r := p521Dbl(diff)
	V := p521Mul(p.X, I)
	r2 := p521Sqr(r)
	X3 := p521Sub(p521Sub(r2, J), p521Dbl(V))
	T1 := p521Sub(V, X3)
	Y3 := p521Sub(p521Mul(r, T1), p521Dbl(p521Mul(p.Y, J)))
	Z3 := p521Mul(p521Dbl(p.Z), H)
	return &jacP521{X: X3, Y: Y3, Z: Z3}
}

func batchNormalizeP521(pts []*jacP521) (xs, ys []Elt521, ok []bool) {
	n := len(pts)
	xs, ys, ok = make([]Elt521, n), make([]Elt521, n), make([]bool, n)
	idx := make([]int, 0, n)
	for i, p := range pts {
		if !p521IsZero(p.Z) {
			idx = append(idx, i)
		}
	}
	if len(idx) == 0 {
		return
	}
	c := make([]Elt521, len(idx))
	acc := p521One
	for k, i := range idx {
		acc = p521Mul(acc, pts[i].Z)
		c[k] = acc
	}
	inv := p521Inverse(acc)
	for k := len(idx) - 1; k >= 0; k-- {
		i := idx[k]
		var zinv Elt521
		if k == 0 {
			zinv = inv
		} else {
			zinv = p521Mul(inv, c[k-1])
		}
		inv = p521Mul(inv, pts[i].Z)
		zinv2 := p521Sqr(zinv)
		zinv3 := p521Mul(zinv2, zinv)
		xs[i] = p521Mul(pts[i].X, zinv2)
		ys[i] = p521Mul(pts[i].Y, zinv3)
		ok[i] = true
	}
	return
}

func buildChainP521(params *CurveParams, genX, genY *big.Int, count int) []*jacP521 {
	out := make([]*jacP521, count)
	if count == 0 {
		return out
	}
	gx, gy := p521FromBig(genX), p521FromBig(genY)
	out[0] = jacAffineP521(gx, gy)
	if count == 1 {
		return out
	}
	x2, y2 := affineDoubleBig(params.P, genX, genY)
	out[1] = jacAffineP521(p521FromBig(x2), p521FromBig(y2))
	for k := 2; k < count; k++ {
		out[k] = mixedAddP521(out[k-1], gx, gy)
	}
	return out
}
