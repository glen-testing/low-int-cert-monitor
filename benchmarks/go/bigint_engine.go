package main

import "math/big"

// ---------------------------------------------------------------------
// Generic (variant 1 & 2) field + Jacobian point arithmetic backed by
// math/big. This is the trusted reference implementation: every other
// backend (hand-rolled limb fields) is validated against it in
// validate_test.go before being trusted for a "clean" verdict.
// ---------------------------------------------------------------------

func mulmod(a, b, m *big.Int) *big.Int {
	z := new(big.Int).Mul(a, b)
	z.Mod(z, m)
	return z
}
func addmod(a, b, m *big.Int) *big.Int {
	z := new(big.Int).Add(a, b)
	z.Mod(z, m)
	return z
}
func submod(a, b, m *big.Int) *big.Int {
	z := new(big.Int).Sub(a, b)
	z.Mod(z, m)
	return z
}
func dblmod(a, m *big.Int) *big.Int {
	z := new(big.Int).Lsh(a, 1)
	z.Mod(z, m)
	return z
}

// jacPointBig is a point in Jacobian coordinates (X,Y,Z) representing
// affine (X/Z^2, Y/Z^3). Z==0 denotes the point at infinity.
type jacPointBig struct{ X, Y, Z *big.Int }

func jacAffineBig(x, y *big.Int) *jacPointBig {
	return &jacPointBig{X: new(big.Int).Set(x), Y: new(big.Int).Set(y), Z: big.NewInt(1)}
}
func jacInfinityBig() *jacPointBig {
	return &jacPointBig{X: big.NewInt(1), Y: big.NewInt(1), Z: big.NewInt(0)}
}

// affineDoubleBig doubles an affine point on a=-3 curves using a single
// modular inverse. Only used on the rare (at most once per chain, or
// once per giant-step walk) H==0-same-point edge case, so its cost is
// negligible overall.
func affineDoubleBig(mod, x, y *big.Int) (x3, y3 *big.Int) {
	num := submod(mulmod(big.NewInt(3), mulmod(x, x, mod), mod), big.NewInt(3), mod)
	den := dblmod(y, mod)
	inv := new(big.Int).ModInverse(den, mod)
	if inv == nil {
		panic("affineDoubleBig: y has no inverse mod p (y==0?)")
	}
	lambda := mulmod(num, inv, mod)
	x3 = submod(mulmod(lambda, lambda, mod), dblmod(x, mod), mod)
	y3 = submod(mulmod(lambda, submod(x, x3, mod), mod), y, mod)
	return
}

// mixedAddBig computes P + (ax,ay) where P is Jacobian and (ax,ay) is
// affine, using the madd-2004-hmv formulas (Z2=1 specialization of the
// general Jacobian addition law), with explicit fallback for the
// doubling / point-at-infinity edge cases that formula cannot handle.
func mixedAddBig(mod *big.Int, p *jacPointBig, ax, ay *big.Int) *jacPointBig {
	if p.Z.Sign() == 0 {
		return jacAffineBig(ax, ay)
	}
	Z1Z1 := mulmod(p.Z, p.Z, mod)
	Z1cubed := mulmod(Z1Z1, p.Z, mod)
	U2 := mulmod(ax, Z1Z1, mod)
	S2 := mulmod(ay, Z1cubed, mod)
	H := submod(U2, p.X, mod)
	if H.Sign() == 0 {
		r0 := submod(S2, p.Y, mod)
		if r0.Sign() == 0 {
			// Same point: P == (ax,ay). Fall back to one-inverse affine doubling.
			px, py := toAffineBig(mod, p)
			x3, y3 := affineDoubleBig(mod, px, py)
			return jacAffineBig(x3, y3)
		}
		// P == -(ax,ay): result is the point at infinity.
		return jacInfinityBig()
	}
	HH := mulmod(H, H, mod)
	I := new(big.Int).Lsh(HH, 2)
	I.Mod(I, mod)
	J := mulmod(H, I, mod)
	r := dblmod(submod(S2, p.Y, mod), mod)
	V := mulmod(p.X, I, mod)
	r2 := mulmod(r, r, mod)
	X3 := submod(submod(r2, J, mod), dblmod(V, mod), mod)
	T1 := submod(V, X3, mod)
	Y3 := submod(mulmod(r, T1, mod), dblmod(mulmod(p.Y, J, mod), mod), mod)
	Z3 := mulmod(dblmod(p.Z, mod), H, mod)
	return &jacPointBig{X: X3, Y: Y3, Z: Z3}
}

func toAffineBig(mod *big.Int, p *jacPointBig) (x, y *big.Int) {
	if p.Z.Sign() == 0 {
		return nil, nil
	}
	if p.Z.Cmp(big.NewInt(1)) == 0 {
		return new(big.Int).Set(p.X), new(big.Int).Set(p.Y)
	}
	zinv := new(big.Int).ModInverse(p.Z, mod)
	zinv2 := mulmod(zinv, zinv, mod)
	zinv3 := mulmod(zinv2, zinv, mod)
	return mulmod(p.X, zinv2, mod), mulmod(p.Y, zinv3, mod)
}

// batchNormalizeBig converts a slice of Jacobian points to affine using
// Montgomery's trick: a single modular inverse for the whole batch.
// Points at infinity (Z==0) normalize to (nil,nil).
func batchNormalizeBig(mod *big.Int, pts []*jacPointBig) (xs, ys []*big.Int) {
	n := len(pts)
	xs = make([]*big.Int, n)
	ys = make([]*big.Int, n)
	idx := make([]int, 0, n)
	for i, p := range pts {
		if p.Z.Sign() != 0 {
			idx = append(idx, i)
		}
	}
	if len(idx) == 0 {
		return
	}
	c := make([]*big.Int, len(idx))
	acc := big.NewInt(1)
	for k, i := range idx {
		acc = mulmod(acc, pts[i].Z, mod)
		c[k] = new(big.Int).Set(acc)
	}
	inv := new(big.Int).ModInverse(acc, mod)
	if inv == nil {
		panic("batchNormalizeBig: batch Z product not invertible")
	}
	for k := len(idx) - 1; k >= 0; k-- {
		i := idx[k]
		var zinv *big.Int
		if k == 0 {
			zinv = inv
		} else {
			zinv = mulmod(inv, c[k-1], mod)
		}
		inv = mulmod(inv, pts[i].Z, mod)
		zinv2 := mulmod(zinv, zinv, mod)
		zinv3 := mulmod(zinv2, zinv, mod)
		xs[i] = mulmod(pts[i].X, zinv2, mod)
		ys[i] = mulmod(pts[i].Y, zinv3, mod)
	}
	return
}

// buildChainBig returns the Jacobian points 1*G, 2*G, ..., count*G
// (chain[k-1] == (k)*G), built with a single one-inverse doubling for
// the 1G->2G step and inversion-free mixed adds thereafter.
func buildChainBig(p *CurveParams, genX, genY *big.Int, count int) []*jacPointBig {
	out := make([]*jacPointBig, count)
	if count == 0 {
		return out
	}
	out[0] = jacAffineBig(genX, genY) // 1*gen
	if count == 1 {
		return out
	}
	x2, y2 := affineDoubleBig(p.P, genX, genY)
	out[1] = jacAffineBig(x2, y2) // 2*gen
	for k := 2; k < count; k++ {
		out[k] = mixedAddBig(p.P, out[k-1], genX, genY)
	}
	return out
}
