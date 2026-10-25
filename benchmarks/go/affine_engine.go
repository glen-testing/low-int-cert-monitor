package main

import "math/big"

// ---------------------------------------------------------------------
// Variant 1: affine + per-step modular inverse (math/big). This mirrors
// the naive Python reference and exists purely as the slow baseline
// data point in `bench`; it is never used for the real sweep.
// ---------------------------------------------------------------------

// affineAddBig adds two distinct affine points, or doubles if they are
// equal, on an a=-3 curve mod p. One ModInverse per call either way.
func affineAddBig(mod, x1, y1, x2, y2 *big.Int) (x3, y3 *big.Int) {
	if x1.Cmp(x2) == 0 {
		if y1.Cmp(y2) == 0 {
			return affineDoubleBig(mod, x1, y1)
		}
		// P + (-P): undefined/infinity. Not reachable while sweeping
		// G with d < n, included only for completeness.
		return big.NewInt(0), big.NewInt(0)
	}
	num := submod(y2, y1, mod)
	den := submod(x2, x1, mod)
	inv := new(big.Int).ModInverse(den, mod)
	if inv == nil {
		panic("affineAddBig: non-invertible denominator")
	}
	lambda := mulmod(num, inv, mod)
	x3 = submod(submod(mulmod(lambda, lambda, mod), x1, mod), x2, mod)
	y3 = submod(mulmod(lambda, submod(x1, x3, mod), mod), y1, mod)
	return
}
