package main

import (
	"math/big"
	"time"
)

// ---------------------------------------------------------------------
// Variant 4: baby-step giant-step on the fastest validated field
// backend for each curve (the hand-rolled limb fields in field_p*.go,
// via the jac_p*.go mixed-add chains). Baby table: jG for j=1..m-1,
// giant stride S=mG. For each target T, walk T, T-S, T-2S, ... in
// blocks, batch-normalizing each block (Montgomery trick) before doing
// map lookups against the baby table. d=i*m+j; m is chosen so
// m*m > max, covering every d in [1,max].
//
// This never needs a general scalar-multiplication or point-doubling
// routine: 1G is direct, 2G uses one one-time affine doubling
// (bridged through math/big), and every other multiple (baby table
// entries, and every giant step T-i*S) is built by repeated mixed
// addition of a fixed affine point (G, or -S) — see jac_p*.go.
//
// Map keys are the raw [N]uint64 limb arrays (comparable, so usable
// directly as Go map keys) rather than math/big-derived byte strings:
// an earlier version converted every giant-step point through
// *big.Int for its lookup key, which allocates on every single step
// and dominated runtime (measured ~300us/add instead of the expected
// sub-microsecond — a real example of why the ns/add number is
// measured directly rather than assumed).
// ---------------------------------------------------------------------

type Hit struct {
	Target Target
	D      uint64
}

func isqrtU64(n uint64) uint64 {
	if n == 0 {
		return 0
	}
	r := new(big.Int).Sqrt(new(big.Int).SetUint64(n))
	return r.Uint64()
}

// giantBlockSize is large enough that the whole giant-step walk for
// max=1e8 (m=isqrt(1e8)+1=10001) fits in a single block per target —
// no block-transition logic exercised at all in the common case,
// and one Montgomery-trick inversion per target instead of three.
const giantBlockSize = 16384

// RunBSGS dispatches to the curve-specific fast-field BSGS sweep.
func RunBSGS(curve CurveID, targets []Target, max uint64) (hits []Hit, addCount uint64, elapsed time.Duration) {
	switch curve {
	case P256:
		return bsgsP256(targets, max)
	case P384:
		return bsgsP384(targets, max)
	case P521:
		return bsgsP521(targets, max)
	}
	panic("RunBSGS: unknown curve")
}

func bsgsP256(targets []Target, max uint64) (hits []Hit, addCount uint64, elapsed time.Duration) {
	params := curveParams[P256]
	t0 := time.Now()
	m := isqrtU64(max) + 1
	chain := buildChainP256(params, params.Gx, params.Gy, int(m))
	addCount += m - 2
	babyline := chain[:m-1]
	xs, ys, ok := batchNormalizeP256(babyline)
	type key = [4]uint64
	babyX := make(map[key]int, len(babyline))
	babyY := make(map[key]Elt256, len(babyline))
	for j := 0; j < len(babyline); j++ {
		if !ok[j] {
			continue
		}
		k := xs[j].l
		babyX[k] = j + 1
		babyY[k] = ys[j]
	}
	Sx, Sy := chain[m-1].toAffine()
	negSy := p256Sub(Elt256{}, Sy)

	for _, tgt := range targets {
		running := jacAffineP256(p256FromBig(tgt.X), p256FromBig(tgt.Y))
		found := false
		for i := uint64(0); i < m && !found; i += giantBlockSize {
			cur := giantBlockSize
			if i+uint64(cur) > m {
				cur = int(m - i)
			}
			block := make([]*jacP256, cur)
			if i == 0 {
				block[0] = running
			} else {
				// running is the previous block's last point (gi=i-1):
				// advance it one more step to reach gi=i. Omitting this
				// is an off-by-one that silently mislabels every giant
				// index from the second block on by +1 (found this via
				// selftest missing exactly the near-max-d controls,
				// whose true d got computed as d+m and filtered by the
				// d<=max check).
				block[0] = mixedAddP256(running, Sx, negSy)
				addCount++
			}
			for t := 1; t < cur; t++ {
				block[t] = mixedAddP256(block[t-1], Sx, negSy)
			}
			addCount += uint64(cur - 1)
			bxs, bys, bok := batchNormalizeP256(block)
			for t := 0; t < cur; t++ {
				gi := i + uint64(t)
				if !bok[t] {
					d := gi * m
					if d >= 1 && d <= max {
						hits = append(hits, Hit{tgt, d})
						found = true
					}
					continue
				}
				if j, ok := babyX[bxs[t].l]; ok && bys[t] == babyY[bxs[t].l] {
					d := gi*m + uint64(j)
					if d >= 1 && d <= max {
						hits = append(hits, Hit{tgt, d})
						found = true
					}
				}
			}
			running = block[cur-1]
		}
	}
	elapsed = time.Since(t0)
	return
}

func bsgsP384(targets []Target, max uint64) (hits []Hit, addCount uint64, elapsed time.Duration) {
	params := curveParams[P384]
	t0 := time.Now()
	m := isqrtU64(max) + 1
	chain := buildChainP384(params, params.Gx, params.Gy, int(m))
	addCount += m - 2
	babyline := chain[:m-1]
	xs, ys, ok := batchNormalizeP384(babyline)
	type key = [6]uint64
	babyX := make(map[key]int, len(babyline))
	babyY := make(map[key]Elt384, len(babyline))
	for j := 0; j < len(babyline); j++ {
		if !ok[j] {
			continue
		}
		k := xs[j].l
		babyX[k] = j + 1
		babyY[k] = ys[j]
	}
	Sx, Sy := chain[m-1].toAffine()
	negSy := p384Sub(Elt384{}, Sy)

	for _, tgt := range targets {
		running := jacAffineP384(p384FromBig(tgt.X), p384FromBig(tgt.Y))
		found := false
		for i := uint64(0); i < m && !found; i += giantBlockSize {
			cur := giantBlockSize
			if i+uint64(cur) > m {
				cur = int(m - i)
			}
			block := make([]*jacP384, cur)
			if i == 0 {
				block[0] = running
			} else {
				block[0] = mixedAddP384(running, Sx, negSy) // see P-256's comment on this off-by-one
				addCount++
			}
			for t := 1; t < cur; t++ {
				block[t] = mixedAddP384(block[t-1], Sx, negSy)
			}
			addCount += uint64(cur - 1)
			bxs, bys, bok := batchNormalizeP384(block)
			for t := 0; t < cur; t++ {
				gi := i + uint64(t)
				if !bok[t] {
					d := gi * m
					if d >= 1 && d <= max {
						hits = append(hits, Hit{tgt, d})
						found = true
					}
					continue
				}
				if j, ok := babyX[bxs[t].l]; ok && bys[t] == babyY[bxs[t].l] {
					d := gi*m + uint64(j)
					if d >= 1 && d <= max {
						hits = append(hits, Hit{tgt, d})
						found = true
					}
				}
			}
			running = block[cur-1]
		}
	}
	elapsed = time.Since(t0)
	return
}

func bsgsP521(targets []Target, max uint64) (hits []Hit, addCount uint64, elapsed time.Duration) {
	params := curveParams[P521]
	t0 := time.Now()
	m := isqrtU64(max) + 1
	chain := buildChainP521(params, params.Gx, params.Gy, int(m))
	addCount += m - 2
	babyline := chain[:m-1]
	xs, ys, ok := batchNormalizeP521(babyline)
	type key = [9]uint64
	babyX := make(map[key]int, len(babyline))
	babyY := make(map[key]Elt521, len(babyline))
	for j := 0; j < len(babyline); j++ {
		if !ok[j] {
			continue
		}
		k := xs[j].l
		babyX[k] = j + 1
		babyY[k] = ys[j]
	}
	Sx, Sy := chain[m-1].toAffine()
	negSy := p521Sub(Elt521{}, Sy)

	for _, tgt := range targets {
		running := jacAffineP521(p521FromBig(tgt.X), p521FromBig(tgt.Y))
		found := false
		for i := uint64(0); i < m && !found; i += giantBlockSize {
			cur := giantBlockSize
			if i+uint64(cur) > m {
				cur = int(m - i)
			}
			block := make([]*jacP521, cur)
			if i == 0 {
				block[0] = running
			} else {
				block[0] = mixedAddP521(running, Sx, negSy) // see P-256's comment on this off-by-one
				addCount++
			}
			for t := 1; t < cur; t++ {
				block[t] = mixedAddP521(block[t-1], Sx, negSy)
			}
			addCount += uint64(cur - 1)
			bxs, bys, bok := batchNormalizeP521(block)
			for t := 0; t < cur; t++ {
				gi := i + uint64(t)
				if !bok[t] {
					d := gi * m
					if d >= 1 && d <= max {
						hits = append(hits, Hit{tgt, d})
						found = true
					}
					continue
				}
				if j, ok := babyX[bxs[t].l]; ok && bys[t] == babyY[bxs[t].l] {
					d := gi*m + uint64(j)
					if d >= 1 && d <= max {
						hits = append(hits, Hit{tgt, d})
						found = true
					}
				}
			}
			running = block[cur-1]
		}
	}
	elapsed = time.Since(t0)
	return
}
