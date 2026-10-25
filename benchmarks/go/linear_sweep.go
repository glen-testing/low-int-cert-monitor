package main

import (
	"time"
)

// ---------------------------------------------------------------------
// `bench --method linear`: one incremental sweep d=1..max per curve
// (G, 2G, 3G, ...) on the fast field backend, batch-normalized in
// blocks, checked against every target on that curve at once. This is
// the O(N) comparison method against BSGS's O(sqrt(N)); it is not
// used by selftest (BSGS is faster and is what selftest requires),
// but is useful for measuring real sweep throughput at scale.
//
// Lookup keys are raw limb arrays (see bsgs.go's comment on why: a
// *big.Int-per-step key allocation measured ~1000x slower than the
// field arithmetic it was supposedly just looking up).
// ---------------------------------------------------------------------

const linearBlockSize = 65536

func linearSweepP256(targets []Target, max uint64) (hits []Hit, addCount uint64, elapsed time.Duration) {
	params := curveParams[P256]
	t0 := time.Now()
	type key = [4]uint64
	targetByX := make(map[key]Target, len(targets))
	targetY := make(map[key]Elt256, len(targets))
	for _, t := range targets {
		k := p256FromBig(t.X).l
		targetByX[k] = t
		targetY[k] = p256FromBig(t.Y)
	}
	remaining := len(targetByX)
	gx, gy := p256FromBig(params.Gx), p256FromBig(params.Gy)

	var running *jacP256
	d := uint64(0)
	for d < max && remaining > 0 {
		cur := linearBlockSize
		if uint64(cur) > max-d {
			cur = int(max - d)
		}
		pts := make([]*jacP256, cur)
		for t := 0; t < cur; t++ {
			d++
			switch {
			case d == 1:
				running = jacAffineP256(gx, gy)
			case d == 2:
				x2, y2 := affineDoubleBig(params.P, params.Gx, params.Gy)
				running = jacAffineP256(p256FromBig(x2), p256FromBig(y2))
			default:
				running = mixedAddP256(running, gx, gy)
				addCount++
			}
			pts[t] = running
		}
		xs, ys, ok := batchNormalizeP256(pts)
		for t := 0; t < cur; t++ {
			if !ok[t] {
				continue
			}
			k := xs[t].l
			if tgt, found := targetByX[k]; found && ys[t] == targetY[k] {
				dHit := d - uint64(cur) + uint64(t) + 1
				hits = append(hits, Hit{tgt, dHit})
				delete(targetByX, k)
				remaining--
			}
		}
	}
	elapsed = time.Since(t0)
	return
}

func linearSweepP384(targets []Target, max uint64) (hits []Hit, addCount uint64, elapsed time.Duration) {
	params := curveParams[P384]
	t0 := time.Now()
	type key = [6]uint64
	targetByX := make(map[key]Target, len(targets))
	targetY := make(map[key]Elt384, len(targets))
	for _, t := range targets {
		k := p384FromBig(t.X).l
		targetByX[k] = t
		targetY[k] = p384FromBig(t.Y)
	}
	remaining := len(targetByX)
	gx, gy := p384FromBig(params.Gx), p384FromBig(params.Gy)

	var running *jacP384
	d := uint64(0)
	for d < max && remaining > 0 {
		cur := linearBlockSize
		if uint64(cur) > max-d {
			cur = int(max - d)
		}
		pts := make([]*jacP384, cur)
		for t := 0; t < cur; t++ {
			d++
			switch {
			case d == 1:
				running = jacAffineP384(gx, gy)
			case d == 2:
				x2, y2 := affineDoubleBig(params.P, params.Gx, params.Gy)
				running = jacAffineP384(p384FromBig(x2), p384FromBig(y2))
			default:
				running = mixedAddP384(running, gx, gy)
				addCount++
			}
			pts[t] = running
		}
		xs, ys, ok := batchNormalizeP384(pts)
		for t := 0; t < cur; t++ {
			if !ok[t] {
				continue
			}
			k := xs[t].l
			if tgt, found := targetByX[k]; found && ys[t] == targetY[k] {
				dHit := d - uint64(cur) + uint64(t) + 1
				hits = append(hits, Hit{tgt, dHit})
				delete(targetByX, k)
				remaining--
			}
		}
	}
	elapsed = time.Since(t0)
	return
}

func linearSweepP521(targets []Target, max uint64) (hits []Hit, addCount uint64, elapsed time.Duration) {
	params := curveParams[P521]
	t0 := time.Now()
	type key = [9]uint64
	targetByX := make(map[key]Target, len(targets))
	targetY := make(map[key]Elt521, len(targets))
	for _, t := range targets {
		k := p521FromBig(t.X).l
		targetByX[k] = t
		targetY[k] = p521FromBig(t.Y)
	}
	remaining := len(targetByX)
	gx, gy := p521FromBig(params.Gx), p521FromBig(params.Gy)

	var running *jacP521
	d := uint64(0)
	for d < max && remaining > 0 {
		cur := linearBlockSize
		if uint64(cur) > max-d {
			cur = int(max - d)
		}
		pts := make([]*jacP521, cur)
		for t := 0; t < cur; t++ {
			d++
			switch {
			case d == 1:
				running = jacAffineP521(gx, gy)
			case d == 2:
				x2, y2 := affineDoubleBig(params.P, params.Gx, params.Gy)
				running = jacAffineP521(p521FromBig(x2), p521FromBig(y2))
			default:
				running = mixedAddP521(running, gx, gy)
				addCount++
			}
			pts[t] = running
		}
		xs, ys, ok := batchNormalizeP521(pts)
		for t := 0; t < cur; t++ {
			if !ok[t] {
				continue
			}
			k := xs[t].l
			if tgt, found := targetByX[k]; found && ys[t] == targetY[k] {
				dHit := d - uint64(cur) + uint64(t) + 1
				hits = append(hits, Hit{tgt, dHit})
				delete(targetByX, k)
				remaining--
			}
		}
	}
	elapsed = time.Since(t0)
	return
}

func RunLinearSweep(curve CurveID, targets []Target, max uint64) (hits []Hit, addCount uint64, elapsed time.Duration) {
	switch curve {
	case P256:
		return linearSweepP256(targets, max)
	case P384:
		return linearSweepP384(targets, max)
	case P521:
		return linearSweepP521(targets, max)
	}
	panic("RunLinearSweep: unknown curve")
}
