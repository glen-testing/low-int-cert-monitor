package main

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"time"

	"filippo.io/nistec"
)

// ---------------------------------------------------------------------
// `bench` subcommand: per-curve, per-variant ns/add microbenchmarks
// (the task's primary metric), plus a real sweep (linear or bsgs) over
// the given targets file for the secondary wall-clock metric.
// ---------------------------------------------------------------------

type benchResult struct {
	curve, variant string
	nsPerAdd        float64
	n               int
}

func timeIt(n int, f func()) time.Duration {
	t0 := time.Now()
	f()
	return time.Since(t0)
}

func microbenchAffineBig(curve CurveID, n int) benchResult {
	p := curveParams[curve]
	x, y := new(big.Int).Set(p.Gx), new(big.Int).Set(p.Gy)
	d := timeIt(n, func() {
		for i := 0; i < n; i++ {
			x, y = affineAddBig(p.P, x, y, p.Gx, p.Gy)
		}
	})
	runtime.KeepAlive(x)
	runtime.KeepAlive(y)
	return benchResult{curve.String(), "1-affine+bigint-modinverse", float64(d.Nanoseconds()) / float64(n), n}
}

func microbenchJacBig(curve CurveID, n int) benchResult {
	p := curveParams[curve]
	x2, y2 := affineDoubleBig(p.P, p.Gx, p.Gy)
	pt := jacAffineBig(x2, y2)
	d := timeIt(n, func() {
		for i := 0; i < n; i++ {
			pt = mixedAddBig(p.P, pt, p.Gx, p.Gy)
		}
	})
	runtime.KeepAlive(pt)
	return benchResult{curve.String(), "2-jacobian+bigint-field", float64(d.Nanoseconds()) / float64(n), n}
}

func microbenchJacFast(curve CurveID, n int) benchResult {
	p := curveParams[curve]
	var d time.Duration
	switch curve {
	case P256:
		chain := buildChainP256(p, p.Gx, p.Gy, 2)
		pt := chain[1]
		d = timeIt(n, func() {
			for i := 0; i < n; i++ {
				pt = mixedAddP256(pt, chain[0].X, chain[0].Y)
			}
		})
		runtime.KeepAlive(pt)
	case P384:
		chain := buildChainP384(p, p.Gx, p.Gy, 2)
		pt := chain[1]
		d = timeIt(n, func() {
			for i := 0; i < n; i++ {
				pt = mixedAddP384(pt, chain[0].X, chain[0].Y)
			}
		})
		runtime.KeepAlive(pt)
	case P521:
		chain := buildChainP521(p, p.Gx, p.Gy, 2)
		pt := chain[1]
		d = timeIt(n, func() {
			for i := 0; i < n; i++ {
				pt = mixedAddP521(pt, chain[0].X, chain[0].Y)
			}
		})
		runtime.KeepAlive(pt)
	}
	return benchResult{curve.String(), "3-jacobian+hand-rolled-limbs", float64(d.Nanoseconds()) / float64(n), n}
}

func microbenchNistec(curve CurveID, n int) benchResult {
	var d time.Duration
	switch curve {
	case P256:
		g := nistec.NewP256Point().SetGenerator()
		q := nistec.NewP256Point().SetGenerator()
		q.Add(q, g)
		d = timeIt(n, func() {
			for i := 0; i < n; i++ {
				q.Add(q, g)
			}
		})
		runtime.KeepAlive(q)
	case P384:
		g := nistec.NewP384Point().SetGenerator()
		q := nistec.NewP384Point().SetGenerator()
		q.Add(q, g)
		d = timeIt(n, func() {
			for i := 0; i < n; i++ {
				q.Add(q, g)
			}
		})
		runtime.KeepAlive(q)
	case P521:
		g := nistec.NewP521Point().SetGenerator()
		q := nistec.NewP521Point().SetGenerator()
		q.Add(q, g)
		d = timeIt(n, func() {
			for i := 0; i < n; i++ {
				q.Add(q, g)
			}
		})
		runtime.KeepAlive(q)
	}
	return benchResult{curve.String(), "5-filippo.io/nistec (Jacobian+Jacobian)", float64(d.Nanoseconds()) / float64(n), n}
}

func microbenchStdlibElliptic(curve CurveID, n int) benchResult {
	p := curveParams[curve]
	var ec elliptic.Curve
	switch curve {
	case P256:
		ec = elliptic.P256()
	case P384:
		ec = elliptic.P384()
	case P521:
		ec = elliptic.P521()
	}
	x, y := new(big.Int).Set(p.Gx), new(big.Int).Set(p.Gy)
	d := timeIt(n, func() {
		for i := 0; i < n; i++ {
			//lint:ignore SA1019 deprecated but this is exactly the comparison datapoint we want
			x, y = ec.Add(x, y, p.Gx, p.Gy)
		}
	})
	runtime.KeepAlive(x)
	runtime.KeepAlive(y)
	return benchResult{curve.String(), "5-crypto/elliptic stdlib (affine in/out)", float64(d.Nanoseconds()) / float64(n), n}
}

// RunMicrobench prints the ns/add table used for the README.
func RunMicrobench(n, affineN int) {
	fmt.Fprintf(os.Stderr, "# ns/add microbenchmark (GOMAXPROCS=%d), n=%d (affine baseline n=%d)\n", runtime.GOMAXPROCS(0), n, affineN)
	fmt.Printf("%-6s %-42s %12s\n", "curve", "variant", "ns/add")
	for _, curve := range []CurveID{P256, P384, P521} {
		results := []benchResult{
			microbenchAffineBig(curve, affineN),
			microbenchJacBig(curve, n),
			microbenchJacFast(curve, n),
			microbenchNistec(curve, n),
			microbenchStdlibElliptic(curve, n),
		}
		for _, r := range results {
			fmt.Printf("%-6s %-42s %12.1f\n", r.curve, r.variant, r.nsPerAdd)
		}
	}
}

// RunSweepBench implements `bench --targets F --max N --method linear|bsgs`.
func RunSweepBench(targetsPath string, max uint64, method string) error {
	targets, err := LoadTargets(targetsPath)
	if err != nil {
		return err
	}
	byCurve := groupByCurve(targets)
	for _, curve := range []CurveID{P256, P384, P521} {
		ts := byCurve[curve]
		if len(ts) == 0 {
			continue
		}
		switch method {
		case "bsgs", "":
			hits, adds, elapsed := RunBSGS(curve, ts, max)
			fmt.Fprintf(os.Stderr, "[bench bsgs] %-6s %4d targets max=%d: %d hits, %v, %d adds, %.1f ns/add\n",
				curve, len(ts), max, len(hits), elapsed, adds, float64(elapsed.Nanoseconds())/float64(maxU64(adds, 1)))
			for _, h := range hits {
				fmt.Printf("HIT %s d=%d x=%s y=%s\n", curve, h.D, h.Target.XHex, h.Target.YHex)
			}
		case "linear":
			hits, adds, elapsed := RunLinearSweep(curve, ts, max)
			fmt.Fprintf(os.Stderr, "[bench linear] %-6s %4d targets max=%d: %d hits, %v, %d adds, %.1f ns/add\n",
				curve, len(ts), max, len(hits), elapsed, adds, float64(elapsed.Nanoseconds())/float64(maxU64(adds, 1)))
			for _, h := range hits {
				fmt.Printf("HIT %s d=%d x=%s y=%s\n", curve, h.D, h.Target.XHex, h.Target.YHex)
			}
		default:
			return fmt.Errorf("unknown --method %q (want linear|bsgs)", method)
		}
	}
	return nil
}
