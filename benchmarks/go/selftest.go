package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// groupByCurve returns one []Target slice per curve, preserving order.
func groupByCurve(targets []Target) map[CurveID][]Target {
	out := map[CurveID][]Target{}
	for _, t := range targets {
		out[t.Curve] = append(out[t.Curve], t)
	}
	return out
}

func targetKey(curve CurveID, xhex, yhex string) string {
	return curve.String() + "|" + xhex + "|" + yhex
}

// RunSelftest sweeps every target in targetsPath up to max using BSGS
// on the fastest validated backend per curve, and checks that exactly
// the controls in answersPath are found, at their published d, with
// zero flags among the rest. Returns a non-zero-worthy error on any
// miss or false positive.
func RunSelftest(targetsPath, answersPath string, max uint64) error {
	targets, err := LoadTargets(targetsPath)
	if err != nil {
		return fmt.Errorf("loading targets: %w", err)
	}
	answers, err := LoadAnswers(answersPath)
	if err != nil {
		return fmt.Errorf("loading answers: %w", err)
	}
	wantD := make(map[string]uint64, len(answers))
	for _, a := range answers {
		wantD[targetKey(a.Curve, a.XHex, a.YHex)] = a.D
	}

	byCurve := groupByCurve(targets)
	gotD := make(map[string]uint64)
	var totalAdds uint64
	var totalElapsed time.Duration

	for _, curve := range []CurveID{P256, P384, P521} {
		ts := byCurve[curve]
		if len(ts) == 0 {
			continue
		}
		hits, adds, elapsed := RunBSGS(curve, ts, max)
		totalAdds += adds
		totalElapsed += elapsed
		fmt.Fprintf(os.Stderr, "[selftest] %-6s %4d targets, max=%d: %d hit(s) in %v (%d point-adds, %.1f ns/add)\n",
			curve, len(ts), max, len(hits), elapsed, adds, float64(elapsed.Nanoseconds())/float64(maxU64(adds, 1)))
		for _, h := range hits {
			k := targetKey(curve, h.Target.XHex, h.Target.YHex)
			if prev, exists := gotD[k]; exists && prev != h.D {
				return fmt.Errorf("target %s:%s matched twice with different d (%d and %d) — bug", curve, h.Target.XHex, prev, h.D)
			}
			gotD[k] = h.D
		}
	}

	fmt.Fprintf(os.Stderr, "[selftest] total: %d point-adds in %v\n", totalAdds, totalElapsed)

	var failures []string
	for k, want := range wantD {
		got, ok := gotD[k]
		if !ok {
			failures = append(failures, fmt.Sprintf("MISS control %s: expected d=%d, found nothing", k, want))
		} else if got != want {
			failures = append(failures, fmt.Sprintf("WRONG-D control %s: expected d=%d, got d=%d", k, want, got))
		}
	}
	falsePositives := 0
	for k, got := range gotD {
		if _, isControl := wantD[k]; !isControl {
			failures = append(failures, fmt.Sprintf("FALSE POSITIVE on live key %s: found d=%d", k, got))
			falsePositives++
		}
	}

	liveCount := len(targets) - len(answers)
	fmt.Fprintf(os.Stderr, "[selftest] controls expected=%d found-correct=%d false-positives=%d/%d live keys\n",
		len(wantD), len(wantD)-countMisses(failures), falsePositives, liveCount)

	if len(failures) > 0 {
		for _, f := range failures {
			fmt.Fprintln(os.Stderr, "[selftest] FAIL: "+f)
		}
		return fmt.Errorf("selftest FAILED: %d problem(s)", len(failures))
	}
	fmt.Fprintf(os.Stderr, "[selftest] PASS: all %d controls found at the correct d, 0 false positives among %d live keys\n",
		len(wantD), liveCount)
	return nil
}

func countMisses(failures []string) int {
	n := 0
	for _, f := range failures {
		if strings.HasPrefix(f, "MISS") || strings.HasPrefix(f, "WRONG-D") {
			n++
		}
	}
	return n
}

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
