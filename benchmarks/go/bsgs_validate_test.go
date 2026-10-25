package main

import "testing"

// TestBSGSFindsAllControls is a regression test for a real bug this
// task's own selftest run caught: the giant-step block loop carried
// the previous block's last point directly into the next block's
// first slot without advancing it one more step, silently mislabeling
// every giant index from the second block onward by +1 (computed
// d = true_d + m, which either got rejected by the d<=max check —
// a silent miss — or, worse, could have been reported as a wrong d).
// With giantBlockSize=4096 and m=isqrt(1e8)+1=10001, any control
// needing gi>=4096 exercises this path; three of the twelve controls
// do. Running only the 12 answers (not all 802 targets) keeps this
// fast while still covering every curve and the exact multi-block
// scenario that broke.
func TestBSGSFindsAllControls(t *testing.T) {
	answers, err := LoadAnswers("/home/ec2-user/p4-inventory/common/answers.tsv")
	if err != nil {
		t.Fatalf("LoadAnswers: %v", err)
	}
	byCurve := map[CurveID][]Target{}
	wantD := map[string]uint64{}
	for _, a := range answers {
		byCurve[a.Curve] = append(byCurve[a.Curve], a.Target)
		wantD[targetKey(a.Curve, a.XHex, a.YHex)] = a.D
	}
	const max = 100_000_000
	for _, curve := range []CurveID{P256, P384, P521} {
		ts := byCurve[curve]
		if len(ts) == 0 {
			continue
		}
		hits, _, _ := RunBSGS(curve, ts, max)
		got := map[string]uint64{}
		for _, h := range hits {
			got[targetKey(curve, h.Target.XHex, h.Target.YHex)] = h.D
		}
		for _, tgt := range ts {
			k := targetKey(curve, tgt.XHex, tgt.YHex)
			want := wantD[k]
			d, found := got[k]
			if !found {
				t.Errorf("%s control d=%d: MISS (bug would show up as this)", curve, want)
				continue
			}
			if d != want {
				t.Errorf("%s control: want d=%d, got d=%d", curve, want, d)
			}
		}
	}
}
