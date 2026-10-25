package main

import (
	"math/big"
	"testing"

	"filippo.io/nistec"
)

// Validates the mixed-add chain (variant 2 formula) on each fast field
// backend (variant 3) against: (a) the generic math/big Jacobian chain
// (variant 1/2 ground truth) and (b) filippo.io/nistec's independent,
// widely-used implementation (the explicit "validate against a known
// library" gate from the task spec), over thousands of sequential
// adds — long enough to surface any incomplete-reduction/carry bug
// that only shows up after many operations.

const chainTestLen = 4000

func TestChainP256MatchesBigInt(t *testing.T) {
	p := curveParams[P256]
	big := buildChainBig(p, p.Gx, p.Gy, chainTestLen)
	fast := buildChainP256(p, p.Gx, p.Gy, chainTestLen)
	for i := 0; i < chainTestLen; i++ {
		bx, by := toAffineBig(p.P, big[i])
		fx, fy := fast[i].toAffine()
		if bx.Cmp(fx.ToBig()) != 0 || by.Cmp(fy.ToBig()) != 0 {
			t.Fatalf("P-256 chain mismatch at k=%d:\n bigint x=%x y=%x\n fast   x=%x y=%x",
				i+1, bx, by, fx.ToBig(), fy.ToBig())
		}
	}
}

func TestChainP384MatchesBigInt(t *testing.T) {
	p := curveParams[P384]
	big := buildChainBig(p, p.Gx, p.Gy, chainTestLen)
	fast := buildChainP384(p, p.Gx, p.Gy, chainTestLen)
	for i := 0; i < chainTestLen; i++ {
		bx, by := toAffineBig(p.P, big[i])
		fx, fy := fast[i].toAffine()
		if bx.Cmp(fx.ToBig()) != 0 || by.Cmp(fy.ToBig()) != 0 {
			t.Fatalf("P-384 chain mismatch at k=%d:\n bigint x=%x y=%x\n fast   x=%x y=%x",
				i+1, bx, by, fx.ToBig(), fy.ToBig())
		}
	}
}

func TestChainP521MatchesBigInt(t *testing.T) {
	p := curveParams[P521]
	big := buildChainBig(p, p.Gx, p.Gy, chainTestLen)
	fast := buildChainP521(p, p.Gx, p.Gy, chainTestLen)
	for i := 0; i < chainTestLen; i++ {
		bx, by := toAffineBig(p.P, big[i])
		fx, fy := fast[i].toAffine()
		if bx.Cmp(fx.ToBig()) != 0 || by.Cmp(fy.ToBig()) != 0 {
			t.Fatalf("P-521 chain mismatch at k=%d:\n bigint x=%x y=%x\n fast   x=%x y=%x",
				i+1, bx, by, fx.ToBig(), fy.ToBig())
		}
	}
}

// --- cross-validation against filippo.io/nistec (independent library) ---

func scalarBytes(k, byteLen int) []byte {
	b := make([]byte, byteLen)
	bi := big.NewInt(int64(k))
	bb := bi.Bytes()
	copy(b[byteLen-len(bb):], bb)
	return b
}

func TestChainP256MatchesNistec(t *testing.T) {
	p := curveParams[P256]
	fast := buildChainP256(p, p.Gx, p.Gy, chainTestLen)
	g := nistec.NewP256Point().SetGenerator()
	q := nistec.NewP256Point().SetGenerator()
	for k := 1; k <= chainTestLen; k++ {
		if k > 1 {
			q.Add(q, g)
		}
		fx, fy := fast[k-1].toAffine()
		want := q.Bytes() // uncompressed 0x04||X||Y
		gotX := fx.ToBig().FillBytes(make([]byte, 32))
		gotY := fy.ToBig().FillBytes(make([]byte, 32))
		if len(want) != 65 || string(want[1:33]) != string(gotX) || string(want[33:65]) != string(gotY) {
			t.Fatalf("P-256 vs nistec mismatch at k=%d", k)
		}
	}
}

func TestChainP384MatchesNistec(t *testing.T) {
	p := curveParams[P384]
	fast := buildChainP384(p, p.Gx, p.Gy, chainTestLen)
	g := nistec.NewP384Point().SetGenerator()
	q := nistec.NewP384Point().SetGenerator()
	for k := 1; k <= chainTestLen; k++ {
		if k > 1 {
			q.Add(q, g)
		}
		fx, fy := fast[k-1].toAffine()
		want := q.Bytes()
		gotX := fx.ToBig().FillBytes(make([]byte, 48))
		gotY := fy.ToBig().FillBytes(make([]byte, 48))
		if len(want) != 97 || string(want[1:49]) != string(gotX) || string(want[49:97]) != string(gotY) {
			t.Fatalf("P-384 vs nistec mismatch at k=%d", k)
		}
	}
}

func TestChainP521MatchesNistec(t *testing.T) {
	p := curveParams[P521]
	fast := buildChainP521(p, p.Gx, p.Gy, chainTestLen)
	g := nistec.NewP521Point().SetGenerator()
	q := nistec.NewP521Point().SetGenerator()
	for k := 1; k <= chainTestLen; k++ {
		if k > 1 {
			q.Add(q, g)
		}
		fx, fy := fast[k-1].toAffine()
		want := q.Bytes()
		gotX := fx.ToBig().FillBytes(make([]byte, 66))
		gotY := fy.ToBig().FillBytes(make([]byte, 66))
		if len(want) != 133 || string(want[1:67]) != string(gotX) || string(want[67:133]) != string(gotY) {
			t.Fatalf("P-521 vs nistec mismatch at k=%d", k)
		}
	}
}

// TestAnswersLandOnControlPoints checks that walking the chain out to
// each control key's published d actually reproduces its (x,y), for
// both the big.Int and fast backends — the end-to-end correctness
// check that matters most for this tool's actual job.
func TestAnswersLandOnControlPoints(t *testing.T) {
	answers, err := LoadAnswers("/home/ec2-user/p4-inventory/common/answers.tsv")
	if err != nil {
		t.Fatalf("LoadAnswers: %v", err)
	}
	for _, a := range answers {
		if a.D > chainTestLen {
			continue // large-d controls are validated end-to-end by selftest's BSGS run instead
		}
		p := curveParams[a.Curve]
		d := int(a.D)
		switch a.Curve {
		case P256:
			chain := buildChainP256(p, p.Gx, p.Gy, d)
			x, y := chain[d-1].toAffine()
			if x.ToBig().Cmp(a.X) != 0 || y.ToBig().Cmp(a.Y) != 0 {
				t.Fatalf("P-256 control d=%d did not reproduce target point", d)
			}
		case P384:
			chain := buildChainP384(p, p.Gx, p.Gy, d)
			x, y := chain[d-1].toAffine()
			if x.ToBig().Cmp(a.X) != 0 || y.ToBig().Cmp(a.Y) != 0 {
				t.Fatalf("P-384 control d=%d did not reproduce target point", d)
			}
		case P521:
			chain := buildChainP521(p, p.Gx, p.Gy, d)
			x, y := chain[d-1].toAffine()
			if x.ToBig().Cmp(a.X) != 0 || y.ToBig().Cmp(a.Y) != 0 {
				t.Fatalf("P-521 control d=%d did not reproduce target point", d)
			}
		}
	}
}
