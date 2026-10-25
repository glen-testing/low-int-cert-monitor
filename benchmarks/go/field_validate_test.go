package main

import (
	"crypto/rand"
	"math/big"
	"testing"
)

// These tests are the correctness gate for the hand-rolled fast field
// arithmetic (variant 3): every op is checked against math/big's
// trusted modular arithmetic over many random vectors, for all three
// curves, before any fast backend is wired into bench/selftest/cert.

func randMod(mod *big.Int) *big.Int {
	v, err := rand.Int(rand.Reader, mod)
	if err != nil {
		panic(err)
	}
	return v
}

func TestFieldP256(t *testing.T) {
	mod := curveParams[P256].P
	for i := 0; i < 20000; i++ {
		a, b := randMod(mod), randMod(mod)
		ea, eb := p256FromBig(a), p256FromBig(b)

		wantAdd := addmod(a, b, mod)
		if got := p256Add(ea, eb).ToBig(); got.Cmp(wantAdd) != 0 {
			t.Fatalf("Add mismatch: a=%x b=%x got=%x want=%x", a, b, got, wantAdd)
		}
		wantSub := submod(a, b, mod)
		if got := p256Sub(ea, eb).ToBig(); got.Cmp(wantSub) != 0 {
			t.Fatalf("Sub mismatch: a=%x b=%x got=%x want=%x", a, b, got, wantSub)
		}
		wantMul := mulmod(a, b, mod)
		if got := p256Mul(ea, eb).ToBig(); got.Cmp(wantMul) != 0 {
			t.Fatalf("Mul mismatch: a=%x b=%x got=%x want=%x", a, b, got, wantMul)
		}
		wantSqr := mulmod(a, a, mod)
		if got := p256Sqr(ea).ToBig(); got.Cmp(wantSqr) != 0 {
			t.Fatalf("Sqr mismatch: a=%x got=%x want=%x", a, got, wantSqr)
		}
	}
	// Edge cases: 0, 1, p-1.
	edge := []*big.Int{big.NewInt(0), big.NewInt(1), new(big.Int).Sub(mod, big.NewInt(1))}
	for _, a := range edge {
		for _, b := range edge {
			ea, eb := p256FromBig(a), p256FromBig(b)
			if got, want := p256Mul(ea, eb).ToBig(), mulmod(a, b, mod); got.Cmp(want) != 0 {
				t.Fatalf("edge Mul mismatch: a=%x b=%x got=%x want=%x", a, b, got, want)
			}
			if got, want := p256Add(ea, eb).ToBig(), addmod(a, b, mod); got.Cmp(want) != 0 {
				t.Fatalf("edge Add mismatch: a=%x b=%x got=%x want=%x", a, b, got, want)
			}
		}
	}
}

// TestFieldP256Fold validates the alternate generalized-Mersenne
// ("Solinas-style") reduction (field_p256_fold.go), kept as the other
// half of the Montgomery-vs-NIST-fast-reduction benchmark comparison.
func TestFieldP256Fold(t *testing.T) {
	mod := curveParams[P256].P
	for i := 0; i < 20000; i++ {
		a, b := randMod(mod), randMod(mod)
		ea, eb := p256FromBigPlain(a), p256FromBigPlain(b)
		wantMul := mulmod(a, b, mod)
		if got := p256MulFold(ea, eb).ToBig(); got.Cmp(wantMul) != 0 {
			t.Fatalf("Mul (fold) mismatch: a=%x b=%x got=%x want=%x", a, b, got, wantMul)
		}
	}
	edge := []*big.Int{big.NewInt(0), big.NewInt(1), new(big.Int).Sub(mod, big.NewInt(1))}
	for _, a := range edge {
		for _, b := range edge {
			ea, eb := p256FromBigPlain(a), p256FromBigPlain(b)
			if got, want := p256MulFold(ea, eb).ToBig(), mulmod(a, b, mod); got.Cmp(want) != 0 {
				t.Fatalf("edge Mul (fold) mismatch: a=%x b=%x got=%x want=%x", a, b, got, want)
			}
		}
	}
}

func TestFieldP384(t *testing.T) {
	mod := curveParams[P384].P
	for i := 0; i < 20000; i++ {
		a, b := randMod(mod), randMod(mod)
		ea, eb := p384FromBig(a), p384FromBig(b)

		if got, want := p384Add(ea, eb).ToBig(), addmod(a, b, mod); got.Cmp(want) != 0 {
			t.Fatalf("Add mismatch: a=%x b=%x got=%x want=%x", a, b, got, want)
		}
		if got, want := p384Sub(ea, eb).ToBig(), submod(a, b, mod); got.Cmp(want) != 0 {
			t.Fatalf("Sub mismatch: a=%x b=%x got=%x want=%x", a, b, got, want)
		}
		if got, want := p384Mul(ea, eb).ToBig(), mulmod(a, b, mod); got.Cmp(want) != 0 {
			t.Fatalf("Mul mismatch: a=%x b=%x got=%x want=%x", a, b, got, want)
		}
		if got, want := p384Sqr(ea).ToBig(), mulmod(a, a, mod); got.Cmp(want) != 0 {
			t.Fatalf("Sqr mismatch: a=%x got=%x want=%x", a, got, want)
		}
	}
	edge := []*big.Int{big.NewInt(0), big.NewInt(1), new(big.Int).Sub(mod, big.NewInt(1))}
	for _, a := range edge {
		for _, b := range edge {
			ea, eb := p384FromBig(a), p384FromBig(b)
			if got, want := p384Mul(ea, eb).ToBig(), mulmod(a, b, mod); got.Cmp(want) != 0 {
				t.Fatalf("edge Mul mismatch: a=%x b=%x got=%x want=%x", a, b, got, want)
			}
		}
	}
}

func TestFieldP521(t *testing.T) {
	mod := curveParams[P521].P
	for i := 0; i < 20000; i++ {
		a, b := randMod(mod), randMod(mod)
		ea, eb := p521FromBig(a), p521FromBig(b)

		if got, want := p521Add(ea, eb).ToBig(), addmod(a, b, mod); got.Cmp(want) != 0 {
			t.Fatalf("Add mismatch: a=%x b=%x got=%x want=%x", a, b, got, want)
		}
		if got, want := p521Sub(ea, eb).ToBig(), submod(a, b, mod); got.Cmp(want) != 0 {
			t.Fatalf("Sub mismatch: a=%x b=%x got=%x want=%x", a, b, got, want)
		}
		if got, want := p521Mul(ea, eb).ToBig(), mulmod(a, b, mod); got.Cmp(want) != 0 {
			t.Fatalf("Mul mismatch: a=%x b=%x got=%x want=%x", a, b, got, want)
		}
		if got, want := p521Sqr(ea).ToBig(), mulmod(a, a, mod); got.Cmp(want) != 0 {
			t.Fatalf("Sqr mismatch: a=%x got=%x want=%x", a, got, want)
		}
	}
	edge := []*big.Int{big.NewInt(0), big.NewInt(1), new(big.Int).Sub(mod, big.NewInt(1))}
	for _, a := range edge {
		for _, b := range edge {
			ea, eb := p521FromBig(a), p521FromBig(b)
			if got, want := p521Mul(ea, eb).ToBig(), mulmod(a, b, mod); got.Cmp(want) != 0 {
				t.Fatalf("edge Mul mismatch: a=%x b=%x got=%x want=%x", a, b, got, want)
			}
		}
	}
}
