package main

import (
	"math/big"
	"testing"
)

// Precise ns/op numbers (Go's benchmark framework, not the CLI's own
// timers) for the README's table. Run with:
//   go test -run NONE -bench . -benchtime 300000x -benchmem

func BenchmarkP256Mul(b *testing.B) {
	x := p256FromBig(curveParams[P256].Gx)
	y := p256FromBig(curveParams[P256].Gy)
	for i := 0; i < b.N; i++ {
		x = p256Mul(x, y)
	}
	_ = x
}

func BenchmarkP256MulFold(b *testing.B) {
	x := p256FromBigPlain(curveParams[P256].Gx)
	y := p256FromBigPlain(curveParams[P256].Gy)
	for i := 0; i < b.N; i++ {
		x = p256MulFold(x, y)
	}
	_ = x
}

func BenchmarkP256MixedAdd(b *testing.B) {
	params := curveParams[P256]
	chain := buildChainP256(params, params.Gx, params.Gy, 2)
	gx, gy := p256FromBig(params.Gx), p256FromBig(params.Gy)
	pt := chain[1]
	for i := 0; i < b.N; i++ {
		pt = mixedAddP256(pt, gx, gy)
	}
	_ = pt
}

func BenchmarkMulSchoolbook256(b *testing.B) {
	x := p256FromBig(curveParams[P256].Gx)
	y := p256FromBig(curveParams[P256].Gy)
	var dst [8]uint64
	for i := 0; i < b.N; i++ {
		mulSchoolbookInto(dst[:], x.l[:], y.l[:])
	}
}

func BenchmarkP384Mul(b *testing.B) {
	x := p384FromBig(curveParams[P384].Gx)
	y := p384FromBig(curveParams[P384].Gy)
	for i := 0; i < b.N; i++ {
		x = p384Mul(x, y)
	}
	_ = x
}

func BenchmarkP384MixedAdd(b *testing.B) {
	params := curveParams[P384]
	chain := buildChainP384(params, params.Gx, params.Gy, 2)
	gx, gy := p384FromBig(params.Gx), p384FromBig(params.Gy)
	pt := chain[1]
	for i := 0; i < b.N; i++ {
		pt = mixedAddP384(pt, gx, gy)
	}
	_ = pt
}

func BenchmarkP521Mul(b *testing.B) {
	x := p521FromBig(curveParams[P521].Gx)
	y := p521FromBig(curveParams[P521].Gy)
	for i := 0; i < b.N; i++ {
		x = p521Mul(x, y)
	}
	_ = x
}

func BenchmarkP521MixedAdd(b *testing.B) {
	params := curveParams[P521]
	chain := buildChainP521(params, params.Gx, params.Gy, 2)
	gx, gy := p521FromBig(params.Gx), p521FromBig(params.Gy)
	pt := chain[1]
	for i := 0; i < b.N; i++ {
		pt = mixedAddP521(pt, gx, gy)
	}
	_ = pt
}

func BenchmarkJacBigMixedAddP256(b *testing.B) {
	params := curveParams[P256]
	x2, y2 := affineDoubleBig(params.P, params.Gx, params.Gy)
	pt := jacAffineBig(x2, y2)
	for i := 0; i < b.N; i++ {
		pt = mixedAddBig(params.P, pt, params.Gx, params.Gy)
	}
	_ = pt
}

func BenchmarkJacBigMixedAddP384(b *testing.B) {
	params := curveParams[P384]
	x2, y2 := affineDoubleBig(params.P, params.Gx, params.Gy)
	pt := jacAffineBig(x2, y2)
	for i := 0; i < b.N; i++ {
		pt = mixedAddBig(params.P, pt, params.Gx, params.Gy)
	}
	_ = pt
}

func BenchmarkJacBigMixedAddP521(b *testing.B) {
	params := curveParams[P521]
	x2, y2 := affineDoubleBig(params.P, params.Gx, params.Gy)
	pt := jacAffineBig(x2, y2)
	for i := 0; i < b.N; i++ {
		pt = mixedAddBig(params.P, pt, params.Gx, params.Gy)
	}
	_ = pt
}

func BenchmarkAffineBigAddP256(b *testing.B) {
	params := curveParams[P256]
	x, y := new(big.Int).Set(params.Gx), new(big.Int).Set(params.Gy)
	for i := 0; i < b.N; i++ {
		x, y = affineAddBig(params.P, x, y, params.Gx, params.Gy)
	}
	_, _ = x, y
}
