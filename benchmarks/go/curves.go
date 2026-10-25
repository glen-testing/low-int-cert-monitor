package main

import (
	"bufio"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
)

// CurveID identifies one of the three supported NIST prime curves.
type CurveID int

const (
	P256 CurveID = iota
	P384
	P521
)

func (c CurveID) String() string {
	switch c {
	case P256:
		return "P-256"
	case P384:
		return "P-384"
	case P521:
		return "P-521"
	}
	return "?"
}

func ParseCurveName(s string) (CurveID, error) {
	switch strings.TrimSpace(s) {
	case "P-256", "P256", "secp256r1", "prime256v1":
		return P256, nil
	case "P-384", "P384", "secp384r1":
		return P384, nil
	case "P-521", "P521", "secp521r1":
		return P521, nil
	}
	return 0, fmt.Errorf("unsupported curve %q", s)
}

// CurveParams holds the big.Int domain parameters for a = -3 short
// Weierstrass curve y^2 = x^3 - 3x + b (mod p), as given in common/spec.md.
type CurveParams struct {
	ID     CurveID
	P      *big.Int
	B      *big.Int
	Gx, Gy *big.Int
	N      *big.Int
	BitLen int // bit length of p (256/384/521), used to size limb arrays
}

func hex(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("bad hex constant: " + s)
	}
	return v
}

var curveParams = map[CurveID]*CurveParams{
	P256: {
		ID: P256,
		P:  hex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"),
		B:  hex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"),
		Gx: hex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
		Gy: hex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"),
		N:  hex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),
		BitLen: 256,
	},
	P384: {
		ID: P384,
		P:  hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF"),
		B:  hex("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF"),
		Gx: hex("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7"),
		Gy: hex("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F"),
		N:  hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"),
		BitLen: 384,
	},
	P521: {
		ID: P521,
		P:  hex("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
		B:  hex("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00"),
		Gx: hex("00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66"),
		Gy: hex("011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650"),
		N:  hex("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409"),
		BitLen: 521,
	},
}

func Params(c CurveID) *CurveParams { return curveParams[c] }

// Target is one public point read from targets.tsv / answers.tsv.
type Target struct {
	Curve      CurveID
	X, Y       *big.Int
	XHex, YHex string // lowercase, unpadded, exactly as in the file (for stable reporting)
	LineNo     int
}

type Answer struct {
	Target
	D uint64
}

func normHex(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// LoadTargets reads curve\tx_hex\ty_hex rows, skipping blank/# lines.
func LoadTargets(path string) ([]Target, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Target
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimRight(sc.Text(), "\r\n")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 3 {
			return nil, fmt.Errorf("%s:%d: expected 3 tab-separated fields, got %d", path, lineNo, len(parts))
		}
		cid, err := ParseCurveName(parts[0])
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
		xh, yh := normHex(parts[1]), normHex(parts[2])
		x, ok := new(big.Int).SetString(xh, 16)
		if !ok {
			return nil, fmt.Errorf("%s:%d: bad x hex", path, lineNo)
		}
		y, ok := new(big.Int).SetString(yh, 16)
		if !ok {
			return nil, fmt.Errorf("%s:%d: bad y hex", path, lineNo)
		}
		out = append(out, Target{Curve: cid, X: x, Y: y, XHex: xh, YHex: yh, LineNo: lineNo})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// LoadAnswers reads curve\tx_hex\ty_hex\td control rows.
func LoadAnswers(path string) ([]Answer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Answer
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimRight(sc.Text(), "\r\n")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 4 {
			return nil, fmt.Errorf("%s:%d: expected 4 tab-separated fields, got %d", path, lineNo, len(parts))
		}
		cid, err := ParseCurveName(parts[0])
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
		xh, yh := normHex(parts[1]), normHex(parts[2])
		x, ok := new(big.Int).SetString(xh, 16)
		if !ok {
			return nil, fmt.Errorf("%s:%d: bad x hex", path, lineNo)
		}
		y, ok := new(big.Int).SetString(yh, 16)
		if !ok {
			return nil, fmt.Errorf("%s:%d: bad y hex", path, lineNo)
		}
		d, err := strconv.ParseUint(strings.TrimSpace(parts[3]), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: bad d: %w", path, lineNo, err)
		}
		out = append(out, Answer{Target: Target{Curve: cid, X: x, Y: y, XHex: xh, YHex: yh, LineNo: lineNo}, D: d})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
