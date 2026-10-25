package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// RunCert extracts the EC public key from an X.509 certificate (PEM or
// DER) and sweeps it for a small private-key d up to max.
func RunCert(path string, max uint64) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}

	der := raw
	if block, _ := pem.Decode(raw); block != nil {
		der = block.Bytes
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("parsing certificate: %w", err)
	}

	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate public key is %T, not an EC key — out of scope for this tool", cert.PublicKey)
	}

	var curve CurveID
	switch pub.Curve.Params().Name {
	case "P-256":
		curve = P256
	case "P-384":
		curve = P384
	case "P-521":
		curve = P521
	default:
		return fmt.Errorf("unsupported curve %s (only P-256/P-384/P-521 are supported)", pub.Curve.Params().Name)
	}

	target := Target{
		Curve: curve,
		X:     pub.X, Y: pub.Y,
		XHex: fmt.Sprintf("%x", pub.X), YHex: fmt.Sprintf("%x", pub.Y),
	}
	fmt.Fprintf(os.Stderr, "cert: %s subject=%q curve=%s sweeping d<=%d...\n", path, cert.Subject.CommonName, curve, max)

	hits, adds, elapsed := RunBSGS(curve, []Target{target}, max)
	fmt.Fprintf(os.Stderr, "cert: %d point-adds in %v\n", adds, elapsed)
	if len(hits) == 0 {
		fmt.Printf("clean: no d<=%d found for %s key (subject=%q)\n", max, curve, cert.Subject.CommonName)
		return nil
	}
	fmt.Printf("WEAK KEY: d=%d  curve=%s  subject=%q  x=%s y=%s\n",
		hits[0].D, curve, cert.Subject.CommonName, target.XHex, target.YHex)
	return nil
}
