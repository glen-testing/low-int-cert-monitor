#!/usr/bin/env python3
import sys, glob, os
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

MAX_D = int(os.environ.get("MAX_D", "1000000"))  # sweep ceiling

# Standard NIST / SECG short-Weierstrass params: y^2 = x^3 + a*x + b (mod p)
# Only p, a, Gx, Gy are needed for the G-incremented sweep; validated at startup.
CURVES = {
 "secp192r1": dict(
   p=0xfffffffffffffffffffffffffffffffeffffffffffffffff, a=-3,
   Gx=0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012,
   Gy=0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811, cls=ec.SECP192R1),
 "secp224r1": dict(
   p=0xffffffffffffffffffffffffffffffff000000000000000000000001, a=-3,
   Gx=0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21,
   Gy=0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34, cls=ec.SECP224R1),
 "secp256r1": dict(
   p=0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff, a=-3,
   Gx=0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
   Gy=0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5, cls=ec.SECP256R1),
 "secp384r1": dict(
   p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff, a=-3,
   Gx=0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
   Gy=0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f, cls=ec.SECP384R1),
 "secp521r1": dict(
   p=0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff, a=-3,
   Gx=0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66,
   Gy=0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650, cls=ec.SECP521R1),
 "secp256k1": dict(
   p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f, a=0,
   Gx=0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
   Gy=0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8, cls=ec.SECP256K1),
}

def ec_add(P, Q, a, p):
    if P is None: return Q
    if Q is None: return P
    x1,y1 = P; x2,y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0: return None          # P + (-P) = O
    if P == Q:
        if y1 == 0: return None
        lam = (3*x1*x1 + a) * pow(2*y1, -1, p) % p            # doubling
    else:
        lam = (y2 - y1) * pow((x2 - x1) % p, -1, p) % p       # addition
    x3 = (lam*lam - x1 - x2) % p
    y3 = (lam*(x1 - x3) - y1) % p
    return (x3, y3)

XCHECK = {}  # curve name -> True if cryptography can cross-verify hits on it

def selftest():
    ok, skipped = [], []
    for name, c in CURVES.items():
        a = c["a"] % c["p"]; G = (c["Gx"], c["Gy"]); cur = None
        try:
            for d in range(1, 7):
                cur = ec_add(cur, G, a, c["p"])
                ref = ec.derive_private_key(d, c["cls"]()).public_key().public_numbers()
                if cur != (ref.x, ref.y):
                    raise SystemExit(f"SELFTEST FAIL {name} d={d}")
            XCHECK[name] = True; ok.append(name)
        except SystemExit:
            raise
        except Exception:
            XCHECK[name] = False; skipped.append(name)
    print(f"[selftest] cross-checked vs cryptography (d=1..6): {', '.join(ok)}", file=sys.stderr)
    if skipped:
        print(f"[selftest] no library cross-check (unused by CAs): {', '.join(skipped)}", file=sys.stderr)

def load_cert(path):
    data = open(path, "rb").read()
    for loader in (x509.load_der_x509_certificate, x509.load_pem_x509_certificate):
        try: return loader(data, default_backend())
        except Exception: pass
    return None

def sweep(path, max_d):
    cert = load_cert(path)
    if cert is None: return (path, "PARSE_FAIL", None, None, None, None, None)
    subj = cert.subject.rfc4514_string()
    iss  = cert.issuer.rfc4514_string()
    pk = cert.public_key()
    if not isinstance(pk, ec.EllipticCurvePublicKey):
        return (path, "NON_EC("+type(pk).__name__+")", None, None, subj, iss, None)
    cn = pk.curve.name
    if cn not in CURVES:
        return (path, "UNSUPPORTED_CURVE:"+cn, None, None, subj, iss, None)
    nums = pk.public_numbers(); Q = (nums.x, nums.y)
    c = CURVES[cn]; a = c["a"] % c["p"]; p = c["p"]; G = (c["Gx"], c["Gy"])
    cur = None
    for d in range(1, max_d+1):
        cur = ec_add(cur, G, a, p)
        if cur == Q:
            if XCHECK.get(cn):
                ref = ec.derive_private_key(d, c["cls"]()).public_key().public_numbers()
                assert (ref.x, ref.y) == Q, "verify mismatch"
            return (path, "TRIVIAL_KEY", d, cn, subj, iss, None)
    return (path, "ok(no small d<=%d)"%max_d, None, cn, subj, iss, None)

if __name__ == "__main__":
    selftest()
    paths = sys.argv[1:] or sorted(glob.glob("certs/*"))
    print(f"[sweep] MAX_D={MAX_D}  {len(paths)} cert file(s)\n", file=sys.stderr)
    hits = []
    for pth in paths:
        try:
            r = sweep(pth, MAX_D)
        except Exception as e:
            r = (pth, "ERROR:"+repr(e), None, None, None, None, None)
        path, status, d, curve, subj, iss, _ = r
        name = os.path.basename(path)
        if status == "TRIVIAL_KEY":
            hits.append(r)
            print(f"*** {name}: PRIVATE KEY = {d}  [{curve}]")
            print(f"      subject: {subj}")
            print(f"      issuer : {iss}")
        else:
            tag = curve or ""
            print(f"    {name}: {status} {tag}".rstrip())
    print()
    if hits:
        print(f"==== {len(hits)} CERT(S) WITH TRIVIAL PRIVATE KEYS ====")
        for path, status, d, curve, subj, iss, _ in hits:
            print(f"  d={d:<4} {curve:<10} {subj}")
    else:
        print("No trivial-key certificates found in the scanned set.")
