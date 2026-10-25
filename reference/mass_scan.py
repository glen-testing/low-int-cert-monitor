#!/usr/bin/env python3
import csv, sys, hashlib
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa, ed25519, ed448
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

MAXD = 10000
csv.field_size_limit(10**7)

# short-Weierstrass params y^2 = x^3 + a x + b (mod p); need p, a, Gx, Gy only
C = {
 "secp256r1":(0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,-3,
   0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
   0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,ec.SECP256R1),
 "secp384r1":(0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,-3,
   0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
   0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f,ec.SECP384R1),
 "secp521r1":(0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,-3,
   0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66,
   0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650,ec.SECP521R1),
 "secp256k1":(0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,0,
   0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
   0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,ec.SECP256K1),
 "secp224r1":(0xffffffffffffffffffffffffffffffff000000000000000000000001,-3,
   0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21,
   0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34,ec.SECP224R1),
 "secp192r1":(0xfffffffffffffffffffffffffffffffeffffffffffffffff,-3,
   0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012,
   0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811,ec.SECP192R1),
 "brainpoolP256r1":(0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377,
   0x7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9,
   0x8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262,
   0x547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997,getattr(ec,"BrainpoolP256R1",None)),
 "brainpoolP384r1":(0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53,
   0x7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826,
   0x1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e,
   0x8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315,getattr(ec,"BrainpoolP384R1",None)),
 "brainpoolP512r1":(0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3,
   0x7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca,
   0x81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822,
   0x7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892,getattr(ec,"BrainpoolP512R1",None)),
}

def add(P,Q,a,p):
    if P is None: return Q
    if Q is None: return P
    x1,y1=P; x2,y2=Q
    if x1==x2 and (y1+y2)%p==0: return None
    if P==Q:
        if y1==0: return None
        lam=(3*x1*x1+a)*pow(2*y1,-1,p)%p
    else:
        lam=(y2-y1)*pow((x2-x1)%p,-1,p)%p
    x3=(lam*lam-x1-x2)%p
    return (x3,(lam*(x1-x3)-y1)%p)

MAPS={}; XCHECK={}
def build():
    for name,(p,a,gx,gy,cls) in C.items():
        a%=p; G=(gx,gy); cur=None; m={}
        # cross-check against library where available
        xc=False
        if cls is not None:
            try:
                for d in range(1,7):
                    t=add(cur,G,a,p); cur=t
                    r=ec.derive_private_key(d,cls()).public_key().public_numbers()
                    if (r.x,r.y)!=cur: raise SystemExit(f"SELFTEST FAIL {name} d={d}")
                xc=True
            except SystemExit: raise
            except Exception: cur=None  # library can't do this curve; fall through
        XCHECK[name]=xc
        cur=None
        for d in range(1,MAXD+1):
            cur=add(cur,G,a,p); m[cur]=d
        MAPS[name]=m
    ok=[n for n in C if XCHECK[n]]; nox=[n for n in C if not XCHECK[n]]
    print(f"[maps] built d=1..{MAXD} for {len(C)} curves; lib-crosschecked: {', '.join(ok)}",file=sys.stderr)
    if nox: print(f"[maps] NOT lib-crosschecked (rare/unsupported by this lib): {', '.join(nox)}",file=sys.stderr)

def pem_from(field):
    s=field.strip().strip("'").strip('"').strip()
    i=s.find("-----BEGIN CERTIFICATE-----")
    return s[i:] if i>=0 else None

def scan(path, kind, rows, seen, hits, stats):
    with open(path,newline='',encoding='utf-8',errors='replace') as f:
        r=csv.DictReader(f)
        for row in r:
            pem=pem_from(row.get("PEM Info","") or "")
            if not pem: stats["no_pem"]+=1; continue
            try:
                cert=x509.load_pem_x509_certificate(pem.encode(),default_backend())
            except Exception as e:
                stats["parse_fail"]+=1; stats["parse_fail_eg"].append(str(e)[:80]); continue
            fp=hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
            if fp in seen: stats["dup"]+=1; continue
            seen.add(fp); stats["unique"]+=1
            pk=cert.public_key()
            if isinstance(pk,ec.EllipticCurvePublicKey):
                cn=pk.curve.name; stats["ec"]+=1; stats["bycurve"][cn]=stats["bycurve"].get(cn,0)+1
                if cn not in MAPS:
                    stats["ec_unsupported"].setdefault(cn,0); stats["ec_unsupported"][cn]+=1; continue
                nums=pk.public_numbers(); d=MAPS[cn].get((nums.x,nums.y))
                if d is not None:
                    if XCHECK[cn]:
                        rr=ec.derive_private_key(d,C[cn][4]()).public_key().public_numbers()
                        assert (rr.x,rr.y)==(nums.x,nums.y)
                    hits.append(dict(kind=kind,d=d,curve=cn,
                        subject=cert.subject.rfc4514_string(),
                        issuer=cert.issuer.rfc4514_string(),
                        serial=format(cert.serial_number,"x"),
                        sha256=fp.upper(),
                        owner=row.get("CA Owner") or row.get("Owner"),
                        parent=row.get("Parent Name") or row.get("Certificate Issuer Organization")))
            elif isinstance(pk,rsa.RSAPublicKey): stats["rsa"]+=1
            elif isinstance(pk,dsa.DSAPublicKey): stats["dsa"]+=1
            elif isinstance(pk,(ed25519.Ed25519PublicKey,ed448.Ed448PublicKey)): stats["eddsa"]+=1
            else: stats["other"]+=1

if __name__=="__main__":
    build()
    seen=set(); hits=[]
    stats=dict(unique=0,dup=0,no_pem=0,parse_fail=0,parse_fail_eg=[],ec=0,rsa=0,dsa=0,eddsa=0,
               other=0,bycurve={},ec_unsupported={})
    scan("ccadb/roots.csv","ROOT",172,seen,hits,stats)
    scan("ccadb/intermediates.csv","INTERMEDIATE",2552,seen,hits,stats)

    print("\n================ COVERAGE ================")
    print(f"unique certs tested : {stats['unique']}   (dupes skipped {stats['dup']}, no-PEM {stats['no_pem']}, parse-fail {stats['parse_fail']})")
    print(f"  RSA        : {stats['rsa']}")
    print(f"  EC         : {stats['ec']}")
    for c,n in sorted(stats['bycurve'].items(),key=lambda x:-x[1]):
        mark="" if c in MAPS else "  <-- NOT in sweep table"
        print(f"       {c:<16} {n}{mark}")
    print(f"  DSA        : {stats['dsa']}")
    print(f"  EdDSA      : {stats['eddsa']}")
    print(f"  other      : {stats['other']}")
    if stats['ec_unsupported']:
        print("  EC CURVES NOT SWEPT (reported, not skipped silently):",stats['ec_unsupported'])
    if stats['parse_fail']:
        print("  parse-fail examples:",stats['parse_fail_eg'][:3])

    print("\n================ TRIVIAL-KEY HITS ================")
    if not hits:
        print("NONE. No root or intermediate in the CCADB set has an EC private key in 1..%d."%MAXD)
    else:
        print(f"{len(hits)} certificate(s) with a trivial private key:\n")
        for h in sorted(hits,key=lambda x:x['d']):
            print(f"  d={h['d']:<5} {h['curve']:<10} {h['kind']:<12} {h['subject']}")
            print(f"        issuer={h['issuer']}")
            print(f"        CA Owner={h['owner']}  serial={h['serial']}  sha256={h['sha256']}")
