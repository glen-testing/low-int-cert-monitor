#!/usr/bin/env python3
import csv, time, hashlib, importlib.util, glob, sys, gc
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

M_B=1_000_000          # baby steps
M_G=101                # giant steps  -> covers d in [0, 101,000,000)
csv.field_size_limit(10**7)
ms=importlib.util.module_from_spec(importlib.util.spec_from_file_location("ms","mass_scan.py"))
importlib.util.spec_from_file_location("ms","mass_scan.py").loader.exec_module(ms)
C=ms.C; add=ms.add

def smul(k,G,a,p):
    R=None; Q=G
    while k:
        if k&1: R=add(R,Q,a,p)
        Q=add(Q,Q,a,p); k>>=1
    return R

def pem_from(s):
    s=(s or "").strip().strip("'").strip('"').strip(); i=s.find("-----BEGIN CERTIFICATE-----")
    return s[i:] if i>=0 else None

targets={}; seen=set(); nec=nrsa=nother=0
def ingest(path,kind):
    global nec,nrsa,nother
    for row in csv.DictReader(open(path,newline='',encoding='utf-8',errors='replace')):
        pem=pem_from(row.get("PEM Info",""))
        if not pem: continue
        try: c=x509.load_pem_x509_certificate(pem.encode(),default_backend())
        except Exception: continue
        fp=hashlib.sha256(c.public_bytes(serialization.Encoding.DER)).hexdigest()
        if fp in seen: continue
        seen.add(fp); pk=c.public_key()
        if isinstance(pk,ec.EllipticCurvePublicKey):
            nec+=1; n=pk.public_numbers()
            targets.setdefault(pk.curve.name,{}).setdefault((n.x,n.y),[]).append(
                f"{kind}: {c.subject.rfc4514_string().split(',')[0]}")
        elif isinstance(pk,rsa.RSAPublicKey): nrsa+=1
        else: nother+=1

t0=time.perf_counter()
ingest("ccadb/roots.csv","ROOT"); ingest("ccadb/intermediates.csv","INTERMEDIATE")
print(f"[ingest] {len(seen)} unique certs  EC={nec} RSA={nrsa} other={nother}  ({time.perf_counter()-t0:.1f}s)",file=sys.stderr)

# ---- controls ----
# low-d: the 8 known eMudhra keys (secp384r1)
for f in glob.glob("scan/PROOF_*.pem"):
    c=x509.load_pem_x509_certificate(open(f,"rb").read(),default_backend())
    pk=c.public_key()
    if isinstance(pk,ec.EllipticCurvePublicKey):
        n=pk.public_numbers()
        targets.setdefault(pk.curve.name,{}).setdefault((n.x,n.y),[]).append(
            "LOW-CTRL eMudhra "+c.subject.rfc4514_string().split(',')[0])
# high-d: synthetic, near 1e8, one per present curve
HI={"secp256r1":99_999_931,"secp384r1":99_999_983,"secp521r1":100_000_000}
for cn,d in HI.items():
    if cn in targets:
        r=ec.derive_private_key(d,C[cn][4]()).public_key().public_numbers()
        targets[cn].setdefault((r.x,r.y),[]).append(f"HIGH-CTRL(expect d={d})")
print(f"[ctrl] low-d eMudhra keys + high-d {HI}",file=sys.stderr)

hits=[]
print(f"[bsgs] M_B={M_B} M_G={M_G} -> covers d in [1,{M_B*M_G}); curves={sorted(targets)}",file=sys.stderr)
for cn in sorted(targets):
    if cn not in C:
        print(f"  !! {cn} not in table, {len(targets[cn])} targets UNSWEPT",file=sys.stderr); continue
    p,a,gx,gy,cls=C[cn]; a%=p; G=(gx,gy); tgt=targets[cn]
    ts=time.perf_counter()
    # baby table {point: j} for j in 0..M_B-1  (j=0 -> point at infinity=None)
    baby={None:0}; cur=None
    for j in range(1,M_B):
        cur=add(cur,G,a,p); baby[cur]=j
    F=smul(M_B,G,a,p); negF=None if F is None else (F[0],(-F[1])%p)
    tb=time.perf_counter()-ts
    found_here=0
    for Q,labels in tgt.items():
        g=Q
        for i in range(M_G):
            j=baby.get(g,-1)
            if j!=-1:
                d=i*M_B+j
                if d>=1:
                    rr=ec.derive_private_key(d,cls()).public_key().public_numbers()
                    assert (rr.x,rr.y)==Q, "verify fail"
                    for lbl in labels: hits.append((d,cn,lbl))
                    found_here+=1
                break
            g=add(g,negF,a,p)
    print(f"  {cn}: {len(tgt)} targets, baby({M_B}) {tb:.1f}s, total {time.perf_counter()-ts:.1f}s, hits={found_here}",file=sys.stderr)
    del baby; gc.collect()

print(f"\n[total wall] {time.perf_counter()-t0:.1f}s")
lo=[h for h in hits if "LOW-CTRL" in h[2]]; hi=[h for h in hits if "HIGH-CTRL" in h[2]]
real=[h for h in hits if "CTRL" not in h[2]]
print("\n=== LOW-D CONTROLS (8 eMudhra keys, expect d=4..237) ===")
for d,cn,l in sorted(lo): print(f"  d={d:<4} {cn}  {l}")
print(f"  {len(lo)}/8 found")
print("\n=== HIGH-D CONTROLS (expect d near 1e8) ===")
for d,cn,l in sorted(hi): print(f"  d={d:<10} {cn}  {l}")
print(f"  {len(hi)}/{sum(1 for c in HI if c in targets)} found")
print(f"\n=== REAL CA HITS (trivial key d in 1..{M_B*M_G}) ===")
if not real: print("  NONE — no live CCADB root or intermediate has an EC private key in 1..101,000,000.")
else:
    for d,cn,l in sorted(real): print(f"  d={d:<10} {cn}  {l}")
