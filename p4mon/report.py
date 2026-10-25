#!/usr/bin/env python3
import sys, subprocess, json, time
MODE = sys.argv[1] if len(sys.argv) > 1 else "daily"
FIND = "/home/ec2-user/p4-inventory/p4mon/findings.jsonl"
def jc(since):
    try: return subprocess.run(["journalctl","-u","p4mon-ct","--since",since,"-o","cat"],
                               capture_output=True,text=True,timeout=20).stdout
    except Exception: return ""
def findings():
    try: return [l for l in open(FIND) if l.strip()]
    except Exception: return []
if MODE == "find":
    # Only non-attacker-controlled fields reach the delivery agent: the recovered
    # scalar d and the SHA-256 fingerprint (both safe) plus a crt.sh lookup link.
    # The cert subject stays in findings.jsonl for the human record, never the prompt.
    fs = findings()
    print("WEAK-KEY CERTIFICATE(S) DETECTED by p4mon on npm-scanner-dev:\n")
    for l in fs[-20:]:
        try:
            d = json.loads(l); fp = d.get("sha256", "")
            print(f"  d={d['d']}  sha256={fp}  https://crt.sh/?sha256={fp}  (unix ts {d['ts']})")
        except Exception:
            pass
    print(f"\nTotal weak-key findings to date: {len(fs)}")
    print("ACTION: these certificates' private keys are trivially recoverable. Revoke and report to the issuing CA and the browser root programs.")
else:
    j = jc("24 hours ago")
    tele = [l for l in j.splitlines() if l.startswith("[t+")]
    tail = [l for l in j.splitlines() if l.startswith("[tail +")]
    restarts = sum(1 for l in j.splitlines() if "FRESH START" in l)
    active = subprocess.run(["systemctl","is-active","p4mon-ct"],capture_output=True,text=True).stdout.strip()
    since = subprocess.run(["systemctl","show","p4mon-ct","-p","ActiveEnterTimestamp","--value"],capture_output=True,text=True).stdout.strip()
    fs = findings()
    print(f"p4mon CT weak-key monitor - daily report {time.strftime('%Y-%m-%d', time.gmtime())} UTC\n")
    print(f"Service: {active}; active since {since}; restarts in last 24h: {restarts}")
    print(f"Latest throughput snapshot: {tele[-1] if tele else 'n/a'}")
    print(f"Latest tailer stats: {tail[-1] if tail else 'n/a'}")
    print(f"WEAK-KEY FINDINGS to date: {len(fs)}")
    if fs:
        print("Recent findings:")
        for l in fs[-10:]: print("  " + l.strip())
    else:
        print("No weak keys found (expected - the live trusted CT stream is clean of this flaw).")
