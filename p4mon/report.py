#!/usr/bin/env python3
import sys, os, subprocess, json, time, re
MODE = sys.argv[1] if len(sys.argv) > 1 else "daily"
FIND = os.environ.get("P4MON_FINDINGS", "/home/ec2-user/p4-inventory/p4mon/findings.jsonl")
MAX_SHOWN = 20
# p4mon already reduces SAN entries to strict hostnames/IPs; re-check here so a
# hand-edited or older findings file cannot put free text into an alert.
SAFE = re.compile(r"^[a-z0-9.*:_/-]{1,253}$")

def jc(since):
    try: return subprocess.run(["journalctl","-u","p4mon-ct","--since",since,"-o","cat"],
                               capture_output=True,text=True,timeout=20).stdout
    except Exception: return ""

def findings():
    try: return [l for l in open(FIND) if l.strip()]
    except Exception: return []

def safe_list(v):
    return [x for x in v if isinstance(x, str) and SAFE.match(x)] if isinstance(v, list) else []

def valid_for(rec):
    """Which sites the flagged certificate is valid for, from p4mon's scope fields."""
    if "names" not in rec:
        return "unknown (recorded before p4mon captured certificate names)"
    if rec.get("tls_server") is False:
        return "no websites (extended key usage excludes TLS server auth)"
    if rec.get("ca"):
        permitted = safe_list(rec.get("permitted"))
        if not permitted:
            return "ANY website (CA certificate without name constraints)"
        excluded = safe_list(rec.get("excluded"))
        ex = "; excluding " + ", ".join(excluded) if excluded else ""
        return "names under " + ", ".join(permitted) + ex + " (name-constrained CA)"
    names = safe_list(rec.get("names"))
    omitted = rec.get("names_omitted", 0) if isinstance(rec.get("names_omitted"), int) else 0
    omitted += len(rec.get("names") or []) - len(names)
    if not names:
        return "no hostnames listed"
    shown = names[:MAX_SHOWN]
    omitted += len(names) - len(shown)
    return ", ".join(shown) + (" (+%d more)" % omitted if omitted else "")

def find_report(fs):
    # The cert subject stays in findings.jsonl only. Alert bodies carry d, the
    # fingerprint, a crt.sh link, and the strict-hostname scope from valid_for().
    out = ["WEAK-KEY CERTIFICATE(S) DETECTED by p4mon on npm-scanner-dev:", ""]
    for l in fs[-20:]:
        try:
            d = json.loads(l); fp = d.get("sha256", "")
            if not re.fullmatch(r"[0-9a-f]{64}", fp): continue
            out.append(f"  d={int(d['d'])}  sha256={fp}  https://crt.sh/?sha256={fp}  (unix ts {int(d['ts'])})")
            out.append(f"    valid for: {valid_for(d)}")
        except Exception:
            pass
    out += ["", f"Total weak-key findings to date: {len(fs)}",
            "ACTION: these certificates' private keys are trivially recoverable. Revoke and report to the issuing CA and the browser root programs."]
    return "\n".join(out)

def daily_report():
    j = jc("24 hours ago")
    tele = [l for l in j.splitlines() if l.startswith("[t+")]
    tail = [l for l in j.splitlines() if l.startswith("[tail +")]
    restarts = sum(1 for l in j.splitlines() if "FRESH START" in l)
    active = subprocess.run(["systemctl","is-active","p4mon-ct"],capture_output=True,text=True).stdout.strip()
    since = subprocess.run(["systemctl","show","p4mon-ct","-p","ActiveEnterTimestamp","--value"],capture_output=True,text=True).stdout.strip()
    fs = findings()
    out = [f"p4mon CT weak-key monitor - daily report {time.strftime('%Y-%m-%d', time.gmtime())} UTC", "",
           f"Service: {active}; active since {since}; restarts in last 24h: {restarts}",
           f"Latest throughput snapshot: {tele[-1] if tele else 'n/a'}",
           f"Latest tailer stats: {tail[-1] if tail else 'n/a'}",
           f"WEAK-KEY FINDINGS to date: {len(fs)}"]
    if fs:
        out.append("Recent findings:")
        for l in fs[-10:]:
            out.append("  " + l.strip())
            try: out.append("    valid for: " + valid_for(json.loads(l)))
            except Exception: pass
    else:
        out.append("No weak keys found (expected - the live trusted CT stream is clean of this flaw).")
    return "\n".join(out)

if __name__ == "__main__":
    print(find_report(findings()) if MODE == "find" else daily_report())
