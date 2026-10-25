#!/usr/bin/env python3
import json, threading, time, base64, struct, urllib.request, urllib.error, urllib.parse, http.client, sys, os, signal, datetime
UA = "p4mon-ct-weakkey-monitor/0.1"
BATCH = 256
MAXLOGS = int(os.environ.get("P4MON_MAXLOGS", "16"))
WINDOW_DAYS = int(os.environ.get("P4MON_WINDOW_DAYS", "400"))
MAX_PER_OP = int(os.environ.get("P4MON_MAX_PER_OP", "4"))
POLL = float(os.environ.get("P4MON_POLL_SEC", "10"))   # idle get-sth interval once caught up
LOGLIST = os.environ.get("P4MON_LOGLIST", "loglist.json")
wlock = threading.Lock(); w = sys.stdout.buffer; t0 = time.time()
stats_lock = threading.Lock()
stats = {}

class Conn:
    # One persistent keep-alive HTTPS connection per log thread (reused across
    # get-sth / get-entries). Close on any error so the next call reconnects.
    def __init__(self, base):
        u = urllib.parse.urlsplit(base)
        self.host = u.netloc; self.prefix = u.path + "ct/v1/"; self.c = None
    def get(self, suffix):
        if self.c is None:
            self.c = http.client.HTTPSConnection(self.host, timeout=20)
        self.c.request("GET", self.prefix + suffix, headers={"User-Agent": UA, "Connection": "keep-alive"})
        r = self.c.getresponse(); body = r.read()
        if r.status != 200:
            raise urllib.error.HTTPError(self.prefix + suffix, r.status, r.reason, r.headers, None)
        return json.loads(body)
    def close(self):
        if self.c:
            try: self.c.close()
            except Exception: pass
            self.c = None

def _u24(b, o):
    if o + 3 > len(b): raise ValueError("u24 out of bounds")
    return int.from_bytes(b[o:o+3], "big"), o + 3
def _opaque24(b, o):
    n, o = _u24(b, o)
    if o + n > len(b): raise ValueError("opaque24 out of bounds")
    return b[o:o+n], o + n

def ders_from(e):
    # Every certificate in the entry: the leaf/precert AND the full chain
    # (intermediates + root). Intermediates are the eMudhra failure point and
    # live only in extra_data, so they must be checked too.
    out = []
    li = base64.b64decode(e["leaf_input"]); xd = base64.b64decode(e["extra_data"])
    if int.from_bytes(li[10:12], "big") == 0:        # x509_entry
        cert, _ = _opaque24(li, 12); out.append(cert)
        total, o = _u24(xd, 0); end = o + total       # certificate_chain<0..2^24-1>
        while o < end: c, o = _opaque24(xd, o); out.append(c)
    else:                                            # precert_entry
        pre, o = _opaque24(xd, 0); out.append(pre)   # full precertificate
        if o < len(xd):
            total, o = _u24(xd, o); end = o + total   # precertificate_chain
            while o < end: c, o = _opaque24(xd, o); out.append(c)
    return [c for c in out if c and c[0] == 0x30]

def _iso(s): return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))

def pick_logs():
    # Shards are split by certificate expiry. Select every usable shard whose
    # temporal_interval overlaps [now, now+WINDOW_DAYS] so currently-issued
    # certs (which expire up to ~13 months out) are all covered.
    now = datetime.datetime.now(datetime.timezone.utc)
    horizon = now + datetime.timedelta(days=WINDOW_DAYS)
    d = json.load(open(LOGLIST)); out = []; per = {}
    for op in d.get("operators", []):
        for log in op.get("logs", []):
            url = log.get("url", ""); st = next(iter((log.get("state") or {}).keys()), "?")
            if st not in ("usable", "qualified") or "cloudflare" in url: continue
            ti = log.get("temporal_interval") or {}
            try: start, endx = _iso(ti["start_inclusive"]), _iso(ti["end_exclusive"])
            except Exception: continue
            if endx <= now or start >= horizon: continue
            if per.get(op["name"], 0) >= MAX_PER_OP: continue
            out.append((op["name"], url)); per[op["name"]] = per.get(op["name"], 0) + 1
            if len(out) >= MAXLOGS: return out
    return out

def tail(name, base):
    conn = Conn(base)
    st = stats[name]
    try:
        with stats_lock: st["sth"] += 1
        cursor = conn.get("get-sth")["tree_size"]    # START FRESH at the head
    except Exception as ex:
        sys.stderr.write(f"  [{name}] initial get-sth failed: {ex}\n"); conn.close(); return
    head = cursor; backoff = 0.5
    while True:
        if cursor >= head:
            with stats_lock: st["sth"] += 1
            try: head = conn.get("get-sth")["tree_size"]
            except Exception: conn.close()
            if cursor >= head: time.sleep(POLL); continue
        end = min(cursor + BATCH - 1, head - 1)
        try:
            es = conn.get(f"get-entries?start={cursor}&end={end}")["entries"]; backoff = 0.5
        except urllib.error.HTTPError as he:
            conn.close()
            if he.code == 429:
                with stats_lock: st["r429"] += 1
                ra = he.headers.get("Retry-After")
                time.sleep(float(ra) if (ra and ra.isdigit()) else backoff); backoff = min(backoff*2, 30); continue
            with stats_lock: st["err"] += 1
            time.sleep(backoff); backoff = min(backoff*2, 30); continue
        except Exception:
            conn.close()
            with stats_lock: st["err"] += 1
            time.sleep(backoff); backoff = min(backoff*2, 30); continue
        if not es: time.sleep(1.0); continue
        blob = bytearray(); c = 0
        for e in es:
            try: ds = ders_from(e)
            except Exception: continue
            for der in ds:
                blob += struct.pack("<I", len(der)); blob += der; c += 1
        with wlock: w.write(blob); w.flush()
        with stats_lock: st["certs"] += c; st["ok"] += 1
        cursor += len(es)

def reporter():
    while True:
        time.sleep(60)
        with stats_lock:
            tot = sum(s["certs"] for s in stats.values()); r429 = sum(s["r429"] for s in stats.values())
            err = sum(s["err"] for s in stats.values()); sth = sum(s["sth"] for s in stats.values())
        sys.stderr.write(f"[tail +{time.time()-t0:.0f}s] fed {tot} certs, get-sth={sth}, 429s={r429}, errs={err}\n"); sys.stderr.flush()

def main():
    signal.signal(signal.SIGTERM, lambda *a: os._exit(0))
    logs = pick_logs()
    sys.stderr.write(f"[tail] FRESH START, {len(logs)} logs, tailing new certs only (no catch-up):\n")
    for n, u in logs: sys.stderr.write(f"    {n:10} {u}\n")
    sys.stderr.flush()
    for n, _ in logs: stats[n] = {"ok": 0, "r429": 0, "err": 0, "certs": 0, "sth": 0}
    threading.Thread(target=reporter, daemon=True).start()
    for n, u in logs: threading.Thread(target=tail, args=(n, u), daemon=True).start()
    while True: time.sleep(3600)

if __name__ == "__main__":
    main()
