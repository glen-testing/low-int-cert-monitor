#!/usr/bin/env python3
import json, threading, time, base64, struct, urllib.request, urllib.error, urllib.parse, http.client, sys, os, signal, datetime, gzip, hashlib, email.utils
from typing import NamedTuple
UA = "p4mon-ct-weakkey-monitor/0.1"
BATCH = 256
TILE = 256                                       # static-ct data tile width (entries)
MAXLOGS = int(os.environ.get("P4MON_MAXLOGS", "16"))
WINDOW_DAYS = int(os.environ.get("P4MON_WINDOW_DAYS", "400"))
MAX_PER_OP = int(os.environ.get("P4MON_MAX_PER_OP", "4"))
POLL = float(os.environ.get("P4MON_POLL_SEC", "10"))   # idle get-sth / checkpoint interval once caught up
PARTIAL_WAIT = float(os.environ.get("P4MON_PARTIAL_WAIT_SEC", "60"))  # max wait for a static-ct tile to fill
LOGLIST = os.environ.get("P4MON_LOGLIST", "loglist.json")
# Some logs (Geomys/Sunlight) throttle readers whose User-Agent has no contact
# address: "429 Please add an email address to your User-Agent."
CONTACT = os.environ.get("P4MON_CONTACT", "")
MAX_RETRY_AFTER = 300.0
wlock = threading.Lock(); w = sys.stdout.buffer; t0 = time.time()
stats_lock = threading.Lock()
stats = {}

def user_agent(contact):
    return f"{UA} ({contact})" if contact else UA

def retry_after(value, now, default):
    # Retry-After is either delay-seconds or an HTTP-date (RFC 9110 10.2.3).
    try:
        secs = float(value) if value.isdigit() else (email.utils.parsedate_to_datetime(value) - now).total_seconds()
    except (AttributeError, TypeError, ValueError):
        return default
    return min(max(secs, 0.0), MAX_RETRY_AFTER)

class Log(NamedTuple):
    name: str
    kind: str     # "rfc6962" (get-sth/get-entries) or "static" (checkpoint + data tiles)
    url: str

def decode_body(body, encoding):
    # static-ct logs MAY gzip data tiles with no negotiation; RFC 6962 logs may too.
    return gzip.decompress(body) if (encoding or "").lower() == "gzip" else body

class Conn:
    # One persistent keep-alive HTTPS connection per log thread (reused across
    # requests). Close on any error so the next call reconnects.
    def __init__(self, base):
        u = urllib.parse.urlsplit(base)
        self.host = u.netloc; self.prefix = u.path.rstrip("/") + "/"; self.c = None
    def raw(self, suffix):
        if self.c is None:
            self.c = http.client.HTTPSConnection(self.host, timeout=20)
        self.c.request("GET", self.prefix + suffix, headers={
            "User-Agent": user_agent(CONTACT), "Connection": "keep-alive", "Accept-Encoding": "gzip, identity"})
        r = self.c.getresponse(); body = r.read()
        if r.status != 200:
            raise urllib.error.HTTPError(self.prefix + suffix, r.status, r.reason, r.headers, None)
        return decode_body(body, r.getheader("Content-Encoding"))
    def get(self, suffix):
        return json.loads(self.raw(suffix))
    def close(self):
        if self.c:
            try: self.c.close()
            except Exception: pass
            self.c = None

def _take(b, o, n):
    if o + n > len(b): raise ValueError("entry out of bounds")
    return b[o:o+n], o + n
def _opaque(b, o, width):
    n, o = _take(b, o, width)
    return _take(b, o, int.from_bytes(n, "big"))
def _u24(b, o):
    n, o = _take(b, o, 3)
    return int.from_bytes(n, "big"), o
def _opaque24(b, o): return _opaque(b, o, 3)

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

# ---- static-ct-api (c2sp.org/static-ct-api) ---------------------------------
def tile_path(n):
    # Tile index as 3-digit path elements, all but the last prefixed with "x".
    parts = [f"{n % 1000:03d}"]
    while n >= 1000:
        n //= 1000; parts.append(f"x{n % 1000:03d}")
    return "/".join(reversed(parts))

def checkpoint_size(body):
    # c2sp.org/tlog-checkpoint: origin line, then the decimal tree size.
    lines = body.split(b"\n")
    if len(lines) < 3 or not lines[1].isdigit(): raise ValueError("malformed checkpoint")
    return int(lines[1])

def tile_leaves(b):
    # Yields (certificate DER, [issuer fingerprints]) for each TileLeaf:
    # TimestampedEntry, then pre_certificate for precert entries, then
    # Fingerprint certificate_chain<0..2^16-1>.
    o = 0
    while o < len(b):
        hdr, o = _take(b, o, 10)                     # uint64 timestamp, uint16 entry_type
        etype = int.from_bytes(hdr[8:10], "big")
        if etype == 0:   cert, o = _opaque24(b, o)   # x509_entry: ASN.1Cert
        elif etype == 1: _, o = _take(b, o, 32); _, o = _opaque24(b, o)  # issuer_key_hash, TBS
        else: raise ValueError(f"unknown entry_type {etype}")
        _, o = _opaque(b, o, 2)                      # CtExtensions
        if etype == 1: cert, o = _opaque24(b, o)     # pre_certificate (the full precert)
        chain, o = _opaque(b, o, 2)
        if len(chain) % 32: raise ValueError("certificate_chain not a list of fingerprints")
        yield cert, [chain[i:i+32] for i in range(0, len(chain), 32)]

class IssuerMismatch(Exception):
    """An issuer response that does not hash to its fingerprint (transient: retry)."""

class IssuerCache:
    # Issuers are shared by millions of entries and referenced by fingerprint in
    # static-ct logs: fetch and emit each one ONCE per process, across all logs
    # (the same cross-log replica skipping p4mon's DEDUP does for leaves).
    def __init__(self): self.lock = threading.Lock(); self.done = set()
    def seen(self, fp):
        with self.lock: return fp in self.done
    def add(self, fp):
        with self.lock: self.done.add(fp)

class Rfc6962:
    def __init__(self, conn): self.conn = conn; self.bad = 0
    def size(self): return self.conn.get("ct/v1/get-sth")["tree_size"]
    def fetch(self, cursor, head):
        end = min(cursor + BATCH - 1, head - 1)
        es = self.conn.get(f"ct/v1/get-entries?start={cursor}&end={end}")["entries"]
        out = []
        for e in es:
            try: out += ders_from(e)
            except Exception: self.bad += 1
        return out, len(es)

class StaticCT:
    def __init__(self, conn, issuers, name="", partial_wait=PARTIAL_WAIT, clock=time.monotonic):
        self.conn = conn; self.issuers = issuers; self.name = name; self.partial_wait = partial_wait
        self.clock = clock; self.waiting = None; self.bad = 0
    def size(self): return checkpoint_size(self.conn.raw("checkpoint"))
    def _issuer(self, fp):
        der = self.conn.raw("issuer/" + fp.hex())
        if hashlib.sha256(der).digest() != fp: raise IssuerMismatch(fp.hex())
        return der
    def _tile_width(self, cursor, head):
        # Full tile when available. The spec asks clients to avoid partial data
        # tiles, but to fetch one that stays partial too long (quiet logs).
        n = cursor // TILE
        if head >= (n + 1) * TILE: return TILE
        if self.waiting is None or self.waiting[0] != cursor: self.waiting = (cursor, self.clock())
        if self.clock() - self.waiting[1] < self.partial_wait: return 0
        return head - n * TILE
    def fetch(self, cursor, head):
        width = self._tile_width(cursor, head)
        if width == 0: return [], 0
        n, skip = divmod(cursor, TILE)
        body = self.conn.raw(f"tile/data/{tile_path(n)}" + ("" if width == TILE else f".p/{width}"))
        out = []; fresh = {}
        try:
            for i, (cert, fps) in enumerate(tile_leaves(body)):
                if i >= width: break
                if i < skip: continue
                if cert and cert[0] == 0x30: out.append(cert)
                for fp in fps:
                    if fp in fresh or self.issuers.seen(fp): continue
                    fresh[fp] = self._issuer(fp); out.append(fresh[fp])
        except ValueError as ex:
            # Tiles are immutable and fully downloaded, so a parse error is
            # permanent: skip the rest of the tile rather than stall the log.
            self.bad += 1
            sys.stderr.write(f"  [{self.name}] malformed data tile {n}: {ex}; skipped\n")
        for fp in fresh: self.issuers.add(fp)
        return out, width - skip

def _iso(s): return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))

def _current(log, now, horizon):
    st = next(iter((log.get("state") or {}).keys()), "?")
    if st not in ("usable", "qualified"): return False
    ti = log.get("temporal_interval") or {}
    try: start, endx = _iso(ti["start_inclusive"]), _iso(ti["end_exclusive"])
    except Exception: return False
    return endx > now and start < horizon

def pick_logs(data, now, max_logs=MAXLOGS, max_per_op=MAX_PER_OP):
    # Shards are split by certificate expiry. Select every usable shard whose
    # temporal_interval overlaps [now, now+WINDOW_DAYS] so currently-issued
    # certs (which expire up to ~13 months out) are all covered. Both RFC 6962
    # logs ("logs") and static-ct logs ("tiled_logs"); a cap of 0 = no cap.
    horizon = now + datetime.timedelta(days=WINDOW_DAYS)
    out = []; per = {}
    for op in data.get("operators", []):
        cands = [Log(lg.get("description", lg.get("url", "")), "rfc6962", lg.get("url", "")) for lg in op.get("logs", []) if _current(lg, now, horizon)]
        cands += [Log(lg.get("description", lg.get("monitoring_url", "")), "static", lg.get("monitoring_url", "")) for lg in op.get("tiled_logs", []) if _current(lg, now, horizon)]
        for lg in cands:
            if not lg.url or "cloudflare" in lg.url: continue
            if max_per_op and per.get(op["name"], 0) >= max_per_op: continue
            out.append(lg); per[op["name"]] = per.get(op["name"], 0) + 1
            if max_logs and len(out) >= max_logs: return out
    return out

ISSUERS = IssuerCache()

def source_for(log):
    conn = Conn(log.url)
    return Rfc6962(conn) if log.kind == "rfc6962" else StaticCT(conn, ISSUERS, log.name)

def tail(log):
    src = source_for(log)
    st = stats[log.name]
    try:
        with stats_lock: st["sth"] += 1
        cursor = src.size()                          # START FRESH at the head
    except Exception as ex:
        sys.stderr.write(f"  [{log.name}] initial size failed: {ex}\n"); src.conn.close(); return
    head = cursor; backoff = 0.5; stale = False
    while True:
        if cursor >= head or stale:
            with stats_lock: st["sth"] += 1
            try: head = src.size(); stale = False
            except Exception: src.conn.close()
            if cursor >= head: time.sleep(POLL); continue
        try:
            ders, n = src.fetch(cursor, head); backoff = 0.5
        except urllib.error.HTTPError as he:
            src.conn.close()
            if he.code == 429:
                with stats_lock: st["r429"] += 1
                now = datetime.datetime.now(datetime.timezone.utc)
                time.sleep(retry_after(he.headers.get("Retry-After"), now, backoff)); backoff = min(backoff*2, 30); continue
            with stats_lock: st["err"] += 1
            time.sleep(backoff); backoff = min(backoff*2, 30); continue
        except Exception:
            src.conn.close()
            with stats_lock: st["err"] += 1
            time.sleep(backoff); backoff = min(backoff*2, 30); continue
        if n == 0: stale = True; time.sleep(POLL); continue
        blob = bytearray()
        for der in ders:
            blob += struct.pack("<I", len(der)); blob += der
        with wlock: w.write(blob); w.flush()
        with stats_lock: st["certs"] += len(ders); st["ok"] += 1; st["bad"] = src.bad
        cursor += n

def reporter():
    while True:
        time.sleep(60)
        with stats_lock:
            tot = sum(s["certs"] for s in stats.values()); r429 = sum(s["r429"] for s in stats.values())
            err = sum(s["err"] for s in stats.values()); sth = sum(s["sth"] for s in stats.values())
            bad = sum(s["bad"] for s in stats.values())
        sys.stderr.write(f"[tail +{time.time()-t0:.0f}s] fed {tot} certs, get-sth={sth}, 429s={r429}, errs={err}, unparsable={bad}\n"); sys.stderr.flush()

def main():
    signal.signal(signal.SIGTERM, lambda *a: os._exit(0))
    logs = pick_logs(json.load(open(LOGLIST)), datetime.datetime.now(datetime.timezone.utc))
    if not CONTACT: sys.stderr.write("[tail] P4MON_CONTACT unset: logs that require a contact address in the User-Agent will throttle us\n")
    sys.stderr.write(f"[tail] FRESH START, {len(logs)} logs, tailing new certs only (no catch-up):\n")
    for lg in logs: sys.stderr.write(f"    {lg.kind:7} {lg.name:28} {lg.url}\n")
    sys.stderr.flush()
    for lg in logs: stats[lg.name] = {"ok": 0, "r429": 0, "err": 0, "certs": 0, "sth": 0, "bad": 0}
    threading.Thread(target=reporter, daemon=True).start()
    for lg in logs: threading.Thread(target=tail, args=(lg,), daemon=True).start()
    while True: time.sleep(3600)

if __name__ == "__main__":
    main()
