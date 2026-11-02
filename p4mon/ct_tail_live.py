#!/usr/bin/env python3
import json, threading, time, base64, struct, urllib.request, urllib.error, urllib.parse, http.client, sys, os, signal, datetime, gzip, hashlib, email.utils, itertools
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
LOGLIST_URL = os.environ.get("P4MON_LOGLIST_URL", "https://www.gstatic.com/ct/log_list/v3/log_list.json")
REFRESH = float(os.environ.get("P4MON_LOGLIST_REFRESH_SEC", "86400"))  # re-read the log list (new shards, retirements)
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
            for cert, fps in itertools.islice(tile_leaves(body), skip, width):
                if cert and cert[0] == 0x30: out.append(cert)
                out += self._issuers_for(fps, fresh)
        except ValueError as ex:
            # Tiles are immutable and fully downloaded, so a parse error is
            # permanent: skip the rest of the tile rather than stall the log.
            self.bad += 1
            sys.stderr.write(f"  [{self.name}] malformed data tile {n}: {ex}; skipped\n")
        for fp in fresh: self.issuers.add(fp)
        return out, width - skip
    def _issuers_for(self, fps, fresh):
        # Issuers not yet emitted by any log; recorded in `fresh` until the
        # whole tile parsed, so a malformed tile cannot hide them for good.
        new = [fp for fp in dict.fromkeys(fps) if fp not in fresh and not self.issuers.seen(fp)]
        for fp in new: fresh[fp] = self._issuer(fp)
        return [fresh[fp] for fp in new]

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
    out = []
    for op in data.get("operators", []):
        out += list(_candidates(op, now, horizon))[:max_per_op or None]
    return out[:max_logs or None]

# (log-list key, Log.kind, URL field) for each API the log list describes.
KINDS = (("logs", "rfc6962", "url"), ("tiled_logs", "static", "monitoring_url"))

def _candidates(op, now, horizon):
    for key, kind, field in KINDS:
        for lg in op.get(key, []):
            url = lg.get(field, "")
            if url and "cloudflare" not in url and _current(lg, now, horizon):
                yield Log(lg.get("description", url), kind, url)

ISSUERS = IssuerCache()

def source_for(log):
    conn = Conn(log.url)
    return Rfc6962(conn) if log.kind == "rfc6962" else StaticCT(conn, ISSUERS, log.name)

def new_stats(): return {"ok": 0, "r429": 0, "err": 0, "certs": 0, "sth": 0, "bad": 0}

def frame(ders):
    # p4mon stream input: [u32 LE length][DER] per certificate.
    return b"".join(struct.pack("<I", len(d)) + d for d in ders)

def write_out(blob):
    with wlock: w.write(blob); w.flush()

def _bump(st, key):
    with stats_lock: st[key] += 1

def _size(src, st):
    # -> (tree size, None) or (None, the error); the connection is reset on error.
    _bump(st, "sth")
    try: return src.size(), None
    except Exception as ex: src.conn.close(); return None, ex

def _new_head(src, st, head):
    # -> (head, stale): the old head stays, still stale, when the read fails.
    size, _ = _size(src, st)
    return (head, True) if size is None else (size, False)

def _delay(ex, st, backoff):
    # Seconds to wait after a failed fetch: the server's Retry-After on 429.
    if isinstance(ex, urllib.error.HTTPError) and ex.code == 429:
        _bump(st, "r429")
        return retry_after(ex.headers.get("Retry-After"), datetime.datetime.now(datetime.timezone.utc), backoff)
    _bump(st, "err")
    return backoff

def tail(log, stop, src=None, sleep=time.sleep, sink=write_out):
    src = src or source_for(log)
    st = stats[log.name]
    head, ex = _size(src, st)                       # START FRESH at the head
    if head is None:
        sys.stderr.write(f"  [{log.name}] initial size failed: {ex}\n"); return
    cursor = head; backoff = 0.5; stale = False
    while not stop.is_set():
        if cursor >= head or stale:
            head, stale = _new_head(src, st, head)
            if cursor >= head: sleep(POLL); continue
        try: ders, n = src.fetch(cursor, head)
        except Exception as ex:
            src.conn.close(); sleep(_delay(ex, st, backoff)); backoff = min(backoff * 2, 30); continue
        backoff = 0.5
        if n == 0: stale = True; sleep(POLL); continue
        sink(frame(ders))
        with stats_lock: st["certs"] += len(ders); st["ok"] += 1; st["bad"] = src.bad
        cursor += n

def refresh_loglist(path, fetch):
    # Replace the log list only with one that parses; keep the old one otherwise.
    try:
        body = fetch(); data = json.loads(body)
        if not isinstance(data.get("operators"), list): raise ValueError("no operators")
    except Exception as ex:
        sys.stderr.write(f"[tail] log list refresh failed, keeping {path}: {ex}\n"); return False
    tmp = path + ".tmp"
    with open(tmp, "wb") as f: f.write(body)
    os.replace(tmp, path)
    return True

def fetch_loglist():
    req = urllib.request.Request(LOGLIST_URL, headers={"User-Agent": user_agent(CONTACT)})
    with urllib.request.urlopen(req, timeout=30) as r: return r.read()

def reconcile(running, picked):
    # -> (logs to start, urls to stop). Logs that left the selection (shard
    # expired, log retired, cap) stop; newly selected ones start.
    want = {lg.url for lg in picked}
    return [lg for lg in picked if lg.url not in running], set(running) - want

def reporter():
    while True:
        time.sleep(60)
        with stats_lock:
            tot = sum(s["certs"] for s in stats.values()); r429 = sum(s["r429"] for s in stats.values())
            err = sum(s["err"] for s in stats.values()); sth = sum(s["sth"] for s in stats.values())
            bad = sum(s["bad"] for s in stats.values())
        sys.stderr.write(f"[tail +{time.time()-t0:.0f}s] fed {tot} certs, get-sth={sth}, 429s={r429}, errs={err}, unparsable={bad}\n"); sys.stderr.flush()

def select(path, now):
    with open(path) as f: return pick_logs(json.load(f), now)

def listing(logs):
    for lg in logs: sys.stderr.write(f"    {lg.kind:7} {lg.name:28} {lg.url}\n")
    sys.stderr.flush()

def banner(logs, contact):
    if not contact: sys.stderr.write("[tail] P4MON_CONTACT unset: logs that require a contact address in the User-Agent will throttle us\n")
    sys.stderr.write(f"[tail] FRESH START, {len(logs)} logs, tailing new certs only (no catch-up):\n")
    listing(logs)

def boot(path, fetch, now):
    if not os.path.exists(path): refresh_loglist(path, fetch)
    return select(path, now)

def start(logs, running):
    for lg in logs:
        stats.setdefault(lg.name, new_stats())
        running[lg.url] = threading.Event()
        threading.Thread(target=tail, args=(lg, running[lg.url]), daemon=True).start()

def refresh_cycle(running, path, fetch, now, launch):
    # New shards start, expired/retired ones stop; a bad list changes nothing.
    if not refresh_loglist(path, fetch): return
    new, gone = reconcile(running, select(path, now))
    for url in gone: running.pop(url).set()
    if new or gone:
        sys.stderr.write(f"[tail] log list refreshed: +{len(new)} -{len(gone)} logs\n"); listing(new)
    launch(new, running)

def utcnow(): return datetime.datetime.now(datetime.timezone.utc)

def main():
    signal.signal(signal.SIGTERM, lambda *a: os._exit(0))
    logs = boot(LOGLIST, fetch_loglist, utcnow())
    banner(logs, CONTACT)
    running = {}
    threading.Thread(target=reporter, daemon=True).start()
    start(logs, running)
    while True:
        time.sleep(REFRESH)
        refresh_cycle(running, LOGLIST, fetch_loglist, utcnow(), start)

if __name__ == "__main__":
    main()
