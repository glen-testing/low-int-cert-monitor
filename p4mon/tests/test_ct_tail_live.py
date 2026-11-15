import base64
import contextlib
import datetime
import gzip
import hashlib
import http.client
import io
import json
import os
import sys
import tempfile
import threading
import urllib.error
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import ct_tail_live as t  # noqa: E402


def u24(b):
    return len(b).to_bytes(3, "big") + b


def u16(b):
    return len(b).to_bytes(2, "big") + b


def cert(tag):
    body = tag.encode()
    return bytes([0x30, len(body)]) + body


def leaf_x509(c, fps=()):
    return (1).to_bytes(8, "big") + b"\x00\x00" + u24(c) + u16(b"") + u16(b"".join(fps))


def leaf_precert(pre, fps=()):
    tbs = b"\x30\x01T"
    return ((1).to_bytes(8, "big") + b"\x00\x01" + b"\x11" * 32 + u24(tbs) + u16(b"")
            + u24(pre) + u16(b"".join(fps)))


def fp(der):
    return hashlib.sha256(der).digest()


class FakeConn:
    def __init__(self, files):
        self.files = files
        self.requested = []
        self.closed = False

    def raw(self, suffix):
        self.requested.append(suffix)
        if suffix not in self.files:
            raise OSError("404 " + suffix)
        return self.files[suffix]

    def get(self, suffix):
        return json.loads(self.raw(suffix))

    def close(self):
        self.closed = True


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def read_json(path):
    with open(path) as f:
        return json.load(f)


OK = lambda body, sig: True                     # signature check stubbed out


def tile(leaves):
    return b"".join(leaves)


class TilePath(unittest.TestCase):
    def test_small_index_is_one_padded_element(self):
        self.assertEqual(t.tile_path(0), "000")
        self.assertEqual(t.tile_path(5), "005")
        self.assertEqual(t.tile_path(999), "999")

    def test_large_index_uses_x_prefixed_elements(self):
        self.assertEqual(t.tile_path(1000), "x001/000")
        self.assertEqual(t.tile_path(1234067), "x001/x234/067")


class Checkpoint(unittest.TestCase):
    def test_size_is_second_line(self):
        body = b"example.com/log\n12345\nAAAA\n\n\xe2\x80\x94 example.com/log sig\n"
        self.assertEqual(t.checkpoint_size(body), 12345)

    def test_garbage_is_rejected(self):
        with self.assertRaises(ValueError):
            t.checkpoint_size(b"not a checkpoint")
        with self.assertRaises(ValueError):
            t.checkpoint_size(b"origin\nlots\nAAAA\n")


class DecodeBody(unittest.TestCase):
    def test_gzip_is_inflated(self):
        self.assertEqual(t.decode_body(gzip.compress(b"tile"), "gzip", 100), b"tile")

    def test_identity_passes_through(self):
        self.assertEqual(t.decode_body(b"tile", None, 100), b"tile")
        self.assertEqual(t.decode_body(b"tile", "identity", 100), b"tile")

    def test_body_exactly_at_the_limit_is_accepted(self):
        self.assertEqual(t.decode_body(gzip.compress(b"x" * 100), "gzip", 100), b"x" * 100)

    def test_bomb_is_rejected_without_inflating_it(self):
        bomb = gzip.compress(b"\0" * 50_000_000)          # ~50 KB on the wire
        with self.assertRaises(t.TooLarge):
            t.decode_body(bomb, "gzip", t.MAX_TILE_BYTES)

    def test_bomb_never_holds_more_than_the_limit_in_memory(self):
        import tracemalloc
        bomb = gzip.compress(b"\0" * 100_000_000)
        tracemalloc.start()
        try:
            with self.assertRaises(t.TooLarge):
                t.decode_body(bomb, "gzip", 1_000_000)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 5_000_000)

    def test_multi_member_gzip_is_concatenated_and_limited(self):
        two = gzip.compress(b"ab") + gzip.compress(b"cd")
        self.assertEqual(t.decode_body(two, "gzip", 4), b"abcd")
        with self.assertRaises(t.TooLarge):
            t.decode_body(two, "gzip", 3)

    def test_truncated_gzip_is_an_error(self):
        with self.assertRaises(t.BadEncoding):
            t.decode_body(gzip.compress(b"tile" * 100)[:-12], "gzip", 1000)


class DecodeBodyEdges(unittest.TestCase):
    def test_trailing_zero_padding_is_ignored_like_gzip_decompress(self):
        body = gzip.compress(b"hello") + b"\0" * 8
        self.assertEqual(t.decode_body(body, "gzip", 100), gzip.decompress(body))

    def test_corrupt_gzip_is_a_bad_encoding(self):
        with self.assertRaises(t.BadEncoding):
            t.decode_body(b"\x1f\x8b\x08\x00garbage-garbage", "gzip", 100)
        with self.assertRaises(t.BadEncoding):
            t.decode_body(gzip.compress(b"hello") + b"junk", "gzip", 100)

    def test_member_count_is_limited(self):
        one = gzip.compress(b"A")
        self.assertEqual(t.decode_body(one * t.MAX_GZIP_MEMBERS, "gzip", 10 ** 6), b"A" * t.MAX_GZIP_MEMBERS)
        with self.assertRaises(t.BadEncoding):
            t.decode_body(one * (t.MAX_GZIP_MEMBERS + 1), "gzip", 10 ** 6)


class FakeResponse:
    def __init__(self, body, status=200, encoding=None):
        self.stream, self.status, self.reason, self.headers = io.BytesIO(body), status, "x", http.client.HTTPMessage()
        if encoding:
            self.headers["Content-Encoding"] = encoding

    def read(self, n=-1):
        self.asked = n
        return self.stream.read(n)

    def getheader(self, k):
        return self.headers.get(k)


class FakeHTTPS:
    def __init__(self, resp):
        self.resp = resp

    def request(self, *a, **k):
        pass

    def getresponse(self):
        return self.resp

    def close(self):
        pass


class ConnLimits(unittest.TestCase):
    def conn(self, resp):
        c = t.Conn("https://log.example/")
        c.c = FakeHTTPS(resp)
        return c

    def test_raw_body_over_limit_is_rejected_reading_only_limit_plus_one(self):
        resp = FakeResponse(b"x" * 1000)
        with self.assertRaises(t.TooLarge):
            self.conn(resp).raw("tile/data/000", limit=10)
        self.assertEqual(resp.asked, 11)

    def test_raw_body_within_limit_is_returned_and_counted(self):
        before = t.reqs[0]
        self.assertEqual(self.conn(FakeResponse(b"x" * 10)).raw("tile/data/000", limit=10), b"x" * 10)
        self.assertEqual(t.reqs[0], before + 1)

    def test_undecodable_tile_is_skipped_not_retried(self):
        src = t.StaticCT(self.conn(FakeResponse(b"\x1f\x8b\x08\x00broken", encoding="gzip")), t.IssuerCache(), clock=Clock())
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(src.fetch(0, 512), ([], 256))
        self.assertEqual(src.bad, 1)

    def test_get_uses_the_json_limit(self):
        body = json.dumps({"tree_size": 1, "pad": "x" * 2_000_000}).encode()
        self.assertEqual(self.conn(FakeResponse(gzip.compress(body), encoding="gzip")).get("ct/v1/get-sth")["tree_size"], 1)


class TileLeaves(unittest.TestCase):
    def test_x509_yields_leaf_and_precert_yields_precertificate(self):
        a, pre = cert("leaf"), cert("precert")
        f1, f2 = b"\x01" * 32, b"\x02" * 32
        got = list(t.tile_leaves(leaf_x509(a, [f1]) + leaf_precert(pre, [f1, f2])))
        self.assertEqual(got, [(a, [f1]), (pre, [f1, f2])])

    def test_truncated_entry_raises(self):
        with self.assertRaises(ValueError):
            list(t.tile_leaves(leaf_x509(cert("leaf"))[:-1]))

    def test_chain_not_multiple_of_32_raises(self):
        bad = (1).to_bytes(8, "big") + b"\x00\x00" + u24(cert("x")) + u16(b"") + u16(b"\x01" * 31)
        with self.assertRaises(ValueError):
            list(t.tile_leaves(bad))

    def test_unknown_entry_type_raises(self):
        with self.assertRaises(ValueError):
            list(t.tile_leaves((1).to_bytes(8, "big") + b"\x00\x07"))


def static_source(files, issuers=None, partial_wait=60.0):
    clock = Clock()
    src = t.StaticCT(FakeConn(files), issuers or t.IssuerCache(), partial_wait=partial_wait, clock=clock)
    return src, clock


class StaticFetch(unittest.TestCase):
    def setUp(self):
        self.leaves = [cert(f"c{i}") for i in range(256)]

    def test_full_tile_is_read_from_cursor_offset(self):
        src, _ = static_source({"tile/data/x001/000": tile(leaf_x509(c) for c in self.leaves)})
        ders, n = src.fetch(1000 * 256 + 250, 10 ** 9)
        self.assertEqual(n, 6)
        self.assertEqual(ders, self.leaves[250:])

    def test_partial_tile_waits_then_is_fetched(self):
        src, clock = static_source({"tile/data/000.p/10": tile(leaf_x509(c) for c in self.leaves[:10])})
        self.assertEqual(src.fetch(3, 10), ([], 0))
        self.assertEqual(src.conn.requested, [])
        clock.now = 61.0
        ders, n = src.fetch(3, 10)
        self.assertEqual((ders, n), (self.leaves[3:10], 7))
        self.assertEqual(src.conn.requested, ["tile/data/000.p/10"])

    def test_partial_wait_restarts_when_cursor_moves(self):
        src, clock = static_source({})
        src.fetch(3, 10)
        clock.now = 50.0
        self.assertEqual(src.fetch(4, 10), ([], 0))
        clock.now = 100.0
        self.assertEqual(src.fetch(4, 10), ([], 0))
        self.assertEqual(src.conn.requested, [])

    def test_issuers_are_fetched_and_emitted_once(self):
        iss = cert("issuer")
        files = {"tile/data/000": tile(leaf_x509(c, [fp(iss)]) for c in self.leaves),
                 "issuer/" + fp(iss).hex(): iss}
        cache = t.IssuerCache()
        src, _ = static_source(files, cache)
        ders, n = src.fetch(254, 512)
        self.assertEqual((ders, n), ([self.leaves[254], iss, self.leaves[255]], 2))
        ders, _ = src.fetch(254, 512)
        self.assertEqual(ders, self.leaves[254:])
        self.assertEqual(src.conn.requested.count("issuer/" + fp(iss).hex()), 1)

    def test_issuer_with_wrong_hash_is_rejected_and_retried(self):
        claimed = b"\x05" * 32
        files = {"tile/data/000": tile(leaf_x509(c, [claimed]) for c in self.leaves),
                 "issuer/" + claimed.hex(): cert("impostor")}
        cache = t.IssuerCache()
        src, _ = static_source(files, cache)
        with self.assertRaises(t.IssuerMismatch):
            src.fetch(0, 512)
        self.assertFalse(cache.seen(claimed))

    def test_malformed_tile_is_skipped_keeping_parsed_entries(self):
        body = leaf_x509(self.leaves[0]) + leaf_x509(self.leaves[1]) + b"\x00\x01"
        src, _ = static_source({"tile/data/000": body})
        ders, n = src.fetch(0, 512)
        self.assertEqual((ders, n), (self.leaves[:2], 256))
        self.assertEqual(src.bad, 1)

    def test_oversized_tile_is_skipped_not_retried(self):
        class Big(FakeConn):
            def raw(self, suffix):
                self.requested.append(suffix)
                raise t.TooLarge("over")
        src = t.StaticCT(Big({}), t.IssuerCache(), clock=Clock())
        self.assertEqual(src.fetch(10, 512), ([], 246))
        self.assertEqual(src.bad, 1)
        self.assertTrue(src.conn.closed)

    def test_size_reads_checkpoint(self):
        src, _ = static_source({"checkpoint": b"o\n77\nAAAA\n\n- sig\n"})
        self.assertEqual(src.size(), 77)


def loglist(now):
    def iv(start_days, end_days):
        s = now + datetime.timedelta(days=start_days)
        e = now + datetime.timedelta(days=end_days)
        return {"start_inclusive": s.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "end_exclusive": e.strftime("%Y-%m-%dT%H:%M:%SZ")}
    usable = {"usable": {}}
    return {"operators": [
        {"name": "A", "logs": [
            {"description": "A rfc", "url": "https://a/rfc/", "state": usable, "temporal_interval": iv(-10, 100)},
            {"description": "A old", "url": "https://a/old/", "state": usable, "temporal_interval": iv(-300, -1)},
            {"description": "A gone", "url": "https://a/gone/", "state": {"retired": {}}, "temporal_interval": iv(-10, 100)},
        ], "tiled_logs": [
            {"description": "A tiles", "monitoring_url": "https://a/mon/", "submission_url": "https://a/sub/",
             "state": {"qualified": {}}, "temporal_interval": iv(50, 200)},
        ]},
        {"name": "B", "logs": [
            {"description": "B cf", "url": "https://ct.cloudflare.com/b/", "state": usable, "temporal_interval": iv(-10, 100)},
            {"description": "B nourl", "state": usable, "temporal_interval": iv(-10, 100)},
            {"description": "B nointerval", "url": "https://b/noiv/", "state": usable},
        ], "tiled_logs": [
            {"description": "B tiles", "monitoring_url": "https://b/mon/", "state": usable,
             "temporal_interval": iv(-10, 100)},
        ]},
    ]}


class PickLogs(unittest.TestCase):
    def setUp(self):
        self.now = datetime.datetime.now(datetime.timezone.utc)
        self.data = loglist(self.now)

    def test_both_kinds_are_selected_and_dead_logs_skipped(self):
        got = t.pick_logs(self.data, self.now, max_logs=0, max_per_op=0)
        self.assertEqual(got, [
            t.Log("A rfc", "rfc6962", "https://a/rfc/"),
            t.Log("A tiles", "static", "https://a/mon/"),
            t.Log("B tiles", "static", "https://b/mon/"),
        ])

    def test_caps_count_both_kinds(self):
        self.assertEqual([lg.name for lg in t.pick_logs(self.data, self.now, max_logs=0, max_per_op=1)],
                         ["A rfc", "B tiles"])
        self.assertEqual(len(t.pick_logs(self.data, self.now, max_logs=2, max_per_op=0)), 2)


class Reconcile(unittest.TestCase):
    def test_new_logs_start_and_dropped_logs_stop(self):
        a, b, c = (t.Log(n, "static", "https://" + n) for n in "abc")
        start, stop = t.reconcile({a.url, b.url}, [b, c])
        self.assertEqual(start, [c])
        self.assertEqual(stop, {a.url})


def rfc_entry(leaf, chain, precert=False):
    head = b"\x00\x00" + (1).to_bytes(8, "big") + (b"\x00\x01" if precert else b"\x00\x00")
    li = head + (b"\x11" * 32 + u24(b"\x30\x01T") if precert else u24(leaf)) + u16(b"")
    links = u24(b"".join(u24(c) for c in chain))
    xd = (u24(leaf) + links) if precert else links
    return {"leaf_input": base64.b64encode(li).decode(), "extra_data": base64.b64encode(xd).decode()}


class Rfc6962Fetch(unittest.TestCase):
    def test_leaf_precert_and_chains_are_emitted_and_junk_counted(self):
        leaf, pre, i1, i2 = cert("leaf"), cert("pre"), cert("i1"), cert("i2")
        entries = [rfc_entry(leaf, [i1, i2]), rfc_entry(pre, [i1], precert=True),
                   rfc_entry(b"\x02notder", []), {"leaf_input": "!!", "extra_data": ""}]
        conn = FakeConn({"ct/v1/get-entries?start=7&end=10": json.dumps({"entries": entries}).encode(),
                         "ct/v1/get-sth": b'{"tree_size": 11}'})
        src = t.Rfc6962(conn)
        self.assertEqual(src.size(), 11)
        self.assertEqual(src.fetch(7, 11), ([leaf, i1, i2, pre, i1], 4))
        self.assertEqual(src.bad, 1)

    def test_precert_without_chain(self):
        pre = cert("pre")
        e = rfc_entry(pre, [], precert=True)
        e["extra_data"] = base64.b64encode(u24(pre)).decode()
        self.assertEqual(t.ders_from(e), [pre])

    def test_batch_is_capped(self):
        conn = FakeConn({f"ct/v1/get-entries?start=0&end={t.BATCH - 1}": b'{"entries": []}'})
        self.assertEqual(t.Rfc6962(conn).fetch(0, 10 ** 6), ([], 0))


class Frame(unittest.TestCase):
    def test_records_are_u32le_length_prefixed(self):
        self.assertEqual(t.frame([b"ab", b"\x30"]), b"\x02\x00\x00\x00ab\x01\x00\x00\x000")


class ScriptedSource:
    def __init__(self, sizes, fetches):
        self.sizes, self.fetches, self.calls = list(sizes), list(fetches), []
        self.conn, self.bad, self.iskip = FakeConn({}), 0, 0

    @staticmethod
    def _play(v):
        if isinstance(v, Exception):
            raise v
        return v

    def size(self):
        return self._play(self.sizes.pop(0))

    def fetch(self, cursor, head):
        self.calls.append((cursor, head))
        return self._play(self.fetches.pop(0))


def throttled(retry):
    hdrs = http.client.HTTPMessage()
    hdrs["Retry-After"] = retry
    return urllib.error.HTTPError("u", 429, "Too Many Requests", hdrs, None)


class Tail(unittest.TestCase):
    def run_tail(self, src, sleeps_before_stop):
        stop, slept, out = threading.Event(), [], []

        def sleep(s):
            slept.append(s)
            if len(slept) >= sleeps_before_stop:
                stop.set()
        name = self.id()
        t.stats[name] = t.new_stats()
        t.tail(t.Log(name, "static", "https://x/"), stop, src, sleep=sleep, sink=out.append)
        return slept, b"".join(out), t.stats[name]

    def test_starts_at_head_backs_off_and_streams_every_entry(self):
        d1, d2 = cert("one"), cert("two")
        src = ScriptedSource(sizes=[10, 12, 12, OSError("sth down")],
                             fetches=[throttled("3"), OSError("reset"), ([d1], 1), ([], 0), ([d2], 1)])
        slept, out, st = self.run_tail(src, 4)
        self.assertEqual(slept, [3.0, 1.0, t.POLL, t.POLL])
        self.assertEqual(out, t.frame([d1]) + t.frame([d2]))
        self.assertEqual(src.calls, [(10, 12), (10, 12), (10, 12), (11, 12), (11, 12)])
        self.assertEqual((st["r429"], st["err"], st["certs"], st["ok"], st["sth"]), (1, 1, 2, 2, 4))
        self.assertTrue(src.conn.closed)

    def test_server_error_backs_off_without_counting_a_429(self):
        src = ScriptedSource(sizes=[0, 5], fetches=[urllib.error.HTTPError("u", 503, "x", http.client.HTTPMessage(), None)])
        slept, _, st = self.run_tail(src, 1)
        self.assertEqual((slept, st["r429"], st["err"]), ([0.5], 0, 1))

    def test_initial_size_failure_gives_up(self):
        src = ScriptedSource(sizes=[OSError("dns")], fetches=[])
        slept, out, _ = self.run_tail(src, 1)
        self.assertEqual((slept, out, src.calls), ([], b"", []))
        self.assertTrue(src.conn.closed)


class RefreshCycle(unittest.TestCase):
    def test_new_list_starts_new_logs_and_stops_dropped_ones(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "loglist.json")
            old = threading.Event()
            running = {"https://gone/": old}
            launched = []
            body = json.dumps(loglist(now)).encode()
            t.refresh_cycle(running, path, lambda: (body, b"sig"), now, lambda logs, r: launched.extend(logs), OK)
            self.assertTrue(old.is_set())
            self.assertNotIn("https://gone/", running)
            self.assertEqual([lg.name for lg in launched], ["A rfc", "A tiles", "B tiles"])
            self.assertEqual(read_json(path), loglist(now))

    def test_list_selecting_no_logs_stops_nothing(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "loglist.json")
            ev = threading.Event()
            running = {"https://a/rfc/": ev}
            with contextlib.redirect_stderr(io.StringIO()):
                t.refresh_cycle(running, path, lambda: (b'{"operators": []}', b"s"), now, lambda *a: self.fail("launched"), OK)
            self.assertEqual(running, {"https://a/rfc/": ev})
            self.assertFalse(ev.is_set() or os.path.exists(path))

    def test_failed_fetch_changes_nothing(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        with tempfile.TemporaryDirectory() as d:
            ev = threading.Event()
            running = {"https://a/rfc/": ev}
            t.refresh_cycle(running, os.path.join(d, "x.json"), lambda: (b"nope", b"sig"), now, lambda *a: self.fail("launched"), OK)
            self.assertEqual(running, {"https://a/rfc/": ev})
            self.assertFalse(ev.is_set())


class Boot(unittest.TestCase):
    def test_missing_list_is_fetched_once(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        calls = []

        def fetch():
            calls.append(1)
            return json.dumps(loglist(now)).encode(), b"sig"
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "loglist.json")
            self.assertTrue(t.boot(path, fetch, now, OK))
            t.boot(path, fetch, now, OK)
            self.assertEqual(len(calls), 1)

    def test_unverified_list_on_disk_is_refetched(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        good = json.dumps(loglist(now)).encode()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "loglist.json")
            with open(path, "wb") as f:
                f.write(b'{"operators": []}')          # no .sig beside it
            verify = lambda b, s: s == b"good"
            self.assertTrue(t.boot(path, lambda: (good, b"good"), now, verify))
            self.assertEqual(read_json(path), loglist(now))

    def test_list_selecting_no_logs_exits(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(SystemExit):
                t.boot(os.path.join(d, "l.json"), lambda: (b'{"operators": []}', b"s"), now, OK)

    def test_no_verified_list_at_all_exits(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                t.boot(os.path.join(d, "l.json"), lambda: (b'{"operators": []}', b"forged"), now, lambda b, s: False)

    def test_banner_warns_without_contact(self):
        logs = [t.Log("L", "static", "https://l/")]
        for contact, warned in (("", True), ("ops@example.org", False)):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                t.banner(logs, contact)
            self.assertEqual("P4MON_CONTACT unset" in err.getvalue(), warned)
            self.assertIn("https://l/", err.getvalue())


class RefreshLoglist(unittest.TestCase):
    def test_valid_list_replaces_file_and_invalid_keeps_it(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "loglist.json")
            self.assertTrue(t.refresh_loglist(path, lambda: (b'{"operators": []}', b"s1"), OK))
            self.assertEqual(read_json(path), {"operators": []})
            with open(path + ".sig", "rb") as f:
                self.assertEqual(f.read(), b"s1")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertFalse(t.refresh_loglist(path, lambda: (b"<html>oops", b"s"), OK))
                self.assertFalse(t.refresh_loglist(path, lambda: (b'{"no": "operators"}', b"s"), OK))
            self.assertEqual(read_json(path), {"operators": []})

    def test_older_signed_list_is_rejected_newer_and_equal_accepted(self):
        lst = lambda ts: json.dumps({"log_list_timestamp": ts, "operators": []}).encode()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "loglist.json")
            self.assertTrue(t.refresh_loglist(path, lambda: (lst("2026-11-14T13:36:22Z"), b"s"), OK))
            with contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertFalse(t.refresh_loglist(path, lambda: (lst("2026-10-01T00:00:00Z"), b"s"), OK))
                self.assertFalse(t.refresh_loglist(path, lambda: (b'{"operators": []}', b"s"), OK))
            self.assertIn("older than the stored list", err.getvalue())
            self.assertEqual(read_json(path)["log_list_timestamp"], "2026-11-14T13:36:22Z")
            self.assertTrue(t.refresh_loglist(path, lambda: (lst("2026-11-14T13:36:22Z"), b"s"), OK))
            self.assertTrue(t.refresh_loglist(path, lambda: (lst("2026-11-15T00:00:00Z"), b"s"), OK))

    def test_stored_list_without_a_valid_sig_does_not_block_an_update(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "loglist.json")
            with open(path, "w") as f:
                json.dump({"log_list_timestamp": "2030-01-01T00:00:00Z", "operators": []}, f)
            body = json.dumps({"log_list_timestamp": "2026-11-14T00:00:00Z", "operators": []}).encode()
            self.assertTrue(t.refresh_loglist(path, lambda: (body, b"s"), lambda b, s: s == b"s"))

    def test_badly_signed_list_is_rejected_and_old_one_kept(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "loglist.json")
            t.refresh_loglist(path, lambda: (b'{"operators": []}', b"s1"), OK)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertFalse(t.refresh_loglist(path, lambda: (b'{"operators": [{}]}', b"x"), lambda b, s: False))
            self.assertEqual(read_json(path), {"operators": []})
            with open(path + ".sig", "rb") as f:
                self.assertEqual(f.read(), b"s1")


class UserAgent(unittest.TestCase):
    def test_contact_is_appended_when_set(self):
        self.assertEqual(t.user_agent(""), t.UA)
        self.assertEqual(t.user_agent("ops@example.org"), t.UA + " (ops@example.org)")


class RetryAfter(unittest.TestCase):
    NOW = datetime.datetime(2026, 11, 2, 21, 24, 0, tzinfo=datetime.timezone.utc)

    def test_seconds_form(self):
        self.assertEqual(t.retry_after("7", self.NOW, 0.5), 7.0)

    def test_http_date_form(self):
        self.assertEqual(t.retry_after("Mon, 02 Nov 2026 21:24:44 GMT", self.NOW, 0.5), 44.0)

    def test_past_date_means_now(self):
        self.assertEqual(t.retry_after("Mon, 02 Nov 2026 21:20:00 GMT", self.NOW, 0.5), 0.0)

    def test_missing_or_garbage_falls_back(self):
        self.assertEqual(t.retry_after(None, self.NOW, 0.5), 0.5)
        self.assertEqual(t.retry_after("soon", self.NOW, 0.5), 0.5)

    def test_absurd_wait_is_capped(self):
        self.assertEqual(t.retry_after("86400", self.NOW, 0.5), t.MAX_RETRY_AFTER)


if __name__ == "__main__":
    unittest.main()


FIX = os.path.join(os.path.dirname(__file__), "fixtures")
CHROME_KEY = os.path.join(os.path.dirname(__file__), "..", "log_list_pubkey.pem")
# Throwaway 2048-bit RSA test key (two primes from `openssl prime -generate`).
TP = 146226641756698600378926642214556422547844387308062101629892334944135058283988942111206798830349448577629908238115717409923225046462052950720090873197169226216459282584181386421074552113901747379537504895821136275092400620146007751801707537545505946561356900386948365373375580458490153312248635607794872418113
TQ = 146482897457479890944344599326215742253294134638705156355675105015369023696350860959359972095966134500926135940742621657958357788182367713892578500246944377032719656475196543267328739961976331628543166746491180066096114757344953982590472868265295257494921101741785537063463374335793202344263373803342216694929
TN, TE = TP * TQ, 65537
TD = pow(TE, -1, (TP - 1) * (TQ - 1))
K = (TN.bit_length() + 7) // 8


def raw_sign(em):
    return pow(int.from_bytes(em, "big"), TD, TN).to_bytes(K, "big")


def pkcs1(msg, digest=None, info=t.SHA256_DIGESTINFO):
    tt = info + (digest or hashlib.sha256(msg).digest())
    return b"\x00\x01" + b"\xff" * (K - len(tt) - 3) + b"\x00" + tt


class LogListSignature(unittest.TestCase):
    def read(self, name):
        with open(os.path.join(FIX, name), "rb") as f:
            return f.read()

    def test_chrome_list_verifies_with_the_pinned_key(self):
        self.assertTrue(t.verify_loglist(self.read("log_list.json"), self.read("log_list.sig"), CHROME_KEY))

    def test_pinned_key_is_chromes_4096_bit_rsa_key(self):
        with open(CHROME_KEY, "rb") as f:
            n, e = t.rsa_pubkey(f.read())
        self.assertEqual((n.bit_length(), e), (4096, 65537))

    def test_one_changed_byte_in_the_list_fails(self):
        body = bytearray(self.read("log_list.json"))
        body[100] ^= 1
        self.assertFalse(t.verify_loglist(bytes(body), self.read("log_list.sig"), CHROME_KEY))

    def test_one_changed_byte_in_the_signature_fails(self):
        sig = bytearray(self.read("log_list.sig"))
        sig[-1] ^= 1
        self.assertFalse(t.verify_loglist(self.read("log_list.json"), bytes(sig), CHROME_KEY))

    def test_truncated_or_padded_signature_fails(self):
        body, sig = self.read("log_list.json"), self.read("log_list.sig")
        for bad in (sig[:-1], sig + b"\0", b"", b"\0" + sig[:-1], b"\0" + sig):  # last: same integer
            self.assertFalse(t.verify_loglist(body, bad, CHROME_KEY))

    def test_test_key_signature_verifies(self):
        self.assertTrue(t.rsa_verify((TN, TE), b"msg", raw_sign(pkcs1(b"msg"))))

    def test_signature_by_another_key_fails_against_chromes_key(self):
        body = self.read("log_list.json")
        sig = raw_sign(pkcs1(body))
        self.assertFalse(t.verify_loglist(body, sig + b"\0" * (512 - len(sig)), CHROME_KEY))
        self.assertFalse(t.verify_loglist(body, sig, CHROME_KEY))

    def test_lax_encodings_are_rejected(self):
        msg = b"msg"
        good = pkcs1(msg)
        dig = hashlib.sha256(msg).digest()
        short_pad = b"\x00\x01" + b"\xff" * 8 + b"\x00" + t.SHA256_DIGESTINFO + dig
        trailing = short_pad + b"\x00" * (K - len(short_pad))         # hash then garbage
        variants = [
            trailing,
            good[:1] + b"\x02" + good[2:],                           # block type 2
            pkcs1(msg, hashlib.sha1(msg).digest(), bytes.fromhex("3021300906052b0e03021a05000414")),  # SHA-1
            pkcs1(msg, b"\0" * 32),                                  # wrong digest
            good[:20] + b"\x00" + good[21:],                         # zero in the padding
        ]
        for em in variants:
            self.assertEqual(len(em), K)
            self.assertFalse(t.rsa_verify((TN, TE), msg, raw_sign(em)))

    def test_signature_not_below_modulus_fails(self):
        self.assertFalse(t.rsa_verify((TN, TE), b"m", TN.to_bytes(K, "big")))

    def test_non_rsa_or_garbled_key_is_rejected(self):
        ec = (b"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEawlNhmSl1/ePv8UlBj/vlbsbqQ6x"
              b"\nS9yjaG6VS6xCJ2D8EiyNHRwH8n7PmMHDL3dY9hAFRFUiFbD/C+L9NqiCTA==\n-----END PUBLIC KEY-----\n")
        for pem in (ec, b"-----BEGIN PUBLIC KEY-----\nMAA=\n-----END PUBLIC KEY-----\n"):
            with self.assertRaises(ValueError):
                t.rsa_pubkey(pem)

    def test_verified_on_disk_needs_the_sig_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "l.json")
            with open(path, "wb") as f:
                f.write(self.read("log_list.json"))
            self.assertFalse(t.verified_on_disk(path, lambda b, s: t.verify_loglist(b, s, CHROME_KEY)))
            with open(path + ".sig", "wb") as f:
                f.write(self.read("log_list.sig"))
            self.assertTrue(t.verified_on_disk(path, lambda b, s: t.verify_loglist(b, s, CHROME_KEY)))


class FlakyConn(FakeConn):
    # Issuer requests fail while self.down is set.
    down = True

    def raw(self, suffix):
        if suffix.startswith("issuer/") and self.down:
            self.requested.append(suffix)
            raise OSError("503")
        return super().raw(suffix)


class IssuerSkip(unittest.TestCase):
    def setUp(self):
        self.iss = cert("issuer")
        self.leaves = [cert(f"c{i}") for i in range(256)]
        files = {"tile/data/000": tile(leaf_x509(c, [fp(self.iss)]) for c in self.leaves),
                 "issuer/" + fp(self.iss).hex(): self.iss}
        self.clock, self.cache = Clock(), t.IssuerCache()
        self.src = t.StaticCT(FlakyConn(files), self.cache, clock=self.clock, max_fails=3, cooldown=600)
        self.ipath = "issuer/" + fp(self.iss).hex()

    def test_failures_below_the_limit_raise_so_the_tile_is_retried(self):
        for _ in range(2):
            with self.assertRaises(OSError):
                self.src.fetch(254, 512)
        self.assertEqual(self.src.iskip, 0)

    def test_after_n_failures_the_issuer_is_skipped_and_leaves_still_flow(self):
        for _ in range(2):
            with self.assertRaises(OSError):
                self.src.fetch(254, 512)
        with contextlib.redirect_stderr(io.StringIO()) as err:
            ders, n = self.src.fetch(254, 512)
        self.assertEqual((ders, n), (self.leaves[254:], 2))
        self.assertIn("skipped for 600s", err.getvalue())
        self.assertFalse(self.cache.seen(fp(self.iss)))
        self.assertTrue(self.src.conn.closed)

    def test_skipped_issuer_is_not_requested_during_the_cooldown(self):
        for _ in range(2):
            with self.assertRaises(OSError):
                self.src.fetch(254, 512)
        with contextlib.redirect_stderr(io.StringIO()):
            self.src.fetch(254, 512)
        asked = self.src.conn.requested.count(self.ipath)
        self.clock.now = 599
        self.assertEqual(self.src.fetch(0, 512)[0], self.leaves)
        self.assertEqual(self.src.conn.requested.count(self.ipath), asked)

    def test_after_the_cooldown_it_is_retried_and_emitted_once_healthy(self):
        for _ in range(2):
            with self.assertRaises(OSError):
                self.src.fetch(254, 512)
        with contextlib.redirect_stderr(io.StringIO()):
            self.src.fetch(254, 512)
        self.clock.now = 601
        self.src.conn.down = False
        ders, _ = self.src.fetch(254, 512)
        self.assertEqual(ders, [self.leaves[254], self.iss, self.leaves[255]])
        self.assertTrue(self.cache.seen(fp(self.iss)))
        self.assertNotIn(fp(self.iss), self.src.ifail)

    def test_still_failing_after_the_cooldown_skips_again_after_one_try(self):
        for _ in range(2):
            with self.assertRaises(OSError):
                self.src.fetch(254, 512)
        with contextlib.redirect_stderr(io.StringIO()):
            self.src.fetch(254, 512)
            self.clock.now = 601
            asked = self.src.conn.requested.count(self.ipath)
            self.assertEqual(self.src.fetch(254, 512)[0], self.leaves[254:])
        self.assertEqual(self.src.conn.requested.count(self.ipath), asked + 1)

    def test_a_transient_failure_then_success_does_not_skip(self):
        with self.assertRaises(OSError):
            self.src.fetch(254, 512)
        self.src.conn.down = False
        ders, _ = self.src.fetch(254, 512)
        self.assertIn(self.iss, ders)
        self.assertEqual((self.src.iskip, self.src.ifail), (0, {}))

    def test_mismatching_issuer_counts_as_a_failure(self):
        claimed = b"\x05" * 32
        files = {"tile/data/000": tile(leaf_x509(c, [claimed]) for c in self.leaves),
                 "issuer/" + claimed.hex(): cert("impostor")}
        src = t.StaticCT(FakeConn(files), t.IssuerCache(), clock=Clock(), max_fails=2, cooldown=60)
        with self.assertRaises(t.IssuerMismatch):
            src.fetch(0, 512)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(src.fetch(0, 512)[0], self.leaves)
        self.assertEqual(src.iskip, 1)


class Rfc6962Limit(unittest.TestCase):
    def test_oversized_range_is_skipped(self):
        class Big(FakeConn):
            def get(self, suffix):
                raise t.TooLarge("over")
        src = t.Rfc6962(Big({}), "L")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(src.fetch(0, 10 ** 6), ([], t.BATCH))
        self.assertEqual(src.bad, 1)


class ReportLine(unittest.TestCase):
    def test_rates_are_per_second_since_the_last_line(self):
        saved, t.stats = t.stats, {"a": t.new_stats()}
        try:
            t.reqs[0] = 100
            t.stats["a"]["certs"] = 600
            line, prev = t.report_line(t.t0 + 60, {"t": t.t0, "certs": 0, "req": 40})
            self.assertIn("fed 600 certs (10/s)", line)
            self.assertIn("requests=100 (1.0/s)", line)
            self.assertIn("issuer_skips=0", line)
            self.assertEqual((prev["req"], prev["certs"]), (100, 600))
        finally:
            t.stats = saved
