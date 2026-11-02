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
        self.assertEqual(t.decode_body(gzip.compress(b"tile"), "gzip"), b"tile")

    def test_identity_passes_through(self):
        self.assertEqual(t.decode_body(b"tile", None), b"tile")
        self.assertEqual(t.decode_body(b"tile", "identity"), b"tile")


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
        self.conn, self.bad = FakeConn({}), 0

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
            t.refresh_cycle(running, path, lambda: body, now, lambda logs, r: launched.extend(logs))
            self.assertTrue(old.is_set())
            self.assertNotIn("https://gone/", running)
            self.assertEqual([lg.name for lg in launched], ["A rfc", "A tiles", "B tiles"])
            self.assertEqual(read_json(path), loglist(now))

    def test_failed_fetch_changes_nothing(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        with tempfile.TemporaryDirectory() as d:
            ev = threading.Event()
            running = {"https://a/rfc/": ev}
            t.refresh_cycle(running, os.path.join(d, "x.json"), lambda: b"nope", now, lambda *a: self.fail("launched"))
            self.assertEqual(running, {"https://a/rfc/": ev})
            self.assertFalse(ev.is_set())


class Boot(unittest.TestCase):
    def test_missing_list_is_fetched_once(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        calls = []

        def fetch():
            calls.append(1)
            return json.dumps(loglist(now)).encode()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "loglist.json")
            self.assertTrue(t.boot(path, fetch, now))
            t.boot(path, fetch, now)
            self.assertEqual(len(calls), 1)

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
            self.assertTrue(t.refresh_loglist(path, lambda: b'{"operators": []}'))
            self.assertEqual(read_json(path), {"operators": []})
            self.assertFalse(t.refresh_loglist(path, lambda: b"<html>oops"))
            self.assertEqual(read_json(path), {"operators": []})
            self.assertFalse(t.refresh_loglist(path, lambda: b'{"no": "operators"}'))
            self.assertEqual(read_json(path), {"operators": []})


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
