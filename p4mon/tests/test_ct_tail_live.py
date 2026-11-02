import datetime
import gzip
import hashlib
import os
import sys
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

    def raw(self, suffix):
        self.requested.append(suffix)
        if suffix not in self.files:
            raise OSError("404 " + suffix)
        return self.files[suffix]

    def close(self):
        pass


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


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
        {"name": "B", "tiled_logs": [
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
