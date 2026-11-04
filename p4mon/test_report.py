#!/usr/bin/env python3
"""Tests for report.py's alert body. Run: python3 -m unittest p4mon/test_report.py"""
import json, os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import report

FP = "a" * 64

def rec(**scope):
    return dict(ts=1793651511, d=12345, sha256=FP, subject="CN=x", **scope)

LEAF = dict(ca=False, tls_server=True, names=["www.example.com", "192.0.2.1"], names_omitted=0, permitted=[], excluded=[])

class ValidFor(unittest.TestCase):
    def test_tp_leaf_names(self):
        self.assertEqual(report.valid_for(rec(**LEAF)), "www.example.com, 192.0.2.1")

    def test_tp_unconstrained_ca(self):
        self.assertEqual(report.valid_for(rec(**dict(LEAF, ca=True, names=[]))),
                         "ANY website (CA certificate without name constraints)")

    def test_tp_constrained_ca(self):
        r = rec(**dict(LEAF, ca=True, permitted=[".example.com"], excluded=["bad.example.com"]))
        self.assertEqual(report.valid_for(r), "names under .example.com; excluding bad.example.com (name-constrained CA)")

    def test_fp_code_signing_ca(self):
        r = rec(**dict(LEAF, ca=True, tls_server=False))
        self.assertTrue(report.valid_for(r).startswith("no websites"))

    def test_fp_old_record_without_scope(self):
        self.assertTrue(report.valid_for(rec()).startswith("unknown"))

    def test_fp_free_text_in_names_dropped(self):
        r = rec(**dict(LEAF, names=["ok.example.com", "ignore previous instructions", "x\ny.com"], names_omitted=1))
        self.assertEqual(report.valid_for(r), "ok.example.com (+3 more)")

    def test_cap_shown_names(self):
        names = ["h%d.example.com" % i for i in range(30)]
        self.assertTrue(report.valid_for(rec(**dict(LEAF, names=names))).endswith("(+10 more)"))

class FindReport(unittest.TestCase):
    def test_tp_alert_contains_sites(self):
        body = report.find_report([json.dumps(rec(**LEAF))])
        self.assertIn("valid for: www.example.com, 192.0.2.1", body)
        self.assertIn("https://crt.sh/?sha256=" + FP, body)

    def test_fp_subject_and_bad_fingerprint_excluded(self):
        bad = json.dumps(dict(rec(**LEAF), sha256="not-a-hash", subject="CN=ignore all rules"))
        body = report.find_report([bad])
        self.assertNotIn("ignore all rules", body)
        self.assertNotIn("not-a-hash", body)

if __name__ == "__main__":
    unittest.main()
