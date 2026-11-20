import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_key_retention as keys


class Pages:
    def __init__(self, pages):
        self.binary = {"kasumid": "daemon"}
        self.pages = iter(pages)
        self.requests = []

    def input(self, name, request):
        self.requests.append(request)
        return name

    def command(self, *args, **kwargs):
        return json.dumps(next(self.pages))


class KeyRetentionDomainTests(unittest.TestCase):
    def setUp(self):
        self.scope = {"kind": "control"}
        one = {"key": {"provider": "file", "key_ref": "control", "version": 1},
               "reference": {"kind": "catalog", "node_id": 1,
                             "catalog_id": "00000000-0000-0000-0000-000000000001", "domain": "node_control"}}
        two = copy.deepcopy(one)
        two["key"]["key_ref"] = "custody"
        two["reference"].update(catalog_id="00000000-0000-0000-0000-000000000002", domain="retirement_custody")
        coverage = {"kind": "complete", "membership_epoch": 1, "coverage_revision": 3, "coverage_sha256": "d" * 64}
        cursor = {"membership_epoch": 1, "coverage_revision": 3, "scope_sha256": keys.digest(
            ["kasumi.key-retention-scope.v1", self.scope]), "inventory_sha256": "f" * 64, "after": one}
        self.pages = [{"entries": [one], "coverage": coverage, "next_cursor": cursor},
                      {"entries": [two], "coverage": copy.deepcopy(coverage), "next_cursor": None}]

    def read(self, pages):
        io = Pages(pages)
        result = keys.read_catalogs(io, "test-page", self.scope, 1, "control")
        self.assertEqual(io.requests[1]["cursor"], self.pages[0]["next_cursor"])
        return result

    def test_physical_pages_bind_cursor_coverage_catalog_and_limit(self):
        entries, coverage, maximum = self.read(self.pages)
        self.assertEqual([row["key"]["key_ref"] for row in entries], ["control", "custody"])
        self.assertEqual((coverage, maximum), (self.pages[0]["coverage"], 1))

    def test_rejects_replaced_rows_stale_coverage_and_truncation(self):
        for field in ("scope_sha256", "membership_epoch", "after"):
            pages = copy.deepcopy(self.pages)
            pages[0]["next_cursor"][field] = None
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.read(pages)
        for field, value in (("coverage", {"kind": "incomplete"}), ("entries", []),
                             ("entries", self.pages[0]["entries"]), ("entries", self.pages[0]["entries"] * 2)):
            pages = copy.deepcopy(self.pages)
            pages[1][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.read(pages)
        pages = copy.deepcopy(self.pages)
        pages[1]["coverage"]["coverage_sha256"] = "9" * 64
        with self.assertRaises(ValueError):
            self.read(pages)
        pages = copy.deepcopy(self.pages)
        pages[0]["next_cursor"] = None
        with self.assertRaises(ValueError):
            self.read(pages)


if __name__ == "__main__":
    unittest.main()
