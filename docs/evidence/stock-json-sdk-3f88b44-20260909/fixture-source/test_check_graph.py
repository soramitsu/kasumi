"""Pure source tests for rejecting false external-dependency provenance claims."""
import copy
from pathlib import Path
import unittest

import check_graph


class GraphProofTests(unittest.TestCase):
    def graph(self, ordered=False, explicit_numbers=False):
        fixture = Path(__file__).resolve().parent
        root = fixture.parents[1]
        packages = [{"id": name, "name": name, "source": None, "version": "0.1.0",
                     "manifest_path": str(root / "crates" / name / "Cargo.toml")}
                    for name in sorted(check_graph.KASUMI)]
        packages.append({"id": "consumer", "name": check_graph.FIXTURE, "version": "0.0.0",
                         "source": None, "manifest_path": str(fixture / "Cargo.toml")})
        for name, version in (("serde_json", "1.0.151"), ("serde", "1.0.229"), ("serde_core", "1.0.229")):
            packages.append({"id": name, "name": name, "version": version,
                             "source": check_graph.REGISTRY, "manifest_path": "/registry/" + name})
        features = ["arbitrary_precision", "raw_value", "std"] + (["preserve_order"] if ordered else [])
        consumer_features = ["default"] + (["numbers-and-raw"] if ordered or explicit_numbers else []) + (["ordered"] if ordered else [])
        data = {"workspace_root": str(fixture), "workspace_members": ["consumer"],
                "packages": packages, "resolve": {"root": "consumer", "nodes": [
                    {"id": p["id"], "features": features if p["name"] == "serde_json" else
                        consumer_features if p["id"] == "consumer" else []}
                    for p in packages]}}
        lock = {"package": [{"name": "serde_json", "version": "1.0.151", "source": check_graph.REGISTRY,
                              "checksum": check_graph.SERDE_JSON_SHA}]}
        return data, lock, fixture

    def test_all_expected_modes_accept_only_their_effective_features(self):
        for mode in ("default", "numbers-and-raw", "ordered"):
            data, lock, fixture = self.graph(mode == "ordered", mode == "numbers-and-raw")
            self.assertTrue(check_graph.verify(data, lock, fixture, mode)["root_patch_absent"])

    def test_root_workspace_fork_duplicate_and_database_graphs_are_rejected(self):
        for violation in ("root", "fork", "duplicate", "database", "fixture-feature", "foreign-path"):
            with self.subTest(violation=violation):
                data, lock, fixture = self.graph()
                decoder = next(p for p in data["packages"] if p["name"] == "serde_json")
                if violation == "root": data["workspace_root"] = str(fixture.parents[1])
                elif violation == "fork": decoder["source"] = None
                elif violation == "duplicate": data["packages"].append(copy.deepcopy(decoder))
                elif violation == "database": data["packages"].append({"name": "kasumi-store", "source": None})
                elif violation == "fixture-feature": data["resolve"]["nodes"][0]["features"] = ["test-utils"]
                elif violation == "foreign-path": data["packages"][0]["manifest_path"] = "/other/Cargo.toml"
                with self.assertRaises(ValueError): check_graph.verify(data, lock, fixture, "default")

    def test_archive_checksum_and_feature_mismatch_cannot_claim_stock_graph(self):
        data, lock, fixture = self.graph()
        lock["package"][0]["checksum"] = "0" * 64
        with self.assertRaises(ValueError): check_graph.verify(data, lock, fixture, "default")
        data, lock, fixture = self.graph(True)
        with self.assertRaises(ValueError): check_graph.verify(data, lock, fixture, "default")
        data, lock, fixture = self.graph()
        with self.assertRaises(ValueError): check_graph.verify(data, lock, fixture, "ordered")
        data, lock, fixture = self.graph(True)
        next(n for n in data["resolve"]["nodes"] if n["id"] == "consumer")["features"] = ["default"]
        with self.assertRaises(ValueError): check_graph.verify(data, lock, fixture, "ordered")


if __name__ == "__main__":
    unittest.main()
