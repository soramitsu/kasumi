"""The stable matrix fails closed on anything upstream adds without a review."""
import copy
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import check_dependency_patches
import dependency_matrix as matrix


class DependencyMatrixTests(unittest.TestCase):
    def setUp(self):
        self.frozen = Path.cwd().resolve()
        self.manifest = check_dependency_patches.read_json(
            self.frozen / "vendor/patch-manifest.json")
        temporary = tempfile.TemporaryDirectory(prefix="matrix-unit-")
        self.addCleanup(temporary.cleanup)
        # Only the manifests are read; targets come from the reviewed inventory.
        self.source = Path(temporary.name).resolve()
        for inventory in self.manifest["inventories"]:
            for name in inventory["files"]:
                if Path(name).name == "Cargo.toml":
                    target = self.source / inventory["path"] / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(self.frozen / inventory["path"] / name, target)

    def package(self, suites, name):
        return next(package for suite in suites for package in suite["packages"]
                    if package["name"] == name)

    def edit(self, relative, old, new):
        path = self.source / relative
        text = path.read_text()
        self.assertEqual(text.count(old), 1, relative)
        path.write_text(text.replace(old, new))

    def test_frozen_vendor_tree_is_completely_classified(self):
        suites = matrix.roster(self.frozen, self.manifest)
        self.assertEqual(suites, matrix.roster(self.source, self.manifest))
        for name, product in matrix.product_features().items():
            case = next(case for case in self.package(suites, name)["cases"]
                        if case["id"] == "product")
            self.assertEqual(case["enabled"], product)
        rmcp = self.package(suites, "rmcp")
        excluded = {target["name"]: target["class"] for target in rmcp["excluded_targets"]}
        self.assertEqual(excluded["test_with_js"], "external-runtime")
        self.assertEqual(excluded["test_with_python"], "external-runtime")
        self.assertEqual(excluded["test_local_client_handler"], "unselected")
        run = {name for case in rmcp["cases"] for name in case["tests"]}
        self.assertFalse(run & set(excluded))
        self.assertEqual(len(run) + len(excluded), 82)
        openraft = self.package(suites, "openraft")
        classes = {feature["name"]: feature["class"] for feature in openraft["excluded_features"]}
        self.assertEqual((classes["bench"], classes["bt"]), ("nightly-only", "nightly-only"))
        self.assertEqual(len(self.package(suites, "tests")["cases"][0]["tests"]), 12)
        recorded = matrix.exclusions(suites)
        self.assertTrue(all(item["class"] in matrix.EXCLUSION_CLASSES for item in recorded))
        self.assertIn({"root": "vendor/openraft-0.9.25", "kind": "member", "name": "rocksstore",
                       "class": "external-native-library", "reason": "links RocksDB"}, recorded)

    def test_new_upstream_feature_member_or_target_is_unclassified(self):
        self.edit("vendor/lru-0.16.4/Cargo.toml", "[features]\n", "[features]\nexperimental = []\n")
        with self.assertRaisesRegex(ValueError, "unclassified or misclassified vendored feature: lru"):
            matrix.roster(self.source, self.manifest)

    def test_new_workspace_member_and_dropped_exclusion_fail(self):
        self.edit("vendor/openraft-0.9.25/Cargo.toml", '    "sledstore",\n',
                  '    "sledstore",\n    "newstore",\n')
        with self.assertRaisesRegex(ValueError, "members differ"):
            matrix.roster(self.source, self.manifest)

    def test_product_default_drift_is_not_silently_tested_as_product(self):
        self.edit("vendor/bitmaps-3.2.1/Cargo.toml", 'default = ["std"]', "default = []")
        with self.assertRaisesRegex(ValueError, "unclassified|product case differs"):
            matrix.roster(self.source, self.manifest)

    def test_case_cannot_enable_a_nightly_or_external_feature(self):
        changed = copy.deepcopy(matrix.MATRIX)
        package = changed["vendor/openraft-0.9.25"]["packages"]["openraft"]
        package["cases"] = (*package["cases"], {"id": "everything", "default_features": True,
                                                "features": ["serde", "bt"]})
        with patch.object(matrix, "MATRIX", changed):
            with self.assertRaisesRegex(ValueError, "enables an excluded feature: openraft"):
                matrix.roster(self.source, self.manifest)

    def test_unknown_exclusion_class_and_absent_excluded_target_fail(self):
        changed = copy.deepcopy(matrix.MATRIX)
        changed["vendor/lru-0.16.4"]["packages"]["."]["excluded_features"]["nightly"]["class"] = \
            "waived"
        with patch.object(matrix, "MATRIX", changed):
            with self.assertRaisesRegex(ValueError, "unknown dependency suite exclusion class"):
                matrix.roster(self.source, self.manifest)
        changed = copy.deepcopy(matrix.MATRIX)
        changed["vendor/rmcp-3.2.0"]["packages"]["."]["excluded_targets"]["test_removed"] = {
            "class": "external-runtime", "reason": "stale"}
        with patch.object(matrix, "MATRIX", changed):
            with self.assertRaisesRegex(ValueError, "excludes an absent test target"):
                matrix.roster(self.source, self.manifest)

    def test_target_needing_features_no_single_case_enables_is_not_dropped(self):
        self.edit("vendor/rmcp-3.2.0/Cargo.toml", '[[test]]\nname = "test_cache_hints"\n',
                  '[[test]]\nname = "test_cache_hints"\nrequired-features = ["not-a-feature"]\n')
        with self.assertRaisesRegex(ValueError, "run by no matrix case: test_cache_hints"):
            matrix.roster(self.source, self.manifest)

    def test_unclassified_automatic_target_directories_fail(self):
        for added in ("examples/demo.rs", "benches/speed.rs", "src/bin/tool.rs"):
            manifest = copy.deepcopy(self.manifest)
            inventory = next(item for item in manifest["inventories"]
                             if item["path"] == "vendor/lru-0.16.4")
            inventory["files"][added] = {}
            with self.subTest(added=added), self.assertRaisesRegex(
                    ValueError, "unclassified automatic target"):
                matrix.roster(self.source, manifest)

    def test_new_automatic_integration_target_joins_the_named_roster(self):
        manifest = copy.deepcopy(self.manifest)
        inventory = next(item for item in manifest["inventories"]
                         if item["path"] == "vendor/openraft-0.9.25")
        inventory["files"]["tests/tests/added_suite/main.rs"] = {}
        suites = matrix.roster(self.source, manifest)
        tests = self.package(suites, "tests")["cases"][0]["tests"]
        self.assertIn("added_suite", tests)
        step = next(step for step in matrix.steps("/native/cargo", self.source, suites, 2)
                    if step["id"] == "openraft-0-9-25-tests-upstream-stable-targets")
        self.assertEqual(step["launches"], 14)
        self.assertIn("added_suite", step["command"])

    def test_optional_dependency_features_follow_cargo_rules(self):
        cargo = {"features": {"default": ["std"], "std": [], "tls": ["dep:rustls", "net/tls"],
                              "trace": ["log/kv"]},
                 "dependencies": {"rustls": {"optional": True}, "log": {"optional": True},
                                  "net": {"version": "1"}}}
        table, implicit = matrix.feature_table(cargo)
        self.assertEqual(implicit, {"log"})
        self.assertEqual(matrix.enabled_features(
            table, implicit, {"default_features": True, "features": ["trace"]}),
            {"default", "std", "trace", "log"})
        self.assertEqual(matrix.enabled_features(
            table, implicit, {"default_features": False, "features": ["tls"]}), {"tls"})
        with self.assertRaisesRegex(ValueError, "unknown feature"):
            matrix.enabled_features(table, implicit,
                                    {"default_features": False, "features": ["absent"]})


if __name__ == "__main__":
    unittest.main()
