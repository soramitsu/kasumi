"""Synthetic dependency counterexamples, never release qualification evidence."""

import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_dependency_patches as checker


class DependencyPatchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="unit-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.cargo = '[patch.crates-io]\nlibrary = { path = "vendor/workspace/library" }\n'
        self.write("Cargo.toml", self.cargo)
        files = {}
        for name, value, mode in [
                ("Cargo.toml", '[workspace]\nmembers = ["library", "macros"]\n', 0o644),
                ("Cargo.lock", "reviewed ignored lockfile\n", 0o644),
                ("library/Cargo.toml", '[package]\nname = "library"\nversion = "1.2.3"\n', 0o644),
                ("library/src/lib.rs", "pub fn reviewed() {}\n", 0o644),
                ("macros/Cargo.toml", '[package]\nname = "library-macros"\nversion = "1.2.3"\n', 0o644),
                ("macros/src/lib.rs", "// selected sibling package\n", 0o644),
                ("scripts/test.sh", "#!/bin/sh\nexit 0\n", 0o755)]:
            files[name] = self.write("vendor/workspace/" + name, value, mode)
        self.manifest = {
            "format": 2,
            "inventories": [{"path": "vendor/workspace", "files": files, "packages": [
                {"name": "library", "version": "1.2.3", "path": "vendor/workspace/library", "patch": True},
                {"name": "library-macros", "version": "1.2.3", "path": "vendor/workspace/macros", "patch": False}]}],
            "support_files": {"README.md": self.write("vendor/README.md", "reviewed support\n")},
        }
        self.save_manifest()
        self.metadata = {"packages": [], "resolve": {"nodes": []}}
        for package in self.manifest["inventories"][0]["packages"]:
            identity = "synthetic-" + package["name"]
            self.metadata["packages"].append({
                "id": identity, "name": package["name"], "version": package["version"],
                "source": None, "manifest_path": str(self.root / package["path"] / "Cargo.toml"),
            })
            self.metadata["resolve"]["nodes"].append({"id": identity})

    def write(self, relative, value, mode=0o644):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)
        path.chmod(mode)
        return {"sha256": checker.digest(path), "bytes": path.stat().st_size, "mode": oct(mode)}

    def save_manifest(self):
        self.write("vendor/patch-manifest.json", json.dumps(self.manifest))

    def verify(self, metadata=None):
        packages = checker.verify_sources(self.root)
        checker.verify_selection(self.root, packages, self.metadata if metadata is None else metadata)

    def test_complete_workspace_and_selected_sibling_are_verified(self):
        self.verify()

    def reviewed_checkpoint(self):
        inventory = self.manifest["inventories"][0]
        directory = "vendor/reviews/openraft"
        source = [{"path": name, **record} for name, record in inventory["files"].items()]
        source_record = self.write(directory + "/source-inventory.json", json.dumps(source))
        checkpoint = {
            "source_inventory": "source-inventory.json",
            "source_inventory_sha256": source_record["sha256"],
            "source_files": len(source),
            "source_bytes": sum(item["bytes"] for item in source),
        }
        checkpoint_record = self.write(directory + "/custody-checkpoint.json", json.dumps(checkpoint))
        for name, record in [("source-inventory.json", source_record),
                             ("custody-checkpoint.json", checkpoint_record)]:
            self.manifest["support_files"]["reviews/openraft/" + name] = record
        inventory["review"] = {
            "kind": "openraft-checkpoint",
            "path": directory + "/custody-checkpoint.json",
            "sha256": checkpoint_record["sha256"],
            "inventory_path": directory + "/source-inventory.json",
            "inventory_sha256": source_record["sha256"],
        }
        self.save_manifest()

    def test_dependency_checkpoint_is_verified_without_archived_evidence(self):
        self.reviewed_checkpoint()
        self.verify()
        self.assertFalse((self.root / "docs/evidence").exists())

    def test_changed_dependency_checkpoint_is_rejected(self):
        self.reviewed_checkpoint()
        self.write("vendor/reviews/openraft/custody-checkpoint.json", "{}")
        with self.assertRaisesRegex(ValueError, "review evidence changed"):
            self.verify()

    def test_unrecorded_review_file_is_rejected(self):
        self.reviewed_checkpoint()
        self.write("vendor/reviews/openraft/unreviewed.json", "{}")
        with self.assertRaisesRegex(ValueError, "vendor tree"):
            self.verify()

    def test_nested_support_files_are_limited_to_review_inputs(self):
        self.manifest["support_files"]["other/input.json"] = self.write("vendor/other/input.json", "{}")
        self.save_manifest()
        with self.assertRaisesRegex(ValueError, "invalid vendor support file"):
            self.verify()

    def test_support_file_cannot_overlap_a_package_inventory(self):
        inventory = self.manifest["inventories"][0]
        old = self.root / "vendor/workspace"
        old.rename(self.root / "vendor/reviews")
        inventory["path"] = "vendor/reviews"
        for package in inventory["packages"]:
            package["path"] = package["path"].replace("vendor/workspace", "vendor/reviews")
        self.write("Cargo.toml", self.cargo.replace("vendor/workspace", "vendor/reviews"))
        self.manifest["support_files"]["reviews/extra.json"] = self.write("vendor/reviews/extra.json", "{}")
        self.save_manifest()
        with self.assertRaisesRegex(ValueError, "invalid vendor support file"):
            checker.verify_sources(self.root)

    def test_missing_patch_is_rejected_even_if_metadata_still_names_local_source(self):
        self.write("Cargo.toml", "[workspace]\n")
        with self.assertRaisesRegex(ValueError, "patch roster"):
            self.verify()

    def test_unrecorded_local_patch_is_rejected(self):
        self.write("Cargo.toml", self.cargo + 'unrecorded = { path = "crates/unrecorded" }\n')
        with self.assertRaisesRegex(ValueError, "patch roster"):
            self.verify()

    def test_wrong_patch_manifest_path_is_rejected(self):
        self.write("Cargo.toml", self.cargo.replace("workspace/library", "workspace/macros"))
        with self.assertRaisesRegex(ValueError, "patch roster"):
            self.verify()

    def test_old_manifest_format_has_no_fallback(self):
        self.manifest["format"] = 1
        self.save_manifest()
        with self.assertRaisesRegex(ValueError, "unsupported"):
            self.verify()

    def test_source_change_cannot_be_hidden_by_unchanged_cargo_metadata(self):
        self.write("vendor/workspace/library/src/lib.rs", "pub fn unreviewed() {}\n")
        with self.assertRaisesRegex(ValueError, "changed without review"):
            self.verify()

    def test_executable_mode_change_is_rejected_with_unchanged_bytes(self):
        (self.root / "vendor/workspace/scripts/test.sh").chmod(0o644)
        with self.assertRaisesRegex(ValueError, "changed without review"):
            self.verify()

    def test_missing_ignored_workspace_lockfile_is_rejected(self):
        (self.root / "vendor/workspace/Cargo.lock").unlink()
        with self.assertRaises(FileNotFoundError):
            self.verify()

    def test_extra_hidden_vendor_file_is_rejected(self):
        self.write("vendor/workspace/.unreviewed", "not a reviewed input")
        with self.assertRaisesRegex(ValueError, "vendor tree"):
            self.verify()

    def test_special_vendor_entry_is_rejected(self):
        os.mkfifo(self.root / "vendor/workspace/unreviewed-pipe")
        with self.assertRaisesRegex(ValueError, "special vendor input"):
            self.verify()

    def test_empty_directories_do_not_change_fresh_checkout_qualification(self):
        empty = self.root / "vendor/workspace/target/empty"
        empty.mkdir(parents=True)
        self.verify()
        empty.rmdir()
        empty.parent.rmdir()
        self.verify()

    def test_file_symlink_is_rejected_even_when_target_bytes_match(self):
        path = self.root / "vendor/workspace/library/src/lib.rs"
        self.write("matching.rs", path.read_text())
        path.unlink()
        path.symlink_to(self.root / "matching.rs")
        with self.assertRaisesRegex(ValueError, "indirect"):
            self.verify()

    def test_directory_symlink_cannot_hide_matching_subtree(self):
        path = self.root / "vendor/workspace/macros"
        path.rename(self.root / "matching-macros")
        path.symlink_to(self.root / "matching-macros", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "indirect"):
            self.verify()

    def test_extra_dangling_symlink_is_rejected(self):
        (self.root / "vendor/.hidden-link").symlink_to("absent")
        with self.assertRaisesRegex(ValueError, "indirect"):
            self.verify()

    def test_selected_package_requires_source_version_path_and_resolution(self):
        for field, value in [("source", "registry+https://example.invalid"),
                             ("version", "9.9.9"),
                             ("manifest_path", str(self.root / "Cargo.toml")),
                             ("id", "not-in-resolve")]:
            with self.subTest(field=field):
                metadata = copy.deepcopy(self.metadata)
                metadata["packages"][1][field] = value
                with self.assertRaisesRegex(ValueError, "source not selected"):
                    self.verify(metadata)

    def test_registry_copy_of_selected_macro_is_rejected(self):
        metadata = copy.deepcopy(self.metadata)
        copied = dict(metadata["packages"][1], source="registry+example")
        metadata["packages"].append(copied)
        with self.assertRaisesRegex(ValueError, "dependency copies"):
            self.verify(metadata)

    def test_duplicate_json_key_is_not_silently_accepted(self):
        path = self.root / "vendor/patch-manifest.json"
        path.write_text(path.read_text().replace('"format": 2', '"format": 1, "format": 2'))
        with self.assertRaisesRegex(ValueError, "duplicate manifest key"):
            self.verify()

    def test_metadata_cannot_rewrite_the_policy_while_preserving_package_paths(self):
        def metadata_with_mutation(*args, **kwargs):
            record = self.write("vendor/workspace/library/src/lib.rs", "pub fn replaced() {}\n")
            self.manifest["inventories"][0]["files"]["library/src/lib.rs"] = record
            self.save_manifest()
            return json.dumps(self.metadata).encode()
        with patch.object(checker.subprocess, "check_output", side_effect=metadata_with_mutation):
            with self.assertRaisesRegex(ValueError, "manifest changed"):
                checker.verify(self.root)


if __name__ == "__main__":
    unittest.main()
