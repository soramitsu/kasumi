"""Synthetic archives; a real published crate is compared only when supplied.

Set KASUMI_UPSTREAM_CRATES to a directory of published ``.crate`` archives to
compare each one present with the frozen vendored tree.
"""
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import check_dependency_patches as checker
import dependency_provenance as provenance

ALPHA, BETA = "vendor/alpha-1.0.0", "vendor/beta-2.0.0"
DELTA = {ALPHA: {"changed": ("src/lib.rs",), "added": ("PATCH.md",), "removed": (".gitignore",)},
         BETA: {"changed": (), "added": (), "removed": ()}}


def crate(prefix, members, *, level=9, extra=None):
    """A published-style archive: one package directory of regular files."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as archive:
        for name, data in members.items():
            entry = tarfile.TarInfo(prefix + "/" + name)
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
        for entry in extra or ():
            archive.addfile(entry, io.BytesIO(b"x" * entry.size) if entry.isfile() else None)
    return gzip.compress(raw.getvalue(), compresslevel=level, mtime=0)


class UpstreamProvenanceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="provenance-unit-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = self.root / "source"
        self.archives = self.root / "crates"
        self.archives.mkdir()
        (self.source / "scripts").mkdir(parents=True)
        shutil.copyfile(provenance.__file__, self.source / provenance.VERIFIER)
        self.upstream = {
            ALPHA: {"Cargo.toml": b'[package]\nname = "alpha"\nversion = "1.0.0"\n',
                    "src/lib.rs": b"pub fn published() {}\n", ".gitignore": b"target\n"},
            BETA: {"Cargo.toml": b'[package]\nname = "beta"\nversion = "2.0.0"\n',
                   "src/lib.rs": b"pub fn untouched() {}\n"}}
        vendored = {ALPHA: {**self.upstream[ALPHA], "src/lib.rs": b"pub fn patched() {}\n",
                            "PATCH.md": b"reviewed change\n"},
                    BETA: dict(self.upstream[BETA])}
        del vendored[ALPHA][".gitignore"]
        (self.source / "Cargo.toml").write_text(
            '[patch.crates-io]\nalpha = { path = "' + ALPHA + '" }\n'
            'beta = { path = "' + BETA + '" }\n')
        inventories = []
        for root, files in vendored.items():
            records = {}
            for name, data in files.items():
                path = self.source / root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                path.chmod(0o644)
                records[name] = {"sha256": hashlib.sha256(data).hexdigest(),
                                 "bytes": len(data), "mode": "0o644"}
            name, version = Path(root).name.rsplit("-", 1)
            data = crate(Path(root).name, self.upstream[root])
            (self.archives / (Path(root).name + ".crate")).write_bytes(data)
            inventories.append({"path": root, "files": records,
                                "published_crate_sha256": hashlib.sha256(data).hexdigest(),
                                "packages": [{"name": name, "version": version, "path": root,
                                              "patch": True}]})
        self.manifest = {"format": 2, "inventories": inventories, "support_files": {}}
        self.save()
        for target, value in (("UPSTREAM_DELTA", DELTA), ("REVIEW_RECORD_ROOTS", {})):
            patcher = patch.object(provenance, target, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def save(self):
        path = self.source / "vendor/patch-manifest.json"
        path.write_text(json.dumps(self.manifest))
        path.chmod(0o644)

    def replace(self, root, data, *, rebind=False):
        (self.archives / (Path(root).name + ".crate")).write_bytes(data)
        if rebind:
            inventory = next(item for item in self.manifest["inventories"] if item["path"] == root)
            inventory["published_crate_sha256"] = hashlib.sha256(data).hexdigest()
            self.save()

    def test_reviewed_delta_and_archive_checksum_are_verified(self):
        receipt = provenance.verify(self.source, self.archives)
        self.assertEqual(receipt["verifier"], {
            "source_path": provenance.VERIFIER,
            "sha256": provenance.file_sha256(self.source / provenance.VERIFIER)})
        alpha, beta = receipt["roots"]
        self.assertEqual((alpha["changed"], alpha["added"], alpha["removed"]),
                         (["src/lib.rs"], ["PATCH.md"], [".gitignore"]))
        self.assertEqual((alpha["upstream_files"], alpha["identical_files"]), (3, 1))
        self.assertEqual((beta["upstream_files"], beta["identical_files"]), (2, 2))
        self.assertEqual(provenance.summary(receipt).count("\n"), 2)
        self.assertEqual(provenance.verify(self.source, self.archives), receipt)

    def test_substituted_archive_is_rejected_even_with_identical_members(self):
        # Different member bytes under the published name.
        changed = {**self.upstream[ALPHA], "Cargo.toml": b'[package]\nname = "alpha"\n'}
        self.replace(ALPHA, crate("alpha-1.0.0", changed))
        with self.assertRaisesRegex(ValueError, "differs from the reviewed published checksum"):
            provenance.verify(self.source, self.archives)
        # The same members repacked: still not the published archive bytes.
        self.replace(ALPHA, crate("alpha-1.0.0", self.upstream[ALPHA], level=1))
        with self.assertRaisesRegex(ValueError, "differs from the reviewed published checksum"):
            provenance.verify(self.source, self.archives)
        # Another crate's valid archive under this package's name.
        self.replace(ALPHA, (self.archives / "beta-2.0.0.crate").read_bytes())
        with self.assertRaisesRegex(ValueError, "differs from the reviewed published checksum"):
            provenance.verify(self.source, self.archives)

    def test_rebound_checksum_cannot_hide_an_unreviewed_source_difference(self):
        # A substituted archive whose checksum was also rewritten in the
        # manifest: the vendored tree no longer has the reviewed delta from it.
        changed = {**self.upstream[BETA], "src/lib.rs": b"pub fn other_upstream() {}\n"}
        self.replace(BETA, crate("beta-2.0.0", changed), rebind=True)
        with self.assertRaisesRegex(ValueError, "differs from the reviewed upstream delta: "
                                    + BETA):
            provenance.verify(self.source, self.archives)

    def test_unreviewed_vendored_addition_or_removal_is_rejected(self):
        for change in ("added", "removed"):
            with self.subTest(change=change):
                members = dict(self.upstream[BETA])
                if change == "added":
                    del members["src/lib.rs"]
                else:
                    members["build.rs"] = b"fn main() {}\n"
                self.replace(BETA, crate("beta-2.0.0", members), rebind=True)
                with self.assertRaisesRegex(ValueError, "reviewed upstream delta"):
                    provenance.verify(self.source, self.archives)

    def test_omitted_package_archive_or_inventory_is_rejected(self):
        (self.archives / "beta-2.0.0.crate").unlink()
        with self.assertRaisesRegex(ValueError, "archive roster omits or adds"):
            provenance.verify(self.source, self.archives)
        self.setUp()
        # The package vanishes from the reviewed manifest, tree and patch table.
        self.manifest["inventories"].pop()
        self.save()
        shutil.rmtree(self.source / BETA)
        (self.source / "Cargo.toml").write_text(
            '[patch.crates-io]\nalpha = { path = "' + ALPHA + '" }\n')
        with self.assertRaisesRegex(ValueError, "omits or adds an upstream provenance root"):
            provenance.verify(self.source, self.archives)
        self.setUp()
        del self.manifest["inventories"][1]["published_crate_sha256"]
        self.save()
        with self.assertRaisesRegex(ValueError, "no reviewed published archive"):
            provenance.verify(self.source, self.archives)

    def test_extra_aliased_and_misnamed_archives_are_rejected(self):
        (self.archives / "gamma-3.0.0.crate").write_bytes(b"unreviewed")
        with self.assertRaisesRegex(ValueError, "archive roster omits or adds"):
            provenance.verify(self.source, self.archives)
        (self.archives / "gamma-3.0.0.crate").unlink()
        original = self.archives / "beta-2.0.0.crate"
        moved = self.root / "elsewhere.crate"
        original.rename(moved)
        original.symlink_to(moved)
        with self.assertRaisesRegex(ValueError, "not a regular file"):
            provenance.verify(self.source, self.archives)
        inventory = self.manifest["inventories"][0]
        with self.assertRaisesRegex(ValueError, "misnamed"):
            provenance.verify_root(inventory, moved)
        alias = self.root / "crates-link"
        alias.symlink_to(self.archives, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "absent or aliased"):
            provenance.verify(self.source, alias)

    def test_unsafe_archive_members_are_rejected(self):
        def entry(name, kind=tarfile.REGTYPE, size=1):
            item = tarfile.TarInfo(name)
            item.type, item.size = kind, size if kind == tarfile.REGTYPE else 0
            item.linkname = "/etc/passwd" if kind != tarfile.REGTYPE else ""
            return item
        for extra, message in (
                (entry("beta-2.0.0/../escape"), "escapes its package directory"),
                (entry("other-9.9.9/src/lib.rs"), "escapes its package directory"),
                (entry("beta-2.0.0/link", tarfile.SYMTYPE), "not a bounded regular file"),
                (entry("beta-2.0.0/src/lib.rs"), "repeats a member")):
            with self.subTest(member=extra.name, message=message):
                self.replace(BETA, crate("beta-2.0.0", self.upstream[BETA], extra=[extra]),
                             rebind=True)
                with self.assertRaisesRegex(ValueError, message):
                    provenance.verify(self.source, self.archives)

    def test_vendored_bytes_are_bound_to_the_reviewed_inventory_first(self):
        (self.source / ALPHA / "src/lib.rs").write_bytes(b"pub fn unreviewed() {}\n")
        with self.assertRaisesRegex(ValueError, "changed without review"):
            provenance.verify(self.source, self.archives)

    def test_review_record_root_cannot_become_an_archive_or_lose_its_review(self):
        inventory = copy.deepcopy(self.manifest["inventories"][1])
        with patch.object(provenance, "REVIEW_RECORD_ROOTS", {BETA: "openraft-checkpoint"}), \
                patch.object(provenance, "UPSTREAM_DELTA", {ALPHA: DELTA[ALPHA]}):
            (self.archives / "beta-2.0.0.crate").unlink()
            with self.assertRaisesRegex(ValueError, "changed its provenance kind"):
                provenance.verify(self.source, self.archives)
        self.assertIn("published_crate_sha256", inventory)

    def test_only_the_frozen_source_verifier_can_report(self):
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith("PYTHON")}
        scripts = self.source / "scripts"
        for name in ("check_dependency_patches.py", "dependency_matrix.py"):
            shutil.copyfile(Path(provenance.__file__).with_name(name), scripts / name)
        frozen = subprocess.run([sys.executable, "-B", "-S", str(scripts / "dependency_provenance.py"),
                                 "--archives", str(self.archives)], env=environment,
                                capture_output=True, text=True)
        # The subprocess uses the frozen roster, not this test's patched one.
        self.assertEqual(frozen.returncode, 1)
        self.assertIn("omits or adds an upstream provenance root", frozen.stderr)
        self.assertEqual(frozen.stdout, "")
        # A copy of the verifier outside the source it inspects has no identity.
        other = self.root / "other-scripts"
        shutil.copytree(scripts, other)
        wrong = subprocess.run([sys.executable, "-B", "-S", str(other / "dependency_provenance.py"),
                                "--archives", str(self.archives), "--source", str(self.source)],
                               env=environment, capture_output=True, text=True)
        self.assertEqual(wrong.returncode, 1)
        self.assertIn("not the frozen source executable", wrong.stderr)
        self.assertEqual(wrong.stdout, "")

    def test_frozen_manifest_roster_matches_the_reviewed_delta_table(self):
        source = Path.cwd().resolve()
        patch.stopall()
        manifest = checker.read_json(source / "vendor/patch-manifest.json")
        hashed = {item["path"] for item in manifest["inventories"]
                  if "published_crate_sha256" in item}
        reviewed = {item["path"] for item in manifest["inventories"] if "review" in item}
        self.assertEqual(hashed, set(provenance.UPSTREAM_DELTA))
        self.assertEqual(reviewed, set(provenance.REVIEW_RECORD_ROOTS))
        for inventory in manifest["inventories"]:
            delta = provenance.UPSTREAM_DELTA.get(inventory["path"])
            if delta is not None:
                self.assertLessEqual(set(delta["changed"]) | set(delta["added"]),
                                     set(inventory["files"]))
                self.assertFalse(set(delta["removed"]) & set(inventory["files"]))

    @unittest.skipUnless(os.environ.get("KASUMI_UPSTREAM_CRATES"),
                         "no published crate archives were supplied")
    def test_supplied_published_archives_match_the_frozen_vendored_tree(self):
        source = Path.cwd().resolve()
        patch.stopall()
        checker.verify_sources(source)
        manifest = checker.read_json(source / "vendor/patch-manifest.json")
        supplied = Path(os.environ["KASUMI_UPSTREAM_CRATES"]).resolve(strict=True)
        compared = []
        for inventory in manifest["inventories"]:
            archive = supplied / provenance.archive_name(inventory["path"])
            if inventory["path"] in provenance.UPSTREAM_DELTA and archive.is_file():
                compared.append(provenance.verify_root(inventory, archive)["package"])
        self.assertTrue(compared, "the supplied directory holds no reviewed archive")
        print("published archives compared: " + ", ".join(sorted(compared)), file=sys.stderr)


if __name__ == "__main__":
    unittest.main()
