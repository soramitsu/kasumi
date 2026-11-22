"""Bundle composition against a small real Git archive."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import compose_release_manifest as composer
import verify_release_acceptance as acceptance


class ComposerTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        (self.repo / "Cargo.lock").write_bytes(b"version = 4\n")
        (self.repo / "vendor").mkdir()
        (self.repo / "vendor/manifest").write_bytes(b"patched\n")
        self.git("add", ".")
        self.git("-c", "user.name=Test", "-c", "user.email=test@local", "-c", "commit.gpgsign=false", "commit", "-qm", "input")
        self.git("archive", "--format=tar", "-o", self.root / "source.tar", "HEAD")
        files = acceptance.archive_inventory(self.root / "source.tar", strip_root=False)
        (self.root / "files.json").write_text(json.dumps(files))
        self.inputs = {"source": {"commit": self.git("rev-parse", "HEAD"), "archive": "source.tar", "files": "files.json"},
                       "configurations": {}, "artifacts": {}, "gates": {}, "candidates": {}, "journals": {}}

    def git(self, *args):
        return subprocess.check_output(["git", "-C", self.repo, *args], text=True).strip()

    def write(self, *, draft=True):
        selection = self.root / "selections.json"
        selection.write_text(json.dumps(self.inputs))
        return composer.write_bundle(selection, self.root / "manifest.json", self.repo, draft=draft)

    def test_incomplete_evidence_only_publishes_an_explicit_draft(self):
        with self.assertRaisesRegex(ValueError, "release selections incomplete"):
            self.write(draft=False)
        self.assertFalse((self.root / "manifest.json").exists())
        self.inputs["configurations"]["limits"] = "files.json"
        first = self.write()
        self.assertEqual(len(first["remaining"]["gates"]), 27)
        self.assertEqual(first, self.write())
        recorded = acceptance.read_json(self.root / "manifest.json")
        inventory = acceptance.read_json(self.root / "files.json")
        self.assertEqual(recorded["source"]["patches_sha256"],
                         acceptance.canonical_hash({"vendor/manifest": inventory["vendor/manifest"]}))
        self.inputs["configurations"].clear()
        with self.assertRaisesRegex(ValueError, "existing output differs"):
            self.write()

    def test_checksum_artifact_covers_each_selected_file(self):
        artifacts = []
        for index, key in enumerate(sorted(acceptance.required_artifacts() - {"checksums"})):
            name = str(index) + ".bin"
            (self.root / name).write_bytes(key.encode())
            artifacts.append({"id": key, "file": composer.attempt_index.file_ref(self.root, self.root / name)})
        composer.write_checksums(self.root, artifacts)
        recorded = {row["id"]: row["file"] for row in artifacts}
        lines = acceptance.reference(self.root, recorded.pop("checksums")).read_text().splitlines()
        self.assertEqual(lines, [f"{ref['sha256']}  {ref['path']}" for ref in recorded.values()])

    def test_failed_gate_and_substituted_source_are_rejected(self):
        name = sorted(acceptance.required_gates())[0]
        (self.root / "gate.json").write_text(json.dumps({"id": name, "status": "failed"}))
        self.inputs["gates"][name] = "gate.json"
        with self.assertRaisesRegex(ValueError, "did not pass"):
            self.write()
        self.inputs["gates"].clear()
        (self.root / "files.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "archive and inventory differ"):
            self.write()
        self.assertFalse((self.root / "manifest.json").exists())


if __name__ == "__main__":
    unittest.main()
