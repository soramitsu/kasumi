"""Counterexamples to provenance claims made by the functional gate runner."""
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import release_gate


class ReleaseGateTests(unittest.TestCase):
    def test_archive_refuses_escape_and_links_without_writing_outside_source(self):
        for name, link in [("../outside", False), ("inside/link", True)]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                with tarfile.open(root / "source.tar", "w") as archive:
                    item = tarfile.TarInfo(name)
                    if link:
                        item.type = tarfile.SYMTYPE
                        item.linkname = "../../outside"
                        archive.addfile(item)
                    else:
                        item.size = 1
                        archive.addfile(item, io.BytesIO(b"x"))
                with self.assertRaises(ValueError):
                    release_gate.extract_source(root / "source.tar", root / "source")
                self.assertFalse((root / "outside").exists())

    def test_failed_gate_retains_log_and_exact_executable_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target").mkdir()
            executable = root / "target" / "tested-artifact"
            executable.write_bytes(b"exact compiled artifact")
            message = {"reason": "compiler-artifact", "executable": str(executable),
                       "target": {"name": "test"}, "profile": {"test": True}, "package_id": "example"}
            command = [sys.executable, "-c", "import sys; print(" + repr(json.dumps(message)) + "); print('failed assertion'); sys.exit(7)"]
            result = release_gate.run_gate("failed", command, root, root, os.environ.copy())
            self.assertEqual(result["exit_code"], 7)
            self.assertIn("failed assertion", (root / "failed.log").read_text())
            recorded = result["executables"]["tested-artifact"]["sha256"]
            self.assertEqual(recorded, hashlib.sha256(b"exact compiled artifact").hexdigest())
            executable.write_bytes(b"a later build overwrote the artifact")
            self.assertNotEqual(recorded, release_gate.sha256(executable))
            self.assertEqual(result["log_sha256"], release_gate.sha256(root / "failed.log"))

    def test_build_inventory_includes_fresh_non_executable_dependencies(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            messages = [
                {"reason": "compiler-artifact", "package_id": "registry+example#dep@1.0.0",
                 "fresh": True, "features": ["std"], "executable": None,
                 "target": {"name": "dep", "kind": ["lib"], "crate_types": ["lib"]}},
                {"reason": "compiler-artifact", "package_id": "registry+example#dep@1.0.0",
                 "features": ["alloc"], "target": {"name": "build-script-build",
                 "kind": ["custom-build"], "crate_types": ["bin"]}},
            ]
            command = [sys.executable, "-c", "print(" + repr("\n".join(map(json.dumps, messages))) + ")"]
            result = release_gate.run_gate("inventory", command, root, root, os.environ.copy())
            self.assertEqual(result["executables"], {})
            package = result["compiled_packages"]["registry+example#dep@1.0.0"]
            self.assertEqual(package["features"], ["alloc", "std"])
            self.assertEqual(len(package["targets"]), 2)

    def test_content_and_new_inputs_change_inventory_without_relying_on_mtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.rs"
            source.write_bytes(b"aaaa")
            initial = release_gate.inventory(root)
            timestamp = source.stat().st_mtime_ns
            source.write_bytes(b"bbbb")
            os.utime(source, ns=(timestamp, timestamp))
            self.assertNotEqual(initial, release_gate.inventory(root))
            source.write_bytes(b"aaaa")
            self.assertEqual(initial, release_gate.inventory(root))
            (root / "injected.rs").write_text("extra build input")
            self.assertNotEqual(initial, release_gate.inventory(root))

    def test_artifact_outside_owned_target_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = {"reason": "compiler-artifact", "executable": str(root / "unowned")}
            command = [sys.executable, "-c", "print(" + repr(json.dumps(artifact)) + ")"]
            with self.assertRaises(ValueError):
                release_gate.run_gate("unowned", command, root, root, os.environ.copy())
            self.assertTrue((root / "unowned.log").is_file())

    def test_cleanup_error_preserves_original_rejection_and_cleanup_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = {"reason": "compiler-artifact", "executable": str(root / "unowned")}
            command = [sys.executable, "-c", "print(" + repr(json.dumps(artifact)) + ")"]
            with patch("release_gate.os.killpg", side_effect=PermissionError("group cleanup denied")):
                with self.assertRaises(ValueError) as raised:
                    release_gate.run_gate("cleanup-error", command, root, root, os.environ.copy())
            self.assertTrue(any("cleanup denied" in note for note in raised.exception.__notes__))
            self.assertTrue((root / "cleanup-error.log").is_file())


if __name__ == "__main__":
    unittest.main()
