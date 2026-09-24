"""Actual-process counterexamples for packaging's metadata custody prerequisite."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import package_release as package
from release_gate import inventory, sha256, write_json


class MetadataCustodyTests(unittest.TestCase):
    def setUp(self):
        base = Path(__file__).resolve().parents[1] / "target" / "package-metadata-tests"
        base.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=base)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "Cargo.lock").write_text("frozen fixture input\n")
        self.inputs = inventory(self.source)
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self.executable = self.tools / "cargo"
        self.target = "aarch64-unknown-linux-gnu"
        self.document = {"version": 1, "packages": [], "workspace_members": [], "resolve": {"nodes": []}}
        self.install_program("import json, sys\nprint(json.dumps(" + repr(self.document) + "))\n"
                             "print('retained diagnostic', file=sys.stderr)\n")
        self.environment = patch.dict(os.environ, {"PATH": str(self.tools) + os.pathsep + os.environ.get("PATH", "")})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def install_program(self, code):
        # A deliberately synthetic Cargo implementation, executed as a real
        # process. It tests the ownership/receipt primitive, never native Cargo
        # semantics or final release acceptance.
        self.executable.write_text("#!" + sys.executable + "\n" + code)
        self.executable.chmod(0o755)

    def capture(self, name="metadata"):
        destination = self.root / name
        result = package.capture_metadata(self.source, destination, self.target, self.inputs)
        return destination, result

    def record(self, directory):
        return json.loads((directory / "attempt.json").read_text())

    def rewrite_process(self, directory, change):
        record = self.record(directory)
        process = json.loads((directory / "process.json").read_text())
        change(process)
        write_json(directory / "process.json", process)
        record["process"] = package._metadata_ref(directory, "process.json")
        write_json(directory / "attempt.json", record)

    def test_real_command_retains_separate_outputs_executable_inputs_and_drained_group(self):
        directory, result = self.capture()
        self.assertEqual(result, self.document)
        record = self.record(directory)
        process = json.loads((directory / "process.json").read_text())
        self.assertEqual(record["command"], package.metadata_command(str(self.executable), self.target))
        self.assertEqual(process["working_directory"], str(self.source.resolve()))
        self.assertEqual(process["executable"]["sha256"], sha256(self.executable))
        self.assertEqual((directory / "executable").read_bytes(), self.executable.read_bytes())
        self.assertTrue(process["cleanup"]["drained"])
        self.assertEqual(process["cleanup"]["after"], [])
        self.assertEqual(process["cleanup"]["signals"], [])
        self.assertIn(b"retained diagnostic", (directory / "stderr.log").read_bytes())
        self.assertNotIn(b"retained diagnostic", (directory / "stdout.json").read_bytes())
        self.assertEqual(process["stdout"], record["stdout"])
        self.assertEqual(process["stderr"], record["stderr"])
        self.assertEqual(package.verify_metadata_capture(directory, self.target, self.inputs), self.document)

    def test_copied_json_and_asserted_status_without_process_custody_are_rejected(self):
        directory = self.root / "copied"
        directory.mkdir()
        write_json(directory / "stdout.json", self.document)
        write_json(directory / "attempt.json", {"schema": package.METADATA_SCHEMA, "status": "passed"})
        with self.assertRaises(ValueError):
            package.verify_metadata_capture(directory, self.target, self.inputs)
        actual, _ = self.capture()
        (actual / "process.json").unlink()
        with self.assertRaises(ValueError):
            package.verify_metadata_capture(actual, self.target, self.inputs)

    def test_rehashed_substituted_output_is_not_the_original_process_output(self):
        directory, _ = self.capture()
        record = self.record(directory)
        write_json(directory / "stdout.json", {**self.document, "packages": [{"id": "substituted"}]})
        record["stdout"] = package._metadata_ref(directory, "stdout.json")
        write_json(directory / "attempt.json", record)
        with self.assertRaisesRegex(ValueError, "do not belong"):
            package.verify_metadata_capture(directory, self.target, self.inputs)

    def test_wrong_command_cwd_executable_or_missing_drain_never_consumes_metadata(self):
        cases = {
            "command": lambda value: value.update(command=[str(self.executable), "--version"]),
            "cwd": lambda value: value.update(working_directory=str(self.root)),
            "executable": lambda value: value["executable"].update(sha256="0" * 64),
            "custody": lambda value: value["cleanup"].update(drained=False, after=[{"pid": 1}]),
            "signal": lambda value: value.update(received_signals=[15]),
            "deadline": lambda value: value.update(timeout_seconds=1),
        }
        for name, change in cases.items():
            with self.subTest(name=name):
                directory, _ = self.capture(name)
                self.rewrite_process(directory, change)
                with self.assertRaises(ValueError):
                    package.verify_metadata_capture(directory, self.target, self.inputs)

    def test_failed_actual_child_and_partial_files_are_preserved_without_retry_overwrite(self):
        self.install_program("import sys\nprint('partial output')\nprint('original failure', file=sys.stderr)\nsys.exit(7)\n")
        directory = self.root / "failed"
        with self.assertRaises(ValueError):
            self.capture("failed")
        record = self.record(directory)
        self.assertEqual(record["status"], "failed")
        process = json.loads((directory / "process.json").read_text())
        self.assertEqual(process["process_exit_code"], 7)
        self.assertTrue(process["cleanup"]["drained"])
        self.assertIn(b"original failure", (directory / "stderr.log").read_bytes())
        before = inventory(directory)
        with self.assertRaises(FileExistsError):
            self.capture("failed")
        self.assertEqual(inventory(directory), before)
        with self.assertRaises(ValueError):
            package.verify_metadata_capture(directory, self.target, self.inputs)

    def test_changed_frozen_input_and_diagnostic_fallback_are_rejected(self):
        self.install_program("from pathlib import Path\nimport json\nPath('Cargo.lock').write_text('changed')\n"
                             "print(json.dumps(" + repr(self.document) + "))\n")
        with self.assertRaisesRegex(ValueError, "changed frozen"):
            self.capture("changed")
        self.assertEqual(self.record(self.root / "changed")["status"], "failed")
        (self.source / "Cargo.lock").write_text("frozen fixture input\n")
        self.install_program("import json\nprint('warning incorrectly on stdout')\nprint(json.dumps(" + repr(self.document) + "))\n")
        with self.assertRaises(ValueError):
            self.capture("mixed")
        self.assertEqual(self.record(self.root / "mixed")["status"], "failed")

    def test_symlink_substitution_of_equal_bytes_is_rejected(self):
        directory, _ = self.capture()
        raw = (directory / "stdout.json").read_bytes()
        outside = self.root / "same-output.json"
        outside.write_bytes(raw)
        (directory / "stdout.json").unlink()
        (directory / "stdout.json").symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "symbolic link"):
            package.verify_metadata_capture(directory, self.target, self.inputs)

    def test_metadata_primitive_does_not_register_a_final_acceptance_domain(self):
        import verify_release_acceptance as acceptance
        self.assertNotIn("repeatable-assembly", acceptance.DOMAIN_ADAPTERS)


if __name__ == "__main__":
    unittest.main()
