"""Actual synthetic-process counterexamples; these are not native release evidence."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

import assembly_inputs
import repeatable_assembly as assembly
from release_gate import inventory, sha256, write_json


class AssemblyCustodyTests(unittest.TestCase):
    def setUp(self):
        base = Path(os.environ["TMPDIR"]) / "repeatable-assembly-tests"
        base.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=base)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        (self.source / "scripts").mkdir(parents=True)
        self.program = self.source / "scripts/package_release.py"
        self.program.write_text("import argparse\nfrom pathlib import Path\n"
                                "p=argparse.ArgumentParser()\n"
                                "p.add_argument('--output')\np.add_argument('--evidence')\n"
                                "p.add_argument('--native-inputs')\na=p.parse_args()\n"
                                "o=Path(a.output);o.mkdir()\n"
                                "(o/'synthetic.tar.gz').write_bytes(b'fixed synthetic artifact')\n"
                                "print('original synthetic packager output')\n")
        self.inputs = {"tools": {"python": {"path": str(Path(sys.executable).resolve())}}}
        self.environment = {"PATH": "/usr/bin:/bin", "TMPDIR": str(self.root), "PYTHONDONTWRITEBYTECODE": "1"}
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        self.custody = self.root / "custody"
        self.custody.mkdir()
        self.declaration = str(self.root / "inputs.json")
        self.selected = [self.inputs["tools"]["python"]["path"], "-B", "-S", "-c", "print('original stdout')"]

    def execute(self):
        observed = []
        result = assembly.execute_pair(self.custody, self.inputs, str(self.source), str(self.evidence),
                                       self.declaration, self.environment,
                                       lambda value: observed.append(copy.deepcopy(value)))
        return result, observed

    def test_two_actual_invocations_have_distinct_groups_and_equal_artifacts(self):
        result, observed = self.execute()
        self.assertEqual([item["id"] for item in result], ["assembly-a", "assembly-b"])
        self.assertEqual(len(observed), 4)
        groups = set()
        for item in result:
            receipt = assembly.read(assembly.check_ref(self.custody, item["process"]["receipt"]))
            groups.add(receipt["process_group"])
            self.assertEqual(receipt["cleanup"]["after"], [])
            self.assertEqual(receipt["cleanup"]["signals"], [])
            self.assertTrue(receipt["outputs_stable"])
            self.assertIn(b"original synthetic packager output", assembly.check_ref(self.custody, item["process"]["stdout"]).read_bytes())
            self.assertEqual(receipt["command"], assembly.command(self.inputs, str(self.source), str(self.evidence),
                             item["output_root"], self.declaration))
        self.assertEqual(len(groups), 2)
        self.assertNotEqual(result[0]["output_root"], result[1]["output_root"])
        self.assertEqual(result[0]["outputs"], result[1]["outputs"])

    def test_failed_second_invocation_preserves_first_original_failure_and_never_retries(self):
        with self.program.open("a") as output:
            output.write("import sys\nif 'assembly-b' in a.output:\n print('second failed', file=sys.stderr)\n sys.exit(7)\n")
        observed = []
        with self.assertRaisesRegex(ValueError, "exact drained"):
            assembly.execute_pair(self.custody, self.inputs, str(self.source), str(self.evidence),
                                  self.declaration, self.environment,
                                  lambda value: observed.append(copy.deepcopy(value)))
        self.assertEqual(len(observed[-1]), 2)
        second = observed[-1][-1]
        self.assertIsNone(second["outputs"])
        process = assembly.read(assembly.check_ref(self.custody, second["process"]["receipt"]))
        self.assertEqual(process["process_exit_code"], 7)
        self.assertTrue(process["cleanup"]["drained"])
        self.assertIn(b"second failed", assembly.check_ref(self.custody, second["process"]["stderr"]).read_bytes())
        before = inventory(self.custody)
        with self.assertRaisesRegex(ValueError, "independently fresh"):
            self.execute()
        self.assertEqual(inventory(self.custody), before)

    def test_preexisting_output_never_dispatches_or_overwrites(self):
        output = self.custody / "assembly-a-output"
        output.mkdir()
        (output / "prior").write_bytes(b"retained previous attempt")
        before = inventory(self.custody)
        with self.assertRaisesRegex(ValueError, "independently fresh"):
            self.execute()
        self.assertEqual(inventory(self.custody), before)
        self.assertFalse((self.custody / "assembly-a").exists())

    def test_timeout_retains_actual_terminal_child_and_rejects_success(self):
        command = self.selected[:-1] + ["import time; print('started', flush=True); time.sleep(30)"]
        item = assembly.run_owned(self.custody, "timeout", command, str(self.source), self.environment, .2)
        process = assembly.read(assembly.check_ref(self.custody, item["receipt"]))
        self.assertTrue(process["timed_out"])
        self.assertEqual(process["exit_code"], 124)
        self.assertTrue(process["cleanup"]["drained"])
        self.assertIn("SIGTERM", process["cleanup"]["signals"])
        self.assertIn(b"started", assembly.check_ref(self.custody, item["stdout"]).read_bytes())
        with self.assertRaisesRegex(ValueError, "exact drained"):
            assembly.check_owned(self.custody, item, command, str(self.source), .2)

    def test_changed_command_cwd_tool_deadline_output_and_drain_are_rejected(self):
        changes = {
            "command": lambda p: p.update(command=[p["command"][0], "--version"]),
            "cwd": lambda p: p.update(working_directory=str(self.root)),
            "tool": lambda p: p["executable"].update(sha256="a" * 64),
            "deadline": lambda p: p.update(timeout_seconds=99),
            "output": lambda p: p["stdout"].update(sha256="a" * 64),
            "drain": lambda p: p["cleanup"].update(drained=False),
        }
        for name, change in changes.items():
            with self.subTest(name=name):
                item = assembly.run_owned(self.custody, name, self.selected, str(self.source), self.environment, 10)
                path = assembly.check_ref(self.custody, item["receipt"])
                process = assembly.read(path)
                change(process)
                write_json(path, process)
                item["receipt"] = assembly.ref(self.custody, path)
                with self.assertRaises(ValueError):
                    assembly.check_owned(self.custody, item, self.selected, str(self.source), 10)

    def test_rehashed_substitute_stdout_does_not_belong_to_original_process(self):
        item = assembly.run_owned(self.custody, "substitution", self.selected, str(self.source), self.environment, 10)
        output = assembly.check_ref(self.custody, item["stdout"])
        output.write_bytes(b"replaced with a claimed pass")
        item["stdout"] = assembly.ref(self.custody, output)
        with self.assertRaisesRegex(ValueError, "original process output"):
            assembly.check_owned(self.custody, item, self.selected, str(self.source), 10)

    def test_arbitrary_copied_archive_and_opaque_pass_do_not_establish_repeat_assembly(self):
        (self.custody / "one.tar.gz").write_bytes(b"same bytes")
        (self.custody / "two.tar.gz").write_bytes(b"same bytes")
        attempt = self.custody / "attempt.json"
        write_json(attempt, {"schema": assembly.SCHEMA, "status": "passed", "report": "two equal archives"})
        with self.assertRaisesRegex(ValueError, "fields differ"):
            assembly.verify(self.custody, assembly.ref(self.custody, attempt))

    def test_declaration_and_inputs_reject_symlinks_and_unbound_python_imports(self):
        linked = self.root / "linked.py"
        linked.symlink_to(self.program)
        with self.assertRaisesRegex(ValueError, "canonical"):
            assembly_inputs.file_identity(linked)
        with self.assertRaisesRegex(ValueError, "unbound module"):
            assembly_inputs.consumed({"roots": {"cargo-registry": str(self.root)}}, self.source,
                                    {"packages": []}, {})

    def test_metadata_dependency_outside_declared_registry_is_rejected(self):
        foreign = self.root / "foreign"
        foreign.mkdir()
        (foreign / "Cargo.toml").write_text('[package]\nname="outside"\n')
        with self.assertRaisesRegex(ValueError, "undeclared package root"):
            assembly_inputs.consumed({"roots": {"cargo-registry": str(self.root / "registry")}}, self.source,
                                    {"packages": [{"manifest_path": str(foreign / "Cargo.toml")}]}, {})

    def test_environment_excludes_ambient_overrides_and_selects_exact_rustc(self):
        inputs = {"tools": {"cargo": {"path": "/native/bin/cargo"}, "rustc": {"path": "/native/bin/rustc"}},
                  "cargo_home": "/owned/cargo-home"}
        environment = assembly_inputs.environment(inputs, self.root)
        self.assertEqual(environment["RUSTC"], "/native/bin/rustc")
        self.assertNotIn("RUSTC_WRAPPER", environment)
        self.assertNotIn("PYTHONPATH", environment)
        self.assertNotIn("RUSTUP_TOOLCHAIN", environment)
        self.assertEqual(environment["CARGO_NET_OFFLINE"], "true")
        self.assertEqual(assembly.probe_commands({"tools": {k: {"path": "/native/bin/" + k}
                                                          for k in assembly_inputs.TOOLS}})["cargo-version"],
                         ["/native/bin/cargo", "-Vv"])


if __name__ == "__main__":
    unittest.main()
