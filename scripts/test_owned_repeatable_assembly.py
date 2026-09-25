"""Synthetic owned-process counterexamples, never native release evidence."""
import copy
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

import attempt_index
import repeatable_assembly as assembly
import run_repeatable_assembly_owned as owned
from release_gate import sha256, write_json
import verify_release_acceptance as acceptance


class OwnedRunnerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="owned-assembly-unit-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve(strict=True)
        self.source = self.root / "source"
        (self.source / "scripts").mkdir(parents=True)
        self.script = self.source / owned.RUNNER
        self.script.write_text("print('synthetic runner', flush=True)\n")
        self.evidence = self.root / "functional"
        self.evidence.mkdir()
        self.declaration = self.root / "inputs.json"
        self.declaration.write_text("{}")
        self.custody = self.root / "custody"
        self.custody.mkdir()
        python = str(Path(sys.executable).resolve(strict=True))
        self.inputs = {"tools": {"python": {"path": python, "sha256": sha256(python)}}}
        self.environment = {"PATH": "/usr/bin:/bin", "TMPDIR": str(self.root),
                            "PYTHONDONTWRITEBYTECODE": "1"}

    def run_runner(self, *, name="runner", timeout=None):
        selected = owned.command(self.inputs, self.source, self.evidence, self.declaration, self.custody)
        return assembly.run_owned(self.custody, name, selected, str(self.source), self.environment,
                                  owned.TIMEOUT_SECONDS if timeout is None else timeout)

    def check(self, item):
        return owned.check_runner(self.custody, item, self.inputs, self.source,
                                  self.evidence, self.declaration, self.custody)

    def rewrite_receipt(self, item, change):
        item = copy.deepcopy(item)
        receipt = assembly.check_ref(self.custody, item["receipt"])
        record = assembly.read(receipt)
        change(record)
        write_json(receipt, record)
        item["receipt"] = assembly.ref(self.custody, receipt)
        return item

    def test_actual_outer_runner_has_exact_command_tool_bytes_and_clean_group(self):
        item = self.run_runner()
        receipt = self.check(item)
        self.assertEqual(receipt["command"], owned.command(self.inputs, self.source, self.evidence,
                                                             self.declaration, self.custody))
        self.assertEqual(receipt["executable"]["sha256"], self.inputs["tools"]["python"]["sha256"])
        self.assertEqual(receipt["cleanup"]["before"], [])
        self.assertEqual(receipt["cleanup"]["after"], [])
        self.assertTrue(receipt["cleanup"]["drained"])
        self.assertEqual(receipt["cleanup"]["signals"], [])
        self.assertIn(b"synthetic runner", assembly.check_ref(self.custody, item["stdout"]).read_bytes())

    def test_child_only_or_modified_runner_command_cwd_tool_and_drain_fail(self):
        original_item = self.run_runner()
        original_receipt = assembly.check_ref(self.custody, original_item["receipt"])
        original_bytes = original_receipt.read_bytes()
        cases = {
            "child-only": lambda item: item.update(id="assembly-a"),
            "tool": lambda item: item["executable"].update(sha256="0" * 64),
            "command": lambda record: record.update(command=[record["command"][0], "--version"]),
            "cwd": lambda record: record.update(working_directory=str(self.root)),
            "signal": lambda record: record.update(received_signals=[15]),
            "timeout": lambda record: record.update(timed_out=True),
            "drain": lambda record: record["cleanup"].update(after=[{"pid": 999}]),
        }
        for case, change in cases.items():
            with self.subTest(case=case):
                original_receipt.write_bytes(original_bytes)
                item = copy.deepcopy(original_item)
                if case in {"child-only", "tool"}:
                    change(item)
                else:
                    item = self.rewrite_receipt(item, change)
                with self.assertRaises(ValueError):
                    self.check(item)

    def test_actual_timeout_keeps_original_signal_and_cannot_pass(self):
        self.script.write_text("import time\nprint('started', flush=True)\ntime.sleep(30)\n")
        with patch.object(owned, "TIMEOUT_SECONDS", .2):
            item = self.run_runner(timeout=.2)
            receipt = assembly.read(assembly.check_ref(self.custody, item["receipt"]))
            self.assertTrue(receipt["timed_out"])
            self.assertEqual(receipt["exit_code"], 124)
            self.assertIn("SIGTERM", receipt["cleanup"]["signals"])
            self.assertTrue(receipt["cleanup"]["drained"])
            with self.assertRaises(ValueError):
                self.check(item)

    def child_fixture(self):
        inner = self.custody / "assembly"
        inner.mkdir()
        probes, assemblies = [], []
        for index, name in enumerate(("cargo-version", "rustc-version", "python-version",
                                      "assembly-a", "assembly-b"), start=1):
            receipt = inner / name / "process.json"
            receipt.parent.mkdir()
            write_json(receipt, self.process(index))
            ref = assembly.ref(inner, receipt)
            if name.endswith("version"):
                probes.append({"id": name, "receipt": ref})
            else:
                assemblies.append({"id": name, "process": {"receipt": ref}})
        for index, name in enumerate(("assembly-a", "assembly-b"), start=6):
            receipt = inner / (name + "-output") / "metadata-custody" / "process.json"
            receipt.parent.mkdir(parents=True)
            write_json(receipt, self.process(index))
        return {"record": {"probes": probes, "assemblies": assemblies}}, inner

    @staticmethod
    def process(group):
        return {"process_group": group, "leader_birth": "linux:" + str(group),
                "executable": {"path": "/synthetic/tool", "sha256": str(group) * 64},
                "status": "passed", "timed_out": False,
                "received_signals": [], "cleanup": {"group": group, "before": [],
                "after": [], "signals": [], "errors": [], "drained": True}}

    def test_all_seven_nested_groups_must_be_distinct_and_drained(self):
        parsed, inner = self.child_fixture()
        self.assertEqual(owned.child_groups(self.custody, parsed, 8), list(range(1, 9)))
        for case in ("missing", "reused-outer", "reused-child", "signal", "survivor"):
            with self.subTest(case=case):
                receipt = inner / "assembly-a-output" / "metadata-custody" / "process.json"
                original = receipt.read_bytes()
                value = assembly.read(receipt)
                if case == "missing":
                    receipt.unlink()
                elif case == "reused-outer":
                    value["process_group"] = value["cleanup"]["group"] = 8
                elif case == "reused-child":
                    value["process_group"] = value["cleanup"]["group"] = 1
                elif case == "signal":
                    value["cleanup"]["signals"] = ["SIGTERM"]
                else:
                    value["cleanup"]["after"] = [{"pid": 999}]
                if case != "missing":
                    write_json(receipt, value)
                with self.assertRaises((ValueError, FileNotFoundError)):
                    owned.child_groups(self.custody, parsed, 8)
                receipt.write_bytes(original)

    def test_original_spawn_graph_binds_parent_executable_birth_and_order(self):
        parsed, inner = self.child_fixture()
        entries = owned.child_ledger(self.custody, parsed, 8)
        self.assertEqual([entry["group"] for entry in entries], [1, 2, 3, 4, 6, 5, 7])
        self.assertEqual([entry["owner_pid"] for entry in entries], [8, 8, 8, 8, 4, 8, 5])
        self.assertEqual([entry["executable_sha256"] for entry in entries],
                         [str(group) * 64 for group in (1, 2, 3, 4, 6, 5, 7)])
        self.assertEqual([entry["leader_birth"] for entry in entries],
                         ["linux:" + str(group) for group in (1, 2, 3, 4, 6, 5, 7)])
        receipt = inner / "assembly-a-output/metadata-custody/process.json"
        original = receipt.read_bytes()
        for missing in ("executable", "leader_birth"):
            with self.subTest(missing=missing):
                value = json.loads(original)
                del value[missing]
                write_json(receipt, value)
                with self.assertRaisesRegex(ValueError, "identity is absent|observation is absent"):
                    owned.child_ledger(self.custody, parsed, 8)
        receipt.write_bytes(original)
        parsed["record"]["assemblies"].reverse()
        with self.assertRaisesRegex(ValueError, "roster differs"):
            owned.child_ledger(self.custody, parsed, 8)

    def test_source_hash_change_and_failed_preflight_are_preserved(self):
        source = self.evidence / "source"
        (source / "scripts").mkdir(parents=True)
        inventory = {}
        for relative in assembly.SCRIPTS:
            target = source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            original = Path(owned.__file__) if relative == owned.LAUNCHER else Path(assembly.__file__).parent / Path(relative).name
            if not original.exists():
                original = Path(assembly.__file__).resolve().parents[5] / "scripts" / Path(relative).name
            shutil.copyfile(original, target)
            inventory[relative] = {"sha256": sha256(target)}
        write_json(self.evidence / "source-files.json", inventory)
        with patch.object(owned, "__file__", str(source / owned.LAUNCHER)):
            self.assertEqual(owned.source_scripts(self.evidence, source)[owned.LAUNCHER],
                             inventory[owned.LAUNCHER]["sha256"])
            (source / owned.RUNNER).write_bytes(b"changed runner source")
            with self.assertRaisesRegex(ValueError, "frozen launcher dependency differs"):
                owned.source_scripts(self.evidence, source)
        output = self.root / "failed-launch"
        with self.assertRaises(ValueError):
            owned.launch(self.evidence, self.declaration, output, self.root, "failed-preflight")
        failed = assembly.read(output / "launcher.json")
        self.assertEqual(failed["status"], "failed")
        self.assertIsNotNone(failed["error"])
        self.assertIsNone(failed["runner_process"])
        self.assertIsNotNone(attempt_index.replay(self.root)["failed-preflight"]["terminal"])
        actual = self.root / "actual-parent"
        actual.mkdir()
        alias = self.root / "alias-parent"
        alias.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(ValueError):
            owned.launch(self.evidence, self.declaration, alias / "failed-launch",
                         self.root, "alias-preflight")
        aliased = assembly.read(actual / "failed-launch" / "launcher.json")
        self.assertEqual(aliased["custody_root"], str(actual / "failed-launch"))
        self.assertEqual(aliased["status"], "failed")
        self.assertIsNotNone(attempt_index.replay(self.root)["alias-preflight"]["terminal"])

    def test_locked_spawn_ledger_seals_admission_and_binds_original_group(self):
        ledger = self.root / "groups.jsonl"
        ledger.write_bytes(b"")
        with patch.dict(os.environ, {assembly.gate_process.GROUP_LEDGER_ENV: str(ledger)}):
            item = self.run_runner()
            group = self.check(item)["process_group"]
            rows, closed = assembly.gate_process.read_group_ledger(ledger)
            self.assertFalse(closed)
            self.assertEqual([row["group"] for row in rows], [group])
            assembly.gate_process.seal_group_ledger(ledger)
            census = owned.terminal_census(self.custody, ledger)
            self.assertTrue(census["complete"])
            self.assertEqual(census["groups"][0]["after"], [])
            selected = owned.command(self.inputs, self.source, self.evidence, self.declaration, self.custody)
            late = assembly.run_owned(self.custody, "late", selected, str(self.source), self.environment, 10)
            receipt = assembly.read(assembly.check_ref(self.custody, late["receipt"]))
            self.assertEqual(receipt["status"], "failed")
            self.assertIsNone(receipt["process_group"])
            self.assertEqual(len(assembly.gate_process.read_group_ledger(ledger)[0]), 2)

    def test_failed_group_registration_drains_the_exact_spawned_process(self):
        self.script.write_text("import time\ntime.sleep(30)\n")
        ledger = self.root / "append-failure.jsonl"
        ledger.write_bytes(b"")
        with patch.dict(os.environ, {assembly.gate_process.GROUP_LEDGER_ENV: str(ledger)}), \
                patch.object(assembly.gate_process, "_group_ledger_append", side_effect=OSError("append failed")):
            item = self.run_runner(timeout=2)
        record = assembly.read(assembly.check_ref(self.custody, item["receipt"]))
        self.assertEqual(record["status"], "failed")
        self.assertIn("append failed", record["error"])
        self.assertEqual(record["process_group"], record["cleanup"]["group"])
        self.assertIn("SIGTERM", record["cleanup"]["signals"])
        self.assertEqual(record["cleanup"]["after"], [])
        self.assertEqual(assembly.gate_process.read_group_ledger(ledger), ([], False))

    def test_terminal_census_terminates_a_live_registered_group(self):
        ledger = self.root / "live-groups.jsonl"
        ledger.write_bytes(b"")
        child = subprocess.Popen([self.inputs["tools"]["python"]["path"], "-c",
                                  "import time; time.sleep(30)"], start_new_session=True)
        reaper = threading.Thread(target=child.wait, daemon=True)
        reaper.start()
        try:
            with ledger.open("ab") as stream:
                stream.write((json.dumps({"schema": 1, "kind": "group", "group": child.pid,
                                          "owner_pid": os.getpid(),
                                          "executable_sha256": self.inputs["tools"]["python"]["sha256"],
                                          "leader_birth": assembly.gate_process.leader_identity(child.pid)["birth"]})
                              + "\n").encode())
                stream.flush()
                os.fsync(stream.fileno())
            assembly.gate_process.seal_group_ledger(ledger)
            census = owned.terminal_census(self.custody, ledger)
            self.assertTrue(census["complete"])
            self.assertIn("SIGTERM", census["groups"][0]["signals"])
            self.assertEqual(census["groups"][0]["after"], [])
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
            reaper.join(timeout=10)

    def test_reused_or_unwitnessed_group_is_not_signalled(self):
        for birth in (None, "darwin:0:0" if sys.platform == "darwin" else "linux:0"):
            with self.subTest(birth=birth):
                ledger = self.root / ("unknown-" + str(birth).replace(":", "-") + ".jsonl")
                child = subprocess.Popen([self.inputs["tools"]["python"]["path"], "-c",
                                          "import time; time.sleep(30)"], start_new_session=True)
                reaper = threading.Thread(target=child.wait, daemon=True)
                reaper.start()
                try:
                    ledger.write_text(json.dumps({"schema": 1, "kind": "group", "group": child.pid,
                                                  "owner_pid": os.getpid(),
                                                  "executable_sha256": self.inputs["tools"]["python"]["sha256"],
                                                  "leader_birth": birth}) + "\n", encoding="utf-8")
                    assembly.gate_process.seal_group_ledger(ledger)
                    with patch.object(owned.os, "killpg") as send_signal:
                        census = owned.terminal_census(self.custody, ledger)
                    send_signal.assert_not_called()
                    self.assertFalse(census["complete"])
                    self.assertEqual(census["groups"][0]["signals"], [])
                    self.assertIn("leader identity", census["groups"][0]["errors"][0])
                finally:
                    if child.poll() is None:
                        os.killpg(child.pid, signal.SIGKILL)
                    reaper.join(timeout=10)

    def test_terminal_census_rejects_own_group_without_signalling_it(self):
        ledger = self.root / "own-group.jsonl"
        ledger.write_text(json.dumps({"schema": 1, "kind": "group", "group": os.getpgrp(),
                                      "owner_pid": os.getpid(),
                                      "executable_sha256": self.inputs["tools"]["python"]["sha256"],
                                      "leader_birth": None})
                          + "\n", encoding="utf-8")
        assembly.gate_process.seal_group_ledger(ledger)
        with patch.object(owned.os, "killpg") as send_signal:
            census = owned.terminal_census(self.custody, ledger)
        send_signal.assert_not_called()
        self.assertFalse(census["complete"])
        self.assertIn("launcher process group", census["groups"][0]["errors"][0])


if __name__ == "__main__":
    unittest.main()
