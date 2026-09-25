"""Synthetic outer-launch integration; the inner native verifier is stubbed."""
import copy
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

import repeatable_assembly as assembly
import attempt_index
import run_repeatable_assembly_owned as owned
import verify_release_acceptance as acceptance
from release_gate import sha256, write_json


STUB_PACKAGER = r'''import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

import gate_process

root, name, source = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
directory = root / (name + "-output") / "metadata-custody"
directory.mkdir(parents=True)
receipt = directory / "process.json"
stdout, stderr = directory / "stdout.json", directory / "stderr.log"
def save(value):
    receipt.write_text(json.dumps(value, sort_keys=True) + "\n")
def ref(path):
    data = path.read_bytes()
    return {"path": path.relative_to(root).as_posix(),
            "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
command = [sys.executable, "-B", "-S", "-c", "print('synthetic metadata', flush=True)"]
with stdout.open("xb") as out, stderr.open("xb") as err:
    process = gate_process.run(command, str(source), dict(os.environ), out, 10, save, stderr=err)
process["outputs_stable"] = process["cleanup"]["drained"] and not process["cleanup"]["errors"]
process["stdout"], process["stderr"] = ref(stdout), ref(stderr)
save(process)
shutil.copyfile(sys.executable, directory / "executable")
raise SystemExit(process["exit_code"])
'''

STUB_RUNNER = r'''import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gate_process

def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True) + "\n")

def ref(root, path):
    data = path.read_bytes()
    return {"path": path.relative_to(root).as_posix(),
            "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}

def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()

args = sys.argv
evidence = Path(args[args.index("--evidence") + 1])
declaration = Path(args[args.index("--native-inputs") + 1])
root = Path(args[args.index("--output") + 1])
root.mkdir(exist_ok=False)
started = now()
source = evidence / "source"
shutil.copyfile(evidence / "source-files.json", root / "source-files.json")
(root / "source.tar").write_bytes(b"synthetic source archive")
save(root / "evidence.json", {"source_commit": "1" * 40, "source_tree": "2" * 40,
                              "lockfile_sha256": "3" * 64})
shutil.copyfile(declaration, root / "declaration.json")

items = {}
for name in ("cargo-version", "rustc-version", "python-version", "assembly-a", "assembly-b"):
    directory = root / name
    directory.mkdir(parents=True)
    receipt = directory / "process.json"
    stdout = directory / "stdout.log"
    stderr = directory / "stderr.log"
    command = ([sys.executable, "-B", "-S", str(source / "scripts/synthetic_packager.py"),
                str(root), name, str(source)] if name.startswith("assembly-") else
               [sys.executable, "-B", "-S", "-c", "print('synthetic child', flush=True)"])
    with stdout.open("xb") as out, stderr.open("xb") as err:
        process = gate_process.run(command, str(source), dict(os.environ), out, 10,
                                   lambda value: save(receipt, value), stderr=err)
    process["outputs_stable"] = process["cleanup"]["drained"] and not process["cleanup"]["errors"]
    process["stdout"] = ref(root, stdout)
    process["stderr"] = ref(root, stderr)
    save(receipt, process)
    executable = directory / "executable"
    shutil.copyfile(sys.executable, executable)
    items[name] = {"id": name, "receipt": ref(root, receipt), "stdout": ref(root, stdout),
                   "stderr": ref(root, stderr), "executable": ref(root, executable)}

archives = ("kasumi-source.tar.gz", "kasumi-aarch64-unknown-linux-gnu.tar.gz")
for name in ("assembly-a", "assembly-b"):
    output = root / (name + "-output")
    for archive in archives:
        (output / archive).write_bytes(("synthetic " + archive).encode())
record = {"schema": "kasumi-repeatable-assembly-v1", "status": "passed",
          "started_at": started, "finished_at": now(), "evidence_root": str(evidence),
          "source_root": str(source), "custody_root": str(root),
          "declaration_path": str(declaration), "declaration": ref(root, root / "declaration.json"),
          "probes": [items[name] for name in ("cargo-version", "rustc-version", "python-version")],
          "assemblies": [{"id": name, "process": items[name]} for name in ("assembly-a", "assembly-b")]}
save(root / "attempt.json", record)
'''

STUB_TIMEOUT_RUNNER = r'''import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gate_process

args = sys.argv
evidence = Path(args[args.index("--evidence") + 1])
root = Path(args[args.index("--output") + 1])
root.mkdir(exist_ok=False)
directory = root / "live-child"
directory.mkdir()
with (directory / "stdout.log").open("xb") as out, (directory / "stderr.log").open("xb") as err:
    gate_process.run([sys.executable, "-B", "-S", "-c", "import time; time.sleep(30)"],
                     str(evidence / "source"), dict(os.environ), out, 40,
                     lambda value: (directory / "process.json").write_text(json.dumps(value) + "\n"),
                     stderr=err)
'''


class OwnedAssemblyIntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="owned-assembly-integration-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve(strict=True)
        self.evidence = self.root / "evidence"
        self.source = self.evidence / "source"
        (self.source / "scripts").mkdir(parents=True)
        checkout_scripts = Path(assembly.__file__).resolve().parents[5] / "scripts"
        inventory = {}
        for relative in assembly.SCRIPTS:
            path = self.source / relative
            original = Path(assembly.__file__).parent / Path(relative).name
            if relative == owned.RUNNER:
                path.write_text(STUB_RUNNER)
            else:
                if not original.exists():
                    original = checkout_scripts / Path(relative).name
                shutil.copyfile(original, path)
            inventory[relative] = {"sha256": sha256(path), "bytes": path.stat().st_size,
                                   "executable": False}
        packager = self.source / "scripts/synthetic_packager.py"
        packager.write_text(STUB_PACKAGER)
        inventory["scripts/synthetic_packager.py"] = {
            "sha256": sha256(packager), "bytes": packager.stat().st_size, "executable": False}
        self.files = inventory
        write_json(self.evidence / "source-files.json", inventory)
        self.declaration = self.root / "inputs.json"
        write_json(self.declaration, {"synthetic": True})
        python = str(Path(sys.executable).resolve(strict=True))
        native = self.root / "native" / "bin"
        native.mkdir(parents=True)
        cargo, rustc = native / "cargo", native / "rustc"
        cargo.write_bytes(b"synthetic cargo, never executed")
        rustc.write_bytes(b"synthetic rustc, never executed")
        self.inputs = {"target": acceptance.REFERENCE, "cargo_home": str(self.root / "cargo-home"),
                       "tools": {"python": {"path": python, "sha256": sha256(python)},
                                 "cargo": {"path": str(cargo), "sha256": sha256(cargo)},
                                 "rustc": {"path": str(rustc), "sha256": sha256(rustc)}}}
        self.launch_root = self.root / "owned"

    def inner_verify(self, root, receipt):
        root = Path(root)
        self.assertEqual(receipt, assembly.ref(root, root / "attempt.json"))
        frozen = {name: {"file": assembly.ref(root, root / name)}
                  for name in ("source-files.json", "source.tar", "evidence.json")}
        return {"record": assembly.read(root / "attempt.json"), "inputs": self.inputs,
                "frozen": frozen, "archives": ["kasumi-source.tar.gz",
                                             "kasumi-aarch64-unknown-linux-gnu.tar.gz"]}

    def file_ref(self, path):
        return assembly.ref(self.root, path)

    def global_ref(self, local_root, ref):
        return self.file_ref(assembly.check_ref(local_root, ref))

    def domain(self, result):
        inner = self.launch_root / "assembly"
        record = assembly.read(inner / "attempt.json")
        frozen = {name: self.file_ref(inner / name) for name in ("source-files.json", "source.tar", "evidence.json")}
        functional = assembly.read(inner / "evidence.json")
        identity = {"source_archive_sha256": frozen["source.tar"]["sha256"],
                    "source_files_sha256": frozen["source-files.json"]["sha256"],
                    **{name: functional[name] for name in ("source_commit", "source_tree", "lockfile_sha256")}}
        package_name = "kasumi-" + acceptance.REFERENCE + ".tar.gz"
        source_name = "kasumi-source.tar.gz"
        artifacts_dir = self.root / "artifacts"
        artifacts_dir.mkdir()
        artifacts = {}
        for artifact_id, filename in (("source", source_name),
                                      ("package:" + acceptance.REFERENCE, package_name)):
            target = artifacts_dir / filename
            shutil.copyfile(inner / "assembly-a-output" / filename, target)
            artifacts[artifact_id] = {"file": self.file_ref(target)}
        runner = result["runner_process"]
        processes = [{"id": "runner", "receipt": self.global_ref(self.launch_root, runner["receipt"]),
                      "log": self.global_ref(self.launch_root, runner["stdout"]),
                      "executable": self.global_ref(self.launch_root, runner["executable"])}]
        for item in [*record["probes"], *(entry["process"] for entry in record["assemblies"])]:
            processes.append({"id": item["id"], "receipt": self.global_ref(inner, item["receipt"]),
                              "log": self.global_ref(inner, item["stdout"]),
                              "executable": self.global_ref(inner, item["executable"])})
        for name in ("assembly-a", "assembly-b"):
            directory = inner / (name + "-output") / "metadata-custody"
            processes.append({"id": name + "-metadata", "receipt": self.file_ref(directory / "process.json"),
                              "log": self.file_ref(directory / "stdout.json"),
                              "executable": self.file_ref(directory / "executable")})
        scenarios = [{"id": name, "status": "passed", "iterations": 1, "failures": 0,
                      "unattempted": 0,
                      "log": next(process["log"] for process in processes if process["id"] == name)}
                     for name in ("assembly-a", "assembly-b")]
        domain = {"id": "repeatable-assembly:" + acceptance.REFERENCE,
                  "runner": {"source_path": owned.LAUNCHER,
                             "sha256": self.files[owned.LAUNCHER]["sha256"]},
                  "identity": identity, "configuration_ids": ["native"],
                  "started_at": result["started_at"], "finished_at": result["finished_at"],
                  "details": {"launcher": self.file_ref(self.launch_root / "launcher.json"),
                              "report": self.file_ref(inner / "attempt.json"),
                              "second_source": self.file_ref(inner / "assembly-b-output" / source_name),
                              "second_package": self.file_ref(inner / "assembly-b-output" / package_name)},
                  "processes": processes, "scenarios": scenarios}
        configs = {"native": {"file": self.file_ref(self.declaration)}}
        return domain, configs, artifacts

    def test_successful_outer_launch_verify_and_disabled_bridge_reject_substitutions(self):
        self.assertEqual(acceptance.DOMAIN_ADAPTERS, {})
        dispatched = []
        original_run_owned = assembly.run_owned

        def witnessed_dispatch(*args, **kwargs):
            rows = attempt_index.replay(self.root, complete=False)
            self.assertEqual(set(rows), {"assembly-test"})
            self.assertIsNone(rows["assembly-test"]["terminal"])
            self.assertTrue((self.root / "attempts/index.jsonl").stat().st_size > 0)
            dispatched.append(args[1])
            return original_run_owned(*args, **kwargs)

        with patch.object(owned.assembly_inputs, "validate_declaration", return_value=self.inputs), \
                patch.object(assembly, "verify", side_effect=self.inner_verify), \
                patch.object(assembly, "run_owned", side_effect=witnessed_dispatch), \
                patch.object(owned, "__file__", str(self.source / owned.LAUNCHER)):
            result = owned.launch(self.evidence, self.declaration, self.launch_root,
                                  self.root, "assembly-test")
            self.assertEqual(dispatched, ["runner"])
            self.assertIsNotNone(attempt_index.replay(self.root)["assembly-test"]["terminal"])
            self.assertEqual(result["status"], "passed")
            observation_path = self.launch_root / owned.DOMAIN_OBSERVATION
            observation = assembly.read(observation_path)
            self.assertEqual(observation["schema"], owned.DOMAIN_SCHEMA)
            self.assertEqual(observation["status"], "unqualified")
            attempt = assembly.read(self.root / "attempts/assembly-test/attempt.json")
            self.assertEqual(attempt["domain_observation"], self.file_ref(observation_path))
            parsed = owned.verify(self.launch_root, assembly.ref(self.launch_root, self.launch_root / "launcher.json"))
            self.assertEqual(len(parsed["groups"]), 8)
            domain, configs, artifacts = self.domain(result)
            assembly.domain_adapter(self.root, domain, self.files, configs, artifacts)
            missing = copy.deepcopy(domain)
            missing["processes"] = [entry for entry in missing["processes"] if entry["id"] != "runner"]
            with self.assertRaisesRegex(ValueError, "omitted or substituted"):
                assembly.domain_adapter(self.root, missing, self.files, configs, artifacts)
            swapped = copy.deepcopy(domain)
            swapped["details"]["second_source"] = artifacts["source"]["file"]
            with self.assertRaises(ValueError):
                assembly.domain_adapter(self.root, swapped, self.files, configs, artifacts)
            changed = copy.deepcopy(observation)
            changed["target"] = "x86_64-unknown-linux-gnu"
            write_json(observation_path, changed)
            with self.assertRaisesRegex(ValueError, "domain observation differs"):
                owned.verify(self.launch_root, assembly.ref(self.launch_root,
                                                            self.launch_root / "launcher.json"))

    def test_actual_nested_graph_rejects_rehashed_ledger_and_census_substitutions(self):
        with patch.object(owned.assembly_inputs, "validate_declaration", return_value=self.inputs), \
                patch.object(assembly, "verify", side_effect=self.inner_verify), \
                patch.object(owned, "__file__", str(self.source / owned.LAUNCHER)):
            result = owned.launch(self.evidence, self.declaration, self.launch_root,
                                  self.root, "assembly-test")
            launcher_path = self.launch_root / "launcher.json"
            runner_path = assembly.check_ref(self.launch_root, result["runner_process"]["receipt"])
            ledger_path = assembly.check_ref(self.launch_root, result["group_ledger"])
            census_path = assembly.check_ref(self.launch_root, result["descendant_census"])
            original = {path: path.read_bytes() for path in
                        (launcher_path, runner_path, ledger_path, census_path)}
            runner_group = assembly.read(runner_path)["process_group"]
            ledger, closed = assembly.gate_process.read_group_ledger(ledger_path)
            self.assertTrue(closed)
            # These identities are from real nested processes. The two metadata
            # children are spawned by their respective packagers, not the runner.
            self.assertEqual([item["owner_pid"] for item in ledger[:-1]],
                             [runner_group] * 4 + [ledger[3]["group"],
                              runner_group, ledger[5]["group"]])
            self.assertEqual(len({item["group"] for item in ledger[:-1]}), 7)
            cases = ("metadata-direct-runner", "metadata-other-packager", "foreign-probe-owner",
                     "ledger-executable", "ledger-birth", "census-owner", "census-executable",
                     "census-birth", "reordered-spawns")
            for case in cases:
                with self.subTest(case=case):
                    for path, data in original.items():
                        path.write_bytes(data)
                    rows = [json.loads(line) for line in original[ledger_path].splitlines()]
                    census = json.loads(original[census_path])
                    if case.startswith("census-"):
                        field = {"census-owner": "owner_pid", "census-executable": "executable_sha256",
                                 "census-birth": "leader_birth"}[case]
                        census["groups"][4][field] = (runner_group if field == "owner_pid" else
                            "0" * 64 if field == "executable_sha256" else "linux:0")
                    elif case == "reordered-spawns":
                        rows[3], rows[5] = rows[5], rows[3]
                        census["groups"][3], census["groups"][5] = census["groups"][5], census["groups"][3]
                    else:
                        index, field, value = {
                            "metadata-direct-runner": (4, "owner_pid", runner_group),
                            "metadata-other-packager": (4, "owner_pid", rows[5]["group"]),
                            "foreign-probe-owner": (0, "owner_pid", rows[3]["group"]),
                            "ledger-executable": (4, "executable_sha256", "0" * 64),
                            "ledger-birth": (4, "leader_birth", "linux:0"),
                        }[case]
                        rows[index][field] = census["groups"][index][field] = value
                    ledger_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows))
                    write_json(census_path, census)
                    changed = json.loads(original[launcher_path])
                    runner = json.loads(original[runner_path])
                    for field, path in (("group_ledger", ledger_path), ("descendant_census", census_path)):
                        runner[field] = changed[field] = assembly.ref(self.launch_root, path)
                    write_json(runner_path, runner)
                    changed["runner_process"]["receipt"] = assembly.ref(self.launch_root, runner_path)
                    write_json(launcher_path, changed)
                    # All enclosing hashes were recomputed. The semantic
                    # ownership relation, not a stale digest, must reject it.
                    with self.assertRaisesRegex(ValueError,
                            "terminal census is incomplete|original process ownership"):
                        owned.verify(self.launch_root, assembly.ref(self.launch_root, launcher_path))
            for path, data in original.items():
                path.write_bytes(data)
            owned.verify(self.launch_root, assembly.ref(self.launch_root, launcher_path))

    def test_outer_timeout_closes_admission_and_retains_terminal_descendant_census(self):
        runner = self.source / owned.RUNNER
        runner.write_text(STUB_TIMEOUT_RUNNER)
        self.files[owned.RUNNER] = {"sha256": sha256(runner), "bytes": runner.stat().st_size,
                                    "executable": False}
        write_json(self.evidence / "source-files.json", self.files)
        with patch.object(owned.assembly_inputs, "validate_declaration", return_value=self.inputs), \
                patch.object(owned, "__file__", str(self.source / owned.LAUNCHER)), \
                patch.object(owned, "TIMEOUT_SECONDS", 1):
            with self.assertRaises(ValueError):
                owned.launch(self.evidence, self.declaration, self.launch_root,
                             self.root, "assembly-test")
        receipt = assembly.read(self.launch_root / "launcher.json")
        self.assertEqual(receipt["status"], "failed")
        runner_process = assembly.read(assembly.check_ref(self.launch_root,
                            receipt["runner_process"]["receipt"]))
        self.assertTrue(runner_process["timed_out"])
        self.assertEqual(runner_process["exit_code"], 124)
        census = assembly.read(assembly.check_ref(self.launch_root, receipt["descendant_census"]))
        self.assertTrue(census["ledger_closed"])
        self.assertTrue(census["complete"])
        self.assertEqual(len(census["groups"]), 1)
        self.assertEqual(census["groups"][0]["after"], [])


if __name__ == "__main__":
    unittest.main()
