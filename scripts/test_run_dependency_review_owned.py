"""Synthetic runner-contract tests; no Cargo command or advisory scan runs."""

import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import dependency_advisory as advisory
import dependency_git
import path_patch_projection
import repeatable_assembly as owned
import run_dependency_review_owned as runner
import run_dependency_review_launcher as launcher
from release_gate import sha256


class DependencyRunnerTests(unittest.TestCase):
    def test_named_memory_safety_requires_each_original_test_verdict(self):
        source = Path.cwd().resolve()
        files = {case["source"]: {"sha256": sha256(source / case["source"])}
                 for case in runner.MEMORY_SAFETY}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            logs = {}
            for case in runner.MEMORY_SAFETY:
                name = case["name"]
                if "{line}" in name:
                    lines = (source / case["source"]).read_text().splitlines()
                    line = next(index + 1 for index, text in enumerate(lines)
                                if text.strip() == "//! ```compile_fail" and
                                any("Kasumi's security patch removes mutable byte access" in previous
                                    for previous in lines[max(0, index - 5):index]))
                    name = name.format(line=line) + " - compile fail"
                logs.setdefault(case["step"], []).append("test " + name + " ... ok")
            steps = []
            for name, lines in logs.items():
                stdout = root / (name + ".stdout")
                stderr = root / (name + ".stderr")
                stdout.write_text("\n".join(lines) + "\n")
                stderr.write_text("")
                steps.append({"id": name, "owned_clean": True, "exit_code": 0,
                              "counts": {"complete": True},
                              "process": {"stdout": owned.ref(root, stdout),
                                          "stderr": owned.ref(root, stderr)}})
            result = runner.named_memory_safety(source, files, steps, root)
            self.assertEqual({row["id"] for row in result},
                             {case["id"] for case in runner.MEMORY_SAFETY})
            self.assertTrue(all(row["verdict"] == "passed" for row in result))
            first = next(step for step in steps if step["id"].startswith("lru-"))
            first["counts"]["complete"] = False
            with self.assertRaisesRegex(ValueError, "incomplete"):
                runner.named_memory_safety(source, files, steps, root)

    def test_advisory_declaration_and_scan_reject_missing_or_unmapped_decisions(self):
        source = Path.cwd().resolve()
        when = dt.datetime.now(dt.timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            database = root / "db"
            for issue, package, _ in advisory.KNOWN:
                item = database / "crates" / package / (issue + ".md")
                item.parent.mkdir(parents=True, exist_ok=True)
                item.write_text("synthetic advisory fixture\n")
            (database / ".git").mkdir()
            (database / ".git/HEAD").write_text("a" * 40 + "\n")
            projected, _ = path_patch_projection.project(source)
            projected_lock = root / "Cargo.lock"
            projected_lock.write_text(projected)
            database_files = advisory.inventory(database)
            decisions = []
            for (issue, package, version), (kind, vendor, regressions) in advisory.KNOWN.items():
                decisions.append({"id": issue, "package": package, "version": version,
                                  "decision": kind, "vendor_root": vendor,
                                  "vendor_manifest_sha256": sha256(source / vendor / "Cargo.toml"),
                                  "regressions": sorted(regressions), "owner": "unit fixture reviewer",
                                  "reviewed_at": when.isoformat(),
                                  "rationale": "Synthetic review data for validator behavior only."})
            value = {"schema": advisory.SCHEMA,
                     "scanner": {"path": str(Path(sys.executable).resolve()),
                                 "sha256": sha256(Path(sys.executable).resolve())},
                     "git": {"path": str(Path(sys.executable).resolve()),
                             "sha256": sha256(Path(sys.executable).resolve())},
                     "database": {"path": str(database),
                                  "files_sha256": advisory.canonical_hash(database_files),
                                  "commit": "a" * 40, "fetched_at": when.isoformat()},
                     "dispositions": decisions}
            observed, mapped, packages = advisory.inspect_declaration(
                value, source, projected_lock, when.isoformat(),
                {case["id"] for case in runner.MEMORY_SAFETY}, "a" * 40)
            self.assertEqual(observed, database_files)
            self.assertEqual(len(mapped), 3)
            self.assertEqual(len(packages), len(advisory.locked_packages(projected_lock)))
            report = {"database": {"advisory-count": 3},
                      "lockfile": {"dependency-count": len(packages)},
                      "settings": {"target_arch": [], "target_os": [], "ignore": [], "severity": None,
                                   "informational_warnings": ["unmaintained", "unsound", "notice"]},
                      "vulnerabilities": {"found": False, "count": 0, "list": []},
                      "warnings": {}}
            self.assertEqual(advisory.parse_report(report, packages), {})
            verdicts = {case["id"]: "passed" for case in runner.MEMORY_SAFETY}
            self.assertEqual(advisory.reconcile({}, mapped, verdicts), [])
            missing = copy.deepcopy(value)
            missing["dispositions"].pop()
            with self.assertRaisesRegex(ValueError, "required source advisory"):
                advisory.inspect_declaration(missing, source, projected_lock,
                                             when.isoformat(), verdicts, "a" * 40)
            changed = copy.deepcopy(value)
            changed["database"]["files_sha256"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "database bytes differ"):
                advisory.inspect_declaration(changed, source, projected_lock,
                                             when.isoformat(), verdicts, "a" * 40)
            changed = copy.deepcopy(value)
            changed["database"]["commit"] = "b" * 40
            with self.assertRaisesRegex(ValueError, "Git commit differs"):
                advisory.inspect_declaration(changed, source, projected_lock,
                                             when.isoformat(), verdicts, "a" * 40)
            unknown = {("RUSTSEC-2099-9999", "lru", "0.16.4"):
                       {"id": "RUSTSEC-2099-9999", "package": "lru", "version": "0.16.4",
                        "category": "unsound", "kind": "unsound"}}
            with self.assertRaisesRegex(ValueError, "undisposed"):
                advisory.reconcile(unknown, mapped, verdicts)
            verdicts["lru-panicking-drop"] = "failed"
            with self.assertRaisesRegex(ValueError, "named passing regressions"):
                advisory.reconcile({}, mapped, verdicts)

    def test_owned_launcher_argv_includes_both_input_declarations(self):
        inputs = {"tools": {"python": {"path": "/native/python"}}}
        self.assertEqual(launcher.command(inputs, "/frozen/source", "/frozen", "/native.json",
                                          "/advisories.json", "/attempt"),
                         ["/native/python", "-B", "-S", "/frozen/source/scripts/run_dependency_review_owned.py",
                          "--evidence", "/frozen", "--native-inputs", "/native.json",
                         "--advisory-inputs", "/advisories.json", "--output", "/attempt/review"])

    def test_packed_git_attestation_and_fabricated_head_fail_closed(self):
        git = shutil.which("git")
        self.assertIsNotNone(git)
        with tempfile.TemporaryDirectory(dir=Path.cwd() / "target/g11-dependency-runner-corrected") as directory:
            database = Path(directory) / "db"
            database.mkdir()
            environment = dependency_git.environment({"PATH": "/usr/bin:/bin"})

            def call(*args):
                return subprocess.run([git, *args], cwd=database, env=environment,
                                      capture_output=True, check=True).stdout

            call("init", "-q", "--initial-branch=master")
            call("config", "user.name", "Synthetic Reviewer")
            call("config", "user.email", "synthetic@example.invalid")
            advisory_file = database / "crates/redb/RUSTSEC-2099-9999.md"
            advisory_file.parent.mkdir(parents=True)
            advisory_file.write_text("synthetic advisory\n")
            call("add", "crates/redb/RUSTSEC-2099-9999.md")
            call("commit", "-qm", "Synthetic advisory fixture")
            declared = call("rev-parse", "HEAD").decode().strip()
            call("repack", "-adq")
            call("prune-packed")
            self.assertTrue(list((database / ".git/objects/pack").glob("*.pack")))
            outputs = {}
            tree = None
            for operation in (dependency_git.OBJECT_FORMAT, dependency_git.HEAD,
                              dependency_git.COMMIT, dependency_git.TREE):
                argument = declared if operation == dependency_git.COMMIT else tree
                selected = dependency_git.command(git, database, operation, argument)
                outputs[operation] = subprocess.run(selected, cwd=database, env=environment,
                                                    capture_output=True, check=True).stdout
                if operation == dependency_git.COMMIT:
                    tree = dependency_git.commit_tree(outputs[operation], declared)
            self.assertEqual(dependency_git.verify_outputs(database, declared, outputs),
                             {"commit": declared, "tree": tree, "files": 1})
            advisory_file.write_text("changed\n")
            with self.assertRaisesRegex(ValueError, "Git blob"):
                dependency_git.verify_outputs(database, declared, outputs)
            advisory_file.write_text("synthetic advisory\n")
            (database / "crates/redb/untracked.md").write_text("extra\n")
            with self.assertRaisesRegex(ValueError, "committed Git tree"):
                dependency_git.verify_outputs(database, declared, outputs)
            (database / "crates/redb/untracked.md").unlink()
            (database / ".git/HEAD").write_text("a" * 40 + "\n")
            selected = dependency_git.command(git, database, dependency_git.HEAD)
            self.assertNotEqual(subprocess.run(selected, cwd=database, env=environment,
                                               capture_output=True).returncode, 0)

    def test_new_patched_package_advisory_is_observed_and_undisposed(self):
        source = Path.cwd().resolve()
        with tempfile.TemporaryDirectory(dir=source / "target/g11-dependency-runner-corrected") as directory:
            projected, _ = path_patch_projection.project(source)
            lock = Path(directory) / "Cargo.lock"
            lock.write_text(projected)
            packages = advisory.locked_packages(lock)
            redb = packages[("redb", "4.2.0")]
            finding = {"kind": "unsound", "package": {"name": "redb", "version": "4.2.0",
                       "source": redb["source"], "checksum": redb["checksum"]},
                       "advisory": {"id": "RUSTSEC-2099-9999", "package": "redb"}}
            report = {"database": {"advisory-count": 1},
                      "lockfile": {"dependency-count": len(packages)},
                      "settings": {"target_arch": [], "target_os": [], "ignore": [], "severity": None,
                                   "informational_warnings": ["unmaintained", "unsound", "notice"]},
                      "vulnerabilities": {"found": False, "count": 0, "list": []},
                      "warnings": {"unsound": [finding]}}
            parsed = advisory.parse_report(report, packages)
            self.assertIn(("RUSTSEC-2099-9999", "redb", "4.2.0"), parsed)
            with self.assertRaisesRegex(ValueError, "undisposed"):
                advisory.reconcile(parsed, {}, {})
            wrong_source = copy.deepcopy(report)
            wrong_source["warnings"]["unsound"][0]["package"]["checksum"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "source or checksum"):
                advisory.parse_report(wrong_source, packages)

    def scanner_receipt_fixture(self, root):
        selected = ["/native/cargo-audit", "audit", "--format", "json"]
        files = root / "advisory-scan"
        files.mkdir()
        executable = root / "blobs" / hashlib.sha256(b"synthetic scanner bytes").hexdigest()
        executable.parent.mkdir()
        executable.write_bytes(b"synthetic scanner bytes")
        original = files / "stdout.log"
        original.write_text('{"database":{"advisory-count":1},"vulnerabilities":{"found":true}}\n')
        alternate = files / "stdout-alternate.json"
        alternate.write_text('{"database":{"advisory-count":1},"vulnerabilities":{"found":false}}\n')
        stderr = files / "stderr.log"
        stderr.write_text("")
        item = {"id": "advisory-scan", "stdout": owned.ref(root, original),
                "stderr": owned.ref(root, stderr), "executable": owned.ref(root, executable)}
        cleanup = {"group": 302, "process_returncode": 1, "drained": True,
                   "before": [], "after": [], "signals": [], "errors": []}
        receipt = {"command": selected, "working_directory": "/frozen/source",
                   "executable": {"path": selected[0], "sha256": item["executable"]["sha256"]},
                   "stdout": item["stdout"], "stderr": item["stderr"],
                   "timeout_seconds": runner.TIMEOUT, "process_group": 302,
                   "exit_code": 1, "process_exit_code": 1, "status": "failed",
                   "outputs_stable": True, "timed_out": False, "received_signals": [],
                   "error": None, "cleanup": cleanup}
        receipt_path = files / "process.json"
        receipt_path.write_text(json.dumps(receipt))
        item["receipt"] = owned.ref(root, receipt_path)
        step = {"id": "advisory-scan", "command": selected, "owned_clean": True, "process": item,
                "exit_code": 1, "tool_sha256": item["executable"]["sha256"],
                "drain": cleanup, "timed_out": False, "received_signals": [],
                "process_error": None, "counts": {"complete": True}}
        return selected, receipt_path, alternate, step, receipt

    def test_scanner_original_stdout_reference_cannot_be_substituted(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd() / "target/g11-dependency-runner-corrected") as directory:
            root = Path(directory)
            selected, _, alternate, step, receipt = self.scanner_receipt_fixture(root)
            self.assertEqual(launcher.check_child_receipt(
                root, step, selected, "/frozen/source", {0, 1})[0], receipt)
            # The substitute is another valid JSON report. Recomputed findings
            # cannot make it the scanner process's original stdout.
            step["process"]["stdout"] = owned.ref(root, alternate)
            with self.assertRaisesRegex(ValueError, "original artifact paths"):
                launcher.check_child_receipt(root, step, selected, "/frozen/source", {0, 1})
            original = root / "advisory-scan/stdout.log"
            original.write_bytes(alternate.read_bytes())
            step["process"]["stdout"] = owned.ref(root, original)
            with self.assertRaisesRegex(ValueError, "receipt or displayed fields"):
                launcher.check_child_receipt(root, step, selected, "/frozen/source", {0, 1})

    def test_scanner_status_group_and_displayed_drain_contradictions_fail(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd() / "target/g11-dependency-runner-corrected") as directory:
            root = Path(directory)
            selected, receipt_path, _, step, receipt = self.scanner_receipt_fixture(root)
            changed = copy.deepcopy(receipt)
            changed["status"] = "passed"
            receipt_path.write_text(json.dumps(changed))
            step["process"]["receipt"] = owned.ref(root, receipt_path)
            with self.assertRaisesRegex(ValueError, "receipt or displayed fields"):
                launcher.check_child_receipt(root, step, selected, "/frozen/source", {0, 1})
            changed = copy.deepcopy(receipt)
            changed["cleanup"]["group"] = 303
            receipt_path.write_text(json.dumps(changed))
            step["process"]["receipt"] = owned.ref(root, receipt_path)
            with self.assertRaisesRegex(ValueError, "receipt or displayed fields"):
                launcher.check_child_receipt(root, step, selected, "/frozen/source", {0, 1})
            receipt_path.write_text(json.dumps(receipt))
            step["process"]["receipt"] = owned.ref(root, receipt_path)
            step["drain"] = {**receipt["cleanup"], "signals": ["SIGTERM"]}
            with self.assertRaisesRegex(ValueError, "receipt or displayed fields"):
                launcher.check_child_receipt(root, step, selected, "/frozen/source", {0, 1})

    def test_dependency_child_ledger_binds_original_owner_executable_birth_and_order(self):
        runner_group = 200
        originals = [{"process_group": 300 + index,
                      "leader_birth": "linux:" + str(1000 + index),
                      "executable": {"sha256": f"{index + 1:064x}"}}
                     for index in range(30)]
        expected = [launcher.original_child_entry(receipt, runner_group)
                    for receipt in originals]

        def census_for(rows):
            return {"schema": 1, "ledger_closed": True, "complete": True,
                    "groups": [{"group": row["group"], "owner_pid": row["owner_pid"],
                                "executable_sha256": row["executable_sha256"],
                                "leader_birth": row["leader_birth"],
                                "before": [], "after": [], "signals": [],
                                "errors": [], "terminal": True} for row in rows]}

        launcher.check_child_custody(expected, True, census_for(expected), expected)
        for field, replacement in (("owner_pid", 999), ("executable_sha256", "0" * 64),
                                   ("leader_birth", "linux:0")):
            with self.subTest(field=field):
                altered = copy.deepcopy(expected)
                altered[4][field] = replacement
                with self.assertRaisesRegex(ValueError, "original process ownership"):
                    launcher.check_child_custody(altered, True, census_for(altered), expected)
        reordered = copy.deepcopy(expected)
        reordered[4], reordered[5] = reordered[5], reordered[4]
        with self.assertRaisesRegex(ValueError, "original process ownership"):
            launcher.check_child_custody(reordered, True, census_for(reordered), expected)
        missing_birth = copy.deepcopy(originals[0])
        del missing_birth["leader_birth"]
        with self.assertRaisesRegex(ValueError, "original process identity"):
            launcher.original_child_entry(missing_birth, runner_group)

    def make_roster(self, root):
        inventories = []
        for relative, names in runner.EXPECTED.items():
            path = root / relative
            path.mkdir(parents=True)
            files = {"Cargo.toml": {}}
            if relative.endswith("openraft-0.9.25"):
                members = ("openraft", "memstore", "macros", "tests", "rocksstore", "sledstore")
                excluded = ("cluster_benchmark", "stores/rocksstore-v2", "examples/memstore",
                            "examples/raft-kv-memstore", "examples/raft-kv-memstore-singlethreaded",
                            "examples/raft-kv-memstore-generic-snapshot-data",
                            "examples/raft-kv-memstore-opendal-snapshot-data",
                            "examples/raft-kv-rocksdb")
                (path / "Cargo.toml").write_text(
                    '[workspace]\nmembers = ' + repr(list(members)).replace("'", '"') +
                    '\nexclude = ' + repr(list(excluded)).replace("'", '"') + '\n')
                files.update({name + "/Cargo.toml": {} for name in members + excluded})
            else:
                (path / "Cargo.toml").write_text(
                    '[package]\nname = "' + next(iter(names)) + '"\nversion = "1.0.0"\n')
                if relative.endswith("redb-4.2.0"):
                    derive = path / "crates/redb-derive"
                    derive.mkdir(parents=True)
                    (derive / "Cargo.toml").write_text(
                        '[package]\nname = "redb-derive"\nversion = "0.1.0"\n')
                    files["crates/redb-derive/Cargo.toml"] = {}
                    files["crates/redb-derive/Cargo.lock"] = {}
            files["Cargo.lock"] = {}
            inventories.append({"path": relative, "files": files,
                                "packages": [{"name": name, "version": "1.0.0",
                                              "path": relative, "patch": True}
                                             for name in sorted(names)]})
        return {"format": 2, "inventories": inventories}

    def test_every_reviewed_root_and_openraft_workspace_is_selected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            suites = runner.suite_roster(root, self.make_roster(root))
            self.assertEqual({s["root"] for s in suites}, set(runner.EXPECTED) |
                             {"vendor/redb-4.2.0/crates/redb-derive"})
            self.assertEqual(sum(s["workspace"] for s in suites), 1)
            openraft_suite = next(s for s in suites if s["workspace"])
            self.assertEqual(len(openraft_suite["excluded_unlocked"]), 8)
            inputs = {"tools": {name: {"path": "/native/" + name}
                                for name in ("python", "cargo", "rustc")}}
            selected = runner.commands(inputs, root, suites)
            self.assertEqual(len(selected), 25)
            self.assertEqual(len({name for name, _, _ in selected}), 25)
            self.assertEqual(sum(kind == "rust" for _, _, kind in selected), 20)
            self.assertTrue(all("--locked" in command and "--offline" in command
                                for _, command, kind in selected if kind == "rust"))
            serde = [(name, command) for name, command, kind in selected
                     if kind == "rust" and name.startswith("serde-json-")]
            self.assertEqual(len(serde), 8)
            expected_features = {
                "default": [],
                "arbitrary-precision": ["--features", "arbitrary_precision"],
                "raw-value": ["--features", "raw_value"],
                "combined": ["--features", "arbitrary_precision,raw_value,float_roundtrip,preserve_order"],
            }
            for label, features in expected_features.items():
                for kind in ("all-targets", "doctests"):
                    command = next(command for name, command in serde
                                   if name == "serde-json-1-0-151-" + label + "-" + kind)
                    self.assertNotIn("--all-features", command)
                    self.assertEqual(command[command.index("--offline") + 1:command.index("--no-fail-fast")],
                                     features)
            self.assertTrue(all("--all-features" in command for name, command, kind in selected
                                if kind == "rust" and not name.startswith("serde-json-")))
            locked_manifests = {command[command.index("--manifest-path") + 1]
                                for _, command, kind in selected if kind == "rust"}
            self.assertEqual(locked_manifests,
                             {str(root / suite["root"] / "Cargo.toml") for suite in suites})
            self.assertIn(str(root / "vendor/redb-4.2.0/crates/redb-derive/Cargo.toml"),
                          locked_manifests)
            openraft = [command for name, command, _ in selected if name.startswith("openraft-")]
            self.assertEqual(len(openraft), 2)
            self.assertTrue(all("--workspace" in command for command in openraft))

    def test_missing_reviewed_root_and_integration_suite_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.make_roster(root)
            missing = copy.deepcopy(manifest)
            missing["inventories"].pop()
            with self.assertRaisesRegex(ValueError, "incomplete"):
                runner.suite_roster(root, missing)
            openraft = next(item for item in manifest["inventories"]
                            if item["path"].endswith("openraft-0.9.25"))
            openraft["files"].pop("tests/Cargo.toml")
            with self.assertRaisesRegex(ValueError, "not all reviewed"):
                runner.suite_roster(root, manifest)

    def test_machine_counts_reject_missing_summary_or_missing_package(self):
        rust = runner.parse_counts("rust", "test result: ok. 3 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.1s\n"
                                   "test thing ... FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s\n",
                                   "     Running unittests src/lib.rs (/tmp/a)\n"
                                   "     Running tests/integration.rs (/tmp/b)\n", [], rust_mode="targets")
        self.assertEqual((rust["suites"], rust["tests"], rust["failed"]), (2, 4, 1))
        self.assertEqual(rust["launched"], 2)
        self.assertEqual(rust["failed_names"], ["thing"])
        self.assertTrue(rust["complete"])
        self.assertFalse(runner.parse_counts("rust", "compiler failed", "", [],
                                             rust_mode="targets")["complete"])
        self.assertFalse(runner.parse_counts("rust", "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s\n",
                                             "     Running unittests src/lib.rs (/tmp/a)\n"
                                             "     Running tests/integration.rs (/tmp/b)\n",
                                             [], rust_mode="targets")["complete"])
        self.assertTrue(runner.parse_counts("rust", "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.0s\n",
                                            "   Doc-tests redb_derive\n", [], rust_mode="doc")["complete"])
        self.assertFalse(runner.parse_counts("rust", "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.0s\n",
                                             "", [], rust_mode="doc")["complete"])
        self.assertEqual(runner.parse_counts("python", "", "Ran 16 tests in 0.1s\n\nOK\n", [])["tests"], 16)
        self.assertFalse(runner.parse_counts("python", "", "OK\n", [])["complete"])
        expected = [("redb", "4.2.0", "vendor/redb-4.2.0")]
        self.assertTrue(runner.parse_counts("verifier", "verified redb 4.2.0 (vendor/redb-4.2.0)\n",
                                            "", expected)["complete"])
        self.assertFalse(runner.parse_counts("verifier", "verified redb 4.2.0 (vendor/redb-4.2.0)\nextra\n",
                                             "", expected)["complete"])
        self.assertFalse(runner.parse_counts("verifier", "verified redb 4.2.0 (vendor/redb-4.2.0)\n",
                                             "cargo warning\n", expected)["complete"])
        ordered = [("redb", "4.2.0", "vendor/redb-4.2.0"),
                   ("openraft", "0.9.25", "vendor/openraft-0.9.25/openraft")]
        self.assertFalse(runner.parse_counts("verifier",
                                             "verified openraft 0.9.25 (vendor/openraft-0.9.25/openraft)\n"
                                             "verified redb 4.2.0 (vendor/redb-4.2.0)\n",
                                             "", ordered)["complete"])
        self.assertFalse(runner.parse_counts("verifier", "", "", expected)["complete"])


if __name__ == "__main__":
    unittest.main()
