"""Synthetic runner-contract tests; no Cargo command or advisory scan runs."""

import copy
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import py_compile
import shutil
import subprocess
import sys
import tempfile
import unittest

import advisory_upstream
import check_dependency_patches
import dependency_advisory as advisory
import dependency_git
import dependency_matrix
import dependency_provenance
import path_patch_projection
import repeatable_assembly as owned
import run_dependency_review_owned as runner
import run_dependency_review_launcher as launcher
from release_gate import sha256


class DependencyRunnerTests(unittest.TestCase):
    def test_owned_python_entrypoints_reject_cached_code_before_local_import(self):
        source_scripts = Path(__file__).resolve().parent
        first_import = {
            "run_dependency_review_launcher.py": "attempt_index",
            "run_dependency_review_owned.py": "assembly_inputs",
            "run_repeatable_assembly_owned.py": "attempt_index",
            "repeatable_assembly.py": "assembly_inputs",
            "package_release.py": "gate_process",
        }
        environment = dict(os.environ)
        environment.pop("PYTHONPYCACHEPREFIX", None)
        for entrypoint, helper in first_import.items():
            for mode in (py_compile.PycInvalidationMode.TIMESTAMP,
                         py_compile.PycInvalidationMode.UNCHECKED_HASH):
                with self.subTest(entrypoint=entrypoint, mode=mode.name), \
                        tempfile.TemporaryDirectory() as directory:
                    scripts = Path(directory) / "scripts"
                    scripts.mkdir()
                    shutil.copyfile(source_scripts / entrypoint, scripts / entrypoint)
                    marker = scripts / "untrusted-code-executed"
                    helper_source = scripts / (helper + ".py")
                    payload = f"open({str(marker)!r}, 'w').write('executed')\n"
                    helper_source.write_text(payload)
                    original_time = helper_source.stat().st_mtime_ns
                    py_compile.compile(str(helper_source), doraise=True,
                                       invalidation_mode=mode)
                    helper_source.write_text("pass\n" + "#" * (len(payload) - 5))
                    os.utime(helper_source, ns=(original_time, original_time))
                    probe = scripts / "probe.py"
                    probe.write_text("import sys\nfrom pathlib import Path\n"
                                     "sys.path.insert(0, str(Path(__file__).resolve().parent))\n"
                                     f"import {helper}\n")
                    baseline = subprocess.run([sys.executable, "-I", "-B", "-S", str(probe)],
                                              env=environment, capture_output=True, text=True)
                    self.assertEqual(baseline.returncode, 0, baseline.stderr)
                    self.assertTrue(marker.exists(), "fixture did not demonstrate cached execution")
                    marker.unlink()
                    blocked = subprocess.run([sys.executable, "-I", "-B", "-S",
                                              str(scripts / entrypoint)], env=environment,
                                             capture_output=True, text=True)
                    self.assertNotEqual(blocked.returncode, 0)
                    self.assertIn("source-only Python imports", blocked.stderr)
                    self.assertFalse(marker.exists(), "launcher imported untrusted cached code")

    def test_owned_python_entrypoints_require_isolation_and_import_clean_sources(self):
        source_scripts = Path(__file__).resolve().parent
        entrypoints = ("run_dependency_review_launcher.py", "run_dependency_review_owned.py",
                       "run_repeatable_assembly_owned.py", "repeatable_assembly.py",
                       "package_release.py")
        environment = dict(os.environ)
        environment.pop("PYTHONPYCACHEPREFIX", None)
        with tempfile.TemporaryDirectory() as directory:
            scripts = Path(directory) / "scripts"
            scripts.mkdir()
            for source in source_scripts.glob("*.py"):
                shutil.copyfile(source, scripts / source.name)
            for entrypoint in entrypoints:
                with self.subTest(entrypoint=entrypoint):
                    selected = str(scripts / entrypoint)
                    unisolated = subprocess.run([sys.executable, "-B", "-S", selected],
                                                env=environment, capture_output=True, text=True)
                    self.assertNotEqual(unisolated.returncode, 0)
                    self.assertIn("requires native Python -I -S -B", unisolated.stderr)
                    clean = subprocess.run([sys.executable, "-I", "-B", "-S", selected],
                                           env=environment, capture_output=True, text=True)
                    self.assertEqual(clean.returncode, 2, clean.stderr)
                    self.assertIn("usage:", clean.stderr)
                    self.assertNotIn("ModuleNotFoundError", clean.stderr)

    def test_named_memory_safety_requires_each_original_test_verdict(self):
        source = Path.cwd().resolve()
        files = {case["source"]: {"sha256": sha256(source / case["source"])}
                 for case in runner.MEMORY_SAFETY}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            logs = {}
            for case in runner.MEMORY_SAFETY:
                name = case["name"]
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
            self.assertEqual(set(mapped), set(advisory.KNOWN))
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
                                          "/advisories.json", "/crates", "/attempt"),
                         ["/native/python", "-I", "-B", "-S", "/frozen/source/scripts/run_dependency_review_owned.py",
                          "--evidence", "/frozen", "--native-inputs", "/native.json",
                          "--advisory-inputs", "/advisories.json", "--upstream-archives", "/crates",
                          "--output", "/attempt/review"])

    def test_launcher_journals_its_record_with_or_without_a_dispatched_runner(self):
        import attempt_index
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            attempt_index.create(root, "unit-journal", "unit-host", runner.REFERENCE)
            started = "2026-09-24T00:00:00+00:00"
            for attempt, dispatched in (("review-preflight", False), ("review-failed", True)):
                output = root / attempt
                attempt_index.begin(root, attempt, "dependency-review", output, started)
                output.mkdir()
                record = {"status": "failed", "finished_at": "2026-09-24T00:00:10+00:00",
                          "runner_process": None}
                if dispatched:
                    files = {}
                    for name in ("process.json", "stdout.log", "python"):
                        (output / name).write_text(name)
                        files[name] = owned.ref(output, output / name)
                    record["runner_process"] = {"id": "runner", "receipt": files["process.json"],
                                                "stdout": files["stdout.log"],
                                                "stderr": files["stdout.log"],
                                                "executable": files["python"]}
                (output / "launcher.json").write_text(json.dumps(record))
                launcher.journal(root, attempt, output, record, dispatched)
                outcome = json.loads((output / "outcome.json").read_text())
                self.assertEqual((outcome["status"], outcome["dispatch_started"]),
                                 ("failed", dispatched))
                receipt = json.loads((root / "attempts" / attempt / "attempt.json").read_text())
                self.assertEqual([item["id"] for item in receipt["processes"]],
                                 ["runner"] if dispatched else [])
                if dispatched:
                    self.assertEqual(receipt["processes"][0]["log"]["path"],
                                     attempt + "/stdout.log")
            self.assertEqual(set(attempt_index.replay(root)), {"review-preflight", "review-failed"})

    def test_owned_dependency_primary_rejects_substitution_and_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            review = root / "review"
            blobs = review / "blobs"
            blobs.mkdir(parents=True)
            evidence = root / "evidence"
            evidence.mkdir()
            functional = {"source_commit": "1" * 40, "source_tree": "2" * 40,
                          "source_archive_sha256": "3" * 64,
                          "source_files_sha256": "4" * 64, "lockfile_sha256": "5" * 64}
            original = evidence / "evidence.json"
            original.write_text(json.dumps(functional) + "\n")
            blob = blobs / sha256(original)
            blob.write_bytes(original.read_bytes())
            inner = {"selected_primary": owned.ref(review, blob),
                     "source": {"commit": functional["source_commit"],
                                "tree": functional["source_tree"],
                                "archive_sha256": functional["source_archive_sha256"],
                                "source_files_sha256": functional["source_files_sha256"],
                                "lockfile_sha256": functional["lockfile_sha256"]}}
            self.assertEqual(launcher.check_selected_primary(
                root, inner, evidence, functional["source_files_sha256"]), functional)

            different = copy.deepcopy(inner)
            different["source"]["commit"] = "9" * 40
            with self.assertRaisesRegex(ValueError, "source identity differs"):
                launcher.check_selected_primary(root, different, evidence,
                                                functional["source_files_sha256"])
            with self.assertRaisesRegex(ValueError, "source identity differs"):
                launcher.check_selected_primary(root, inner, evidence, "0" * 64)

            original.write_text('{"source_commit":"other"}\n')
            with self.assertRaisesRegex(ValueError, "did not retain"):
                launcher.check_selected_primary(root, inner, evidence,
                                                functional["source_files_sha256"])
            original.write_bytes(blob.read_bytes())
            blob.write_text('{"source_commit":"tampered"}\n')
            with self.assertRaises(ValueError):
                launcher.check_selected_primary(root, inner, evidence,
                                                functional["source_files_sha256"])

    def test_packed_git_attestation_and_fabricated_head_fail_closed(self):
        git = shutil.which("git")
        self.assertIsNotNone(git)
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory).resolve() / "db"
            database.mkdir()
            environment = dependency_git.environment({"PATH": "/usr/bin:/bin"})

            def call(*args):
                return subprocess.run([git, *args], cwd=database, env=environment,
                                      capture_output=True, check=True).stdout

            call("init", "-q", "--initial-branch=master")
            call("config", "user.name", "Synthetic Reviewer")
            call("config", "user.email", "synthetic@example.invalid")
            advisory_file = database / "crates/rmcp/RUSTSEC-2099-9999.md"
            advisory_file.parent.mkdir(parents=True)
            advisory_file.write_text("synthetic advisory\n")
            call("add", "crates/rmcp/RUSTSEC-2099-9999.md")
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
            (database / "crates/rmcp/untracked.md").write_text("extra\n")
            with self.assertRaisesRegex(ValueError, "committed Git tree"):
                dependency_git.verify_outputs(database, declared, outputs)
            (database / "crates/rmcp/untracked.md").unlink()
            (database / ".git/HEAD").write_text("a" * 40 + "\n")
            selected = dependency_git.command(git, database, dependency_git.HEAD)
            self.assertNotEqual(subprocess.run(selected, cwd=database, env=environment,
                                               capture_output=True).returncode, 0)

    def test_new_patched_package_advisory_is_observed_and_undisposed(self):
        source = Path.cwd().resolve()
        with tempfile.TemporaryDirectory() as directory:
            projected, _ = path_patch_projection.project(source)
            lock = Path(directory) / "Cargo.lock"
            lock.write_text(projected)
            packages = advisory.locked_packages(lock)
            rmcp = packages[("rmcp", "3.2.0")]
            finding = {"kind": "unsound", "package": {"name": "rmcp", "version": "3.2.0",
                       "source": rmcp["source"], "checksum": rmcp["checksum"]},
                       "advisory": {"id": "RUSTSEC-2099-9999", "package": "rmcp"}}
            report = {"database": {"advisory-count": 1},
                      "lockfile": {"dependency-count": len(packages)},
                      "settings": {"target_arch": [], "target_os": [], "ignore": [], "severity": None,
                                   "informational_warnings": ["unmaintained", "unsound", "notice"]},
                      "vulnerabilities": {"found": False, "count": 0, "list": []},
                      "warnings": {"unsound": [finding]}}
            parsed = advisory.parse_report(report, packages)
            self.assertIn(("RUSTSEC-2099-9999", "rmcp", "3.2.0"), parsed)
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
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
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
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
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

    def frozen_roster(self):
        source = Path.cwd().resolve()
        manifest = check_dependency_patches.read_json(source / "vendor/patch-manifest.json")
        return source, manifest, dependency_matrix.roster(source, manifest)

    def test_every_reviewed_root_runs_an_explicit_stable_matrix(self):
        source, manifest, suites = self.frozen_roster()
        self.assertEqual({suite["root"] for suite in suites}, set(dependency_matrix.MATRIX))
        self.assertEqual(sum(suite["workspace"] for suite in suites), 1)
        openraft = next(suite for suite in suites if suite["workspace"])
        self.assertEqual(len(openraft["excluded_unlocked"]), 8)
        self.assertEqual([member["member"] for member in openraft["excluded_members"]],
                         ["rocksstore", "sledstore"])
        inputs = {"tools": {name: {"path": "/native/" + name}
                            for name in ("python", "cargo", "rustc")}}
        selected = runner.commands(inputs, Path("/frozen/source"), suites, Path("/custody/crates"))
        names = [step["id"] for step in selected]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(names[:7], ["cargo-version", "rustc-version", "python-version",
                                     "official-verifier", "upstream-provenance",
                                     "python-regressions", "advisory-upstream"])
        self.assertEqual(selected[6]["command"], ["/native/python", "-I", "-B", "-S",
                                                   "/frozen/source/scripts/advisory_upstream.py"])
        self.assertEqual(selected[4]["command"],
                         ["/native/python", "-B", "-S",
                          "/frozen/source/scripts/dependency_provenance.py",
                          "--archives", "/custody/crates"])
        rust = [step for step in selected if step["kind"] == "rust"]
        self.assertEqual(len(rust), len(selected) - 7)
        unbuildable = {feature["name"] for suite in suites for package in suite["packages"]
                       for feature in package["excluded_features"]
                       if feature["class"] != "unselected"}
        self.assertEqual(unbuildable, {"bench", "bt", "nightly", "reqwest-native-tls"})
        for step in rust:
            command = step["command"]
            with self.subTest(step=step["id"]):
                self.assertIn("--locked", command)
                self.assertIn("--offline", command)
                # No blanket selection: nightly features, external stores and
                # runtime-launching targets cannot enter through a wildcard.
                for forbidden in ("--all-features", "--workspace", "--all-targets", "--tests",
                                  "test_with_js", "test_with_python", "test_expand",
                                  "openraft-rocksstore", "openraft-sledstore"):
                    self.assertNotIn(forbidden, command)
                if "--features" in command:
                    enabled = set(command[command.index("--features") + 1].split(","))
                    self.assertFalse(enabled & unbuildable)
                if step["mode"] == "doc":
                    self.assertEqual(step["launches"], 1)
        # Each memory-safety regression names a command that still exists.
        self.assertLessEqual({case["step"] for case in runner.MEMORY_SAFETY}, set(names))
        # Only the OpenRaft integration suite declares a generated output.
        self.assertEqual({step["id"]: step["generated_output"] for step in selected
                          if step["generated_output"]},
                         {"openraft-0-9-25-tests-upstream-stable-targets":
                          "vendor/openraft-0.9.25/tests/_log"})
        serde = {step["id"]: step["command"] for step in rust
                 if step["id"].startswith("serde-json-")}
        self.assertEqual(len(serde), 10)
        self.assertEqual(serde["serde-json-1-0-151-default-targets"].count("--features"), 0)

    def test_missing_reviewed_root_and_integration_suite_fail_closed(self):
        source, manifest, _ = self.frozen_roster()
        missing = copy.deepcopy(manifest)
        missing["inventories"].pop()
        with self.assertRaisesRegex(ValueError, "incomplete"):
            dependency_matrix.roster(source, missing)
        absent = copy.deepcopy(manifest)
        openraft = next(item for item in absent["inventories"]
                        if item["path"].endswith("openraft-0.9.25"))
        openraft["files"].pop("tests/Cargo.toml")
        with self.assertRaisesRegex(ValueError, "members differ"):
            dependency_matrix.roster(source, absent)

    def test_generated_suite_output_leaves_the_frozen_source_for_custody(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source, output = root / "source", root / "review"
            logs = source / "vendor/openraft-0.9.25/tests/_log"
            logs.mkdir(parents=True)
            (logs / "ut.log").write_text("suite log\n")
            output.mkdir()
            step = {"id": "openraft-suite-targets",
                    "generated_output": "vendor/openraft-0.9.25/tests/_log"}
            retained = runner.retain_generated(step, source, output)
            self.assertFalse(logs.exists())
            self.assertEqual(retained["path"], "generated/openraft-suite-targets")
            self.assertEqual((output / retained["path"] / "ut.log").read_text(), "suite log\n")
            launcher.check_generated(output, {"id": step["id"], "generated": retained}, step)
            (output / retained["path"] / "ut.log").write_text("rewritten\n")
            with self.assertRaisesRegex(ValueError, "retained inventory"):
                launcher.check_generated(output, {"id": step["id"], "generated": retained}, step)
            # An undeclared write stays in the source for the caller to reject.
            self.assertIsNone(runner.retain_generated(
                {"id": "other", "generated_output": None}, source, output))
            logs.parent.rmdir()
            logs.parent.symlink_to(root, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "aliased"):
                runner.retain_generated({**step, "id": "aliased"}, source, output)

    def test_upstream_archives_are_retained_by_name_and_reject_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            supplied, output = root / "crates", root / "review"
            supplied.mkdir()
            output.mkdir()
            (supplied / "alpha-1.0.0.crate").write_bytes(b"published archive bytes")
            copied, retained = runner.retain_archives(output, supplied)
            self.assertEqual(copied, output / runner.ARCHIVES)
            self.assertEqual(set(retained), {"alpha-1.0.0.crate"})
            self.assertEqual(retained["alpha-1.0.0.crate"]["sha256"],
                             hashlib.sha256(b"published archive bytes").hexdigest())
            second = root / "second"
            second.mkdir()
            (supplied / "linked.crate").symlink_to(supplied / "alpha-1.0.0.crate")
            with self.assertRaisesRegex(ValueError, "not a regular file"):
                runner.retain_archives(second, supplied)

    def test_machine_counts_reject_missing_summary_or_missing_package(self):
        rust = runner.parse_counts("rust", "test result: ok. 3 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.1s\n"
                                   "test thing ... FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s\n",
                                   "     Running unittests src/lib.rs (/tmp/a)\n"
                                   "     Running tests/integration.rs (/tmp/b)\n", [], rust_mode="targets",
                                   launches=2)
        self.assertEqual((rust["suites"], rust["tests"], rust["failed"]), (2, 4, 1))
        self.assertEqual(rust["launched"], 2)
        self.assertEqual(rust["failed_names"], ["thing"])
        self.assertTrue(rust["complete"])
        self.assertFalse(runner.parse_counts("rust", "compiler failed", "", [],
                                             rust_mode="targets", launches=1)["complete"])
        one = ("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s\n",
               "     Running unittests src/lib.rs (/tmp/a)\n")
        self.assertTrue(runner.parse_counts("rust", *one, [], rust_mode="targets",
                                            launches=1)["complete"])
        # Cargo skipped a named executable, or the expected count is unknown.
        self.assertFalse(runner.parse_counts("rust", *one, [], rust_mode="targets",
                                             launches=2)["complete"])
        self.assertFalse(runner.parse_counts("rust", *one, [], rust_mode="targets")["complete"])
        self.assertFalse(runner.parse_counts("rust", "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.1s\n",
                                             "     Running unittests src/lib.rs (/tmp/a)\n"
                                             "     Running tests/integration.rs (/tmp/b)\n",
                                             [], rust_mode="targets", launches=2)["complete"])
        self.assertTrue(runner.parse_counts("rust", "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.0s\n",
                                            "   Doc-tests rmcp\n", [], rust_mode="doc",
                                            launches=1)["complete"])
        self.assertFalse(runner.parse_counts("rust", "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.0s\n",
                                             "", [], rust_mode="doc", launches=1)["complete"])
        expected_output = "upstream alpha 1.0.0 " + "a" * 64 + " changed=1 added=0 removed=0\n"
        self.assertTrue(runner.parse_counts("provenance", expected_output, "", [],
                                            expected_output=expected_output)["complete"])
        for stdout, stderr in ((expected_output + "extra\n", ""), (expected_output, "warning\n"),
                               ("", ""), (expected_output.replace("a", "b"), "")):
            self.assertFalse(runner.parse_counts("provenance", stdout, stderr, [],
                                                 expected_output=expected_output)["complete"])
        self.assertFalse(runner.parse_counts("provenance", "", "", [],
                                             expected_output="")["complete"])
        self.assertEqual(runner.parse_counts("python", "", "Ran 16 tests in 0.1s\n\nOK\n", [])["tests"], 16)
        self.assertFalse(runner.parse_counts("python", "", "OK\n", [])["complete"])
        expected = [("rmcp", "3.2.0", "vendor/rmcp-3.2.0")]
        self.assertTrue(runner.parse_counts("verifier", "verified rmcp 3.2.0 (vendor/rmcp-3.2.0)\n",
                                            "", expected)["complete"])
        self.assertFalse(runner.parse_counts("verifier", "verified rmcp 3.2.0 (vendor/rmcp-3.2.0)\nextra\n",
                                             "", expected)["complete"])
        self.assertFalse(runner.parse_counts("verifier", "verified rmcp 3.2.0 (vendor/rmcp-3.2.0)\n",
                                             "cargo warning\n", expected)["complete"])
        ordered = [("rmcp", "3.2.0", "vendor/rmcp-3.2.0"),
                   ("openraft", "0.9.25", "vendor/openraft-0.9.25/openraft")]
        self.assertFalse(runner.parse_counts("verifier",
                                             "verified openraft 0.9.25 (vendor/openraft-0.9.25/openraft)\n"
                                             "verified rmcp 3.2.0 (vendor/rmcp-3.2.0)\n",
                                             "", ordered)["complete"])
        self.assertFalse(runner.parse_counts("verifier", "", "", expected)["complete"])


class AdvisoryUpstreamTests(unittest.TestCase):
    def test_partial_yank_check_cannot_pass_using_the_json_findings(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            stdout, stderr = root / "stdout", root / "stderr"
            stdout.write_text('{"vulnerabilities":{"found":false}}')
            stderr.write_text("error: couldn't check if the package is yanked: no such crate\n")
            scan = {"process": {"stdout": owned.ref(root, stdout), "stderr": owned.ref(root, stderr)}}
            with self.assertRaisesRegex(ValueError, "incomplete check"):
                runner.scanner_report(root, scan)
            stderr.write_text("")
            scan["process"]["stderr"] = owned.ref(root, stderr)
            self.assertEqual(runner.scanner_report(root, scan), json.loads(stdout.read_text()))

    def test_authenticates_scanned_commit_and_checks_observation_age(self):
        commit = "a" * 40
        body = {"ref": "refs/heads/main", "object": {"type": "commit", "sha": commit}}
        observation = {"url": "https://api.github.com" + advisory_upstream.PATH,
                       "tls_peer_sha256": "b" * 64, "response": body,
                       "http_date": "Wed, 18 Nov 2026 10:05:01 GMT",
                       "observed_at": "2026-11-18T10:05:00+00:00"}
        def check(item, expected=commit, checked="2026-11-18T10:10:00+00:00"):
            return advisory_upstream.verify(item, expected, started_at="2026-11-18T10:00:00+00:00",
                                            checked_at=checked, max_age_hours=72)
        self.assertEqual(check(observation), commit)
        with self.assertRaisesRegex(ValueError, "scanned Git commit"):
            check(observation, expected="f" * 40)
        with self.assertRaisesRegex(ValueError, "stale or outside"):
            check(observation, checked="2026-11-21T10:05:01+00:00")
        for changed in ({"http_date": "Tue, 17 Nov 2026 10:05:00 GMT"},
                        {"response": {**body, "ref": "refs/heads/test"}},
                        {"url": "https://example.test/ref"}, {"tls_peer_sha256": ""},
                        {"observed_at": "2026-11-18T09:59:00+00:00"}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                check({**observation, **changed})


if __name__ == "__main__":
    unittest.main()
