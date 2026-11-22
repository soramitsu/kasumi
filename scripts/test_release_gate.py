"""Counterexamples to provenance claims made by the functional gate runner."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import struct
import sys
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

import attempt_index
import release_gate

OPENRAFT_LOG = "vendor/openraft-0.9.25/tests/_log"
WRITE_OPENRAFT_LOG = ("from pathlib import Path; log = Path(" + repr(OPENRAFT_LOG) + "); log.mkdir(); "
                      "(log / 'ut.2026-09-27-00').write_text('fixture trace\\n')")


class ReleaseGateTests(unittest.TestCase):
    def dispatch(self, root, gates, prepare=None):
        """Dispatch gates against a minimal frozen source and keep the record terminal."""
        output = root / "run"
        source = output / "source"
        (source / "vendor/openraft-0.9.25/tests").mkdir(parents=True)
        (source / "vendor/openraft-0.9.25/tests/Cargo.toml").write_text("[package]\nname = \"tests\"\n")
        if prepare is not None:
            prepare(source)
        original = release_gate.inventory(source)
        record = {"schema": 1, "status": "running", "gates": []}
        release_gate.write_json(output / "evidence.json", record)
        with contextlib.redirect_stdout(io.StringIO()), release_gate.terminal_record(record, output):
            release_gate.dispatch_gates(gates, source, output, os.environ.copy(), 5, record, original)
        return output, record

    def test_export_must_match_committed_bytes_modes_and_file_set(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            (repo / ".gitattributes").write_text("/docs/evidence export-ignore\n")
            evidence = repo / "docs" / "evidence"
            evidence.mkdir(parents=True)
            (evidence / "raw").write_text("separate evidence")
            program = repo / "tool"
            program.write_text("original")
            program.chmod(0o755)
            git = ["git", "-C", str(repo)]
            subprocess.run(git + ["add", "."], check=True)
            subprocess.run(git + ["-c", "user.name=test", "-c", "user.email=test@invalid",
                                  "commit", "-qm", "source"], check=True)
            archive, source = root / "source.tar", root / "source"
            subprocess.run(git + ["archive", "-o", str(archive), "HEAD"], check=True)
            release_gate.extract_source(archive, source)

            def verify():
                release_gate.verify_export(repo, "HEAD", source, release_gate.inventory(source))

            verify()
            self.assertFalse((source / "docs/evidence/raw").exists())
            program = source / "tool"
            program.write_text("modified")
            with self.assertRaisesRegex(ValueError, "bytes or mode"):
                verify()
            program.write_text("original")
            program.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "bytes or mode"):
                verify()
            program.unlink()
            with self.assertRaisesRegex(ValueError, "paths differ"):
                verify()

    def test_roster_matches_all_frozen_gates_with_openraft_custody_commands(self):
        gates = release_gate.functional_gates(3, "/native/python3")
        self.assertEqual([name for name, _ in gates], [
            "toolchain", "format", "python", "dependency-patches", "lru",
            "serde-json-default", "serde-json-number", "serde-json-raw", "serde-json-combined",
            "rmcp-terminal-ownership", "rmcp-upstream-protocol", "openraft-units",
            "openraft-integration", "openraft-singlethreaded", "openraft-clippy", "workspace",
            "workspace-docs", "clippy", "network-features", "network-driver",
            "production-features", "production"])
        self.assertEqual(len(dict(gates)), 22)
        self.assertEqual([name for name, *_ in release_gate.VENDOR_SUITES],
                         [name for name, _ in gates[4:15]])
        # docs/evidence/openraft-canonical-20260920 attempts 46-49, under the
        # pinned toolchain, jobs and the runner's JSON encoding.
        openraft = ["--manifest-path", "vendor/openraft-0.9.25/Cargo.toml"]
        features = "serde,storage-v2,single-term-leader,generic-snapshot-data"
        tail = ["--locked", "-j", "3", "--message-format=json-render-diagnostics"]
        self.assertEqual({name: command for name, command in gates if name.startswith("openraft-")}, {
            "openraft-units": ["cargo", "+1.97.1", "test", *openraft, "-p", "openraft", "--lib",
                               "--features", features, *tail],
            "openraft-integration": ["cargo", "+1.97.1", "test", *openraft, "-p", "tests",
                                     "--test", "life_cycle", "--test", "client_api",
                                     "--test", "membership", "--test", "snapshot_streaming", *tail],
            "openraft-singlethreaded": ["cargo", "+1.97.1", "check", *openraft, "-p", "openraft",
                                        "--all-targets", "--features", "singlethreaded," + features, *tail],
            "openraft-clippy": ["cargo", "+1.97.1", "clippy", *openraft, "-p", "openraft", "--all-targets",
                                "--features", features, "--locked", "-j", "3", "--", "-D", "warnings"],
        })
        self.assertEqual(release_gate.GENERATED_OUTPUTS, {"openraft-integration": OPENRAFT_LOG})
        self.assertEqual(release_gate.generated_output_paths("openraft-integration"), {
            "source": OPENRAFT_LOG, "path": "generated/openraft-integration/_log",
            "files": "generated/openraft-integration/_log-files.json"})

    def test_openraft_integration_log_is_moved_out_of_source_with_hashed_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            gates = [("openraft-integration", [sys.executable, "-c", WRITE_OPENRAFT_LOG]),
                     ("openraft-singlethreaded", [sys.executable, "-c", "pass"])]
            output, record = self.dispatch(Path(temporary), gates)
            self.assertEqual(record["status"], "passed")
            self.assertEqual(json.loads((output / "evidence.json").read_text()), record)
            integration, later = record["gates"]
            self.assertEqual(later["generated_outputs"], [])
            retained, = integration["generated_outputs"]
            self.assertEqual({key: retained[key] for key in ("source", "path", "files")},
                             release_gate.generated_output_paths("openraft-integration"))
            self.assertFalse(os.path.lexists(output / "source" / OPENRAFT_LOG))
            log = output / "generated/openraft-integration/_log/ut.2026-09-27-00"
            self.assertEqual(log.read_text(), "fixture trace\n")
            files = output / retained["files"]
            self.assertEqual(release_gate.sha256(files), retained["files_sha256"])
            self.assertEqual(json.loads(files.read_text()), {"ut.2026-09-27-00": {
                "sha256": release_gate.sha256(log), "bytes": log.stat().st_size, "executable": False}})

    def test_any_other_source_write_aborts_before_later_dispatch(self):
        link_log = ("import os; os.symlink(os.path.abspath('../outside'), " + repr(OPENRAFT_LOG) + ")")
        file_log = "from pathlib import Path; Path(" + repr(OPENRAFT_LOG) + ").write_text('not a directory')"
        nested_link = WRITE_OPENRAFT_LOG + "; import os; os.symlink('/etc/hosts', " + repr(OPENRAFT_LOG + "/linked") + ")"
        extra = WRITE_OPENRAFT_LOG + "; Path('vendor/openraft-0.9.25/tests/stray.rs').write_text('extra')"
        cases = {
            "extra-file": ("openraft-integration", extra, RuntimeError, "changed frozen source"),
            "other-gate-log": ("openraft-units", WRITE_OPENRAFT_LOG, ValueError, "another gate"),
            "linked-log": ("openraft-integration", link_log, ValueError, "symbolic link"),
            "file-log": ("openraft-integration", file_log, ValueError, "not an owned directory"),
            "linked-member": ("openraft-integration", nested_link, ValueError, "symbolic link"),
            "frozen-log": ("openraft-integration", "pass", ValueError, "source contains a generated"),
        }
        for case, (name, script, error, message) in cases.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "run").mkdir()
                (root / "run/outside").mkdir()
                prepare = None
                if case == "frozen-log":
                    def prepare(source):
                        (source / OPENRAFT_LOG).mkdir()
                        (source / OPENRAFT_LOG / "ut.frozen").write_text("frozen input")
                gates = [(name, [sys.executable, "-c", script]),
                         ("later", [sys.executable, "-c", "open('dispatched', 'w').close()"])]
                with self.assertRaisesRegex(error, message):
                    self.dispatch(root, gates, prepare)
                output = root / "run"
                self.assertFalse((output / "later.log").exists())
                self.assertFalse((output / "source/dispatched").exists())
                evidence = json.loads((output / "evidence.json").read_text())
                self.assertEqual(evidence["status"], "failed")
                self.assertIn(message, evidence["runner_error"])
                self.assertEqual([gate["name"] for gate in evidence["gates"]],
                                 [] if case == "frozen-log" else [name])
                self.assertEqual(os.listdir(output / "outside"), [])
                if case in {"other-gate-log", "linked-log", "file-log"}:
                    self.assertTrue(os.path.lexists(output / "source" / OPENRAFT_LOG))
                    self.assertFalse((output / "generated").exists())
                if case in {"extra-file", "linked-member"}:
                    self.assertTrue((output / "generated/openraft-integration/_log/ut.2026-09-27-00").is_file())
                    self.assertFalse(os.path.lexists(output / "source" / OPENRAFT_LOG))

    def test_sigterm_during_openraft_integration_leaves_drained_receipt_and_interrupted_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
            command = [sys.executable, "-c", WRITE_OPENRAFT_LOG + "; import os, signal, time; "
                       "os.kill(os.getppid(), signal.SIGTERM); time.sleep(30)"]
            gates = [("openraft-integration", command),
                     ("later", [sys.executable, "-c", "open('dispatched', 'w').close()"])]
            with self.assertRaisesRegex(KeyboardInterrupt, "cancelled after owned gate cleanup"):
                self.dispatch(Path(temporary), gates)
            output = Path(temporary) / "run"
            self.assertEqual(previous, {number: signal.getsignal(number) for number in previous})
            evidence = json.loads((output / "evidence.json").read_text())
            self.assertEqual(evidence["status"], "interrupted")
            gate, = evidence["gates"]
            self.assertEqual(gate["received_signals"], [signal.SIGTERM])
            self.assertEqual(gate["exit_code"], 128 + signal.SIGTERM)
            receipt = json.loads((output / gate["process"]).read_text())
            self.assertEqual(release_gate.sha256(output / gate["process"]), gate["process_sha256"])
            self.assertEqual(receipt["status"], "failed")
            self.assertTrue(receipt["cleanup"]["drained"])
            self.assertEqual(receipt["cleanup"]["after"], [])
            self.assertEqual(receipt["cleanup"]["errors"], [])
            self.assertEqual(release_gate.gate_process.group_members(receipt["process_group"]), [])
            self.assertEqual(len(gate["generated_outputs"]), 1)
            self.assertTrue((output / "generated/openraft-integration/_log/ut.2026-09-27-00").is_file())
            self.assertFalse((output / "later.log").exists())
            self.assertFalse((output / "source/dispatched").exists())

    def test_superseded_linux_gate_script_is_absent_and_unreferenced(self):
        repository = Path(__file__).resolve().parent.parent
        name = "validate_linux" + ".sh"
        self.assertFalse(os.path.lexists(repository / "scripts" / name))
        # Retained historical evidence records the commands that actually ran.
        # The ignored root output archive also contains historical source copies;
        # nested source directories named output remain subject to this check.
        historical = {"docs/evidence", "benchmarks/results", "output"}
        skipped = {".git", "target", "tmp", "vendor", "__pycache__"}
        referencing = []
        for directory, children, files in os.walk(repository):
            relative = Path(directory).relative_to(repository).as_posix()
            prefix = "" if relative == "." else relative + "/"
            children[:] = [child for child in children
                           if child not in skipped and prefix + child not in historical]
            for file in files:
                path = Path(directory) / file
                if path.is_file() and not path.is_symlink() and name.encode() in path.read_bytes():
                    referencing.append(prefix + file)
        self.assertEqual(referencing, [])

    def test_dispatch_retains_selected_executable_and_its_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command = [sys.executable, "-c", "pass"]
            result = release_gate.run_gate("identity", command, root, root, os.environ.copy())
            receipt = json.loads((root / result["process"]).read_text())
            self.assertEqual(receipt["executable"], {"path": os.path.abspath(sys.executable),
                                                    "sha256": release_gate.sha256(sys.executable)})
            self.assertEqual(result["exit_code"], 0)

    def test_child_path_is_resolved_once_from_its_working_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "bin").mkdir()
            interpreter = root / "bin/fixture-python"
            interpreter.symlink_to(sys.executable)
            environment = {**os.environ, "PATH": "bin"}
            result = release_gate.run_gate("relative-path", ["fixture-python", "-c", "pass"],
                                           root, root, environment)
            receipt = json.loads((root / result["process"]).read_text())
            self.assertEqual(receipt["executable"]["path"], str(root.resolve() / "bin/fixture-python"))
            self.assertEqual(receipt["executable"]["sha256"], release_gate.sha256(sys.executable))
            self.assertEqual(result["exit_code"], 0)

    def test_executable_substitution_after_dispatch_cannot_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identity = release_gate.gate_process.executable_identity
            count = 0

            def replaced(*args):
                nonlocal count
                count += 1
                result = identity(*args)
                if count == 2:
                    result["sha256"] = "0" * 64
                return result

            with patch.object(release_gate.gate_process, "executable_identity", replaced):
                result = release_gate.run_gate("changed-executable", [sys.executable, "-c", "pass"],
                                               root, root, os.environ.copy())
            self.assertEqual(result["exit_code"], 125)
            self.assertTrue(result["process_cleanup"]["drained"])
            self.assertIn("executable changed", result["process_error"])

    def test_child_oom_counters_survive_failed_gate_without_claiming_private_peak(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cgroups = root / "cgroups"
            child = cgroups / "owned"
            child.mkdir(parents=True)
            membership = root / "membership"
            membership.write_text("0::/owned\n")
            events = child / "memory.events"
            events.write_text("oom 0\noom_kill 0\n")
            (child / "memory.peak").write_text("1234\n")
            (cgroups / "memory.events").write_text("oom 9\noom_kill 3\n")
            observe = release_gate.memory_observation
            command = [sys.executable, "-c", "from pathlib import Path; import sys; Path(" + repr(str(events))
                       + ").write_text('oom 1\\noom_kill 1\\n'); sys.exit(7)"]
            with patch.object(release_gate, "memory_observation", lambda: observe(membership, cgroups)):
                result = release_gate.run_gate("child-oom", command, root, root, os.environ.copy())
            self.assertEqual(result["exit_code"], 7)
            resources = root / result["resources"]
            self.assertEqual(release_gate.sha256(resources), result["resources_sha256"])
            report = json.loads(resources.read_text())
            self.assertEqual(report["before"]["cgroups"][str(child)]["memory.events"], "oom 0\noom_kill 0\n")
            self.assertEqual(report["after"]["cgroups"][str(child)]["memory.events"], "oom 1\noom_kill 1\n")
            self.assertEqual(report["after"]["cgroups"][str(cgroups)]["memory.events"], "oom 9\noom_kill 3\n")
            missing = observe(root / "missing", cgroups)
            self.assertFalse(missing["available"])
            self.assertTrue(missing["errors"])

    def test_compiled_fixture_or_test_artifact_cannot_pass_production_driver(self):
        command = dict(release_gate.functional_gates(2, sys.executable))["network-driver"]
        self.assertNotIn("--bins", command)
        self.assertEqual([command[i + 1] for i, value in enumerate(command) if value == "--bin"],
                         ["kasumi-bench-network", "kasumi-bench-capacity"])
        for violation in ("test-utils", "embedded-fixture", "loopback-fixture", "test-artifact", "missing-inventory"):
            with self.subTest(violation=violation):
                result = {"exit_code": 0,
                          "executables": {"release/kasumi-bench-network": {
                              "target": "kasumi-bench-network", "test": violation == "test-artifact"},
                              "release/kasumi-bench-capacity": {"target": "kasumi-bench-capacity", "test": False}},
                          "compiled_packages": {"dependency": {"features": [violation]}}}
                if violation == "missing-inventory":
                    result["compiled_packages"] = {}
                release_gate.validate_production_artifacts("network-driver", result)
                self.assertEqual(result["exit_code"], 1)

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

    def test_compiler_artifact_parser_bounds_lines_and_rejects_ambiguous_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "cargo.log"
            log.write_bytes(b"x" * 129 + b"\n")
            with patch.object(release_gate, "MAX_CARGO_LOG_LINE_BYTES", 128):
                with self.assertRaisesRegex(ValueError, "oversized Cargo gate log line"):
                    list(release_gate.compiler_artifact_messages(log))
            log.write_bytes(b'{"reason":"compiler-artifact","reason":"compiler-artifact"}\n')
            with self.assertRaisesRegex(ValueError, "malformed JSON-looking"):
                list(release_gate.compiler_artifact_messages(log))
            log.write_bytes(b'{"reason":"compiler\\u002dartifact","executable":null}\n')
            self.assertEqual(len(list(release_gate.compiler_artifact_messages(log))), 1)

    def test_runner_records_escaped_reason_and_rejects_duplicate_executable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target").mkdir()
            executable = root / "target" / "compiled-test"
            executable.write_bytes(b"compiled test")
            message = {"reason": "compiler-artifact", "executable": str(executable),
                       "target": {"name": "compiled-test", "kind": ["test"],
                                  "crate_types": ["bin"]}, "profile": {"test": True},
                       "features": [],
                       "package_id": "synthetic:compiled-test"}
            encoded = json.dumps(message).replace("compiler-artifact", "compiler\\u002dartifact")
            command = [sys.executable, "-c", "print(" + repr(encoded) + ")"]
            result = release_gate.run_gate("escaped", command, root, root, os.environ.copy())
            self.assertIn("compiled-test", result["executables"])
            command = [sys.executable, "-c", "print(" + repr(encoded) + "); print(" + repr(encoded) + ")"]
            with self.assertRaisesRegex(ValueError, "duplicate compiler-artifact"):
                release_gate.run_gate("duplicate", command, root, root, os.environ.copy())
            self.assertTrue((root / "duplicate-process.json").is_file())

    def test_failed_gate_retains_log_and_exact_executable_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "target").mkdir()
            executable = root / "target" / "tested-artifact"
            executable.write_bytes(b"exact compiled artifact")
            message = {"reason": "compiler-artifact", "executable": str(executable),
                       "target": {"name": "test", "kind": ["test"],
                                  "crate_types": ["bin"]}, "profile": {"test": True},
                       "features": [], "package_id": "example"}
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

    def test_compiler_artifact_package_metadata_is_typed_before_custody(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            message = {"reason": "compiler-artifact", "package_id": "fixture",
                       "executable": None, "features": "test-utils",
                       "target": {"name": "fixture", "kind": ["lib"],
                                  "crate_types": ["lib"]}}
            command = [sys.executable, "-c", "print(" + repr(json.dumps(message)) + ")"]
            with self.assertRaisesRegex(ValueError, "package metadata is malformed"):
                release_gate.run_gate("malformed-features", command, root, root, os.environ.copy())

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

    def test_uncertain_cleanup_stops_before_parsing_or_hashing_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = {"reason": "compiler-artifact", "executable": str(root / "unowned")}
            command = [sys.executable, "-c", "print(" + repr(json.dumps(artifact)) + ")"]
            uncertain = {"group": 123, "before": None, "after": None, "signals": [],
                         "errors": ["group cleanup denied"], "drained": False,
                         "process_returncode": 0}
            with patch("gate_process.drain", return_value=uncertain):
                with self.assertRaisesRegex(RuntimeError, "logs and artifacts remain unverified") as raised:
                    release_gate.run_gate("cleanup-error", command, root, root, os.environ.copy())
            self.assertTrue(any("cleanup denied" in note for note in raised.exception.__notes__))
            self.assertTrue((root / "cleanup-error.log").is_file())
            receipt = json.loads((root / "cleanup-error-process.json").read_text())
            self.assertEqual(receipt["status"], "failed")
            self.assertFalse(receipt["cleanup"]["drained"])
            self.assertFalse(receipt["outputs_stable"])

    def test_silent_command_times_out_and_retains_exact_owned_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command = [sys.executable, "-c", "import time; time.sleep(30)"]
            result = release_gate.run_gate("silent", command, root, root, os.environ.copy(), .15)
            self.assertEqual(result["exit_code"], 124)
            self.assertTrue(result["timed_out"])
            self.assertTrue(result["process_cleanup"]["drained"])
            receipt = json.loads((root / result["process"]).read_text())
            self.assertEqual(receipt["command"], command)
            self.assertEqual(receipt["timeout_seconds"], .15)
            self.assertEqual(receipt["process_group"], result["process_cleanup"]["group"])
            self.assertEqual(release_gate.sha256(root / result["process"]), result["process_sha256"])

    def test_successful_leader_cannot_hide_a_surviving_child(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command = [sys.executable, "-c",
                       "import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'])"]
            result = release_gate.run_gate("orphan", command, root, root, os.environ.copy(), 5)
            self.assertEqual(result["exit_code"], 125)
            self.assertTrue(result["process_cleanup"]["before"])
            self.assertEqual(result["process_cleanup"]["after"], [])
            self.assertTrue(result["process_cleanup"]["drained"])

    def test_repeated_signals_drain_before_restoring_original_handlers(self):
        import signal
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
            command = [sys.executable, "-c",
                       "import os,signal,time; os.kill(os.getppid(),signal.SIGTERM); "
                       "os.kill(os.getppid(),signal.SIGINT); time.sleep(30)"]
            result = release_gate.run_gate("cancel", command, root, root, os.environ.copy(), 5)
            self.assertNotEqual(result["exit_code"], 0)
            self.assertIn(signal.SIGTERM, result["received_signals"])
            self.assertIn(signal.SIGINT, result["received_signals"])
            self.assertTrue(result["process_cleanup"]["drained"])
            self.assertEqual(previous, {number: signal.getsignal(number) for number in previous})

    def test_missing_process_inventory_still_terminates_live_owned_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command = [sys.executable, "-c", "import time; time.sleep(30)"]
            with patch("gate_process.group_members", side_effect=OSError("process inventory unavailable")):
                with self.assertRaisesRegex(RuntimeError, "process custody is uncertain"):
                    release_gate.run_gate("uncertain", command, root, root, os.environ.copy(), .15)
            receipt = json.loads((root / "uncertain-process.json").read_text())
            self.assertEqual(receipt["exit_code"], 124)
            self.assertFalse(receipt["cleanup"]["drained"])
            self.assertIsNone(receipt["cleanup"]["after"])
            self.assertTrue(receipt["cleanup"]["errors"])
            self.assertIn("SIGTERM", receipt["cleanup"]["signals"])
            self.assertIsNotNone(receipt["cleanup"]["process_returncode"])
            self.assertEqual(release_gate.gate_process.group_members(receipt["process_group"]), [])

    def test_signal_before_popen_returns_cannot_lose_the_new_process_owner(self):
        import signal
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = release_gate.gate_process.subprocess.Popen
            owned = []

            def interrupted_launch(*args, **kwargs):
                child = original(*args, **kwargs)
                owned.append(child)
                signal.raise_signal(signal.SIGTERM)
                return child

            command = [sys.executable, "-c", "import time; time.sleep(30)"]
            # Patch only the first launch; inspection's ps subprocesses must
            # not send signals or become part of the tested ownership boundary.
            def launch_once(*args, **kwargs):
                return original(*args, **kwargs) if owned else interrupted_launch(*args, **kwargs)

            with patch("gate_process.subprocess.Popen", side_effect=launch_once):
                result = release_gate.run_gate("launch-cancel", command, root, root, os.environ.copy(), 5)
            self.assertEqual(result["received_signals"], [signal.SIGTERM])
            self.assertTrue(result["process_cleanup"]["drained"])
            self.assertIsNotNone(owned[0].poll())

    def test_executing_runner_and_helper_must_match_the_frozen_repository(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            (source / "scripts").mkdir()
            for relative, original in (("release_gate.py", release_gate.__file__),
                                       ("gate_process.py", release_gate.gate_process.__file__)):
                (source / "scripts" / relative).write_bytes(Path(original).read_bytes())
            inputs = release_gate.verify_runner_inputs(source)
            self.assertEqual(set(inputs), {"scripts/release_gate.py", "scripts/gate_process.py"})
            helper = source / "scripts/gate_process.py"
            helper.write_bytes(helper.read_bytes() + b"\n# Different frozen input\n")
            with self.assertRaisesRegex(ValueError, "executing release tool differs"):
                release_gate.verify_runner_inputs(source)

    def test_delayed_observation_cannot_accept_a_completion_after_original_deadline(self):
        import time
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def observe(record):
                if record["status"] == "running" and record["process_group"] is not None:
                    time.sleep(.1)

            with (root / "delayed.log").open("wb") as stream:
                result = release_gate.gate_process.run([sys.executable, "-c", "pass"], root,
                                                       os.environ.copy(), stream, .05, observe,
                                                       stderr=subprocess.STDOUT)
            self.assertEqual(result["exit_code"], 124)
            self.assertTrue(result["timed_out"])
            self.assertTrue(result["cleanup"]["drained"], result["cleanup"])

    def test_signal_permission_race_requires_reaped_leader_and_empty_group(self):
        zombie = [{"pid": 123, "ppid": 1, "group": 123, "state": "Z"}]
        for reaped, remaining in ((True, []), (True, zombie), (False, [])):
            with self.subTest(reaped=reaped, remaining=remaining):
                process = Mock(pid=123, returncode=None)
                polls = 0
                inventories = 0

                def poll():
                    nonlocal polls
                    polls += 1
                    if polls > 1 and reaped:
                        process.returncode = 0
                    return process.returncode

                def members(_group):
                    nonlocal inventories
                    inventories += 1
                    return zombie if inventories <= 2 else remaining

                process.poll.side_effect = poll
                with patch("gate_process.group_members", side_effect=members), \
                        patch("gate_process.os.killpg", side_effect=PermissionError(1, "Operation not permitted")):
                    result = release_gate.gate_process.drain(process, grace_seconds=0)
                self.assertEqual(result["drained"], reaped and remaining == [])
                self.assertEqual(bool(result["errors"]), not result["drained"])


NATIVE = release_gate.NATIVE_TARGETS.get((platform.system(), platform.machine()))
# Twenty-byte executable headers accepted by package_release.verify_architecture.
HEADERS = {"x86_64-unknown-linux-gnu": b"\x7fELF\x02\x01\x01" + bytes(9) + struct.pack("<HH", 2, 62),
           "aarch64-unknown-linux-gnu": b"\x7fELF\x02\x01\x01" + bytes(9) + struct.pack("<HH", 2, 183),
           "aarch64-apple-darwin": b"\xcf\xfa\xed\xfe" + struct.pack("<I", 0x100000C) + bytes(12)}
# A stand-in Cargo: it emits the compiler-artifact transcript and outputs that
# the real gates would, so the whole journaled launcher, runner and attempt
# journal run for real. No Rust code is compiled; this is not release evidence.
FAKE_CARGO = """import json, os, signal, sys, time
from pathlib import Path
args = sys.argv[1:]
if os.environ.get("KASUMI_FAKE_FAIL") in args:
    print("fixture gate failure", flush=True)
    sys.exit(3)
if os.environ.get("KASUMI_FAKE_SIGNAL") in args:
    os.kill(int(os.environ["KASUMI_FAKE_SIGNAL_PID"]), signal.SIGTERM)
    time.sleep(30)
target = Path(os.environ["CARGO_TARGET_DIR"])
def emit(package, name):
    path = target / "release" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(HEADER + name.encode())
    path.chmod(0o755)
    print(json.dumps({"reason": "compiler-artifact", "package_id": "path+file:///fixture/" + package + "#0.1.0",
                      "target": {"name": name, "kind": ["bin"], "crate_types": ["bin"]},
                      "profile": {"test": False}, "features": [], "executable": str(path), "fresh": False}))
if "life_cycle" in args:
    log = Path("vendor/openraft-0.9.25/tests/_log")
    log.mkdir()
    (log / "ut.fixture").write_text("fixture trace\\n")
if "build" in args and "kasumi-server" in args:
    for name in ("kasumid", "kasumictl", "kasumi-authority"):
        emit("kasumi-server", name)
if "build" in args and "kasumi-bench" in args:
    for name in ("kasumi-bench-network", "kasumi-bench-capacity"):
        emit("kasumi-bench", name)
if "tree" in args:
    print("kasumi-server v0.1.0 default")
"""


class JournaledFunctionalRunTests(unittest.TestCase):
    """The primary functional attempt end to end, against a stand-in toolchain."""

    def setUp(self):
        if NATIVE is None:
            self.skipTest("no native release target on this host")
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.repository = self.base / "repository"
        scripts = self.repository / "scripts"
        scripts.mkdir(parents=True)
        for module in (release_gate, release_gate.gate_process, attempt_index):
            shutil.copyfile(module.__file__, scripts / Path(module.__file__).name)
        (scripts / "test_fixture.py").write_text(
            "import unittest\n\nclass Fixture(unittest.TestCase):\n    def test_passes(self):\n        pass\n")
        (scripts / "check_dependency_patches.py").write_text("print('fixture patches checked')\n")
        (self.repository / "Cargo.lock").write_text("# fixture lockfile\n")
        (self.repository / "vendor/openraft-0.9.25/tests").mkdir(parents=True)
        (self.repository / "vendor/openraft-0.9.25/tests/Cargo.toml").write_text("[package]\nname = \"tests\"\n")
        git = ["git", "-C", str(self.repository)]
        subprocess.run(["git", "init", "-q", str(self.repository)], check=True)
        subprocess.run(git + ["add", "."], check=True)
        subprocess.run(git + ["-c", "user.name=test", "-c", "user.email=test@invalid", "commit", "-qm", "fixture"],
                       check=True)
        tools = self.base / "toolchain"
        tools.mkdir()
        for name, program in (("cargo", "HEADER = " + repr(HEADERS[NATIVE]) + "\n" + FAKE_CARGO),
                              ("rustc", "print('rustc 1.97.1 (fixture)\\nhost: " + NATIVE + "')\n")):
            (tools / name).write_text("#!" + sys.executable + "\n" + program)
            (tools / name).chmod(0o755)
        self.root = self.base / "custody"
        self.root.mkdir()
        attempt_index.create(self.root, "journal-unit", "host-unit", NATIVE)
        environment = {key: value for key, value in os.environ.items()
                       if key != release_gate.gate_process.GROUP_LEDGER_ENV}
        environment["PATH"] = str(tools) + os.pathsep + os.environ.get("PATH", os.defpath)
        self.environment = environment

    def launch(self, *extra, journaled=True, output=None, **variables):
        arguments = ["--repository", str(self.repository), "--output", str(output or self.root / "run"),
                     "--execution-description", "stand-in toolchain unit run", "--jobs", "1",
                     "--gate-timeout-seconds", "60", *extra]
        if journaled:
            arguments += ["--attempt-root", str(self.root), "--attempt-id", "functional-1"]
        with patch.dict(os.environ, {**self.environment, **variables}, clear=True), \
                contextlib.redirect_stdout(io.StringIO()):
            return release_gate.main(arguments)

    def attempt(self):
        receipt = attempt_index.file_ref(self.root, self.root / "attempts/functional-1/attempt.json")
        record = json.loads((self.root / receipt["path"]).read_bytes())
        outcome = json.loads((self.root / record["evidence"]["path"]).read_bytes())
        return receipt, record, outcome

    def verify(self, selected=None):
        import verify_release_acceptance as acceptance

        receipt, _, _ = self.attempt()
        acceptance.verify_attempts(self.root, [{"id": "functional-1", "receipt": receipt}], selected or {},
                                   head=attempt_index.head(self.root), original_root=str(self.root))

    def test_passed_attempt_binds_original_evidence_products_and_runner_custody(self):
        import package_release

        self.assertEqual(self.launch(), 0)
        output = self.root / "run"
        receipt, record, outcome = self.attempt()
        self.assertEqual(record["status"], "passed")
        self.assertEqual(record["evidence"]["path"], "run/outcome.json")
        self.assertEqual((outcome["status"], outcome["dispatch_started"], outcome["error"],
                          outcome["functional_status"], outcome["target"]),
                         ("passed", True, None, "passed", NATIVE))
        self.assertEqual({item["id"]: item["file"]["path"] for item in outcome["products"]},
                         release_gate.FUNCTIONAL_PRODUCTS)
        # The original evidence is the qualification record, unchanged since.
        self.assertEqual(outcome["build_evidence"], attempt_index.file_ref(output, output / "evidence.json"))
        evidence = json.loads((output / "evidence.json").read_bytes())
        self.assertEqual((evidence["status"], evidence["dispatch_started"], evidence["attempt"]["id"],
                          evidence["started_at"]), ("passed", True, "functional-1", record["started_at"]))
        self.assertEqual(len(evidence["gates"]), 22)
        self.assertEqual(evidence["journal_inputs"], {"scripts/attempt_index.py": release_gate.sha256(
            self.repository / "scripts/attempt_index.py")})
        # One owned runner: the frozen script under the retained interpreter.
        runner, = record["processes"]
        process = json.loads((self.root / runner["receipt"]["path"]).read_bytes())
        self.assertEqual(process["command"][0], process["executable"]["path"])
        self.assertEqual(process["command"][1:], ["-B", "-S", str(output / "source/scripts/release_gate.py"),
                                                  release_gate.PREPARED_COMMAND, "--output", str(output)])
        self.assertEqual(runner["executable"]["path"], "run/tools/python")
        self.assertEqual(runner["executable"]["sha256"], process["executable"]["sha256"])
        census = json.loads((output / "runner/gate-census.json").read_bytes())
        self.assertTrue(census["complete"])
        self.assertEqual([item["receipt"] for item in census["groups"] if item["drained_by_runner"]],
                         sorted(gate["process"] for gate in evidence["gates"]))
        self.assertEqual(process["gate_census"]["path"], "runner/gate-census.json")
        # The verifier's own checks: drained runner custody, the selected
        # build's products beside evidence.json, and the functional contract.
        self.verify({"run/evidence.json": "functional"})
        _, _, host, binaries = package_release.verify_evidence(output)
        self.assertEqual((host, set(binaries)), (NATIVE, set(release_gate.PRODUCTION_BINARIES)))
        # A second admission of the same id is refused before writing, and a
        # development run cannot reuse the attempt's output.
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            self.launch(output=self.root / "second")
        with self.assertRaises(FileExistsError):
            self.launch(journaled=False, output=output)
        self.assertFalse((self.root / "second").exists())
        self.assertEqual(list(attempt_index.replay(self.root)), ["functional-1"])

    def test_failed_gate_is_retained_and_cannot_be_selected(self):
        self.assertEqual(self.launch(KASUMI_FAKE_FAIL="--doc"), 1)
        _, record, outcome = self.attempt()
        self.assertEqual((record["status"], outcome["functional_status"]), ("failed", "failed"))
        self.assertIn("functional evidence status is failed", outcome["error"])
        evidence = json.loads((self.root / "run/evidence.json").read_bytes())
        self.assertEqual([gate["name"] for gate in evidence["gates"] if gate["exit_code"]], ["workspace-docs"])
        # Later gates still ran; their retained outputs stay named and hashed.
        self.assertEqual({item["id"] for item in outcome["products"]}, set(release_gate.FUNCTIONAL_PRODUCTS))
        self.assertEqual(outcome["build_evidence"]["sha256"], release_gate.sha256(self.root / "run/evidence.json"))
        self.verify()
        with self.assertRaisesRegex(ValueError, "selected attempt failed"):
            self.verify({"run/evidence.json": "functional"})

    def test_pre_dispatch_failure_retains_evidence_without_child_custody(self):
        with patch.object(release_gate, "verify_export", side_effect=ValueError("fixture export mismatch")):
            self.assertEqual(self.launch(), 1)
        _, record, outcome = self.attempt()
        self.assertEqual((record["status"], record["processes"], outcome["dispatch_started"]), ("failed", [], False))
        self.assertIn("fixture export mismatch", outcome["error"])
        evidence = json.loads((self.root / "run/evidence.json").read_bytes())
        self.assertEqual((evidence["status"], evidence["dispatch_started"], evidence["gates"]), ("failed", False, []))
        self.assertIn("fixture export mismatch", evidence["runner_error"])
        self.assertFalse((self.root / "run/runner").exists())
        self.assertEqual({item["id"] for item in outcome["products"]}, {"source-archive"})
        self.verify()

    def test_sigterm_drains_runner_and_terminates_an_interrupted_attempt(self):
        previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
        self.assertEqual(self.launch(KASUMI_FAKE_SIGNAL="--doc", KASUMI_FAKE_SIGNAL_PID=str(os.getpid())), 130)
        self.assertEqual(previous, {number: signal.getsignal(number) for number in previous})
        _, record, outcome = self.attempt()
        self.assertEqual((record["status"], outcome["functional_status"], outcome["dispatch_started"]),
                         ("interrupted", "interrupted", True))
        process = json.loads((self.root / record["processes"][0]["receipt"]["path"]).read_bytes())
        self.assertEqual(process["received_signals"], [signal.SIGTERM])
        self.assertTrue(process["outputs_stable"] and process["cleanup"]["drained"])
        evidence = json.loads((self.root / "run/evidence.json").read_bytes())
        self.assertEqual(evidence["gates"][-1]["name"], "workspace-docs")
        self.assertEqual(evidence["gates"][-1]["received_signals"], [signal.SIGTERM])
        census = json.loads((self.root / "run/runner/gate-census.json").read_bytes())
        self.assertTrue(census["complete"])
        # The interrupted gate itself still ran with deliverable signals.
        gate = json.loads((self.root / "run/workspace-docs-process.json").read_bytes())
        self.assertEqual((gate["cleanup"]["signals"], gate["cleanup"]["drained"]), (["SIGTERM"], True))
        self.verify()

    def test_refusals_before_admission_write_nothing(self):
        head = attempt_index.head(self.root)
        cases = {"partial": ["--attempt-root", str(self.root)],
                 "outside": ["--attempt-root", str(self.root), "--attempt-id", "functional-1"]}
        for case, extra in cases.items():
            output = self.base / "elsewhere" if case == "outside" else self.root / "run"
            with self.subTest(case=case), self.assertRaises(SystemExit), \
                    contextlib.redirect_stderr(io.StringIO()):
                self.launch(*extra, journaled=False, output=output)
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            self.launch(**{release_gate.gate_process.GROUP_LEDGER_ENV: str(self.base / "ledger")})
        other = self.base / "other-target"
        other.mkdir()
        foreign = next(target for target in sorted(attempt_index.TARGETS) if target != NATIVE)
        attempt_index.create(other, "journal-other", "host-unit", foreign)
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()) as error:
            self.launch("--attempt-root", str(other), "--attempt-id", "functional-1",
                        journaled=False, output=other / "run")
        self.assertIn("not this native host", error.getvalue())
        self.assertFalse((self.root / "run").exists() or (other / "run").exists())
        self.assertEqual(attempt_index.head(self.root), head)

    def test_development_run_stays_unjournaled(self):
        import package_release

        output = self.base / "development"
        self.assertEqual(self.launch(journaled=False, output=output), 0)
        self.assertFalse((output / "outcome.json").exists() or (output / "runner").exists())
        record, _, host, _ = package_release.verify_evidence(output)
        self.assertNotIn("attempt", record)
        self.assertEqual(host, NATIVE)
        self.assertEqual(attempt_index.head(self.root)["sequence"], 1)

    def test_runner_refuses_an_unprepared_run_without_rewriting_it(self):
        output = self.base / "development"
        self.assertEqual(self.launch(journaled=False, output=output), 0)
        before = release_gate.sha256(output / "evidence.json")
        with patch.dict(os.environ, {release_gate.RUNNER_ENV: "functional-1"}), \
                self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            release_gate.main([release_gate.PREPARED_COMMAND, "--output", str(output)])
        self.assertEqual(release_gate.sha256(output / "evidence.json"), before)


class GroupLedgerSpawnTests(unittest.TestCase):
    """A ledgered spawn stays atomic without handing the child a blocked signal mask.

    Every child here is a real, benign Python process; nothing is mocked
    between the owner and the kernel except where a signal is injected.
    """

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.ledger = self.root / "groups.jsonl"
        self.ledger.touch()

    def mask(self):
        return {int(number) for number in signal.pthread_sigmask(signal.SIG_BLOCK, [])}

    def run_ledgered(self, program, timeout):
        before = self.mask()
        log = self.root / "child.log"
        with patch.dict(os.environ, {release_gate.gate_process.GROUP_LEDGER_ENV: str(self.ledger)}), \
                log.open("wb") as stream:
            record = release_gate.gate_process.run([sys.executable, "-c", program], self.root, dict(os.environ),
                                                   stream, timeout, lambda value: None,
                                                   stderr=subprocess.STDOUT)
        self.assertEqual(self.mask(), before)
        rows, closed = release_gate.gate_process.read_group_ledger(self.ledger)
        self.assertFalse(closed)
        self.assertEqual([(row["group"], row["leader_birth"]) for row in rows],
                         [(record["process_group"], record["leader_birth"])])
        self.assertTrue(record["cleanup"]["drained"])
        self.assertEqual(record["cleanup"]["after"], [])
        return record, log.read_text()

    def test_ledgered_child_receives_sigint_and_sigterm_through_its_own_handlers(self):
        program = ("import os, signal, sys, time\n"
                   "blocked = sorted(int(s) for s in signal.pthread_sigmask(signal.SIG_BLOCK, []))\n"
                   "print('blocked', blocked, flush=True)\n"
                   "seen = []\n"
                   "for number in (signal.SIGINT, signal.SIGTERM):\n"
                   "    signal.signal(number, lambda n, _f: seen.append(n))\n"
                   "    os.kill(os.getpid(), number)\n"
                   "deadline = time.monotonic() + 5\n"
                   "while len(seen) < 2 and time.monotonic() < deadline:\n"
                   "    time.sleep(.01)\n"
                   "print('seen', sorted(seen), flush=True)\n"
                   "sys.exit(0 if sorted(seen) == [2, 15] else 9)\n")
        record, log = self.run_ledgered(program, 30)
        self.assertEqual((record["exit_code"], record["status"]), (0, "passed"), log)
        blocked = json.loads(log.splitlines()[0].split(" ", 1)[1])
        self.assertNotIn(signal.SIGINT, blocked)
        self.assertNotIn(signal.SIGTERM, blocked)
        self.assertIn("seen [2, 15]", log)
        self.assertEqual(record["cleanup"]["signals"], [])

    def test_ledgered_child_is_stopped_by_sigterm_alone(self):
        record, _ = self.run_ledgered("import time\ntime.sleep(30)\n", 1)
        self.assertTrue(record["timed_out"])
        # A blocked SIGTERM would wait out drain's grace and need SIGKILL.
        self.assertEqual(record["cleanup"]["signals"], ["SIGTERM"])
        self.assertEqual(record["cleanup"]["process_returncode"], -signal.SIGTERM)
        self.assertLess(record["duration_seconds"], 1 + 8)

    def test_signal_during_ledgered_admission_still_registers_and_drains_the_group(self):
        identity = release_gate.gate_process.leader_identity
        injected = []

        def interrupted_admission(pid, **options):
            # Between Popen and the group row, under the ledger lock.
            witness = identity(pid, **options)
            if not injected:
                injected.append(pid)
                signal.raise_signal(signal.SIGTERM)
            return witness

        previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
        with patch.object(release_gate.gate_process, "leader_identity", interrupted_admission):
            record, _ = self.run_ledgered("import time\ntime.sleep(30)\n", 30)
        self.assertEqual(previous, {number: signal.getsignal(number) for number in previous})
        self.assertEqual(injected, [record["process_group"]])
        self.assertEqual(record["received_signals"], [signal.SIGTERM])
        self.assertEqual(record["exit_code"], 128 + signal.SIGTERM)
        self.assertEqual(record["cleanup"]["signals"], ["SIGTERM"])
        self.assertEqual(record["cleanup"]["process_returncode"], -signal.SIGTERM)

    def test_sealed_ledger_still_refuses_the_spawn(self):
        release_gate.gate_process.seal_group_ledger(self.ledger)
        with patch.dict(os.environ, {release_gate.gate_process.GROUP_LEDGER_ENV: str(self.ledger)}), \
                (self.root / "late.log").open("wb") as stream:
            record = release_gate.gate_process.run([sys.executable, "-c", "open('spawned', 'w').close()"],
                                                   self.root, dict(os.environ), stream, 30, lambda value: None,
                                                   stderr=subprocess.STDOUT)
        self.assertIsNone(record["process_group"])
        self.assertIn("admission is closed", record["error"])
        self.assertFalse((self.root / "spawned").exists())
        self.assertEqual(release_gate.gate_process.read_group_ledger(self.ledger), ([{"schema": 1, "kind": "closed"}], True))


class GateGroupCensusTests(unittest.TestCase):
    def orphan(self):
        """A sleeping new-session process whose parent has exited, as after a killed runner."""
        program = ("import subprocess, sys; child = subprocess.Popen([sys.executable, '-c', "
                   "'import time; time.sleep(30)'], start_new_session=True, stdin=subprocess.DEVNULL, "
                   "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); print(child.pid)")
        pid = int(subprocess.run([sys.executable, "-c", program], check=True, capture_output=True,
                                 text=True).stdout)

        def kill():
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(pid, signal.SIGKILL)
        self.addCleanup(kill)
        return pid

    def receipt(self, root, name, group, birth, cleanup=None):
        release_gate.write_json(root / (name + "-process.json"), {
            "status": "running", "process_group": group, "leader_birth": birth, "cleanup": cleanup})

    def test_undrained_gate_group_is_terminated_and_fails_the_census(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pid = self.orphan()
            self.receipt(root, "workspace", pid, release_gate.gate_process.leader_identity(pid)["birth"])
            with self.assertRaisesRegex(RuntimeError, "outlived their runner"):
                release_gate.census_gate_groups(root, root / "census.json")
            group, = json.loads((root / "census.json").read_text())["groups"]
            self.assertEqual((group["receipt"], group["signals"][:1], group["after"]),
                             ("workspace-process.json", ["SIGTERM"], []))

    def test_changed_leader_is_never_signalled(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pid = self.orphan()
            self.receipt(root, "workspace", pid, "linux:0" if sys.platform.startswith("linux") else "darwin:0:0")
            with self.assertRaisesRegex(RuntimeError, "could not be inspected"):
                release_gate.census_gate_groups(root, root / "census.json")
            group, = json.loads((root / "census.json").read_text())["groups"]
            self.assertEqual(group["signals"], [])
            self.assertIn("leader is unavailable or changed", group["errors"][0])
            self.assertEqual(release_gate.gate_process.group_members(pid)[0]["pid"], pid)

    def test_drained_and_unspawned_gates_complete_the_census_without_inspection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pid = self.orphan()
            # A drained gate's numeric group may be reused by an unrelated live group.
            self.receipt(root, "format", pid, "darwin:0:0", {"drained": True, "after": []})
            self.receipt(root, "toolchain", None, None)
            census = release_gate.census_gate_groups(root, root / "census.json")
            self.assertTrue(census["complete"])
            self.assertEqual([(item["receipt"], item["before"]) for item in census["groups"]],
                             [("format-process.json", None), ("toolchain-process.json", None)])
            (root / "torn-process.json").write_text("{")
            with self.assertRaisesRegex(RuntimeError, "could not be inspected"):
                release_gate.census_gate_groups(root, root / "census.json")


class ReleaseWorkflowJournalTests(unittest.TestCase):
    def test_native_entrypoints_admit_the_primary_functional_attempt_to_one_journal(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/release-candidate.yml").read_text()
        self.assertIn("KASUMI_FUNCTIONAL_ATTEMPT_ID: functional-${{ matrix.target }}", workflow)
        self.assertIn("KASUMI_JOURNAL_ID: native-${{ matrix.target }}", workflow)
        self.assertIn('--env KASUMI_FUNCTIONAL_ATTEMPT_ID="$KASUMI_FUNCTIONAL_ATTEMPT_ID"', workflow)
        for root, output in (("/evidence", "/evidence/run"), ('"$KASUMI_RUN"', '"$KASUMI_RUN/run"')):
            with self.subTest(root=root):
                created = workflow.index("attempt_index.py create --root " + root)
                gate = workflow.index("release_gate.py", created)
                admitted = workflow.index("--attempt-root " + root + ' --attempt-id "$KASUMI_FUNCTIONAL_ATTEMPT_ID"',
                                          gate)
                assembly = workflow.index("run_repeatable_assembly_owned.py", admitted)
                self.assertIn("--output " + output, workflow[gate:admitted])
                self.assertIn("--attempt-root " + root, workflow[assembly:assembly + 400])
        self.assertEqual(workflow.count('--attempt-id "$KASUMI_FUNCTIONAL_ATTEMPT_ID"'), 2)
        self.assertIn("attempt_index.py head --root /evidence", workflow)
        self.assertIn("/evidence/run/outcome.json", workflow)
        self.assertIn("${{ runner.temp }}/${{ env.KASUMI_RUN_NAME }}/run/runner/**", workflow)


if __name__ == "__main__":
    unittest.main()
