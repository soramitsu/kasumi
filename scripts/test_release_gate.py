"""Counterexamples to provenance claims made by the functional gate runner."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import sys
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

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

    def test_roster_is_exactly_the_23_gates_with_openraft_custody_commands(self):
        gates = release_gate.functional_gates(3, "/native/python3")
        self.assertEqual([name for name, _ in gates], [
            "toolchain", "format", "python", "dependency-patches", "bitmaps", "lru",
            "serde-json-default", "serde-json-number", "serde-json-raw", "serde-json-combined",
            "rmcp-terminal-ownership", "rmcp-upstream-protocol", "openraft-units",
            "openraft-integration", "openraft-singlethreaded", "openraft-clippy", "workspace",
            "workspace-docs", "clippy", "network-features", "network-driver",
            "production-features", "production"])
        self.assertEqual(len(dict(gates)), 23)
        self.assertEqual([name for name, *_ in release_gate.VENDOR_SUITES],
                         [name for name, _ in gates[4:16]])
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
        historical = {"docs/evidence", "benchmarks/results"}
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


if __name__ == "__main__":
    unittest.main()
