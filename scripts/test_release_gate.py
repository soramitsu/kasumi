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
                                                       os.environ.copy(), stream, .05, observe)
            self.assertEqual(result["exit_code"], 124)
            self.assertTrue(result["timed_out"])
            self.assertTrue(result["cleanup"]["drained"])


if __name__ == "__main__":
    unittest.main()
