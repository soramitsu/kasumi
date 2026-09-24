"""Pure counterexamples for the native diagnostic; no sockets or Kasumi processes."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import small_native_smoke as smoke


class SmokeTests(unittest.TestCase):
    def evidence(self):
        return {"source_commit": "a" * 40, "source_tree": "b" * 40,
                "lockfile_sha256": "c" * 64, "toolchain": "1.97.1", "status": "failed",
                "finished_at": "2026-09-09T00:00:00+00:00",
                "gates": [{"name": gate, "exit_code": 0,
                           "compiled_packages": {"real-package": {"features": ["std"]}},
                           "executables": {"release/" + binary: {"target": binary, "test": False,
                                                               "sha256": "d" * 64}
                                           for binary, selected in smoke.BINARIES.items() if selected == gate}}
                          for gate in ("production", "network-driver")]}

    def validate(self, evidence):
        return smoke.validate_build_evidence(evidence, "a" * 40, "b" * 40, "c" * 64)

    def test_failed_workspace_may_supply_proven_builds_without_becoming_a_release_candidate(self):
        evidence = self.evidence()
        result = self.validate(evidence)
        self.assertEqual(set(result), set(smoke.BINARIES))
        self.assertEqual(evidence["status"], "failed")

    def test_build_provenance_rejects_unknown_features_tests_and_mismatched_sources(self):
        for bad in ("fixture", "missing-inventory", "test-binary", "source", "tree", "lock", "toolchain", "gate-failed", "hash"):
            with self.subTest(bad=bad):
                evidence = self.evidence()
                gate = evidence["gates"][0]
                if bad == "fixture":
                    gate["compiled_packages"]["real-package"]["features"].append("test-utils")
                elif bad == "missing-inventory":
                    gate["compiled_packages"] = {}
                elif bad == "test-binary":
                    gate["executables"]["release/kasumid"]["test"] = True
                elif bad == "source":
                    evidence["source_commit"] = "e" * 40
                elif bad == "tree":
                    evidence["source_tree"] = "e" * 40
                elif bad == "lock":
                    evidence["lockfile_sha256"] = "e" * 64
                elif bad == "toolchain":
                    evidence["toolchain"] = "stable"
                elif bad == "gate-failed":
                    gate["exit_code"] = 1
                else:
                    del gate["executables"]["release/kasumid"]["sha256"]
                with self.assertRaises(ValueError):
                    self.validate(evidence)

    def test_duplicate_gate_or_ambiguous_artifact_is_not_an_exact_build(self):
        evidence = self.evidence()
        evidence["gates"].append(copy.deepcopy(evidence["gates"][0]))
        with self.assertRaises(ValueError):
            self.validate(evidence)
        evidence = self.evidence()
        evidence["gates"][0]["executables"]["other/kasumid"] = copy.deepcopy(
            evidence["gates"][0]["executables"]["release/kasumid"])
        with self.assertRaises(ValueError):
            self.validate(evidence)

    def test_pending_or_unknown_build_outcome_cannot_supply_binary_evidence(self):
        for status in (None, "running", "interrupted", "unknown"):
            with self.subTest(status=status), self.assertRaises(ValueError):
                self.validate({**self.evidence(), "status": status})
        with self.assertRaises(ValueError):
            self.validate({**self.evidence(), "finished_at": None})

    def test_prepare_copies_only_exact_build_artifacts_and_preserves_failed_baseline(self):
        for changed in (False, True):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                incoming, output = root / "incoming", root / "output"
                incoming.mkdir()
                output.mkdir()
                lock = b"exact frozen lockfile"
                evidence = self.evidence()
                evidence["lockfile_sha256"] = hashlib.sha256(lock).hexdigest()
                for gate in evidence["gates"]:
                    for artifact in gate["executables"].values():
                        content = ("non-executable mock bytes for " + artifact["target"]).encode()
                        artifact["sha256"] = hashlib.sha256(content).hexdigest()
                        (incoming / artifact["target"]).write_bytes(content)
                if changed:
                    (incoming / "kasumid").write_bytes(b"another build")
                report = root / "build.json"
                report.write_text(json.dumps(evidence))
                runner = self.runner(output)
                runner.args.repository = root / "unused-repository"
                runner.args.source = "a" * 40
                runner.args.build_evidence = report
                runner.args.binaries = incoming
                def source_command(name, command):
                    argument = command[-1]
                    if argument == "a" * 40 + "^{commit}":
                        content = ("a" * 40 + "\n").encode()
                    elif argument == "a" * 40 + "^{tree}":
                        content = ("b" * 40 + "\n").encode()
                    elif argument == "a" * 40 + ":Cargo.lock":
                        content = lock
                    elif argument == "a" * 40 + ":benchmarks/capacity-collection.json":
                        content = b'{"name":"capacity"}'
                    else:
                        self.fail("unexpected source command")
                    path = output / (name + ".log")
                    path.write_bytes(content)
                    return path
                with patch.object(runner, "command", side_effect=source_command):
                    if changed:
                        with self.assertRaisesRegex(ValueError, "differs from its build evidence"):
                            runner.prepare()
                    else:
                        runner.prepare()
                        self.assertEqual(runner.record["build_overall_status"], "failed")
                        self.assertEqual((output / "provenance/build-evidence.json").read_bytes(), report.read_bytes())
                        for binary, path in runner.binaries.items():
                            self.assertEqual(path.parent, output / "binaries")
                            self.assertEqual(path.read_bytes(), (incoming / binary).read_bytes())
                            self.assertEqual(path.stat().st_mode & 0o777, 0o700)

    def test_independent_python_corpus_matches_published_rust_vectors(self):
        for ordinal, expected in [(0, "394fe15da12aa133d39dce92047bd3286962ba6d6136a0615b19d3f8565ac67a"),
                                  (999, "0f2ce61facf68acfb2587f4d7ce740598149abeea7491f1ee373f5e092ad2a7b")]:
            value = smoke.corpus_document(ordinal)
            encoded = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
            self.assertEqual(len(encoded), 1024)
            self.assertEqual(hashlib.sha256(encoded).hexdigest(), expected)

    def test_driver_failure_requires_an_actual_auth_denial_before_any_verified_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config.json"
            config.write_text("{}")
            started = {"event": "started", "configuration_sha256": smoke.sha256(config),
                       "executable_sha256": "d" * 64}
            for code in (None, "Unavailable", "DeadlineExceeded", "Internal", "Unauthenticated", "PermissionDenied"):
                events = [started, {"event": "failed", "transport_code": code}]
                (root / "events.jsonl").write_text("\n".join(map(json.dumps, events)))
                if code in ("Unauthenticated", "PermissionDenied"):
                    smoke.driver_result(root, config, "d" * 64, denied=True)
                else:
                    with self.assertRaises(ValueError):
                        smoke.driver_result(root, config, "d" * 64, denied=True)
            events.insert(1, {"event": "verified_prefix", "documents": 1})
            (root / "events.jsonl").write_text("\n".join(map(json.dumps, events)))
            with self.assertRaises(ValueError):
                smoke.driver_result(root, config, "d" * 64, denied=True)

    def test_driver_success_is_bound_to_exact_binary_config_counts_and_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config.json"
            config.write_text("{}")
            started = {"event": "started", "configuration_sha256": smoke.sha256(config),
                       "executable_sha256": "d" * 64}
            passed = {"event": "passed", "documents": 129, "canonical_bytes": 129 * 1024,
                      "expected_sha256": "e" * 64, "observed_sha256": "e" * 64}
            for bad in (None, "binary", "config", "counts", "digest"):
                first, last = started.copy(), passed.copy()
                if bad == "binary":
                    first["executable_sha256"] = "f" * 64
                elif bad == "config":
                    first["configuration_sha256"] = "f" * 64
                elif bad == "counts":
                    last["documents"] = 128
                elif bad == "digest":
                    last["expected_sha256"] = "f" * 64
                (root / "events.jsonl").write_text("\n".join(map(json.dumps, [first, last])))
                if bad is None:
                    self.assertEqual(smoke.driver_result(root, config, "d" * 64), passed)
                else:
                    with self.assertRaises(ValueError):
                        smoke.driver_result(root, config, "d" * 64)

    def test_local_restore_requires_finished_exact_input_and_local_fencing_scope(self):
        request = {"operation_id": "original", "target_incarnation": "target"}
        status = {"request": request, "phase": "finished", "fencing_scope": "exclusive_local_installation",
                  "last_failure": None, "client_profile": "/owned/profile.json"}
        self.assertEqual(smoke.validate_local_restore(status, request), Path("/owned/profile.json"))
        for field, value in (("phase", "activate"), ("fencing_scope", "global"), ("last_failure", "unknown"),
                             ("request", {"operation_id": "different"})):
            with self.subTest(field=field), self.assertRaises(ValueError):
                smoke.validate_local_restore({**status, field: value}, request)

    def test_private_atomic_output_rejects_symlink_without_overwriting_unrelated_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "original"
            original.write_bytes(b"unrelated")
            link = root / "link"
            link.symlink_to(original)
            with self.assertRaises(ValueError):
                smoke.private_write(link, b"replacement")
            self.assertEqual(original.read_bytes(), b"unrelated")
            self.assertFalse(list(root.glob("*.pending-*")))
            output = root / "private"
            smoke.private_write(output, b"first")
            smoke.private_write(output, b"second")
            self.assertEqual(output.read_bytes(), b"second")
            self.assertEqual(output.stat().st_mode & 0o077, 0)

    def test_mcp_request_has_exact_stateless_metadata_and_distinct_request_identity(self):
        value = smoke.mcp_request("tools/call", 2, {"name": "kasumi_get", "arguments": {"id": "first"}})
        self.assertEqual(value["id"], 2)
        self.assertEqual(value["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"], "2026-07-28")
        self.assertEqual(value["params"]["name"], "kasumi_get")

    def test_required_directory_policy_preserves_exact_bytes_and_rejects_old_or_invalid_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            raw = b'{ "extent_bytes": 1048576, "max_entries": 32768 }\n'
            path.write_bytes(raw)
            copied, policy = smoke.load_directory_policy(path)
            self.assertEqual(copied, raw)
            self.assertEqual(policy, {"extent_bytes": 1048576, "max_entries": 32768})
            for invalid in [b'{}', b'{"extent_bytes":1}', b'{"extent_bytes":true,"max_entries":1}',
                            b'{"extent_bytes":1,"max_entries":1,"legacy_default":true}',
                            b'{"max_directory_bytes":1,"max_entries":1}',
                            b'{"extent_bytes":1,"max_entries":1,"extent_bytes":2}', b' ' * 4097]:
                path.write_bytes(invalid)
                with self.assertRaises((ValueError, AssertionError, RuntimeError)):
                    smoke.load_directory_policy(path)

    def runner(self, root):
        return smoke.Runner(SimpleNamespace(output=root, stop_timeout=1, command_timeout=1,
                                            ready_timeout=1, execution_description="pure mocked tests"))

    def test_timeout_retains_failure_logs_and_drains_only_the_owned_process_group(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = self.runner(Path(directory))
            process = Mock(pid=12345, returncode=0)
            process.wait.side_effect = [subprocess.TimeoutExpired(["mock"], 1), 0]
            process.poll.return_value = 0
            with patch.object(smoke.subprocess, "Popen", return_value=process), \
                    patch.object(smoke.os, "killpg", side_effect=[None, ProcessLookupError()]) as kill:
                with self.assertRaises(subprocess.TimeoutExpired):
                    runner.command("timeout", ["never-executed"])
            self.assertEqual(kill.call_args_list[0].args, (12345, signal.SIGTERM))
            self.assertEqual(kill.call_args_list[1].args, (12345, 0))
            step = runner.record["steps"][0]
            self.assertEqual(step["status"], "failed")
            self.assertEqual(step["error_type"], "TimeoutExpired")
            self.assertTrue(step["process_group_drained"])
            self.assertEqual(step["stderr_sha256"], smoke.sha256(Path(directory) / "timeout.stderr.log"))

    def test_cleanup_failure_preserves_original_command_failure_and_retries_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = self.runner(Path(directory))
            process = Mock(pid=12345, returncode=7)
            process.wait.return_value = 7
            process.poll.return_value = 7
            with patch.object(smoke.subprocess, "Popen", return_value=process), \
                    patch.object(smoke.os, "killpg", side_effect=PermissionError("denied")):
                with self.assertRaisesRegex(ValueError, "expected exit"):
                    runner.command("failed", ["never-executed"])
            self.assertEqual(runner.record["steps"][0]["exit_code"], 7)
            self.assertEqual(runner.record["cleanup_errors"][0]["error_type"], "PermissionError")
            with patch.object(smoke.os, "killpg", side_effect=ProcessLookupError()) as kill:
                runner.cleanup()
            kill.assert_called_once_with(12345, signal.SIGTERM)
            self.assertTrue(runner.record["steps"][0]["process_group_drained"])

    def test_descendant_forced_drain_waits_for_the_owned_group_and_retains_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = self.runner(Path(directory))
            process = Mock(pid=12345, returncode=0)
            process.wait.return_value = 0
            process.poll.return_value = 0
            # The child leader is reaped but a descendant still owns the group.
            with patch.object(smoke.subprocess, "Popen", return_value=process), \
                    patch.object(smoke.os, "killpg", side_effect=[None, None, None, None, ProcessLookupError()]) as kill, \
                    patch.object(smoke.time, "sleep"):
                runner.command("descendant", ["never-executed"])
            self.assertTrue(runner.record["steps"][0]["forced_stop"])
            self.assertTrue(runner.record["steps"][0]["process_group_drained"])
            self.assertEqual([call.args for call in kill.call_args_list],
                             [(12345, signal.SIGTERM), (12345, 0), (12345, signal.SIGKILL),
                              (12345, 0), (12345, 0)])

    def test_log_sync_failure_closes_every_log_and_retains_cleanup_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = self.runner(Path(directory))
            process = Mock(pid=12345, returncode=0)
            process.poll.return_value = 0
            with patch.object(smoke.subprocess, "Popen", return_value=process):
                child = smoke.OwnedProcess(runner, "sync-failure", ["never-executed"])
            real_sync = smoke.os.fsync
            bad_descriptor = child.streams[0].fileno()
            def sync(descriptor):
                if descriptor == bad_descriptor and not child.streams[0].closed:
                    raise OSError("injected log sync failure")
                return real_sync(descriptor)
            with patch.object(smoke.os, "fsync", side_effect=sync):
                child.finish()
            self.assertTrue(all(stream.closed for stream in child.streams))
            self.assertEqual(runner.record["cleanup_errors"][0]["operation"], "sync-process-log")

    def test_protected_readiness_rejects_a_tcp_live_but_unready_service(self):
        for status, body in [(200, b'{"ready":false,"lifecycle":"starting"}'), (403, b"denied")]:
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                runner = self.runner(Path(directory))
                runner.control = {"administrative_members": {"1": {"endpoint": "https://localhost:1234", "certificate_pins": ["ab" * 32]}}}
                runner.config_file = Path("unused")
                runner.binaries = {"kasumid": Path("never-executed")}
                child = SimpleNamespace(process=Mock(), entry={})
                child.process.poll.return_value = None
                with patch.object(smoke, "OwnedProcess", return_value=child), \
                        patch.object(runner, "http", return_value=(status, body, {})):
                    with self.assertRaises(ValueError):
                        runner.start("unready")
                self.assertEqual(child.entry["status"], "failed")


if __name__ == "__main__":
    unittest.main()
