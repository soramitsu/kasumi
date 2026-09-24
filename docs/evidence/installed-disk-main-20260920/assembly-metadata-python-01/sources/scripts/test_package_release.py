"""Counterexamples for candidate artifact provenance and deterministic packaging."""
import io
import json
import os
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
import unittest

import package_release as package
from release_gate import functional_gates, inventory, sha256, write_json


class PackageReleaseTests(unittest.TestCase):
    def make_evidence(self, root):
        source = root / "source"
        source.mkdir()
        (source / "Cargo.lock").write_text("locked input")
        (source / "scripts").mkdir()
        runner_inputs = {}
        for name in ("release_gate.py", "gate_process.py"):
            path = source / "scripts" / name
            path.write_text("fixture runner input: " + name)
            runner_inputs["scripts/" + name] = sha256(path)
        (root / "source.tar").write_bytes(b"unit fixture archive")
        write_json(root / "source-files.json", inventory(source))
        (root / "target").mkdir()
        (root / "tools").mkdir()
        (root / "tools/python").write_bytes(b"synthetic remote interpreter bytes")
        interpreter = {"path": "/native/remote/bin/python3.13", "artifact": "tools/python",
                       "sha256": sha256(root / "tools/python")}
        artifacts = {}
        for name in package.BINARIES:
            binary = root / "target" / name
            header = bytearray(20)
            header[:6] = b"\x7fELF\x02\x01"
            struct.pack_into("<H", header, 18, 183)
            binary.write_bytes(header)
            artifacts[name] = {"target": name, "test": False, "sha256": sha256(binary)}
        gates = []
        for name, command in functional_gates(2, interpreter["path"]):
            log = root / (name + ".log")
            log.write_text("host: aarch64-unknown-linux-gnu\n" if name == "toolchain" else "fixture\n")
            resources = root / (name + "-resources.json")
            write_json(resources, {"before": {"available": False}, "after": {"available": False}})
            gate = {"name": name, "command": command, "exit_code": 0,
                    "log": log.name, "log_sha256": sha256(log),
                    "resources": resources.name, "resources_sha256": sha256(resources)}
            cleanup = {"group": 123, "before": [], "after": [], "signals": [],
                       "errors": [], "drained": True, "process_returncode": 0}
            process = root / (name + "-process.json")
            write_json(process, {"status": "passed", "outputs_stable": True, "command": command, "exit_code": 0,
                                 "executable": {"path": interpreter["path"], "sha256": interpreter["sha256"]}
                                 if name in {"python", "dependency-patches"} else
                                 {"path": "/native/remote/bin/" + command[0], "sha256": "a" * 64},
                                 "process_exit_code": 0, "timeout_seconds": 14400, "timed_out": False,
                                 "received_signals": [], "error": None, "process_group": 123,
                                 "cleanup": cleanup})
            gate.update(process=process.name, process_sha256=sha256(process), process_cleanup=cleanup,
                        timeout_seconds=14400, timed_out=False, received_signals=[], process_error=None)
            if name == "production":
                gate.update(executables=artifacts, compiled_packages={"fixture": {"features": []}})
            gates.append(gate)
        record = {"schema": 1, "status": "passed", "toolchain": package.TOOLCHAIN, "jobs": 2,
                  "gate_timeout_seconds": 14400,
                  "python_executable": interpreter,
                  "runner_inputs": runner_inputs,
                  "gates": gates, "source_files_sha256": sha256(root / "source-files.json"),
                  "source_archive_sha256": sha256(root / "source.tar"),
                  "lockfile_sha256": sha256(source / "Cargo.lock")}
        write_json(root / "evidence.json", record)
        return record

    def test_remote_python_identity_survives_verification_on_another_host(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record = self.make_evidence(root)
            self.assertNotEqual(record["python_executable"]["path"], sys.executable)
            self.assertFalse(Path(record["python_executable"]["path"]).exists())
            self.assertEqual(package.verify_evidence(root)[0], record)

    def test_python_evidence_cannot_replace_or_omit_the_dispatched_interpreter(self):
        for changed in ("missing", "relative", "bytes", "digest", "different-process", "missing-process", "different-command"):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                record = self.make_evidence(root)
                gate = next(g for g in record["gates"] if g["name"] == "python")
                if changed == "missing":
                    del record["python_executable"]
                elif changed == "relative":
                    record["python_executable"]["path"] = "python3"
                elif changed == "bytes":
                    (root / "tools/python").write_bytes(b"substituted interpreter")
                elif changed == "digest":
                    record["python_executable"]["sha256"] = "z" * 64
                else:
                    path = root / gate["process"]
                    process = json.loads(path.read_text())
                    if changed == "different-process":
                        process["executable"]["sha256"] = "0" * 64
                    elif changed == "missing-process":
                        del process["executable"]
                    else:
                        process["command"][0] = sys.executable
                        gate["command"][0] = sys.executable
                    write_json(path, process)
                    gate["process_sha256"] = sha256(path)
                write_json(root / "evidence.json", record)
                with self.assertRaises(ValueError):
                    package.verify_evidence(root)

    def test_changed_binary_log_source_and_failed_gate_cannot_be_packaged(self):
        for changed in ("binary", "log", "source", "failed", "missing-inventory", "missing-doc-gate", "missing-network-gate",
                        "weakened-clippy", "different-build", "missing-jobs", "resources", "missing-resources"):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                record = self.make_evidence(root)
                package.verify_evidence(root)
                if changed == "binary":
                    (root / "target/kasumid").write_bytes(b"different artifact")
                elif changed == "log":
                    (root / "workspace.log").write_text("changed result")
                elif changed == "resources":
                    (root / "workspace-resources.json").write_text("hidden OOM event")
                elif changed == "missing-resources":
                    del record["gates"][0]["resources"]
                elif changed == "source":
                    (root / "source/new-input.rs").write_text("injected")
                elif changed == "failed":
                    record["gates"][2]["exit_code"] = 7
                elif changed == "missing-inventory":
                    record["gates"][-1]["compiled_packages"] = {}
                elif changed == "weakened-clippy":
                    next(g for g in record["gates"] if g["name"] == "clippy")["command"].remove("--all-targets")
                elif changed == "different-build":
                    record["gates"][-1]["command"].remove("--no-default-features")
                elif changed == "missing-jobs":
                    del record["jobs"]
                elif changed == "missing-network-gate":
                    record["gates"] = [g for g in record["gates"] if g["name"] != "network-driver"]
                else:
                    record["gates"] = [g for g in record["gates"] if g["name"] != "workspace-docs"]
                write_json(root / "evidence.json", record)
                with self.assertRaises(ValueError):
                    package.verify_evidence(root)

    def test_archive_is_identical_across_paths_mtimes_and_creation_order(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, order in (("a", ["file", "bin/run"]), ("b", ["bin/run", "file"])):
                source = root / name
                source.mkdir()
                for relative in order:
                    path = source / relative
                    path.parent.mkdir(exist_ok=True)
                    path.write_bytes(relative.encode())
                    path.chmod(0o755 if relative.startswith("bin/") else 0o644)
                    os.utime(path, (100 if name == "a" else 200, 100 if name == "a" else 200))
                package.normalized_archive(source, root / (name + ".tar.gz"), "kasumi-0.1.0", 1788827482)
            self.assertEqual(sha256(root / "a.tar.gz"), sha256(root / "b.tar.gz"))
            with tarfile.open(root / "a.tar.gz") as archive:
                self.assertEqual(archive.extractfile("kasumi-0.1.0/file").read(), b"file")
                self.assertEqual(archive.getmember("kasumi-0.1.0/bin/run").mode, 0o755)

    def test_absent_changed_or_uncertain_process_receipt_cannot_be_packaged(self):
        for changed in ("missing", "bytes", "timed-out", "signals", "unknown-members", "forced-drain",
                        "wrong-command", "wrong-timeout", "missing-timeout", "missing-runner", "changed-helper"):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                record = self.make_evidence(root)
                gate = record["gates"][0]
                path = root / gate["process"]
                process = json.loads(path.read_text())
                if changed == "missing":
                    del gate["process"]
                elif changed == "missing-timeout":
                    del record["gate_timeout_seconds"]
                elif changed == "missing-runner":
                    del record["runner_inputs"]
                elif changed == "changed-helper":
                    record["runner_inputs"]["scripts/gate_process.py"] = "0" * 64
                else:
                    if changed == "timed-out":
                        process["timed_out"] = True
                    elif changed == "signals":
                        process["received_signals"] = [15]
                    elif changed == "unknown-members":
                        process["cleanup"]["after"] = None
                    elif changed == "forced-drain":
                        process["cleanup"]["signals"] = ["SIGTERM"]
                    elif changed == "wrong-command":
                        process["command"] = ["true"]
                    elif changed == "wrong-timeout":
                        process["timeout_seconds"] += 1
                    else:
                        process["unrecorded-change"] = True
                    write_json(path, process)
                    if changed != "bytes":
                        gate["process_sha256"] = sha256(path)
                write_json(root / "evidence.json", record)
                with self.assertRaises(ValueError):
                    package.verify_evidence(root)

    def test_cached_notice_must_match_locked_archive_and_cannot_follow_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            crate = root / "registry/src/index/example-1.0.0"
            crate.mkdir(parents=True)
            cache = root / "registry/cache/index"
            cache.mkdir(parents=True)
            (crate / "LICENSE").write_bytes(b"original license")
            (crate / "Cargo.toml").write_bytes(b"original manifest")
            archive = cache / "example-1.0.0.crate"
            with tarfile.open(archive, "w:gz") as tar:
                for name in ("LICENSE", "Cargo.toml"):
                    data = (crate / name).read_bytes()
                    item = tarfile.TarInfo("example-1.0.0/" + name)
                    item.size = len(data)
                    tar.addfile(item, io.BytesIO(data))
            dependency = {"manifest_path": str(crate / "Cargo.toml"), "source": "registry+example",
                          "name": "example", "version": "1.0.0"}
            files = [(crate / "LICENSE", "LICENSE", None)]
            digest = sha256(archive)
            package.verify_registry_notices(dependency, files, digest)
            (crate / "LICENSE").write_bytes(b"altered license")
            with self.assertRaises(ValueError):
                package.verify_registry_notices(dependency, files, digest)
            (crate / "LICENSE").unlink()
            (crate / "LICENSE").symlink_to(crate / "Cargo.toml")
            with self.assertRaises(ValueError):
                package.owned_file(crate, "LICENSE")

    def test_architecture_cannot_be_relabeled(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.make_evidence(root)
            with self.assertRaises(ValueError):
                package.verify_architecture(root / "target/kasumid", "x86_64-unknown-linux-gnu")


if __name__ == "__main__":
    unittest.main()
