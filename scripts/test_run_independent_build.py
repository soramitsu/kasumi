"""Synthetic independent-build producer runs; these fixtures are never release evidence.

A stand-in Rustup ``cargo`` proxy emits Cargo's JSON transcript and writes
target-shaped stub executables. The producer's original custody is then
transported into a bundle layout and judged by the frozen verifier itself.
"""
import datetime as dt
import io
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import attempt_index
import release_gate
import release_host
import run_independent_build as producer
import verify_release_acceptance as acceptance

TARGET = release_host.host_target(platform.system(), platform.machine())
SCRIPTS = Path(producer.__file__).resolve(strict=True).parent
JOURNAL = "unit-journal"
HOST = "unit-host"

# Runs as Rustup's proxy: it is invoked through a symlink named cargo and only
# accepts the pinned selector when the declared sysroot is installed.
FAKE_RUSTUP = r'''
import json, os, sys, time
from pathlib import Path

invoked, arguments = sys.argv[1], sys.argv[2:]
mode = json.loads(Path(__file__).with_name("cargo-mode.json").read_text())
toolchain = Path(os.environ["RUSTUP_HOME"]) / "toolchains" / ("1.97.1-" + mode["target"])
if Path(invoked).name != "cargo" or arguments[:1] != ["+1.97.1"] or not toolchain.is_dir():
    print("error: toolchain '1.97.1' is not installed", file=sys.stderr)
    sys.exit(1)
if arguments[1:] != mode["arguments"]:
    print("error: unexpected cargo invocation", file=sys.stderr)
    sys.exit(2)
Path(mode["observed"]).write_text(json.dumps({"cwd": os.getcwd(), "environment": dict(os.environ)}))
release = Path(os.environ["CARGO_TARGET_DIR"]) / "release"
release.mkdir(parents=True)

def emit(message):
    print(json.dumps(message), flush=True)

print("   Compiling unit-dependency v1.0.0", file=sys.stderr, flush=True)
dependency = "registry+https://github.com/rust-lang/crates.io-index#unit-dependency@1.0.0"
emit({"reason": "compiler-artifact", "package_id": dependency, "features": mode["dependency_features"],
      "target": {"name": "unit_dependency", "kind": ["lib"], "crate_types": ["lib"]},
      "profile": {"test": False}, "executable": None, "fresh": False})
server = "path+file://" + os.getcwd() + "/crates/kasumi-server#kasumi-server@0.1.0"
emit({"reason": "compiler-artifact", "package_id": server, "features": [],
      "target": {"name": "build-script-build", "kind": ["custom-build"], "crate_types": ["bin"]},
      "profile": {"test": False}, "executable": None, "fresh": False})
if mode["sleep"]:
    Path(mode["started"]).write_text("started")
    time.sleep(mode["sleep"])
for name in mode["binaries"]:
    path = release / name
    path.write_bytes(bytes.fromhex(mode["header"]) + name.encode())
    path.chmod(0o755)
    emit({"reason": "compiler-artifact", "package_id": server, "features": [],
          "target": {"name": name, "kind": ["bin"], "crate_types": ["bin"]},
          "profile": {"test": False}, "executable": str(path), "fresh": False})
emit({"reason": "build-finished", "success": mode["exit"] == 0})
sys.exit(mode["exit"])
'''


def header(target):
    kind, machine = acceptance.package.TARGETS[target]
    if kind == "elf":
        value = bytearray(20)
        value[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", value, 18, machine)
        return bytes(value)
    return b"\xcf\xfa\xed\xfe" + struct.pack("<I", machine) + bytes(12)


def executable(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0o755)
    return path


@unittest.skipUnless(TARGET is not None and sys.platform in ("darwin", "linux")
                     and sys.version_info >= (3, 11), "independent build producer needs a release host platform")
class IndependentBuildTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="independent-build-unit-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve(strict=True)
        environment = patch.dict(os.environ, {"RUSTFLAGS": "--cfg unit_ambient_leak",
                                              "KASUMI_UNIT_AMBIENT": "leak"})
        environment.start()
        self.addCleanup(environment.stop)
        os.environ.pop(producer.gate_process.GROUP_LEDGER_ENV, None)
        self.native = self.root / "native"
        self.native.mkdir()
        attempt_index.create(self.native, JOURNAL, HOST, TARGET)
        self.python = Path(sys.executable).resolve(strict=True)
        self.toolchain()
        self.files = {"Cargo.toml": b"[workspace]\nmembers = [\"crates/kasumi-server\"]\n",
                      "Cargo.lock": b"# synthetic unit lockfile\nversion = 4\n",
                      "crates/kasumi-server/Cargo.toml": b"[package]\nname = \"kasumi-server\"\n",
                      "vendor/unit-dependency/Cargo.toml": b"[package]\nname = \"unit-dependency\"\n",
                      **{relative: (SCRIPTS / Path(relative).name).read_bytes()
                         for relative in producer.RUNNER_INPUTS}}
        self.archive, self.identity = self.source(self.files, "source.tar")
        now = dt.datetime.now(dt.timezone.utc)
        self.reservation = {"id": "unit-reservation", "starts_at": (now - dt.timedelta(days=1)).isoformat(),
                            "ends_at": (now + dt.timedelta(days=30)).isoformat(), "cpu_count": 4,
                            "memory_bytes": 16 << 30, "disk_bytes": 128 << 30}
        self.preflight = {"schema": 3, "os": platform.system(), "machine": platform.machine(),
                          "requested_target": TARGET, "errors": [], "translated": False,
                          "effective_memory_bytes": 16 << 30}
        self.attestation = self.root / "operator" / "host-attestation.txt"
        self.attestation.write_text("synthetic operator host attestation\n")
        self.mode()

    def toolchain(self):
        """A Rustup layout: direct sysroot tools plus a cargo proxy symlink in Cargo home."""
        self.sysroot = self.root / "rustup" / "toolchains" / (producer.TOOLCHAIN + "-" + TARGET)
        executable(self.sysroot / "bin" / "cargo",
                   "#!/bin/sh\necho \"error: no such command: $1\" >&2\nexit 101\n")
        executable(self.sysroot / "bin" / "rustc", "#!/bin/sh\nexit 0\n")
        self.cargo_home = self.root / "cargo-home"
        (self.cargo_home / "registry").mkdir(parents=True)
        (self.root / "python-runtime").mkdir()
        (self.root / "operator").mkdir()
        fake = self.root / "fake-rustup.py"
        fake.write_text(FAKE_RUSTUP)
        self.rustup = executable(self.cargo_home / "bin" / "rustup",
                                 f"#!/bin/sh\nexec '{self.python}' -I -S -B '{fake}' \"$0\" \"$@\"\n")
        (self.cargo_home / "bin" / "cargo").symlink_to("rustup")
        self.inventory = self.root / "operator" / "host-inventory.txt"
        self.inventory.write_text("synthetic host dependency inventory\n")

    def declaration(self, host_files=None):
        def tool(path):
            return {"path": str(path), "sha256": release_gate.sha256(path)}
        return {"schema": "kasumi-assembly-inputs-v1", "target": TARGET,
                "tools": {"python": tool(self.python), "cargo": tool(self.sysroot / "bin" / "cargo"),
                          "rustc": tool(self.sysroot / "bin" / "rustc")},
                "roots": {"python-runtime": str(self.root / "python-runtime"), "rust-sysroot": str(self.sysroot),
                          "cargo-registry": str(self.cargo_home / "registry")},
                "host_files": [tool(self.rustup)] if host_files is None else host_files,
                "host_inventory": tool(self.inventory), "cargo_home": str(self.cargo_home)}

    def source(self, files, name):
        """A Git-archive-shaped tar and the verifier's identity for its exact bytes."""
        path = self.root / "operator" / name
        with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as archive:
            for relative, data in sorted(files.items()):
                item = tarfile.TarInfo(relative)
                item.size, item.mtime = len(data), 1700000000
                item.mode = 0o755 if relative.startswith("scripts/") else 0o644
                archive.addfile(item, io.BytesIO(data))
        scratch = self.root / ("inventory-" + name)
        scratch.mkdir()
        release_gate.extract_source(path, scratch / "source")
        inventory = release_gate.inventory(scratch / "source")
        release_gate.write_json(scratch / "source-files.json", inventory)
        vendor = {key: value for key, value in inventory.items() if key.startswith("vendor/")}
        return path, {"source_commit": "1" * 40, "source_tree": "2" * 40,
                      "source_archive_sha256": release_gate.sha256(path),
                      "source_files_sha256": release_gate.sha256(scratch / "source-files.json"),
                      "lockfile_sha256": inventory["Cargo.lock"]["sha256"],
                      "patches_sha256": acceptance.canonical_hash(vendor),
                      "configurations_sha256": "3" * 64}

    def mode(self, **changes):
        self.observed = self.root / "observed-cargo.json"
        self.started = self.root / "cargo-started"
        value = {"target": TARGET, "header": header(TARGET).hex(), "exit": 0, "sleep": 0,
                 "binaries": sorted(acceptance.package.BINARIES), "dependency_features": ["std"],
                 "arguments": producer.production_command("cargo", 2)[2:],
                 "observed": str(self.observed), "started": str(self.started), **changes}
        (self.root / "cargo-mode.json").write_text(json.dumps(value))

    def build(self, attempt_id, *, identity=None, declaration=None, preflight=None, reservation=None,
              archive=None, timeout_seconds=60):
        directory = self.root / "operator" / attempt_id
        directory.mkdir()
        values = {"identity": identity or self.identity, "native_inputs": declaration or self.declaration(),
                  "host_preflight": preflight or self.preflight, "host_reservation": reservation or self.reservation}
        inputs = {"source_archive": str(archive or self.archive), "host_attestation": str(self.attestation)}
        for key, value in values.items():
            (directory / (key + ".json")).write_text(json.dumps(value))
            inputs[key] = str(directory / (key + ".json"))
        return producer.produce(self.native, attempt_id, self.native / attempt_id, inputs,
                                jobs=2, timeout_seconds=timeout_seconds)

    def outcome(self, attempt_id):
        output = self.native / attempt_id
        return (json.loads((output / "outcome.json").read_text()),
                json.loads((self.native / "attempts" / attempt_id / "attempt.json").read_text()),
                json.loads((output / producer.RECORD).read_text()))

    def transport(self, selected):
        """Copy original custody into a bundle and replay it against the anchored head."""
        bundle = self.root / "bundle"
        shutil.rmtree(bundle, ignore_errors=True)
        custody = bundle / "native-attempts" / JOURNAL
        shutil.copytree(self.native, custody, symlinks=True)
        names = sorted(path.name for path in (custody / "attempts").iterdir() if path.is_dir())
        retained = [{"id": name, "receipt": attempt_index.file_ref(
                        custody, custody / "attempts" / name / "attempt.json")} for name in names]
        acceptance.verify_attempts(custody, retained, selected, head=attempt_index.head(self.native),
                                   original_root=str(self.native))
        return bundle

    def test_command_is_the_verifiers_exact_fixture_free_production_gate(self):
        command = producer.production_command("/unit/cargo-home/bin/cargo", 7)
        self.assertEqual(command[0], "/unit/cargo-home/bin/cargo")
        self.assertEqual(command[1:], dict(acceptance.functional_gates(7, "/unit/python"))["production"][1:])
        self.assertIn("--no-default-features", command)
        self.assertEqual(set(producer.RECORD_FIELDS), {
            "schema", "status", "identity", "toolchain", "platform", "jobs", "started_at", "finished_at",
            "build_id", "build_root", "environment_id", "environment", "fresh_build_root", "host",
            "processes", "compiled_packages", "binaries", "source_archive", "source_files"})

    def test_passed_build_binds_actual_binaries_and_verifies_after_transport(self):
        summary = self.build("independent-1")
        self.assertEqual(summary["status"], "passed", summary["error"])
        output = self.native / "independent-1"
        outcome, receipt, record = self.outcome("independent-1")
        self.assertEqual(outcome["build_evidence"], attempt_index.file_ref(output, output / producer.RECORD))
        self.assertTrue(outcome["dispatch_started"])
        self.assertEqual([item["id"] for item in outcome["products"]], sorted(acceptance.package.BINARIES))
        self.assertEqual([item["id"] for item in receipt["processes"]], ["production"])
        actual = {name: release_gate.sha256(output / "build/target/release" / name)
                  for name in acceptance.package.BINARIES}
        self.assertEqual(summary["binaries"], actual)
        self.assertEqual(record["build_root"], str(output / "build"))
        self.assertTrue(all(item["file"]["path"] == f"native-attempts/{JOURNAL}/independent-1/build/target/release/"
                            + item["name"] for item in record["binaries"]))
        self.assertEqual(summary["head"], attempt_index.head(self.native))

        observed = json.loads(self.observed.read_text())
        self.assertEqual(observed["cwd"], str(output / "build/source"))
        variables = observed["environment"]
        self.assertEqual((variables["CARGO_TARGET_DIR"], variables["HOME"], variables["CARGO_HOME"],
                          variables["RUSTC"], variables["RUSTUP_HOME"], variables["CARGO_NET_OFFLINE"],
                          variables["RUSTUP_AUTO_INSTALL"]),
                         (str(output / "build/target"), str(output / "home"), str(self.cargo_home),
                          str(self.sysroot / "bin/rustc"), str(self.root / "rustup"), "true", "0"))
        self.assertNotIn("RUSTFLAGS", variables)
        self.assertNotIn("KASUMI_UNIT_AMBIENT", variables)

        selection = "independent-1/" + producer.RECORD
        bundle = self.transport({selection: "independent-build"})
        ref = attempt_index.file_ref(bundle, bundle / summary["bundle_record"])
        primary = {"build_id": JOURNAL + ":functional-1", "build_root": "/unit/functional",
                   "environment_id": "functional-environment"}
        acceptance.check_independent_build(bundle, ref, primary, TARGET, self.identity, actual)
        with self.assertRaisesRegex(ValueError, "binary hashes differ"):
            acceptance.check_independent_build(bundle, ref, primary, TARGET, self.identity,
                                               {**actual, "kasumid": "0" * 64})
        with self.assertRaisesRegex(ValueError, "reused primary build_root"):
            acceptance.check_independent_build(bundle, ref, {**primary, "build_root": record["build_root"]},
                                               TARGET, self.identity, actual)

    def test_failed_compilation_is_preserved_with_partial_products(self):
        self.mode(exit=101, binaries=["kasumid"])
        summary = self.build("independent-failed")
        self.assertEqual(summary["status"], "failed")
        self.assertIn("exit code 101", summary["error"])
        outcome, receipt, record = self.outcome("independent-failed")
        self.assertEqual([item["id"] for item in outcome["products"]], ["kasumid"])
        self.assertTrue(outcome["dispatch_started"])
        self.assertEqual(len(receipt["processes"]), 1)
        self.assertEqual(record["status"], "failed")
        self.transport({})
        with self.assertRaisesRegex(ValueError, "selected attempt failed"):
            self.transport({"independent-failed/" + producer.RECORD: "independent-build"})

    def test_fixture_capabilities_fail_the_original_attempt(self):
        self.mode(dependency_features=["std", "test-utils"])
        summary = self.build("independent-fixture")
        self.assertEqual(summary["status"], "failed")
        self.assertIn("fixture capabilities", summary["error"])
        self.assertEqual(len(summary["binaries"]), 3)
        self.transport({})

    def test_rejected_inputs_are_admitted_and_finished_before_dispatch(self):
        stale = {**self.reservation, "ends_at": "2026-01-02T00:00:00+00:00",
                 "starts_at": "2026-01-01T00:00:00+00:00"}
        changed = {**self.files, "scripts/release_gate.py": self.files["scripts/release_gate.py"] + b"# changed\n"}
        foreign, foreign_identity = self.source(changed, "foreign-runner.tar")
        cases = {
            "archive": ({"identity": {**self.identity, "source_archive_sha256": "0" * 64}},
                        "source archive differs"),
            "translated": ({"preflight": {**self.preflight, "translated": True}}, "native host preflight failed"),
            "reservation": ({"reservation": stale}, "does not cover the admitted attempt"),
            "undeclared-proxy": ({"declaration": self.declaration(host_files=[
                {"path": str(self.inventory), "sha256": release_gate.sha256(self.inventory)}])},
                "not a declared native host file"),
            "runner": ({"archive": foreign, "identity": foreign_identity},
                       "differs from frozen source: scripts/release_gate.py"),
        }
        for name, (changes, message) in cases.items():
            with self.subTest(case=name):
                summary = self.build("rejected-" + name, **changes)
                self.assertEqual(summary["status"], "failed")
                self.assertIn(message, summary["error"])
                outcome, receipt, record = self.outcome("rejected-" + name)
                self.assertIs(outcome["dispatch_started"], False)
                self.assertEqual((receipt["processes"], outcome["products"], record["processes"]), ([], [], []))
                self.assertFalse((self.native / ("rejected-" + name) / "production-process.json").exists())
                self.assertFalse(self.observed.exists())
        self.transport({})

    def test_existing_output_is_never_admitted(self):
        before = attempt_index.head(self.native)
        (self.native / "taken").mkdir()
        with self.assertRaisesRegex(ValueError, "fresh absolute path"):
            self.build("taken")
        self.assertEqual(attempt_index.head(self.native), before)

    def test_cancellation_is_an_original_interrupted_attempt(self):
        self.mode(sleep=30)
        resources = self.native / "independent-cancelled" / "production-resources.json"
        opening = []

        def cancel():
            deadline = time.monotonic() + 20
            while not self.started.exists() and time.monotonic() < deadline:
                time.sleep(.05)
            if self.started.exists():
                if resources.is_file():
                    opening.append(json.loads(resources.read_bytes()))
                os.kill(os.getpid(), signal.SIGINT)

        thread = threading.Thread(target=cancel)
        thread.start()
        try:
            summary = self.build("independent-cancelled", timeout_seconds=25)
        finally:
            thread.join()
        self.assertEqual(summary["status"], "interrupted", summary["error"])
        outcome, receipt, _ = self.outcome("independent-cancelled")
        self.assertEqual(outcome["products"], [])
        process = json.loads((self.native / "independent-cancelled" / "production-process.json").read_text())
        self.assertEqual((process["received_signals"], process["cleanup"]["drained"]), ([signal.SIGINT], True))
        final = json.loads(resources.read_bytes())
        self.assertEqual(opening, [{"before": final["before"], "after": None}])
        self.assertIsNotNone(final["after"])
        self.transport({})

    def test_cli_requires_isolated_python_and_reports_the_anchorable_head(self):
        scripts = self.root / "frozen-scripts"
        scripts.mkdir()
        for relative in producer.RUNNER_INPUTS:
            shutil.copyfile(SCRIPTS / Path(relative).name, scripts / Path(relative).name)
        directory = self.root / "operator" / "cli"
        directory.mkdir()
        values = {"identity": self.identity, "native-inputs": self.declaration(),
                  "host-preflight": self.preflight, "host-reservation": self.reservation}
        arguments = ["--journal", str(self.native), "--attempt-id", "independent-cli",
                     "--output", str(self.native / "independent-cli"), "--source-archive", str(self.archive),
                     "--host-attestation", str(self.attestation), "--jobs", "2", "--timeout-seconds", "60"]
        for key, value in values.items():
            (directory / (key + ".json")).write_text(json.dumps(value))
            arguments += ["--" + key, str(directory / (key + ".json"))]
        before = attempt_index.head(self.native)
        script = str(scripts / "run_independent_build.py")
        rejected = subprocess.run([sys.executable, "-B", script, *arguments], capture_output=True, text=True)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("requires native Python -I -S -B", rejected.stderr)
        self.assertEqual(attempt_index.head(self.native), before)
        result = subprocess.run([sys.executable, "-I", "-S", "-B", script, *arguments],
                                capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads(result.stdout)
        self.assertEqual((summary["status"], summary["head"]), ("passed", attempt_index.head(self.native)))
        self.assertFalse((scripts / "__pycache__").exists())
        self.transport({"independent-cli/" + producer.RECORD: "independent-build"})


if __name__ == "__main__":
    unittest.main()
