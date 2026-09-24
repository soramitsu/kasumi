"""Synthetic transitive-export counterexamples; never native release evidence."""
import io
import json
from pathlib import Path
import shutil
import stat
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import export_functional_evidence as exporter
from release_gate import inventory, record_compiled_package, sha256, write_json
import verify_release_acceptance as acceptance


TARGET = "aarch64-unknown-linux-gnu"


class FunctionalExportTests(unittest.TestCase):
    def setUp(self):
        base = Path(__file__).resolve().parents[2] / "tmp"
        base.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=base)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.run = self.root / "original-run"
        self.run.mkdir()
        self.source = self.run / "source"
        self.source.mkdir()
        self.file("source/Cargo.lock", b"locked source\n")
        self.file("source/.cargo/config.toml", b"[net]\noffline = true\n")
        self.source_files = inventory(self.source)
        write_json(self.run / "source-files.json", self.source_files)
        self.write_source_tar()
        self.file("tools/python", b"synthetic Python executable", executable=True)
        gates = []
        for name in ("toolchain", "workspace", "production"):
            self.file(name + ".log", b"synthetic original log\n")
            self.file(name + "-process.json", (json.dumps({"working_directory": str(self.source.resolve())}) + "\n").encode())
            self.file(name + "-resources.json", b"{}\n")
            gates.append({"name": name, "log": name + ".log", "log_sha256": sha256(self.run / (name + ".log")),
                          "process": name + "-process.json",
                          "process_sha256": sha256(self.run / (name + "-process.json")),
                          "resources": name + "-resources.json",
                          "resources_sha256": sha256(self.run / (name + "-resources.json")),
                          "executables": {}, "compiled_packages": {}})
        self.file("target/debug/deps/workspace-test", b"synthetic nonproduction test executable", executable=True)
        self.file("target/release/kasumid", b"synthetic production executable", executable=True)
        for gate, relative in ((gates[1], "debug/deps/workspace-test"),
                               (gates[2], "release/kasumid")):
            path = self.run / "target" / relative
            name = "workspace-test" if gate["name"] == "workspace" else "kasumid"
            message = {"reason": "compiler-artifact", "executable": str(path),
                       "target": {"name": name,
                                  "kind": ["test" if gate["name"] == "workspace" else "bin"],
                                  "crate_types": ["bin"]},
                       "profile": {"test": gate["name"] == "workspace"},
                       "package_id": "synthetic:" + gate["name"], "features": []}
            with (self.run / gate["log"]).open("ab") as log:
                log.write((json.dumps(message) + "\n").encode())
            gate["log_sha256"] = sha256(self.run / gate["log"])
            record_compiled_package(gate["compiled_packages"], message)
            gate["executables"][relative] = {"sha256": sha256(path), "bytes": path.stat().st_size,
                                              "target": name, "test": message["profile"]["test"],
                                              "package_id": message["package_id"]}
        self.file("target/debug/incremental/unreferenced-cache", b"not evidence")
        self.record = {"schema": 1, "status": "passed", "python_executable": {
            "artifact": "tools/python", "sha256": sha256(self.run / "tools/python")},
            "source_files_sha256": sha256(self.run / "source-files.json"),
            "source_archive_sha256": sha256(self.run / "source.tar"), "gates": gates}
        write_json(self.run / "evidence.json", self.record)
        self.patched_package = patch.object(exporter.package, "verify_evidence", side_effect=self.fake_package_verify)
        self.patched_package.start()
        self.addCleanup(self.patched_package.stop)

    def file(self, relative, contents, executable=False):
        path = self.run / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
        path.chmod(0o755 if executable else 0o644)
        return path

    def write_source_tar(self, omitted=()):
        with tarfile.open(self.run / "source.tar", "w") as archive:
            for relative, entry in self.source_files.items():
                if relative in omitted:
                    continue
                data = (self.source / relative).read_bytes()
                info = tarfile.TarInfo(relative)
                info.mode = 0o755 if entry["executable"] else 0o644
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))

    def fake_package_verify(self, directory):
        record = acceptance.read_json(Path(directory) / "evidence.json")
        if record.get("status") != "passed":
            raise ValueError("synthetic fixture is not passed")
        for gate in record["gates"]:
            process = acceptance.read_json(exporter.package.owned_file(directory, gate["process"]))
            exporter.package.verify_compiler_executables(directory, gate, process)
        production = next(gate for gate in record["gates"] if gate["name"] == "production")
        return record, production, TARGET, {}

    def test_unicode_escaped_cargo_reason_still_requires_executable(self):
        omitted = self.file("target/debug/deps/escaped-test", b"compiled but omitted", executable=True)
        gate = next(gate for gate in self.record["gates"] if gate["name"] == "workspace")
        message = {"reason": "compiler-artifact", "executable": str(omitted),
                   "target": {"name": "escaped-test", "kind": ["test"], "crate_types": ["bin"]},
                   "profile": {"test": True}, "package_id": "synthetic:workspace",
                   "features": []}
        encoded = json.dumps(message).replace("compiler-artifact", "compiler\\u002dartifact")
        self.assertNotIn("compiler-artifact", encoded)
        with (self.run / gate["log"]).open("ab") as log:
            log.write((encoded + "\n").encode())
        gate["log_sha256"] = sha256(self.run / gate["log"])
        record_compiled_package(gate["compiled_packages"], message)
        write_json(self.run / "evidence.json", self.record)
        with self.assertRaisesRegex(ValueError, "executable set differs"):
            exporter.export(self.run, self.root / "escaped-reason", 1 << 20)

    def test_malformed_executable_metadata_and_duplicate_event_fail(self):
        gate = next(gate for gate in self.record["gates"] if gate["name"] == "workspace")
        path = self.file("target/debug/deps/typed-test", b"compiled typed test", executable=True)
        message = {"reason": "compiler-artifact", "executable": str(path),
                   "target": {"name": "typed-test", "kind": ["test"], "crate_types": ["bin"]},
                   "profile": {"test": "true"}, "package_id": "synthetic:workspace",
                   "features": []}
        with (self.run / gate["log"]).open("ab") as log:
            log.write((json.dumps(message) + "\n").encode())
        gate["log_sha256"] = sha256(self.run / gate["log"])
        record_compiled_package(gate["compiled_packages"], message)
        write_json(self.run / "evidence.json", self.record)
        with self.assertRaisesRegex(ValueError, "metadata is malformed"):
            exporter.export(self.run, self.root / "invalid-profile", 1 << 20)
        # Reset to the original event and replay it exactly: duplicate paths are
        # rejected rather than allowing the receipt map to erase multiplicity.
        lines = (self.run / gate["log"]).read_bytes().splitlines(keepends=True)
        (self.run / gate["log"]).write_bytes(b"".join(lines[:-1]) + lines[-2])
        gate["log_sha256"] = sha256(self.run / gate["log"])
        write_json(self.run / "evidence.json", self.record)
        with self.assertRaisesRegex(ValueError, "duplicate compiler-artifact"):
            exporter.export(self.run, self.root / "duplicate-event", 1 << 20)

    def test_omitted_emitted_executable_fails_even_with_rehashed_log_and_receipt(self):
        omitted = self.file("target/debug/deps/omitted-test", b"another compiled test", executable=True)
        gate = next(gate for gate in self.record["gates"] if gate["name"] == "workspace")
        message = {"reason": "compiler-artifact", "executable": str(omitted),
                   "target": {"name": "omitted-test", "kind": ["test"], "crate_types": ["bin"]},
                   "profile": {"test": True}, "package_id": "synthetic:workspace",
                   "features": []}
        with (self.run / gate["log"]).open("ab") as log:
            log.write((json.dumps(message) + "\n").encode())
        gate["log_sha256"] = sha256(self.run / gate["log"])
        record_compiled_package(gate["compiled_packages"], message)
        write_json(self.run / "evidence.json", self.record)
        destination = self.root / "missing-emitted-executable"
        with self.assertRaisesRegex(ValueError, "executable set differs"):
            exporter.export(self.run, destination, 1 << 20)
        self.assertFalse(destination.exists())

    def test_unlogged_receipt_executable_fails_before_transport(self):
        extra = self.file("target/debug/deps/unlogged-test", b"unlogged compiled test", executable=True)
        gate = next(gate for gate in self.record["gates"] if gate["name"] == "workspace")
        gate["executables"]["debug/deps/unlogged-test"] = {
            "sha256": sha256(extra), "bytes": extra.stat().st_size,
            "target": "unlogged-test", "test": True, "package_id": "synthetic:workspace"}
        write_json(self.run / "evidence.json", self.record)
        destination = self.root / "unlogged-receipt-executable"
        with self.assertRaisesRegex(ValueError, "executable set differs"):
            exporter.export(self.run, destination, 1 << 20)
        self.assertFalse(destination.exists())

    def test_transported_artifact_log_replay_needs_no_original_build_root(self):
        exported = self.root / "export"
        manifest_digest = exporter.export(self.run, exported, 1 << 20)
        archive = self.root / "transport.tar"
        archive_digest = exporter.create_transport(exported, manifest_digest, archive, 1 << 20)
        shutil.rmtree(self.run)
        readback = self.root / "portable-readback"
        exporter.check_transport(archive, archive_digest, manifest_digest, 1 << 20, readback)
        self.assertIn("target/debug/deps/workspace-test", exporter.verify(readback, manifest_digest)["files"])

    def test_export_retains_nonproduction_executable_and_hidden_source_without_cache(self):
        destination = self.root / "export"
        digest = exporter.export(self.run, destination, 1 << 20)
        manifest = exporter.verify(destination, digest)
        self.assertIn("target/debug/deps/workspace-test", manifest["files"])
        self.assertIn("source/.cargo/config.toml", manifest["files"])
        self.assertNotIn("target/debug/incremental/unreferenced-cache", manifest["files"])
        self.assertEqual(inventory(destination / "run"), manifest["files"])
        for directory in (destination, destination / "run", destination / "run/source/.cargo",
                          destination / "run/target/debug/deps"):
            with self.subTest(directory=directory):
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)

    def test_missing_changed_or_short_original_test_executable_fails_before_export(self):
        path = self.run / "target/debug/deps/workspace-test"
        for change in ("missing", "changed", "short"):
            with self.subTest(change=change):
                original = path.read_bytes()
                if change == "missing":
                    path.unlink()
                elif change == "changed":
                    path.write_bytes(b"X" + original[1:])
                else:
                    path.write_bytes(original[:-1])
                destination = self.root / ("export-" + change)
                with self.assertRaises(ValueError):
                    exporter.export(self.run, destination, 1 << 20)
                self.assertFalse(destination.exists())
                path.write_bytes(original)
                path.chmod(0o755)

    def test_missing_original_process_receipt_fails_before_export(self):
        path = self.run / "workspace-process.json"
        path.unlink()
        with self.assertRaises(ValueError):
            exporter.export(self.run, self.root / "missing-process", 1 << 20)
        self.assertFalse((self.root / "missing-process").exists())

    def test_budget_and_failed_original_run_cannot_produce_passing_export(self):
        with self.assertRaisesRegex(ValueError, "byte budget"):
            exporter.export(self.run, self.root / "too-small", 1)
        self.assertFalse((self.root / "too-small").exists())
        files, _ = exporter.roster(self.run)
        with self.assertRaisesRegex(ValueError, "byte budget"):
            exporter.export(self.run, self.root / "no-manifest-budget",
                            sum(value["bytes"] for value in files.values()))
        self.assertFalse((self.root / "no-manifest-budget").exists())
        self.record["status"] = "failed"
        write_json(self.run / "evidence.json", self.record)
        with self.assertRaisesRegex(ValueError, "passed original"):
            exporter.export(self.run, self.root / "failed", 1 << 20)
        self.assertFalse((self.root / "failed").exists())

    def test_transport_rejects_missing_changed_extra_and_wrong_manifest_digest(self):
        destination = self.root / "export"
        digest = exporter.export(self.run, destination, 1 << 20)
        for relative, change in (("target/debug/deps/workspace-test", "missing"),
                                 ("target/release/kasumid", "changed"),
                                 ("source/.cargo/config.toml", "short"),
                                 ("target/debug/extra-cache", "extra")):
            with self.subTest(change=change):
                path = destination / "run" / relative
                original = path.read_bytes() if path.exists() else None
                if change == "missing":
                    path.unlink()
                elif change == "changed":
                    path.write_bytes(b"X" + original[1:])
                elif change == "short":
                    path.write_bytes(original[:-1])
                else:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b"extra")
                with self.assertRaises(ValueError):
                    exporter.verify(destination, digest)
                if original is None:
                    path.unlink()
                else:
                    path.write_bytes(original)
                    path.chmod(0o755 if relative.startswith("target/") else 0o644)
        with self.assertRaisesRegex(ValueError, "manifest digest"):
            exporter.verify(destination, "0" * 64)
        manifest_path = destination / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["total_bytes"] = 0
        write_json(manifest_path, manifest)
        with self.assertRaisesRegex(ValueError, "byte accounting"):
            exporter.verify(destination, sha256(manifest_path))

    def test_source_archive_must_retain_hidden_source_bytes(self):
        self.write_source_tar(omitted={".cargo/config.toml"})
        self.record["source_archive_sha256"] = sha256(self.run / "source.tar")
        write_json(self.run / "evidence.json", self.record)
        with self.assertRaisesRegex(ValueError, "source archive differs"):
            exporter.export(self.run, self.root / "short-source", 1 << 20)
        self.assertFalse((self.root / "short-source").exists())

    def test_interrupted_copy_never_writes_a_passing_manifest(self):
        destination = self.root / "interrupted"
        original = exporter.copy_checked
        calls = 0
        def interrupt(source, copied, expected):
            nonlocal calls
            original(source, copied, expected)
            calls += 1
            if calls == 2:
                raise RuntimeError("synthetic copy interruption")
        with patch.object(exporter, "copy_checked", side_effect=interrupt):
            with self.assertRaisesRegex(RuntimeError, "copy interruption"):
                exporter.export(self.run, destination, 1 << 20)
        self.assertTrue((destination / "run").exists())
        self.assertFalse((destination / "manifest.json").exists())

    def test_archive_readback_preserves_modes_and_all_declared_bytes(self):
        exported = self.root / "export"
        manifest_digest = exporter.export(self.run, exported, 1 << 20)
        archive = self.root / "transport.tar"
        archive_digest = exporter.create_transport(exported, manifest_digest, archive, 1 << 20)
        self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o600)
        readback = self.root / "readback"
        exporter.check_transport(archive, archive_digest, manifest_digest, 1 << 20, readback)
        self.assertEqual(inventory(readback / "run"), inventory(exported / "run"))
        exporter.verify(readback, manifest_digest)
        for directory in (readback, readback / "run", readback / "run/source/.cargo"):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        for relative in ("tools/python", "target/debug/deps/workspace-test", "target/release/kasumid"):
            self.assertEqual(stat.S_IMODE((readback / "run" / relative).stat().st_mode), 0o755)

    def test_archive_readback_preserves_long_hidden_source_path_via_canonical_pax(self):
        relative = ".github/workflows/" + "x" * 120 + ".yml"
        self.assertGreater(len(relative.encode()), 100)
        self.file("source/" + relative, b"long hidden frozen source path\n")
        self.source_files = inventory(self.source)
        write_json(self.run / "source-files.json", self.source_files)
        self.write_source_tar()
        self.record["source_files_sha256"] = sha256(self.run / "source-files.json")
        self.record["source_archive_sha256"] = sha256(self.run / "source.tar")
        write_json(self.run / "evidence.json", self.record)
        exported = self.root / "export"
        manifest_digest = exporter.export(self.run, exported, 1 << 20)
        archive = self.root / "transport.tar"
        archive_digest = exporter.create_transport(exported, manifest_digest, archive, 1 << 20)
        name = "run/source/" + relative
        with tarfile.open(archive, "r:") as source:
            self.assertEqual(source.getmember(name).pax_headers, {"path": name})
        readback = self.root / "readback"
        exporter.check_transport(archive, archive_digest, manifest_digest, 1 << 20, readback)
        self.assertEqual((readback / name).read_bytes(), b"long hidden frozen source path\n")
        exporter.verify(readback, manifest_digest)

    def test_archive_and_readback_budgets_and_digest_must_bind_original_transport(self):
        exported = self.root / "export"
        manifest_digest = exporter.export(self.run, exported, 1 << 20)
        with self.assertRaisesRegex(ValueError, "byte budget"):
            exporter.create_transport(exported, manifest_digest, self.root / "too-small.tar", 1)
        self.assertFalse((self.root / "too-small.tar").exists())
        archive = self.root / "transport.tar"
        archive_digest = exporter.create_transport(exported, manifest_digest, archive, 1 << 20)
        with self.assertRaisesRegex(ValueError, "byte budget"):
            exporter.check_transport(archive, archive_digest, manifest_digest,
                                     archive.stat().st_size - 1, self.root / "too-small-readback")
        self.assertFalse((self.root / "too-small-readback").exists())
        altered = self.root / "altered.tar"
        content = archive.read_bytes()
        altered.write_bytes(b"X" + content[1:])
        with self.assertRaisesRegex(ValueError, "archive digest"):
            exporter.check_transport(altered, archive_digest, manifest_digest,
                                     1 << 20, self.root / "altered-readback")
        self.assertFalse((self.root / "altered-readback").exists())

    def test_archive_rejects_traversal_links_duplicates_and_omissions(self):
        exported = self.root / "export"
        manifest_digest = exporter.export(self.run, exported, 1 << 20)
        files = json.loads((exported / "manifest.json").read_text())["files"]
        names = ["run/" + relative for relative in sorted(files)]
        for kind in ("traversal", "symlink", "duplicate", "missing-hidden", "extra-pax",
                     "redundant-pax"):
            with self.subTest(kind=kind):
                archive = self.root / (kind + ".tar")
                with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT) as output:
                    manifest = exported / "manifest.json"
                    with manifest.open("rb") as stream:
                        output.addfile(exporter.archive_member("manifest.json", manifest, 0o600), stream)
                    for name in names:
                        if kind == "missing-hidden" and name == "run/source/.cargo/config.toml":
                            continue
                        if kind == "traversal" and name == names[0]:
                            info = tarfile.TarInfo("../escape")
                            info.size = 1
                            output.addfile(info, io.BytesIO(b"x"))
                            continue
                        if kind == "symlink" and name == names[0]:
                            info = tarfile.TarInfo(name)
                            info.type = tarfile.SYMTYPE
                            info.linkname = "../escape"
                            output.addfile(info)
                            continue
                        path = exported / name
                        mode = 0o755 if files[name.removeprefix("run/")]["executable"] else 0o644
                        with path.open("rb") as stream:
                            info = exporter.archive_member(name, path, mode)
                            if kind == "extra-pax" and name == names[0]:
                                info.pax_headers = {"comment": "unbound transport metadata"}
                            if kind == "redundant-pax" and name == names[0]:
                                info.pax_headers = {"path": name}
                            output.addfile(info, stream)
                    if kind == "duplicate":
                        name = names[-1]
                        path = exported / name
                        mode = 0o755 if files[name.removeprefix("run/")]["executable"] else 0o644
                        with path.open("rb") as stream:
                            output.addfile(exporter.archive_member(name, path, mode), stream)
                readback = self.root / (kind + "-readback")
                with self.assertRaisesRegex(ValueError, "PAX" if kind.endswith("pax") else "."):
                    exporter.check_transport(archive, sha256(archive), manifest_digest, 1 << 20, readback)
                self.assertFalse((readback / "manifest.json").exists())
                self.assertFalse((self.root.parent / "escape").exists())

    def test_archive_rejects_truncation_even_with_matching_new_digest(self):
        exported = self.root / "export"
        manifest_digest = exporter.export(self.run, exported, 1 << 20)
        archive = self.root / "transport.tar"
        exporter.create_transport(exported, manifest_digest, archive, 1 << 20)
        truncated = self.root / "truncated.tar"
        truncated.write_bytes(archive.read_bytes()[:1024])
        readback = self.root / "truncated-readback"
        with self.assertRaises((ValueError, OSError, tarfile.TarError)):
            exporter.check_transport(truncated, sha256(truncated), manifest_digest, 1 << 20, readback)
        self.assertFalse((readback / "manifest.json").exists())

    def test_failed_final_readback_verification_removes_success_manifest(self):
        exported = self.root / "export"
        manifest_digest = exporter.export(self.run, exported, 1 << 20)
        archive = self.root / "transport.tar"
        archive_digest = exporter.create_transport(exported, manifest_digest, archive, 1 << 20)
        readback = self.root / "readback"
        with patch.object(exporter, "verify", side_effect=ValueError("synthetic final readback failure")):
            with self.assertRaisesRegex(ValueError, "final readback failure"):
                exporter.check_transport(archive, archive_digest, manifest_digest, 1 << 20, readback)
        self.assertFalse((readback / "manifest.json").exists())


if __name__ == "__main__":
    unittest.main()
