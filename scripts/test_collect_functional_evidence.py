"""Synthetic collector tests; none are native release evidence."""
import contextlib
import io
import json
from pathlib import Path
import shutil
import stat
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import collect_functional_evidence as collector
import export_functional_evidence as exporter
from release_gate import inventory, sha256, write_json
import verify_release_acceptance as acceptance


TARGET = "aarch64-unknown-linux-gnu"


class CollectorTests(unittest.TestCase):
    def setUp(self):
        base = Path(__file__).resolve().parents[1] / "tmp"
        base.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=base)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.run = self.root / "original"
        self.run.mkdir()
        self.source = self.run / "source"
        self.source.mkdir()
        self.file("source/Cargo.lock", b"synthetic lock\n")
        self.file("source/.cargo/config.toml", b"[net]\noffline = true\n")
        self.file("source/scripts/export_functional_evidence.py", Path(exporter.__file__).read_bytes())
        source_files = inventory(self.source)
        write_json(self.run / "source-files.json", source_files)
        with tarfile.open(self.run / "source.tar", "w") as archive:
            for relative, value in source_files.items():
                data = (self.source / relative).read_bytes()
                item = tarfile.TarInfo(relative)
                item.size = len(data)
                item.mode = 0o755 if value["executable"] else 0o644
                archive.addfile(item, io.BytesIO(data))
        interpreter = self.file("tools/python", b"synthetic interpreter", executable=True)
        executable = self.file("target/debug/deps/workspace-test", b"synthetic test", executable=True)
        log = self.file("workspace.log", (json.dumps({
            "reason": "compiler-artifact", "executable": str(executable),
            "target": {"name": "workspace-test"}, "profile": {"test": True},
            "package_id": "synthetic:workspace"}) + "\n").encode())
        process = self.file("workspace-process.json", b"{}\n")
        resources = self.file("workspace-resources.json", b"{}\n")
        self.record = {
            "schema": 1, "status": "passed", "toolchain": "1.97.1",
            "source_commit": "1" * 40, "source_tree": "2" * 40,
            "source_archive_sha256": sha256(self.run / "source.tar"),
            "source_files_sha256": sha256(self.run / "source-files.json"),
            "lockfile_sha256": sha256(self.source / "Cargo.lock"),
            "started_at": "2026-09-24T00:00:00+00:00",
            "finished_at": "2026-09-24T00:00:01+00:00",
            "python_executable": {"artifact": "tools/python", "sha256": sha256(interpreter)},
            "gates": [{"name": "workspace", "log": "workspace.log", "log_sha256": sha256(log),
                       "process": "workspace-process.json", "process_sha256": sha256(process),
                       "resources": "workspace-resources.json", "resources_sha256": sha256(resources),
                       "executables": {"debug/deps/workspace-test": {
                           "sha256": sha256(executable), "bytes": executable.stat().st_size}}}],
        }
        write_json(self.run / "evidence.json", self.record)
        self.fake_verifier = patch.object(exporter.package, "verify_evidence", side_effect=self.verify_synthetic)
        self.fake_verifier.start()
        self.addCleanup(self.fake_verifier.stop)

    def file(self, relative, contents, executable=False):
        path = self.run / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
        path.chmod(0o755 if executable else 0o644)
        return path

    def verify_synthetic(self, directory):
        record = acceptance.read_json(Path(directory) / "evidence.json")
        if record.get("status") != "passed":
            raise ValueError("synthetic functional record failed")
        return record, record["gates"][0], TARGET, {}

    def transport(self):
        exported = self.root / "export"
        manifest_sha = exporter.export(self.run, exported, 1 << 20)
        archive = self.root / "downloaded.tar"
        archive_sha = exporter.create_transport(exported, manifest_sha, archive, 1 << 20)
        return archive, archive_sha, manifest_sha

    def expected(self, archive, archive_sha, manifest_sha, output):
        producer = self.root / ("producer-" + output.name + ".json")
        producer_sha = exporter.produce_identity(
            self.run, self.root / "export", archive, manifest_sha, archive_sha,
            TARGET, self.record["source_commit"], self.record["source_tree"],
            1 << 20, producer)
        return {"archive": archive, "producer_manifest": producer,
                "producer_sha256": producer_sha, "max_bytes": 1 << 20,
                "output": output}

    def change_producer(self, args, section, field, value):
        path = args["producer_manifest"]
        record = acceptance.read_json(path)
        if section is None:
            record[field] = value
        else:
            record[section][field] = value
        write_json(path, record)
        args["producer_sha256"] = sha256(path)

    def test_collector_receipt_follows_portable_tar_readback_and_exact_identity(self):
        archive, archive_sha, manifest_sha = self.transport()
        args = self.expected(archive, archive_sha, manifest_sha, self.root / "collected")
        shutil.rmtree(self.run)
        shutil.rmtree(self.root / "export")
        receipt = collector.collect(**args)
        self.assertEqual(acceptance.read_json(args["output"] / "receipt.json"), receipt)
        self.assertEqual({p.name for p in args["output"].iterdir()},
                         {"receipt.json", "readback", "producer.json"})
        self.assertEqual(stat.S_IMODE((args["output"] / "receipt.json").stat().st_mode), 0o600)
        self.assertEqual(receipt["target"], TARGET)
        self.assertEqual(receipt["run"]["evidence_sha256"],
                         sha256(args["output"] / "readback/run/evidence.json"))
        self.assertEqual(receipt["producer"]["sha256"], args["producer_sha256"])
        self.assertEqual(sha256(args["output"] / "producer.json"), args["producer_sha256"])
        self.assertEqual(receipt["archive"]["sha256"], archive_sha)
        self.assertIn("target/debug/deps/workspace-test",
                      exporter.verify(args["output"] / "readback", manifest_sha)["files"])

    def test_external_digests_and_cap_fail_without_success_receipt(self):
        archive, archive_sha, manifest_sha = self.transport()
        changes = {"producer_sha256": "0" * 64, "archive_sha256": "0" * 64,
                   "manifest_sha256": "0" * 64,
                   "max_bytes": archive.stat().st_size - 1}
        for index, (field, value) in enumerate(changes.items()):
            with self.subTest(field=field):
                args = self.expected(archive, archive_sha, manifest_sha, self.root / f"bad-{index}")
                if field in ("archive_sha256", "manifest_sha256"):
                    self.change_producer(args, "transport", field, value)
                else:
                    args[field] = value
                with self.assertRaises(ValueError):
                    collector.collect(**args)
                self.assertFalse((args["output"] / "receipt.json").exists())

    def test_producer_json_is_exact_canonical_and_typed(self):
        archive, archive_sha, manifest_sha = self.transport()
        duplicate = self.expected(archive, archive_sha, manifest_sha, self.root / "duplicate-producer")
        path = duplicate["producer_manifest"]
        data = path.read_bytes()
        self.assertIn(b'"status": "passed",', data)
        path.write_bytes(data.replace(b'"status": "passed",',
                                      b'"status": "passed", "status": "passed",', 1))
        duplicate["producer_sha256"] = sha256(path)
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            collector.collect(**duplicate)
        self.assertFalse((duplicate["output"] / "receipt.json").exists())

        untyped = self.expected(archive, archive_sha, manifest_sha, self.root / "untyped-producer")
        self.change_producer(untyped, "transport", "max_bytes", True)
        with self.assertRaisesRegex(ValueError, "bounded integer"):
            collector.collect(**untyped)
        self.assertFalse((untyped["output"] / "receipt.json").exists())

        noncanonical = self.expected(archive, archive_sha, manifest_sha,
                                     self.root / "noncanonical-producer")
        path = noncanonical["producer_manifest"]
        path.write_text(json.dumps(acceptance.read_json(path), separators=(",", ":")) + "\n")
        noncanonical["producer_sha256"] = sha256(path)
        with self.assertRaisesRegex(ValueError, "not canonical"):
            collector.collect(**noncanonical)
        self.assertFalse((noncanonical["output"] / "receipt.json").exists())

    def test_target_source_and_run_drift_leave_no_collector_success(self):
        archive, archive_sha, manifest_sha = self.transport()
        changes = {"target": "x86_64-unknown-linux-gnu", "source_commit": "3" * 40,
                   "source_tree": "4" * 40, "source_archive_sha256": "5" * 64,
                   "source_files_sha256": "6" * 64, "lockfile_sha256": "7" * 64,
                   "evidence_sha256": "8" * 64}
        for index, (field, value) in enumerate(changes.items()):
            with self.subTest(field=field):
                args = self.expected(archive, archive_sha, manifest_sha, self.root / f"drift-{index}")
                section, key = {
                    "target": (None, "target"),
                    "source_commit": ("source", "commit"),
                    "source_tree": ("source", "tree"),
                    "source_archive_sha256": ("source", "archive_sha256"),
                    "source_files_sha256": ("source", "files_sha256"),
                    "lockfile_sha256": ("source", "lockfile_sha256"),
                    "evidence_sha256": ("run", "evidence_sha256"),
                }[field]
                self.change_producer(args, section, key, value)
                with self.assertRaisesRegex(ValueError, "identity differs"):
                    collector.collect(**args)
                self.assertFalse((args["output"] / "receipt.json").exists())

    def test_zero_duration_run_cannot_gain_collector_success(self):
        archive, archive_sha, manifest_sha = self.transport()
        args = self.expected(archive, archive_sha, manifest_sha, self.root / "zero-duration")
        producer = acceptance.read_json(args["producer_manifest"])
        self.change_producer(args, "run", "finished_at", producer["run"]["started_at"])
        with self.assertRaisesRegex(ValueError, "positive UTC interval"):
            collector.collect(**args)
        self.assertFalse((args["output"] / "receipt.json").exists())

    def test_extra_tar_member_rejected_even_with_new_archive_digest(self):
        archive, archive_sha, manifest_sha = self.transport()
        tampered = self.root / "extra.tar"
        with tarfile.open(archive, "r:") as original, tarfile.open(tampered, "w:", format=tarfile.PAX_FORMAT) as changed:
            for item in original:
                changed.addfile(item, original.extractfile(item))
            extra = tarfile.TarInfo("run/extra")
            extra.size = 1
            changed.addfile(extra, io.BytesIO(b"x"))
        args = self.expected(archive, archive_sha, manifest_sha, self.root / "extra-readback")
        args["archive"] = tampered
        self.change_producer(args, "transport", "archive_name", tampered.name)
        self.change_producer(args, "transport", "archive_sha256", sha256(tampered))
        self.change_producer(args, "transport", "archive_bytes", tampered.stat().st_size)
        with self.assertRaisesRegex(ValueError, "extra member"):
            collector.collect(**args)
        self.assertFalse((args["output"] / "receipt.json").exists())

    def test_missing_tar_member_rejected_even_with_new_archive_digest(self):
        archive, archive_sha, manifest_sha = self.transport()
        shortened = self.root / "missing.tar"
        with tarfile.open(archive, "r:") as original, tarfile.open(shortened, "w:", format=tarfile.PAX_FORMAT) as changed:
            for item in original:
                if item.name == "run/target/debug/deps/workspace-test":
                    continue
                changed.addfile(item, original.extractfile(item))
        args = self.expected(archive, archive_sha, manifest_sha, self.root / "missing-readback")
        args["archive"] = shortened
        self.change_producer(args, "transport", "archive_name", shortened.name)
        self.change_producer(args, "transport", "archive_sha256", sha256(shortened))
        self.change_producer(args, "transport", "archive_bytes", shortened.stat().st_size)
        with self.assertRaisesRegex(ValueError, "unsafe or mismatched|omitted a required file"):
            collector.collect(**args)
        self.assertFalse((args["output"] / "receipt.json").exists())

    def test_readback_mutation_before_identity_check_cannot_publish_receipt(self):
        archive, archive_sha, manifest_sha = self.transport()
        args = self.expected(archive, archive_sha, manifest_sha, self.root / "mutated-readback")
        original = exporter.check_transport

        def mutated(*values):
            manifest = original(*values)
            evidence = args["output"] / "readback/run/evidence.json"
            evidence.write_bytes(evidence.read_bytes() + b"tampered")
            return manifest

        with patch.object(collector.exporter, "check_transport", side_effect=mutated):
            with self.assertRaises(ValueError):
                collector.collect(**args)
        self.assertFalse((args["output"] / "receipt.json").exists())

    def test_failed_final_receipt_readback_removes_success_marker(self):
        archive, archive_sha, manifest_sha = self.transport()
        args = self.expected(archive, archive_sha, manifest_sha, self.root / "receipt-changed")
        original = acceptance.read_json

        def substituted(path):
            value = original(path)
            if Path(path).name == "receipt.json":
                return {**value, "status": "substituted"}
            return value

        with patch.object(collector.acceptance, "read_json", side_effect=substituted):
            with self.assertRaisesRegex(ValueError, "success receipt changed"):
                collector.collect(**args)
        self.assertFalse((args["output"] / "receipt.json").exists())

    def test_cli_returns_failure_for_wrong_target_and_success_for_exact_inputs(self):
        archive, archive_sha, manifest_sha = self.transport()
        args = self.expected(archive, archive_sha, manifest_sha, self.root / "cli-success")
        def command(values):
            return ["--archive", str(values["archive"]),
                    "--producer-manifest", str(values["producer_manifest"]),
                    "--producer-sha256", values["producer_sha256"],
                    "--max-bytes", str(values["max_bytes"]), "--output", str(values["output"])]
        bad = {**args, "producer_sha256": "0" * 64, "output": self.root / "cli-bad"}
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(collector.main(command(bad)), 1)
        self.assertFalse((bad["output"] / "receipt.json").exists())
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(collector.main(command(args)), 0)
        self.assertTrue((args["output"] / "receipt.json").is_file())

    def test_native_producer_rejects_wrong_git_and_tampered_transport(self):
        archive, archive_sha, manifest_sha = self.transport()
        with self.assertRaisesRegex(ValueError, "Git identity differs"):
            exporter.produce_identity(
                self.run, self.root / "export", archive, manifest_sha, archive_sha,
                TARGET, "9" * 40, self.record["source_tree"], 1 << 20,
                self.root / "wrong-git-producer.json")
        self.assertFalse((self.root / "wrong-git-producer.json").exists())
        archive.write_bytes(archive.read_bytes() + b"extra")
        with self.assertRaisesRegex(ValueError, "digest differs"):
            exporter.produce_identity(
                self.run, self.root / "export", archive, manifest_sha, archive_sha,
                TARGET, self.record["source_commit"], self.record["source_tree"],
                1 << 20, self.root / "tampered-producer.json")
        self.assertFalse((self.root / "tampered-producer.json").exists())


if __name__ == "__main__":
    unittest.main()
