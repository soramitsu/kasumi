"""Synthetic transport attacks; these are not native assembly evidence."""
import copy
import hashlib
import io
import json
from pathlib import Path
import stat
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import transport_assembly_evidence as transport
from release_gate import sha256


IDENTITY = {"target": "aarch64-unknown-linux-gnu",
            "source_commit": "1" * 40, "source_tree": "2" * 40,
            "functional_sha256": "3" * 64, "launcher_sha256": "4" * 64}


class AssemblyTransportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="assembly-transport-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve(strict=True)
        self.assembly = self.root / "owned"
        self.assembly.mkdir(mode=0o700)
        (self.assembly / "assembly").mkdir(mode=0o700)
        (self.assembly / "empty").mkdir(mode=0o750)
        (self.assembly / ("dir-" + "あ" * 60)).mkdir(mode=0o750)
        (self.assembly / "launcher.json").write_bytes(b'{"status":"passed"}\n')
        (self.assembly / "assembly/attempt.json").write_bytes(b'{"status":"passed"}\n')
        script = self.assembly / "assembly" / ("unicode-" + "あ" * 60)
        script.write_bytes(b"synthetic bytes and executable mode\n")
        script.chmod(0o750)
        (self.assembly / "launcher.json").chmod(0o600)
        (self.assembly / "assembly/attempt.json").chmod(0o600)
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        self.archive = self.root / "native-assembly.tar"
        self.producer = self.root / "native-assembly.json"
        self.receipt = self.root / "native-receipt.json"
        self.identity = patch.object(transport, "assembly_identity", return_value=IDENTITY)
        self.identity.start()
        self.addCleanup(self.identity.stop)

    def produce(self, max_bytes=1 << 20):
        return transport.produce(self.assembly, self.evidence, self.archive,
                                 self.producer, self.receipt, max_bytes,
                                 IDENTITY["target"], IDENTITY["source_commit"],
                                 IDENTITY["source_tree"])

    def failure_paths(self):
        return (self.root / "failed-assembly.tar", self.root / "failed-producer.json",
                self.root / "failure-transport.json")

    def snapshot_failure(self, max_bytes=1 << 20):
        archive, producer, receipt = self.failure_paths()
        return transport.produce_failure(self.assembly, archive, producer, receipt,
                                         max_bytes, IDENTITY["target"],
                                         IDENTITY["source_commit"], IDENTITY["source_tree"])

    def manifest(self):
        with tarfile.open(self.archive, "r:") as source:
            first = next(iter(source))
            return source.extractfile(first).read()

    def rewrite(self, alter):
        members = []
        with tarfile.open(self.archive, "r:") as source:
            for member in source:
                stream = source.extractfile(member)
                members.append((copy.copy(member), stream.read() if stream else b""))
        alter(members)
        changed = self.root / "changed.tar"
        with tarfile.open(changed, "w", format=tarfile.PAX_FORMAT) as output:
            for member, data in members:
                output.addfile(member, io.BytesIO(data))
        return changed

    def test_roundtrip_preserves_file_and_empty_directory_modes(self):
        native = self.produce()
        self.assertEqual(native["schema"], transport.NATIVE_SCHEMA)
        self.assertEqual(transport.read_native_receipt(self.receipt), native)
        self.assertEqual(sha256(self.archive), native["archive"]["sha256"])
        self.assertEqual(sha256(self.producer), native["producer"]["sha256"])
        collected = self.root / "collected"
        record = transport.collect(self.archive, self.producer,
                                   native["producer"]["sha256"], 1 << 20, collected)
        self.assertEqual(record["identity"], IDENTITY)
        self.assertEqual(stat.S_IMODE((collected / "assembly/empty").stat().st_mode), 0o750)
        self.assertEqual(transport.census(self.assembly, 1 << 20),
                         transport.census(collected / "assembly", 1 << 20))
        self.assertEqual(sha256(collected / "producer.json"), native["producer"]["sha256"])
        with tarfile.open(self.archive, "r:") as raw:
            names = raw.getnames()
        self.assertIn("assembly", names)
        self.assertIn("assembly/empty", names)
        extracted = self.root / "ordinary-extraction"
        extracted.mkdir()
        subprocess.run(["tar", "-xpf", str(self.archive), "-C", str(extracted)], check=True)
        self.assertEqual(stat.S_IMODE((extracted / "assembly/empty").stat().st_mode), 0o750)

    def test_external_producer_digest_and_archive_bytes_are_required(self):
        native = self.produce()
        with self.assertRaisesRegex(ValueError, "external digest"):
            transport.collect(self.archive, self.producer, "0" * 64,
                              1 << 20, self.root / "bad-producer")
        self.assertFalse((self.root / "bad-producer").exists())
        with self.archive.open("ab") as stream:
            stream.write(b"changed")
        with self.assertRaisesRegex(ValueError, "differs from producer"):
            transport.collect(self.archive, self.producer, native["producer"]["sha256"],
                              1 << 20, self.root / "bad-archive")
        self.assertFalse((self.root / "bad-archive/receipt.json").exists())

    def test_native_sidecar_rejects_extra_fields_even_when_rewritten(self):
        self.produce()
        sidecar = json.loads(self.receipt.read_text())
        sidecar["waiver"] = True
        self.receipt.write_text(json.dumps(sidecar, indent=2, sort_keys=True) + "\n")
        with self.assertRaisesRegex(ValueError, "fields differ"):
            transport.read_native_receipt(self.receipt)

    def test_rehashed_member_mode_extra_and_missing_are_rejected(self):
        native = self.produce()
        manifest_sha = native["manifest_sha256"]
        for name, edit in (
            ("mode", lambda members: setattr(members[-1][0], "mode", 0o644)),
            ("extra", lambda members: members.append(copy.deepcopy(members[-1]))),
            ("missing", lambda members: members.pop()),
            ("directory-mode", lambda members: setattr(members[1][0], "mode", 0o755)),
            ("missing-directory", lambda members: members.pop(1)),
            ("extra-directory", lambda members: members.insert(2, copy.deepcopy(members[1]))),
            ("data", lambda members: members.__setitem__(
                -1, (members[-1][0], b"X" + members[-1][1][1:]))),
        ):
            with self.subTest(name=name):
                changed = self.rewrite(edit)
                with self.assertRaises(ValueError):
                    transport.check_archive(changed, sha256(changed), manifest_sha, 1 << 20)
                changed.unlink()

    def test_rehashed_appended_tar_trailer_is_rejected(self):
        native = self.produce()
        changed = self.root / "appended.tar"
        changed.write_bytes(self.archive.read_bytes() + b"\x00" * 10240)
        with self.assertRaisesRegex(ValueError, "trailer"):
            transport.check_archive(changed, sha256(changed), native["manifest_sha256"], 1 << 20)

    def test_symlink_and_byte_cap_fail_before_success_marker(self):
        (self.assembly / "alias").symlink_to(self.assembly / "launcher.json")
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.produce()
        self.assertFalse(self.receipt.exists())
        (self.assembly / "alias").unlink()
        with self.assertRaisesRegex(ValueError, "payload exceeds byte cap"):
            self.produce(1)
        self.assertFalse(self.archive.exists())
        self.assertFalse(self.producer.exists())
        self.assertFalse(self.receipt.exists())

    def test_failed_original_owned_verification_cannot_publish(self):
        self.identity.stop()
        with patch.object(transport.owned, "verify", side_effect=ValueError("owned launcher failed")):
            with self.assertRaisesRegex(ValueError, "owned launcher failed"):
                self.produce()
        self.assertFalse(self.archive.exists())
        self.assertFalse(self.producer.exists())
        self.assertFalse(self.receipt.exists())

    def test_failed_attempt_roundtrip_covers_hidden_files_and_empty_directory(self):
        (self.assembly / "launcher.json").write_text(json.dumps({
            "schema": transport.owned.SCHEMA, "status": "failed"}) + "\n")
        (self.assembly / "assembly/attempt.json").unlink()
        (self.assembly / "assembly/.hidden").write_bytes(b"failed hidden data")
        (self.assembly / "assembly/.hidden").chmod(0o640)
        archive, producer, receipt = self.failure_paths()
        with patch.object(transport, "assembly_identity", side_effect=AssertionError(
                "failure snapshot must not assert assembly success")):
            native = self.snapshot_failure()
            collected = self.root / "failed-collected"
            record = transport.collect(archive, producer, native["producer"]["sha256"],
                                       1 << 20, collected)
        self.assertEqual(native["status"], "failed")
        self.assertEqual(record["schema"], transport.FAILURE_COLLECTOR_SCHEMA)
        self.assertEqual(record["status"], "failed")
        self.assertEqual(transport.read_native_receipt(receipt), native)
        self.assertEqual(transport.census(self.assembly, 1 << 20, require_receipts=False),
                         transport.census(collected / "assembly", 1 << 20,
                                          require_receipts=False))
        self.assertEqual(stat.S_IMODE((collected / "assembly/empty").stat().st_mode), 0o750)
        self.assertFalse(self.receipt.exists())
        extracted = self.root / "ordinary-failure-extraction"
        extracted.mkdir()
        subprocess.run(["tar", "-xpf", str(archive), "-C", str(extracted)], check=True)
        self.assertEqual((extracted / "assembly/assembly/.hidden").read_bytes(),
                         b"failed hidden data")
        self.assertEqual(stat.S_IMODE((extracted / "assembly/empty").stat().st_mode),
                         0o750)

    def test_interrupted_attempt_without_launcher_or_child_receipt(self):
        (self.assembly / "launcher.json").unlink()
        (self.assembly / "assembly/attempt.json").unlink()
        archive, producer, receipt = self.failure_paths()
        native = self.snapshot_failure()
        record = transport.collect(archive, producer, native["producer"]["sha256"],
                                   1 << 20, self.root / "interrupted-collected")
        self.assertEqual(native["status"], "interrupted")
        self.assertEqual(record["status"], "interrupted")
        self.assertFalse(self.receipt.exists())
        self.assertTrue(receipt.exists())

    def test_empty_interrupted_root(self):
        for path in self.assembly.rglob("*"):
            if path.is_file():
                path.unlink()
        for path in sorted(self.assembly.rglob("*"), key=lambda p: len(p.parts), reverse=True):
            if path.is_dir():
                path.rmdir()
        native = self.snapshot_failure()
        self.assertEqual(native["status"], "interrupted")
        archive, producer, _ = self.failure_paths()
        record = transport.collect(archive, producer, native["producer"]["sha256"],
                                   1 << 20, self.root / "empty-collected")
        self.assertEqual(record["file_count"], 0)
        self.assertEqual(record["directory_count"], 0)
        self.assertFalse(self.receipt.exists())

    def test_success_transport_failure_is_only_interrupted_snapshot(self):
        actual_publish = transport.publish
        def reject_success_producer(path, value):
            if value.get("schema") == transport.PRODUCER_SCHEMA:
                raise OSError("synthetic success producer failure")
            return actual_publish(path, value)
        with patch.object(transport, "publish", side_effect=reject_success_producer):
            with self.assertRaisesRegex(OSError, "synthetic success producer failure"):
                self.produce()
        self.assertFalse(self.receipt.exists())
        native = self.snapshot_failure()
        self.assertEqual(native["status"], "interrupted")
        self.assertFalse(self.receipt.exists())

    def test_cleanup_failure_after_passed_transport_keeps_both_records(self):
        passed = self.produce()
        original_archive_sha = passed["archive"]["sha256"]
        interrupted = self.snapshot_failure()
        failure_archive, failure_producer, failure_receipt = self.failure_paths()
        self.assertEqual(interrupted["status"], "interrupted")
        self.assertEqual(transport.read_native_receipt(failure_receipt)["status"],
                         "interrupted")
        self.assertEqual(transport.read_native_receipt(self.receipt)["status"], "passed")
        self.assertEqual(sha256(self.archive), original_archive_sha)
        collected = transport.collect(failure_archive, failure_producer,
                                      interrupted["producer"]["sha256"], 1 << 20,
                                      self.root / "cleanup-failure-collected")
        self.assertEqual(collected["schema"], transport.FAILURE_COLLECTOR_SCHEMA)

    def test_unreadable_failed_file_is_fail_closed_without_mutation(self):
        path = self.assembly / "assembly/unreadable"
        path.write_bytes(b"preserve only with authorized custody")
        path.chmod(0o000)
        before = stat.S_IMODE(path.stat().st_mode)
        with self.assertRaisesRegex(ValueError, "mode is unsupported"):
            self.snapshot_failure()
        archive, producer, receipt = self.failure_paths()
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), before)
        self.assertFalse(archive.exists())
        self.assertFalse(producer.exists())
        self.assertFalse(receipt.exists())
        self.assertFalse(self.receipt.exists())

    def test_transport_cap_failure_retains_original_and_no_terminal_marker(self):
        before = transport.census(self.assembly, 1 << 20, require_receipts=False)
        with self.assertRaises(ValueError):
            self.snapshot_failure(1)
        archive, producer, receipt = self.failure_paths()
        self.assertFalse(archive.exists())
        self.assertFalse(producer.exists())
        self.assertFalse(receipt.exists())
        self.assertFalse(self.receipt.exists())
        self.assertEqual(before, transport.census(self.assembly, 1 << 20,
                                                 require_receipts=False))

    def test_failure_publication_error_can_retry_without_losing_original(self):
        original = transport.census(self.assembly, 1 << 20, require_receipts=False)
        actual_publish = transport.publish
        def reject_producer(path, value):
            if value.get("schema") == transport.FAILURE_PRODUCER_SCHEMA:
                raise OSError("synthetic publication failure")
            return actual_publish(path, value)
        with patch.object(transport, "publish", side_effect=reject_producer):
            with self.assertRaisesRegex(OSError, "synthetic publication failure"):
                self.snapshot_failure()
        archive, producer, receipt = self.failure_paths()
        self.assertFalse(archive.exists())
        self.assertFalse(producer.exists())
        self.assertFalse(receipt.exists())
        self.assertEqual(original, transport.census(self.assembly, 1 << 20,
                                                    require_receipts=False))
        self.assertEqual(self.snapshot_failure()["status"], "interrupted")


if __name__ == "__main__":
    unittest.main()
