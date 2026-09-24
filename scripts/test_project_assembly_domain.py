"""Synthetic counterexamples for a non-acceptance assembly projection."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import project_assembly_domain as projection
from release_gate import sha256
import repeatable_assembly as assembly
import transport_assembly_evidence as transport
import verify_release_acceptance as acceptance

TARGET = "aarch64-unknown-linux-gnu"
COMMIT = "1" * 40
TREE = "2" * 40
START = "2026-09-24T00:00:00+00:00"
END = "2026-09-24T00:10:00+00:00"


class ProjectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="assembly-domain-projection-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve(strict=True)
        self.primary_root = self.root / "selected"
        self.primary_root.mkdir()
        self.primary = self.primary_root / "evidence.json"
        self.primary_record = {"status": "passed", "source_commit": COMMIT,
                               "source_tree": TREE}
        self.primary.write_text(json.dumps(self.primary_record) + "\n")
        self.original = self.root / "original"
        inner = self.original / "assembly"
        inner.mkdir(parents=True)
        (self.original / "launcher.json").write_text('{"status":"passed"}\n')
        (inner / "attempt.json").write_text('{"status":"passed"}\n')
        blobs = inner / "blobs"
        blobs.mkdir()
        source_files = {projection.SOURCE_PATH: {"sha256": sha256(projection.__file__)}}
        (blobs / "source-files.json").write_text(json.dumps(source_files) + "\n")
        self.names = ["candidate-source.tar.gz", "candidate-" + TARGET + ".tar.gz"]
        for prefix in ("assembly-a-output", "assembly-b-output"):
            output = inner / prefix
            output.mkdir()
            for name in self.names:
                (output / name).write_bytes((name + "\n").encode())
        self.identity = {"target": TARGET, "source_commit": COMMIT,
                         "source_tree": TREE, "functional_sha256": sha256(self.primary),
                         "launcher_sha256": sha256(self.original / "launcher.json")}
        self.functional = self.root / "functional"
        self.functional.mkdir()
        self.archive = self.root / "assembly.tar"
        self.producer = self.root / "producer.json"
        self.native = self.root / "native.json"
        with patch.object(transport, "assembly_identity", return_value=self.identity):
            self.native_record = transport.produce(
                self.original, self.functional, self.archive, self.producer, self.native,
                1 << 20, TARGET, COMMIT, TREE)
        self.attestation = self.root / "operator-attestation.bin"
        self.attestation.write_bytes(b"synthetic untrusted host claim\n")
        self.reservation = self.root / "reservation.json"
        self.reservation_claim = {"schema": projection.RESERVATION_SCHEMA,
                                  "attempt_id": "attempt-001", "host_id": "claimed-host-1",
                                  "target": TARGET, "starts_at": START,
                                  "ends_at": END, "cpu_count": 2,
                                  "memory_bytes": 15 << 30, "disk_bytes": 64 << 30}
        self.write_reservation()
        self.attempt_record = self.root / "attempt-record.json"
        self.attempt_claim = {"schema": projection.ATTEMPT_SCHEMA,
                              "attempt_id": "attempt-001", "registry_id": "unverified-ledger-1",
                              "sequence": 1, "previous_sha256": "0" * 64,
                              "issued_at": "2026-09-23T23:59:00+00:00",
                              "target": TARGET, "source_commit": COMMIT}
        self.write_attempt()
        self.output = self.root / "projection"

    def write_reservation(self):
        self.reservation.write_bytes(transport.canonical(self.reservation_claim))

    def write_attempt(self):
        self.attempt_record.write_bytes(transport.canonical(self.attempt_claim))

    def project(self, *, producer_sha=None, selected=None, attempt_id="attempt-001"):
        inner = self.original / "assembly"
        frozen = {"source-files.json": {"file": assembly.ref(
            inner, inner / "blobs/source-files.json")}}
        fake_owned = {"record": {"started_at": START, "finished_at": END},
                      "inner": {"frozen": frozen, "archives": self.names}}
        selected = selected or self.primary
        selected_record = acceptance.read_json(selected)
        with patch.object(transport, "assembly_identity", return_value=self.identity), \
             patch.object(projection.owned, "verify", return_value=fake_owned), \
             patch.object(projection.package, "verify_evidence",
                          return_value=(selected_record, None, TARGET, {})):
            return projection.project(
                self.archive, self.producer,
                producer_sha or self.native_record["producer"]["sha256"],
                1 << 20, selected, self.attestation, self.reservation,
                attempt_id, self.attempt_record, self.output)

    def test_collects_raw_bytes_and_never_emits_release_success(self):
        value = self.project()
        self.assertEqual(value["schema"], projection.SCHEMA)
        self.assertEqual(value["status"], "unqualified")
        self.assertNotEqual(value["schema"], acceptance.SCHEMA)
        self.assertFalse(value["unverified_claims"]["authenticated_host"])
        self.assertFalse(value["unverified_claims"]["durable_attempt_completeness"])
        self.assertFalse(value["unverified_claims"]["selected_by_final_manifest"])
        self.assertEqual(value["unverified_claims"]["files"]["attempt_record"]["sha256"],
                         sha256(self.attempt_record))
        self.assertEqual(value["derived"]["functional_sha256"], sha256(self.primary))
        self.assertEqual(value["derived"]["supplied_producer_sha256"],
                         self.native_record["producer"]["sha256"])
        self.assertEqual(len(value["derived"]["archives"]), 2)
        self.assertTrue((self.output / "collection/assembly/assembly/attempt.json").exists())
        self.assertEqual(acceptance.read_json(self.output / "projection.json"), value)
        self.assertEqual(acceptance.DOMAIN_ADAPTERS, {})

    def test_external_producer_digest_is_required(self):
        with self.assertRaisesRegex(ValueError, "external digest"):
            self.project(producer_sha="0" * 64)
        self.assertFalse((self.output / "projection.json").exists())

    def test_failed_or_interrupted_raw_transport_cannot_project_success(self):
        self.archive = self.root / "failed-assembly.tar"
        self.producer = self.root / "failed-producer.json"
        self.native = self.root / "failed-native.json"
        self.native_record = transport.produce_failure(
            self.original, self.archive, self.producer, self.native,
            1 << 20, TARGET, COMMIT, TREE)
        self.assertEqual(self.native_record["status"], "interrupted")
        with self.assertRaisesRegex(ValueError, "not passing transport"):
            self.project()
        self.assertFalse((self.output / "projection.json").exists())

    def test_raw_archive_mutation_rejects_before_projection(self):
        with self.archive.open("ab") as stream:
            stream.write(b"after native producer")
        with self.assertRaisesRegex(ValueError, "differs from producer"):
            self.project()
        self.assertFalse((self.output / "projection.json").exists())

    def test_substituted_selected_primary_is_rejected(self):
        different = self.root / "different"
        different.mkdir()
        selected = different / "evidence.json"
        selected.write_text(json.dumps({**self.primary_record, "other": True}) + "\n")
        with self.assertRaisesRegex(ValueError, "target/source differ"):
            self.project(selected=selected)
        self.assertFalse((self.output / "projection.json").exists())

    def test_reservation_attempt_and_interval_are_only_bounded_claims(self):
        self.reservation_claim["attempt_id"] = "another-attempt"
        self.write_reservation()
        with self.assertRaisesRegex(ValueError, "claimed attempt"):
            self.project()
        self.assertFalse(self.output.exists())
        self.reservation_claim["attempt_id"] = "attempt-001"
        self.reservation_claim["ends_at"] = "2026-09-24T00:05:00+00:00"
        self.write_reservation()
        with self.assertRaisesRegex(ValueError, "claimed reservation interval"):
            self.project()
        self.assertFalse((self.output / "projection.json").exists())

    def test_attempt_registry_claim_mismatch_is_rejected_without_immutability_claim(self):
        self.attempt_claim["attempt_id"] = "different"
        self.write_attempt()
        with self.assertRaisesRegex(ValueError, "does not identify this attempt"):
            self.project()
        self.assertFalse(self.output.exists())
        self.attempt_claim["attempt_id"] = "attempt-001"
        self.attempt_claim["source_commit"] = "9" * 40
        self.write_attempt()
        with self.assertRaisesRegex(ValueError, "target/source differ"):
            self.project()
        self.assertFalse((self.output / "projection.json").exists())

    def test_frozen_source_mismatch_rejects_projection(self):
        inner = self.original / "assembly"
        path = inner / "blobs/source-files.json"
        path.write_text(json.dumps({projection.SOURCE_PATH: {"sha256": "0" * 64}}) + "\n")
        # A new original would carry its own transport identity; this test
        # exercises the final source join on a freshly rebuilt raw archive.
        self.archive.unlink()
        self.producer.unlink()
        self.native.unlink()
        with patch.object(transport, "assembly_identity", return_value=self.identity):
            self.native_record = transport.produce(
                self.original, self.functional, self.archive, self.producer, self.native,
                1 << 20, TARGET, COMMIT, TREE)
        with self.assertRaisesRegex(ValueError, "projection implementation differs"):
            self.project()
        self.assertFalse((self.output / "projection.json").exists())


if __name__ == "__main__":
    unittest.main()
