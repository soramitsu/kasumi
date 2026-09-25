"""Synthetic attempt-journal counterexamples, never native release evidence."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import attempt_index as index


class AttemptIndexTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="attempt-index-unit-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve(strict=True)
        self.output = self.root / "assembly-one"
        self.started = "2026-09-24T00:00:00+00:00"
        self.finished = "2026-09-24T00:00:10+00:00"
        self.journal = self.root / "attempts/index.jsonl"

    def begin(self, attempt_id="assembly-one", output=None):
        return index.begin(self.root, attempt_id, "repeatable-assembly",
                           output or self.output, self.started)

    def finish(self, attempt_id="assembly-one", output=None, status="passed",
               schema="kasumi-owned-repeatable-assembly-v1", custody_root=None):
        output = output or self.output
        output.mkdir()
        outcome = output / "launcher.json"
        outcome.write_text(json.dumps({"schema": schema,
                                       "custody_root": custody_root or str(output),
                                       "attempt_id": attempt_id, "status": status,
                                       "started_at": self.started, "finished_at": self.finished}) + "\n")
        domain_ref = None
        if status == "passed":
            inner = output / "assembly"
            inner.mkdir()
            report = inner / "attempt.json"
            report.write_text('{"synthetic":true}\n')
            outputs = []
            for kind, name in (("package", "kasumi-aarch64-unknown-linux-gnu.tar.gz"),
                               ("source", "kasumi-source.tar.gz")):
                refs = {}
                for side, directory in (("first", "assembly-a-output"),
                                        ("second", "assembly-b-output")):
                    path = inner / directory / name
                    path.parent.mkdir(exist_ok=True)
                    path.write_bytes(("synthetic " + name).encode())
                    refs[side] = index.file_ref(output, path)
                outputs.append({"id": kind, "name": name, **refs})
            domain = {"schema": index.DOMAIN_SCHEMA, "status": "unqualified",
                      "attempt_id": attempt_id, "custody_root": str(output),
                      "target": "aarch64-unknown-linux-gnu",
                      "started_at": self.started, "finished_at": self.finished,
                      "launcher": index.file_ref(output, outcome),
                      "report": index.file_ref(output, report), "outputs": outputs}
            path = output / "domain-observation.json"
            path.write_bytes(index.canonical(domain))
            domain_ref = index.file_ref(self.root, path)
        receipt = {"schema": index.ACCEPTANCE_SCHEMA, "id": attempt_id, "status": status,
                   "evidence": index.file_ref(self.root, outcome),
                   "domain_observation": domain_ref,
                   "started_at": self.started, "finished_at": self.finished,
                   "processes": []}
        return index.finish(self.root, attempt_id, receipt)

    def complete(self):
        self.begin()
        self.finish()
        self.assertEqual(set(index.replay(self.root)), {"assembly-one"})

    def test_begin_is_visible_before_output_and_unfinished_attempt_rejects_acceptance(self):
        row = self.begin()
        self.assertEqual(row["event"], "begin")
        self.assertFalse(self.output.exists())
        self.assertTrue(self.journal.is_file())
        self.assertEqual(set(index.replay(self.root, complete=False)), {"assembly-one"})
        with self.assertRaisesRegex(ValueError, "unfinished admission"):
            index.replay(self.root)
        with self.assertRaisesRegex(ValueError, "reuses an id or output"):
            self.begin()

    def test_unregistered_kind_is_rejected_before_admission(self):
        with self.assertRaisesRegex(ValueError, "unknown native attempt kind"):
            index.begin(self.root, "assembly-one", "unregistered", self.output, self.started)
        self.assertFalse(self.journal.exists())

    def test_attempt_outputs_must_have_disjoint_namespaces(self):
        self.begin()
        self.begin("sibling", self.root / "assembly-one-extra")
        with self.assertRaisesRegex(ValueError, "reuses an id or output"):
            self.begin("nested", self.output / "nested")
        self.assertFalse((self.root / "attempts/nested").exists())

        self.begin("child", self.root / "parent/child")
        with self.assertRaisesRegex(ValueError, "reuses an id or output"):
            self.begin("parent", self.root / "parent")
        self.assertFalse((self.root / "attempts/parent").exists())

    def test_replay_rejects_rehashed_overlapping_output_admissions(self):
        self.begin()
        original = self.journal.read_bytes()
        forged = {"schema": index.SCHEMA, "sequence": 2,
                  "previous_sha256": hashlib.sha256(original).hexdigest(),
                  "event": "begin", "id": "nested", "kind": "repeatable-assembly",
                  "output": "assembly-one/nested", "started_at": self.started}
        (self.root / "attempts/nested").mkdir()
        self.journal.write_bytes(original + index.canonical(forged))
        with self.assertRaisesRegex(ValueError, "duplicate or invalid native attempt admission"):
            index.replay(self.root, complete=False)

    def test_terminal_rejects_outcome_with_wrong_schema(self):
        self.begin()
        with self.assertRaisesRegex(ValueError, "differs from original outcome"):
            self.finish(schema="unregistered-outcome-v1")

    def test_terminal_rejects_outcome_with_wrong_custody_root(self):
        self.begin()
        with self.assertRaisesRegex(ValueError, "differs from original outcome"):
            self.finish(custody_root=str(self.root / "another-output"))

    def test_replay_rejects_rehashed_outcome_with_wrong_custody_root(self):
        self.complete()
        outcome_path = self.output / "launcher.json"
        receipt_path = self.root / "attempts/assembly-one/attempt.json"
        outcome = json.loads(outcome_path.read_text())
        outcome["custody_root"] = str(self.root / "another-output")
        outcome_path.write_bytes(index.canonical(outcome))
        receipt = json.loads(receipt_path.read_text())
        receipt["evidence"] = index.file_ref(self.root, outcome_path)
        receipt_path.write_bytes(index.canonical(receipt))
        rows = [json.loads(line) for line in self.journal.read_bytes().splitlines()]
        rows[1]["receipt"] = index.file_ref(self.root, receipt_path)
        self.journal.write_bytes(b"".join(index.canonical(row) for row in rows))
        with self.assertRaisesRegex(ValueError, "differs from original outcome"):
            index.replay(self.root)

    def test_terminal_binds_original_outcome_and_exact_receipt_bytes(self):
        self.complete()
        receipt = self.root / "attempts/assembly-one/attempt.json"
        original = receipt.read_bytes()
        receipt.write_bytes(original + b" ")
        with self.assertRaisesRegex(ValueError, "reference bytes differ"):
            index.replay(self.root)
        receipt.write_bytes(original)
        outcome = self.output / "launcher.json"
        outcome.write_text(outcome.read_text().replace('"passed"', '"failed"'))
        with self.assertRaisesRegex(ValueError, "reference bytes differ"):
            index.replay(self.root)

    def test_domain_observation_is_retained_and_rejects_substitution(self):
        self.complete()
        path = self.output / "domain-observation.json"
        original = path.read_bytes()
        path.write_bytes(original.replace(b'"unqualified"', b'"passed"'))
        with self.assertRaisesRegex(ValueError, "reference bytes differ"):
            index.replay(self.root)

    def test_rehashed_stale_domain_observation_rejects(self):
        self.complete()
        path = self.output / "domain-observation.json"
        receipt_path = self.root / "attempts/assembly-one/attempt.json"
        domain = json.loads(path.read_bytes())
        domain["launcher"]["sha256"] = "0" * 64
        path.write_bytes(index.canonical(domain))
        receipt = json.loads(receipt_path.read_bytes())
        receipt["domain_observation"] = index.file_ref(self.root, path)
        receipt_path.write_bytes(index.canonical(receipt))
        rows = [json.loads(line) for line in self.journal.read_bytes().splitlines()]
        rows[1]["receipt"] = index.file_ref(self.root, receipt_path)
        self.journal.write_bytes(b"".join(index.canonical(row) for row in rows))
        with self.assertRaisesRegex(ValueError, "selected another launcher"):
            index.replay(self.root)

    def test_missing_domain_observation_rejects_success(self):
        self.begin()
        with self.assertRaisesRegex(ValueError, "domain observation reference"):
            self._finish_without_domain()

    def _finish_without_domain(self):
        self.output.mkdir()
        outcome = self.output / "launcher.json"
        outcome.write_bytes(index.canonical({"schema": index.KIND_OUTCOMES["repeatable-assembly"],
                                             "custody_root": str(self.output),
                                             "attempt_id": "assembly-one", "status": "passed",
                                             "started_at": self.started, "finished_at": self.finished}))
        index.finish(self.root, "assembly-one", {
            "schema": index.ACCEPTANCE_SCHEMA, "id": "assembly-one", "status": "passed",
            "evidence": index.file_ref(self.root, outcome),
            "domain_observation": None, "started_at": self.started,
            "finished_at": self.finished, "processes": []})

    def test_replay_rejects_missing_indexed_or_extra_unindexed_attempt(self):
        self.complete()
        (self.root / "attempts/extra").mkdir()
        with self.assertRaisesRegex(ValueError, "omits or invents"):
            index.replay(self.root)
        (self.root / "attempts/extra").rmdir()
        (self.root / "attempts/assembly-one/attempt.json").unlink()
        (self.root / "attempts/assembly-one").rmdir()
        with self.assertRaises((ValueError, FileNotFoundError)):
            index.replay(self.root)

    def test_replay_rejects_truncated_reordered_duplicate_and_rewritten_rows(self):
        self.complete()
        original = self.journal.read_bytes()
        rows = original.splitlines(keepends=True)
        for name, changed in (("truncated", rows[0] + rows[1][:-1]),
                              ("reordered", rows[1] + rows[0]),
                              ("duplicate", original + rows[1]),
                              ("rewritten", rows[0].replace(b"assembly-one", b"assembly-two") + rows[1])):
            with self.subTest(name=name):
                self.journal.write_bytes(changed)
                with self.assertRaises(ValueError):
                    index.replay(self.root)
        self.journal.write_bytes(original)
        self.assertEqual(set(index.replay(self.root)), {"assembly-one"})

    def test_corrupt_journal_blocks_new_admission_before_output_creation(self):
        self.complete()
        self.journal.write_bytes(self.journal.read_bytes() + b"{" )
        next_output = self.root / "assembly-two"
        with self.assertRaises(ValueError):
            self.begin("assembly-two", next_output)
        self.assertFalse(next_output.exists())
        self.assertFalse((self.root / "attempts/assembly-two").exists())

    def test_output_or_index_alias_is_rejected(self):
        outside = self.root.parent / (self.root.name + "-outside")
        with self.assertRaisesRegex(ValueError, "escapes permanent custody"):
            self.begin(output=outside)
        self.assertFalse(outside.exists())
        self.journal.unlink()
        self.journal.symlink_to(self.root / "outside-index")
        with self.assertRaises(OSError):
            self.begin()

    def test_missing_index_and_extra_attempt_file_reject_replay(self):
        self.complete()
        extra = self.root / "attempts/assembly-one/hidden-result.json"
        extra.write_text("{}\n")
        with self.assertRaisesRegex(ValueError, "invents terminal custody"):
            index.replay(self.root)
        extra.unlink()
        self.journal.unlink()
        with self.assertRaises(FileNotFoundError):
            index.replay(self.root)


if __name__ == "__main__":
    unittest.main()
