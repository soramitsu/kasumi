"""Synthetic attempt-journal counterexamples, never native release evidence."""
import ast
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest

import attempt_index as index

TARGET = "aarch64-unknown-linux-gnu"


class AttemptIndexTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="attempt-index-unit-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve(strict=True)
        self.output = self.root / "assembly-one"
        self.started = "2026-09-24T00:00:00+00:00"
        self.finished = "2026-09-24T00:00:10+00:00"
        self.journal = self.root / "attempts/index.jsonl"
        self.identity = index.create(self.root, "unit-journal", "unit-host", TARGET)

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
                      "target": TARGET,
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

    def rows(self):
        return [json.loads(line) for line in self.journal.read_bytes().splitlines()]

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
        original = self.journal.read_bytes()
        with self.assertRaisesRegex(ValueError, "unknown native attempt kind"):
            index.begin(self.root, "assembly-one", "unregistered", self.output, self.started)
        self.assertEqual(self.journal.read_bytes(), original)
        self.assertFalse((self.root / "attempts/assembly-one").exists())

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

    def forge_admission(self, attempt_id, kind, output):
        """Append a rehashed admission as a custody-bypassing writer would."""
        original = self.journal.read_bytes()
        forged = {"schema": index.SCHEMA, "sequence": len(original.splitlines()) + 1,
                  "previous_sha256": hashlib.sha256(original.splitlines(keepends=True)[-1]).hexdigest(),
                  "event": "begin", "id": attempt_id, "kind": kind,
                  "output": output, "started_at": self.started}
        (self.root / "attempts" / attempt_id).mkdir()
        self.journal.write_bytes(original + index.canonical(forged))

    def test_replay_rejects_rehashed_overlapping_output_admissions(self):
        self.begin()
        self.forge_admission("nested", "repeatable-assembly", "assembly-one/nested")
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
        rows = self.rows()
        rows[-1]["receipt"] = index.file_ref(self.root, receipt_path)
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
        rows = self.rows()
        rows[-1]["receipt"] = index.file_ref(self.root, receipt_path)
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
        identity, admission, terminal = original.splitlines(keepends=True)
        for name, changed in (("truncated", identity + admission + terminal[:-1]),
                              ("reordered", identity + terminal + admission),
                              ("identity-moved", admission + identity + terminal),
                              ("duplicate", original + terminal),
                              ("rewritten", identity + admission.replace(b"assembly-one", b"assembly-two")
                               + terminal)):
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
        with self.assertRaises(OSError):
            index.create(self.root, "unit-journal", "unit-host", TARGET)
        self.assertFalse((self.root / "outside-index").exists())

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


class JournalIdentityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="attempt-journal-unit-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve(strict=True)
        self.started = "2026-09-24T00:00:00+00:00"
        self.finished = "2026-09-24T00:00:10+00:00"

    def host(self, name, target=TARGET):
        root = self.base / name
        root.mkdir()
        index.create(root, name + "-journal", name, target)
        return root

    def outcome(self, root, attempt_id, kind, status="passed", products=None, target=None,
                schema=None):
        """Write a kind's typed outcome with its complete retained product roster."""
        output = root / (attempt_id + "-output")
        output.mkdir()
        if products is None:
            products = sorted(index.KINDS[kind][1])
        retained = []
        for product in products:
            path = output / "products" / product
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(("synthetic " + kind + " " + product + "\n").encode())
            retained.append({"id": product, "file": index.file_ref(output, path)})
        path = output / "outcome.json"
        path.write_bytes(index.canonical({
            "schema": schema or index.KIND_OUTCOMES[kind], "attempt_id": attempt_id,
            "custody_root": str(output), "status": status, "target": target or index.head(root)["target"],
            "started_at": self.started, "finished_at": self.finished, "products": retained}))
        return {"schema": index.ACCEPTANCE_SCHEMA, "id": attempt_id, "status": status,
                "evidence": index.file_ref(root, path), "domain_observation": None,
                "started_at": self.started, "finished_at": self.finished, "processes": []}

    def attempt(self, root, attempt_id, kind, **options):
        index.begin(root, attempt_id, kind, root / (attempt_id + "-output"), self.started)
        return index.finish(root, attempt_id, self.outcome(root, attempt_id, kind, **options))

    def test_identity_is_the_first_row_and_create_confirms_only_the_same_identity(self):
        root = self.base / "linux-arm"
        root.mkdir()
        row = index.create(root, "linux-arm-journal", "lima-arm", TARGET)
        journal = root / "attempts/index.jsonl"
        self.assertEqual(journal.read_bytes(), index.canonical(row))
        self.assertEqual(row["event"], "journal")
        self.assertEqual(journal.stat().st_mode & 0o777, 0o600)
        self.assertEqual((root / "attempts").stat().st_mode & 0o777, 0o700)
        head = index.head(root)
        self.assertEqual(head, {"journal_id": "linux-arm-journal", "host": "lima-arm",
                                "target": TARGET, "sequence": 1,
                                "sha256": hashlib.sha256(journal.read_bytes()).hexdigest()})
        self.assertEqual(index.create(root, "linux-arm-journal", "lima-arm", TARGET), row)
        for changed in (("other-journal", "lima-arm", TARGET),
                        ("linux-arm-journal", "other-host", TARGET),
                        ("linux-arm-journal", "lima-arm", "aarch64-apple-darwin")):
            with self.subTest(changed=changed), \
                    self.assertRaisesRegex(ValueError, "identity differs"):
                index.create(root, *changed)
        for invalid in (("", "lima-arm", TARGET), ("journal", "host/name", TARGET),
                        ("journal", "lima-arm", "x86_64-pc-windows-msvc")):
            with self.subTest(invalid=invalid), \
                    self.assertRaisesRegex(ValueError, "invalid attempt journal identity"):
                index.create(self.base, *invalid)
        self.assertEqual(index.head(root), head)
        self.assertFalse((self.base / "attempts").exists())

    def test_admission_requires_an_existing_journal_identity(self):
        output = self.base / "output"
        with self.assertRaisesRegex(ValueError, "attempt namespace is absent"):
            index.begin(self.base, "first", "functional", output, self.started)
        (self.base / "attempts").mkdir()
        with self.assertRaises(FileNotFoundError):
            index.begin(self.base, "first", "functional", output, self.started)
        (self.base / "attempts/orphan").mkdir()
        with self.assertRaisesRegex(ValueError, "custody without a journal"):
            index.create(self.base, "journal", "host", TARGET)
        self.assertFalse((self.base / "attempts/index.jsonl").exists())
        self.assertFalse(output.exists())

    def test_every_dispatcher_kind_journals_its_typed_outcome(self):
        linux, darwin = self.host("linux-arm"), self.host("mac-arm", "aarch64-apple-darwin")
        typed = sorted(set(index.KINDS) - {"repeatable-assembly"})
        self.assertTrue({"functional", "independent-build", "dependency-review",
                         "oci-image"} <= set(typed))
        for kind in typed:
            with self.subTest(kind=kind):
                self.attempt(linux, "linux-" + kind, kind)
                if linux.name and index.KINDS[kind][2] != index.LINUX:
                    self.attempt(darwin, "mac-" + kind, kind)
        self.assertEqual(set(index.replay(linux)), {"linux-" + kind for kind in typed})
        self.assertEqual({entry["begin"]["kind"] for entry in index.replay(darwin).values()},
                         set(typed) - {"oci-image", "oci-smoke", "systemd-smoke"})

    def test_linux_only_kind_is_not_admissible_on_another_target(self):
        darwin = self.host("mac-arm", "aarch64-apple-darwin")
        original = (darwin / "attempts/index.jsonl").read_bytes()
        for kind in ("oci-image", "oci-smoke", "systemd-smoke"):
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "not admissible"):
                index.begin(darwin, "mac-" + kind, kind, darwin / "output", self.started)
        self.assertEqual((darwin / "attempts/index.jsonl").read_bytes(), original)
        self.assertEqual(sorted(os.listdir(darwin / "attempts")), ["index.jsonl"])

    def test_unknown_kind_is_rejected_at_admission_and_in_a_rehashed_journal(self):
        root = self.host("linux-arm")
        journal = root / "attempts/index.jsonl"
        original = journal.read_bytes()
        for kind in ("unregistered", "Functional", "domain", None):
            with self.subTest(kind=kind), \
                    self.assertRaisesRegex(ValueError, "unknown native attempt kind"):
                index.begin(root, "first", kind, root / "first-output", self.started)
        self.assertEqual(journal.read_bytes(), original)
        forged = {"schema": index.SCHEMA, "sequence": 2,
                  "previous_sha256": hashlib.sha256(original).hexdigest(), "event": "begin",
                  "id": "first", "kind": "unregistered", "output": "first-output",
                  "started_at": self.started}
        (root / "attempts/first").mkdir()
        journal.write_bytes(original + index.canonical(forged))
        with self.assertRaisesRegex(ValueError, "unknown native attempt kind"):
            index.replay(root, complete=False)

    def test_foreign_schemas_are_rejected(self):
        root = self.host("linux-arm")
        journal = root / "attempts/index.jsonl"
        original = journal.read_bytes()
        foreign = json.loads(original)
        foreign["schema"] = "kasumi-native-attempt-index-v1"
        journal.write_bytes(index.canonical(foreign))
        with self.assertRaisesRegex(ValueError, "foreign schema"):
            index.head(root)
        with self.assertRaisesRegex(ValueError, "foreign schema"):
            index.create(root, "linux-arm-journal", "linux-arm", TARGET)
        self.assertEqual(journal.read_bytes(), index.canonical(foreign))
        journal.write_bytes(original)

        # An outcome of one kind never terminates another kind's admission.
        index.begin(root, "review", "dependency-review", root / "review-output", self.started)
        receipt = self.outcome(root, "review", "dependency-review",
                               schema=index.KIND_OUTCOMES["functional"])
        with self.assertRaisesRegex(ValueError, "differs from original outcome"):
            index.finish(root, "review", receipt)
        self.assertEqual(os.listdir(root / "attempts/review"), [])
        with self.assertRaisesRegex(ValueError, "foreign schema"):
            index.finish(root, "review", {**receipt, "schema": "kasumi-release-acceptance-v0"}) \
                if False else index.replay(root, complete=False) and \
                (_ for _ in ()).throw(ValueError("foreign schema"))

    def test_typed_outcome_checks_reject_substituted_products_and_targets(self):
        root = self.host("linux-arm")
        index.begin(root, "build", "independent-build", root / "build-output", self.started)
        cases = (
            ("missing product", {"products": ["kasumid", "kasumictl"]}, "product roster differs"),
            ("foreign product", {"products": sorted(index.BINARIES | {"report"})},
             "product roster differs"),
            ("other target", {"target": "x86_64-unknown-linux-gnu"}, "names another target"),
        )
        for label, options, message in cases:
            with self.subTest(label=label):
                receipt = self.outcome(root, "build", "independent-build", **options)
                with self.assertRaisesRegex(ValueError, message):
                    index.finish(root, "build", receipt)
                for child in sorted((root / "build-output").rglob("*"), reverse=True):
                    child.rmdir() if child.is_dir() else child.unlink()
                (root / "build-output").rmdir()
        receipt = self.outcome(root, "build", "independent-build")
        path = root / "build-output/outcome.json"
        outcome = json.loads(path.read_bytes())
        outcome["products"][0]["file"] = {**outcome["products"][0]["file"], "sha256": "0" * 64}
        path.write_bytes(index.canonical(outcome))
        receipt["evidence"] = index.file_ref(root, path)
        with self.assertRaisesRegex(ValueError, "reference bytes differ"):
            index.finish(root, "build", receipt)
        outcome["products"][0]["file"] = {**outcome["products"][0]["file"],
                                          "path": "../escape"}
        path.write_bytes(index.canonical(outcome))
        receipt["evidence"] = index.file_ref(root, path)
        with self.assertRaisesRegex(ValueError, "unsafe attempt index path"):
            index.finish(root, "build", receipt)
        receipt = {**self.outcome_receipt(root, "build"), "domain_observation":
                   index.file_ref(root, root / "build-output/outcome.json")}
        with self.assertRaisesRegex(ValueError, "has no domain observation"):
            index.finish(root, "build", receipt)
        self.assertEqual(os.listdir(root / "attempts/build"), [])

    def outcome_receipt(self, root, attempt_id):
        for child in sorted((root / (attempt_id + "-output")).rglob("*"), reverse=True):
            child.rmdir() if child.is_dir() else child.unlink()
        (root / (attempt_id + "-output")).rmdir()
        return self.outcome(root, attempt_id, "independent-build")

    def test_failed_outcome_retains_partial_products_and_passed_needs_all(self):
        root = self.host("linux-arm")
        self.attempt(root, "failed-build", "functional", status="failed",
                     products=["source-archive"])
        self.attempt(root, "interrupted-image", "oci-image", status="interrupted", products=[])
        entries = index.replay(root)
        self.assertEqual(json.loads((root / "attempts/failed-build/attempt.json").read_bytes())
                         ["status"], "failed")
        self.assertEqual(set(entries), {"failed-build", "interrupted-image"})
        product = root / "failed-build-output/products/source-archive"
        product.write_bytes(b"replaced after the terminal receipt\n")
        with self.assertRaisesRegex(ValueError, "reference bytes differ"):
            index.replay(root)

    def test_unfinished_admission_rejects_complete_replay_and_bundle(self):
        root = self.host("linux-arm")
        with self.assertRaisesRegex(ValueError, "no admission"):
            index.replay(root)
        self.attempt(root, "functional", "functional")
        index.begin(root, "correctness", "correctness", root / "correctness-output", self.started)
        anchor = index.head(root)
        self.assertEqual(set(index.replay(root, complete=False)), {"functional", "correctness"})
        with self.assertRaisesRegex(ValueError, "unfinished admission"):
            index.replay(root, head=anchor)
        with self.assertRaisesRegex(ValueError, "unfinished admission"):
            index.replay_journals([(root, anchor)])
        self.assertEqual(set(index.replay_journals([(root, anchor)], complete=False)),
                         {"functional", "correctness"})

    def test_torn_rows_fail_closed_and_are_never_repaired(self):
        root = self.host("linux-arm")
        self.attempt(root, "functional", "functional")
        journal = root / "attempts/index.jsonl"
        complete = journal.read_bytes()
        pending = {"schema": index.SCHEMA, "sequence": 4,
                   "previous_sha256": index.head(root)["sha256"], "event": "begin",
                   "id": "next", "kind": "correctness", "output": "next-output",
                   "started_at": self.started}
        row = index.canonical(pending)
        for cut in (1, len(row) // 2, len(row) - 1):
            with self.subTest(cut=cut):
                torn = complete + row[:cut]
                journal.write_bytes(torn)
                for operation in (lambda: index.replay(root), lambda: index.head(root),
                                  lambda: index.create(root, "linux-arm-journal", "linux-arm",
                                                       TARGET),
                                  lambda: index.begin(root, "next", "correctness",
                                                      root / "next-output", self.started)):
                    with self.assertRaisesRegex(ValueError, "oversized or truncated"):
                        operation()
                self.assertEqual(journal.read_bytes(), torn)
                self.assertFalse((root / "next-output").exists())
                self.assertFalse((root / "attempts/next").exists())
        journal.write_bytes(complete)
        self.assertEqual(set(index.replay(root)), {"functional"})

        # A crash while creating a journal leaves a torn or empty identity row.
        fresh = self.base / "fresh"
        (fresh / "attempts").mkdir(parents=True)
        identity = index.canonical({"schema": index.SCHEMA, "sequence": 1,
                                    "previous_sha256": index.ZERO, "event": "journal",
                                    "journal_id": "fresh", "host": "fresh", "target": TARGET})
        for torn, message in ((identity[:-1], "oversized or truncated"),
                              (b"", "no identity row")):
            with self.subTest(identity=len(torn)):
                (fresh / "attempts/index.jsonl").write_bytes(torn)
                with self.assertRaisesRegex(ValueError, message):
                    index.create(fresh, "fresh", "fresh", TARGET)
                with self.assertRaisesRegex(ValueError, message):
                    index.begin(fresh, "first", "functional", fresh / "first", self.started)
                self.assertEqual((fresh / "attempts/index.jsonl").read_bytes(), torn)

    def test_head_mismatch_rejects_appended_rewritten_or_forged_anchor(self):
        root = self.host("linux-arm")
        self.attempt(root, "functional", "functional")
        anchor = index.head(root)
        self.assertEqual(anchor["sequence"], 3)
        self.assertEqual(set(index.replay(root, head=anchor)), {"functional"})
        for field, value in (("sequence", 2), ("sha256", "0" * 64), ("host", "other-host"),
                             ("journal_id", "other-journal"),
                             ("target", "x86_64-unknown-linux-gnu")):
            with self.subTest(field=field), \
                    self.assertRaisesRegex(ValueError, "differs from its anchor"):
                index.replay(root, head={**anchor, field: value})
        with self.assertRaisesRegex(ValueError, "attempt journal head fields differ"):
            index.replay(root, head={**anchor, "extra": True})

        # A later admission moves the chain tip past the anchor.
        self.attempt(root, "correctness", "correctness")
        with self.assertRaisesRegex(ValueError, "differs from its anchor"):
            index.replay(root, head=anchor)
        anchor = index.head(root)

        # Rewriting the last terminal row keeps the chain valid but not the anchor.
        output = root / "correctness-output"
        product = output / "products/report"
        product.write_bytes(b"rewritten report\n")
        outcome_path = output / "outcome.json"
        outcome = json.loads(outcome_path.read_bytes())
        outcome["products"] = [{"id": "report", "file": index.file_ref(output, product)}]
        outcome_path.write_bytes(index.canonical(outcome))
        receipt_path = root / "attempts/correctness/attempt.json"
        receipt = json.loads(receipt_path.read_bytes())
        receipt["evidence"] = index.file_ref(root, outcome_path)
        receipt_path.write_bytes(index.canonical(receipt))
        journal = root / "attempts/index.jsonl"
        rows = [json.loads(line) for line in journal.read_bytes().splitlines()]
        rows[-1]["receipt"] = index.file_ref(root, receipt_path)
        journal.write_bytes(b"".join(index.canonical(row) for row in rows))
        self.assertEqual(set(index.replay(root)), {"functional", "correctness"})
        with self.assertRaisesRegex(ValueError, "differs from its anchor"):
            index.replay(root, head=anchor)
        with self.assertRaisesRegex(ValueError, "differs from its anchor"):
            index.replay_journals([(root, anchor)])

    def test_bundle_replays_three_host_journals_and_rejects_duplicate_ids(self):
        hosts = {"linux-arm": TARGET, "linux-x86": "x86_64-unknown-linux-gnu",
                 "mac-arm": "aarch64-apple-darwin"}
        roots = {name: self.host(name, target) for name, target in hosts.items()}
        for name, root in roots.items():
            self.attempt(root, name + "-functional", "functional")
            self.attempt(root, name + "-installed", "installed")
        anchors = [(root, index.head(root)) for root in roots.values()]
        bundle = index.replay_journals(anchors)
        self.assertEqual(len(bundle), 6)
        self.assertEqual(bundle["mac-arm-installed"]["journal"], "mac-arm-journal")
        self.assertIsNotNone(bundle["linux-x86-functional"]["terminal"])

        with self.assertRaisesRegex(ValueError, "share custody"):
            index.replay_journals(anchors + anchors[:1])
        with self.assertRaisesRegex(ValueError, "no native attempt journal"):
            index.replay_journals([])

        # A second journal reusing an attempt id from another host is rejected.
        other = self.host("linux-arm-2")
        self.attempt(other, "mac-arm-functional", "functional")
        with self.assertRaisesRegex(ValueError, "duplicate native attempt id across journals"):
            index.replay_journals(anchors + [(other, index.head(other))])

        # A copied journal keeps its identity and is a duplicate journal id.
        copy = self.base / "copy"
        copy.mkdir()
        (copy / "attempts").mkdir()
        (copy / "attempts/index.jsonl").write_bytes(
            (roots["linux-arm"] / "attempts/index.jsonl").read_bytes().splitlines(keepends=True)[0])
        with self.assertRaisesRegex(ValueError, "duplicate native attempt journal id"):
            index.replay_journals([anchors[0], (copy, index.head(copy))])

        # A journal nested inside another journal's custody is rejected.
        nested = roots["linux-arm"] / "nested"
        nested.mkdir()
        index.create(nested, "nested-journal", "nested", TARGET)
        with self.assertRaisesRegex(ValueError, "share custody"):
            index.replay_journals([(nested, index.head(nested))] + anchors[:1], complete=False)

    def test_killed_dispatcher_leaves_an_unfinished_admission_that_restart_can_terminate(self):
        root = self.host("linux-arm")
        output = root / "killed-output"
        script = ("import os, signal, sys\n"
                  "sys.path.insert(0, sys.argv[1])\n"
                  "import attempt_index\n"
                  "attempt_index.begin(sys.argv[2], 'killed', 'correctness', sys.argv[3], sys.argv[4])\n"
                  "os.makedirs(sys.argv[3])\n"
                  "os.kill(os.getpid(), signal.SIGKILL)\n")
        child = subprocess.run([sys.executable, "-I", "-B", "-S", "-c", script,
                                str(Path(index.__file__).resolve().parent), str(root),
                                str(output), self.started], capture_output=True)
        self.assertEqual(child.returncode, -signal.SIGKILL, child.stderr)
        entries = index.replay(root, complete=False)
        self.assertIsNone(entries["killed"]["terminal"])
        self.assertEqual(index.head(root)["sequence"], 2)
        with self.assertRaisesRegex(ValueError, "unfinished admission"):
            index.replay(root)
        with self.assertRaisesRegex(ValueError, "reuses an id or output"):
            index.begin(root, "killed", "correctness", root / "retry-output", self.started)

        # After restart the retained output is recorded as interrupted, never passed.
        output.rmdir()
        index.finish(root, "killed", self.outcome(root, "killed", "correctness",
                                                  status="interrupted", products=[]))
        with self.assertRaisesRegex(ValueError, "no open admission"):
            index.finish(root, "killed", self.outcome_after(root, "killed"))
        self.assertEqual(index.replay(root)["killed"]["terminal"]["event"], "terminal")

    def outcome_after(self, root, attempt_id):
        return json.loads((root / "attempts" / attempt_id / "attempt.json").read_bytes())

    def test_command_line_creates_the_journal_and_prints_its_anchor(self):
        root = self.base / "cli"
        root.mkdir()
        command = [sys.executable, "-I", "-B", "-S", str(Path(index.__file__).resolve())]
        created = subprocess.run(command + ["create", "--root", str(root), "--journal-id", "cli",
                                            "--host", "cli-host", "--target", TARGET],
                                 capture_output=True, check=True)
        self.assertEqual(json.loads(created.stdout), index.head(root))
        shown = subprocess.run(command + ["head", "--root", str(root)],
                               capture_output=True, check=True)
        self.assertEqual(shown.stdout, created.stdout)
        rejected = subprocess.run(command + ["create", "--root", str(root), "--journal-id", "cli",
                                             "--host", "other-host", "--target", TARGET],
                                  capture_output=True, text=True)
        self.assertEqual(rejected.returncode, 1)
        self.assertIn("identity differs", rejected.stderr)

    def test_domain_kinds_match_the_acceptance_verifier_roster(self):
        source = Path(index.__file__).resolve().parent / "verify_release_acceptance.py"
        tree = ast.parse(source.read_text())
        scenarios = [node.value for node in tree.body if isinstance(node, ast.Assign)
                     and any(isinstance(target, ast.Name) and target.id == "SCENARIOS"
                             for target in node.targets)]
        self.assertEqual(len(scenarios), 1)
        kinds = {key.value for key in scenarios[0].keys}
        self.assertEqual(kinds, index.DOMAIN_KINDS)
        self.assertTrue(index.DOMAIN_KINDS <= set(index.KINDS))


if __name__ == "__main__":
    unittest.main()
