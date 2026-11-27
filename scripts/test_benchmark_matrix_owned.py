import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import run_benchmark_matrix_owned as matrix

acceptance = matrix.acceptance
BOUNDS = {"attempts": 4, "budget_milliseconds": 60_000, "initial_backoff_milliseconds": 100,
          "maximum_backoff_milliseconds": 1_000, "maximum_affected_batches": 1}


def step(action, offset, elapsed, outcome, code=None, message=None):
    return {"action": action, "offset_ns": offset, "elapsed_ns": elapsed, "outcome": outcome,
            "code": code, "message": message}


DEADLINE = "write deadline exceeded; resolve or retry with the same idempotency key"
# The first backoff sleeps the declared initial delay.
PAUSE = BOUNDS["initial_backoff_milliseconds"] * 1_000_000
# The original attempt missed the deadline; the lookup raced it, so the batch
# was resent once under the same identity and the retained receipt confirmed it.
CONFIRMED = [step("send", 0, 10_000, "uncertain", "UNKNOWN_OUTCOME", DEADLINE), step("lookup", 10_000, 20, "absent"),
             step("backoff", 10_020, PAUSE, "slept"), step("send", 10_020 + PAUSE, 30, "committed"),
             step("lookup", 10_050 + PAUSE, 20, "found")]
FOUND = [step("send", 0, 10_000, "uncertain", "UNKNOWN_OUTCOME", DEADLINE), step("lookup", 10_000, 25, "found")]


def load_records(tenants, documents, attempt, disputed=None, size=256, principal="bench-app"):
    """Rows as the installed driver writes them to load-batches.jsonl."""
    disputed = disputed or {}
    records, start = [], 7
    for index, tenant in enumerate(tenants):
        ordinals = list(range(index, documents, len(tenants)))
        revision = 2
        for at in range(0, len(ordinals), size):
            chunk, sequence = ordinals[at:at + size], len(records)
            key = f"{attempt}-load-{sequence}"
            scope = {"tenant": tenant, "incarnation": "incarnation-" + tenant, "principal": principal}
            steps = copy.deepcopy(disputed.get(sequence, [step("send", 0, 50 + sequence, "committed")]))
            label = acceptance.LOAD_FIRST_ATTEMPT
            receipt = effects = None
            effects_ns = 0
            if sequence in disputed:
                label = acceptance.LOAD_FOUND_BEFORE_RESEND if sum(
                    s["action"] == "send" for s in steps) == 1 else acceptance.LOAD_CONFIRMED_AFTER_RESEND
                receipt = {"scope": dict(scope), "request_digest": acceptance.corpus_batch_digest(key, chunk, len(tenants)),
                           "revision": revision, "versions": {f"/docs/{o}": revision for o in chunk}}
                effects = [{"id": str(o), "version": revision, "body_sha256": hashlib.sha256(
                    acceptance.canonical_json(acceptance.corpus_body(o, len(tenants)))).hexdigest()} for o in chunk]
                effects_ns = 40
            elapsed = steps[-1]["offset_ns"] + steps[-1]["elapsed_ns"]
            records.append({"sequence": sequence, "tenant": tenant, "first": chunk[0], "documents": len(chunk),
                            "canonical_bytes": 1024 * len(chunk), "idempotency_key": key,
                            "request_digest": acceptance.corpus_batch_digest(key, chunk, len(tenants)),
                            "scope": scope, "started_ns": start, "elapsed_ns": elapsed, "steps": steps,
                            "resolution": label, "failure": None, "revision": revision, "receipt": receipt,
                            "effects": effects, "effects_elapsed_ns": effects_ns})
            start += elapsed + effects_ns + 3
            revision += 5
    return records


def write_records(path, records):
    path.write_bytes(b"".join(json.dumps(row, ensure_ascii=False).encode() + b"\n" for row in records))


class InstalledMatrixTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.out = self.root / "local-1.native"
        self.out.mkdir()
        self.digest = "c" * 64
        self.plan = {"nodes": [{"sha256": "a" * 64}], "load": dict(BOUNDS),
                     "tenants": {"alpha": {"administrator": "bench-admin", "application": "bench-app"}}}
        self.nodes = [{"database_id": "id", "mode": "standalone", "tenants": [
            {"tenant": "alpha", "incarnation": "incarnation-alpha", "keys": {"kind": "transit"},
             "custody_keys": {"kind": "file"}}]}]
        self.case = {"schema": "kasumi-installed-embedded-v2", "executable_sha256": self.digest,
                     "plan_sha256": "b" * 64, "mode": "local", "attempt": "attempt-id", "tenants": ["alpha"],
                     "nodes": [{"configuration_sha256": "a" * 64, "database_id": "id", "voter": None,
                                "providers": {"alpha": ["transit", "file"]}}], "voters": {"alpha": [1]},
                     "documents": 3, "canonical_bytes": 3072, "complete": True, "measurements": []}
        for name in sorted(matrix.acceptance.BASE_WORKLOADS):
            self.case["measurements"].append({"name": name, "successful_elapsed_ns": [900, 400, 500],
                "requested_operations": 3, "attempted_operations": 3, "successful_operations": 3,
                "failed_operations": 0, "unattempted_operations": 0, "failed_attempts": [],
                "latency": {"operations": 3, "p50_microseconds": .5, "p99_microseconds": .9, "max_microseconds": .9}})
        self.records = load_records(["alpha"], 3, "attempt-id", {0: CONFIRMED})
        self.case["load"] = self.summary(self.records)

    def summary(self, records):
        """What the driver reports: recomputed here from the same rows."""
        path = self.root / "summary-records.jsonl"
        write_records(path, records)
        summary = acceptance.check_load(self.root, matrix.owned.ref(self.root, path), BOUNDS, 1, 3)[0]
        path.unlink()
        return summary

    def seal(self, case, records):
        (self.out / "case.json").write_text(json.dumps(case))
        write_records(self.out / "load-batches.jsonl", records)
        return json.dumps({"schema": "kasumi-benchmark-outputs-v1", "files": {
            p.name: matrix.sha256(p) for p in self.out.iterdir()}}).encode()

    def collect(self, seal, replay=False):
        with patch.object(matrix.probes, "DOCUMENTS", 3), patch.object(matrix.probes, "OPERATIONS", 3):
            return matrix.installed_case(self.root, self.out, "local-1", self.digest, seal,
                                         self.plan, self.nodes, None, replay)

    def test_replay_original_receipts_and_scope(self):
        seal = self.seal(self.case, self.records)
        case = self.collect(seal)
        self.assertEqual(self.collect(seal, True), case)
        load = case["load"]
        self.assertEqual(load["records"]["path"], "local-1.native/load-batches.jsonl")
        self.assertEqual((load["affected_batches"], load["commit_confirmed_after_resend"], load["resends"],
                          load["lookups"], load["first_attempt_deadline_misses"], load["unresolved"]),
                         (1, 1, 1, 2, 1, 0))
        self.assertEqual(load["first_attempt_ns"], {"p50": 10_000, "p99": 10_000, "max": 10_000})
        self.assertEqual(load["end_to_end_ns"]["max"], 10_070 + PAUSE)
        self.assertEqual(load["documents_per_second"], 3 * 1e9 / load["wall_ns"])
        samples = self.root / case["workloads"][0]["samples"]["path"]
        rows = samples.read_text().splitlines()
        samples.write_text("\n".join(reversed(rows)) + "\n")
        with self.assertRaisesRegex(ValueError, "retained rows"):
            self.collect(seal, True)

    def test_clean_load_reports_explicit_zeros(self):
        records = load_records(["alpha"], 3, "attempt-id")
        case = {**self.case, "load": self.summary(records)}
        load = self.collect(self.seal(case, records))["load"]
        self.assertEqual([load[k] for k in ("first_attempt_deadline_misses", "affected_batches", "resends",
                                            "lookups", "unresolved")], [0] * 5)
        self.assertIs(type(load["first_attempt_deadline_miss_rate"]), float)
        # A loosely equal false or float counter is not an explicit zero.
        for field, value in (("unresolved", False), ("resends", 0.0)):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "summary differs"):
                self.collect(self.seal({**case, "load": {**case["load"], field: value}}, records))
        missing = copy.deepcopy(case)
        del missing["load"]["lookups"]
        with self.assertRaisesRegex(ValueError, "summary differs"):
            self.collect(self.seal(missing, records))

    def test_load_records_bind_this_plan_attempt_and_installed_identity(self):
        for label, change in (
            ("attempt", lambda row: row.update(idempotency_key="other-" + row["idempotency_key"])),
            ("principal", lambda row: row["scope"].update(principal="other")),
            ("incarnation", lambda row: row["scope"].update(incarnation="other")),
        ):
            records = copy.deepcopy(self.records)
            for row in records:
                change(row)
                row["receipt"]["scope"] = dict(row["scope"])
                row["request_digest"] = row["receipt"]["request_digest"] = acceptance.corpus_batch_digest(
                    row["idempotency_key"], [0, 1, 2], 1)
            with self.subTest(label=label), self.assertRaisesRegex(ValueError, "differ from this plan and attempt"):
                self.collect(self.seal({**self.case, "load": self.summary(records)}, records))
        with self.assertRaisesRegex(ValueError, "corpus load bound outside release limits"):
            matrix.plan_inputs({"mode": "local", "documents": 3, "operations": 3, "nodes": [], "tenants": {},
                                "load": {**BOUNDS, "attempts": 100}}, "local", 1, None, "local-1")

    def test_original_hashes_partial_corpus_and_provider_cannot_be_substituted(self):
        seal = self.seal(self.case, self.records)
        (self.out / "case.json").write_text("{}")
        with self.assertRaises(ValueError):
            self.collect(seal)
        for field, value in [("first", 1), ("documents", 2), ("revision", 0), ("canonical_bytes", 0)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.collect(self.seal(self.case, [{**self.records[0], field: value}]))
        with self.assertRaisesRegex(ValueError, "cover every tenant-strided ordinal"):
            self.collect(self.seal(self.case, []))
        other = copy.deepcopy(self.case)
        other["nodes"][0]["providers"]["alpha"][0] = "fixture"
        with self.assertRaisesRegex(ValueError, "provider"):
            self.collect(self.seal(other, self.records))
        with self.assertRaisesRegex(ValueError, "corpus or driver"):
            self.collect(self.seal({**self.case, "complete": False}, self.records))
        with self.assertRaisesRegex(ValueError, "corpus or driver"):
            self.collect(self.seal({**self.case, "schema": "kasumi-installed-embedded-v1"}, self.records))
