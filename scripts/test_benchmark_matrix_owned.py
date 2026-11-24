import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import run_benchmark_matrix_owned as matrix


class InstalledMatrixTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.out = self.root / "local-1.native"
        self.out.mkdir()
        self.digest = "c" * 64
        self.plan = {"nodes": [{"sha256": "a" * 64}], "tenants": {"alpha": {}}}
        self.nodes = [{"database_id": "id", "mode": "standalone", "tenants": [
            {"tenant": "alpha", "keys": {"kind": "transit"}, "custody_keys": {"kind": "file"}}]}]
        self.case = {"schema": "kasumi-installed-embedded-v1", "executable_sha256": self.digest,
                     "plan_sha256": "b" * 64, "mode": "local", "attempt": "id", "tenants": ["alpha"],
                     "nodes": [{"configuration_sha256": "a" * 64, "database_id": "id", "voter": None,
                                "providers": {"alpha": ["transit", "file"]}}], "voters": {"alpha": [1]},
                     "documents": 3, "canonical_bytes": 3072, "receipts": 1, "complete": True, "measurements": []}
        for name in sorted(matrix.acceptance.BASE_WORKLOADS):
            self.case["measurements"].append({"name": name, "successful_elapsed_ns": [900, 400, 500],
                "requested_operations": 3, "attempted_operations": 3, "successful_operations": 3,
                "failed_operations": 0, "unattempted_operations": 0, "failed_attempts": [],
                "latency": {"operations": 3, "p50_microseconds": .5, "p99_microseconds": .9, "max_microseconds": .9}})
        self.batch = {"tenant": "alpha", "first": 0, "documents": 3, "canonical_bytes": 3072, "revision": 2}

    def seal(self, case, batch):
        (self.out / "case.json").write_text(json.dumps(case))
        (self.out / "load-receipts.jsonl").write_text(json.dumps(batch) + "\n")
        return json.dumps({"schema": "kasumi-benchmark-outputs-v1", "files": {
            p.name: matrix.sha256(p) for p in self.out.iterdir()}}).encode()

    def collect(self, seal, replay=False):
        with patch.object(matrix.probes, "DOCUMENTS", 3), patch.object(matrix.probes, "OPERATIONS", 3):
            return matrix.installed_case(self.root, self.out, "local-1", self.digest, seal,
                                         self.plan, self.nodes, None, replay)

    def test_replay_original_receipts_and_scope(self):
        seal = self.seal(self.case, self.batch)
        case = self.collect(seal)
        self.assertEqual(self.collect(seal, True), case)
        samples = self.root / case["workloads"][0]["samples"]["path"]
        rows = samples.read_text().splitlines()
        samples.write_text("\n".join(reversed(rows)) + "\n")
        with self.assertRaisesRegex(ValueError, "retained rows"):
            self.collect(seal, True)

    def test_original_hashes_partial_corpus_and_provider_cannot_be_substituted(self):
        seal = self.seal(self.case, self.batch)
        (self.out / "case.json").write_text("{}")
        with self.assertRaises(ValueError):
            self.collect(seal)
        for field, value in [("first", 1), ("documents", 2), ("revision", 0), ("canonical_bytes", 0)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.collect(self.seal(self.case, {**self.batch, field: value}))
        other = copy.deepcopy(self.case)
        other["nodes"][0]["providers"]["alpha"][0] = "fixture"
        with self.assertRaisesRegex(ValueError, "provider"):
            self.collect(self.seal(other, self.batch))
        with self.assertRaisesRegex(ValueError, "corpus or driver"):
            self.collect(self.seal({**self.case, "complete": False}, self.batch))
