import copy
import json
from pathlib import Path
import tempfile
import unittest

import run_benchmark_probes as probe


class BenchmarkProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.original = {
            "format": "kasumi-raw-matrix-v1", "tenants": 1, "documents": 2, "payload_bytes": 2048,
            "provider": "none", "executable_sha256": "a" * 64,
            "measurement": {"name": "raw_hashmap_borrowed_lookup", "requested_operations": 3,
                "attempted_operations": 3, "successful_operations": 3, "failed_operations": 0,
                "unattempted_operations": 0, "failed_attempts": [], "successful_elapsed_ns": [900, 200, 700],
                "latency": {"operations": 3, "p50_microseconds": .7, "p99_microseconds": .9, "max_microseconds": .9}},
        }

    def collect(self, original):
        return probe.raw_case(self.root, original, "a" * 64, 1, documents=2, operations=3)

    def test_original_order_is_retained(self):
        case = self.collect(self.original)
        measured, = case["workloads"]
        rows = [json.loads(line) for line in (self.root / measured["samples"]["path"]).read_bytes().splitlines()]
        self.assertEqual([r["elapsed_ns"] for r in rows], [900, 200, 700])
        self.assertEqual([r["sequence"] for r in rows], [0, 1, 2])

    def test_summary_cannot_replace_or_relabel_native_observations(self):
        edits = [
            ("payload_bytes", 0), ("executable_sha256", "b" * 64), ("documents", 1),
            ("measurement.successful_elapsed_ns", []), ("measurement.successful_elapsed_ns", [200] * 3),
            ("measurement.failed_operations", 1), ("measurement.failed_attempts", [{"operation_index": 2}]),
            ("measurement.latency.max_microseconds", 1.0),
        ]
        for field, value in edits:
            with self.subTest(field=field):
                original = copy.deepcopy(self.original)
                target = original
                parts = field.split(".")
                for part in parts[:-1]:
                    target = target[part]
                target[parts[-1]] = value
                with self.assertRaises(ValueError):
                    self.collect(original)
                self.assertFalse((self.root / "raw-1.jsonl").exists())

    def test_wire_workload_requires_both_protocols_and_credential_paths(self):
        target = {"token_file": "/private/a", "mutation_body": "/private/doc.json", "query": {}}
        config = {"cases": [{"name": protocol, "protocol": protocol, "endpoint": "https://localhost",
                            "operations": probe.OPERATIONS, "targets": [target], "ca_pem": "/private/ca.pem"}
                           for protocol in ("grpc", "mcp")]}
        self.assertEqual(set(probe.network_inputs(config, 1)), {"grpc", "mcp"})
        with self.assertRaises(ValueError):
            probe.network_inputs(config, 100)
        config["cases"][1]["targets"][0]["token_file"] = "relative"
        with self.assertRaises(ValueError):
            probe.network_inputs(config, 1)
