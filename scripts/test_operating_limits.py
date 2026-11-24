"""Synthetic samples exercise the renderer independently of native qualification."""
import json
from pathlib import Path
import tempfile
import unittest

import attempt_index
import operating_limits as limits
import verify_release_acceptance as acceptance


class OperatingLimitsTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.source = {"commit": "a" * 40, "tree": "b" * 40}

    def file(self, name, data):
        path = self.root / name
        path.write_bytes(data)
        return attempt_index.file_ref(self.root, path)

    def jsonl(self, name, records):
        return self.file(name, b"".join(attempt_index.canonical(row) for row in records))

    def gates(self):
        samples = self.jsonl("latency.jsonl", [{"sequence": n, "status": "passed", "elapsed_ns": t}
                                              for n, t in enumerate([100, 277, 511])])
        work = {"name": "point-lookup", "requested_operations": 3, "attempted_operations": 3,
                "successful_operations": 3, "unattempted_operations": 0, "failed_operations": 0, "samples": samples}
        resources = self.jsonl("resources.jsonl", [{"elapsed_seconds": n, **dict.fromkeys(limits.METRICS, value)}
                                                   for n, value in enumerate([15, 17])])
        heartbeats = self.jsonl("heartbeats.jsonl", [{"elapsed_seconds": n * 60, "successful_operations": n + 1,
                                                      "unexpected_errors": 0, "integrity_mismatches": 0} for n in range(1441)])
        results = {}
        for kind in limits.KINDS:
            identifier = f"{kind}:{acceptance.REFERENCE}"
            names = sorted(acceptance.SCENARIOS[kind])
            if kind.startswith("capacity-"):
                details = {"corpus": {"documents": 400, "canonical_bytes": 4000, "compression": {"output_bytes": 3500}},
                           "operations": [{"id": name, "resources": resources, "limits": dict.fromkeys(limits.METRICS, 20),
                                           "read_retention_budget_bytes": 100} for name in names]}
            elif kind == "concurrency":
                details = {"workloads": [{"name": name, "workers": 3, "peak_inflight": 2, "measurement": work} for name in names]}
            elif kind == "benchmark-matrix":
                details = {"cases": [{"id": name, "mode": name.split("-")[0], "tenants": int(name.split("-")[1]),
                                      "documents": 1_000_000, "workloads": [work]} for name in names]}
            else:
                details = {"duration_seconds": 86400, "heartbeats": heartbeats, "report": self.file("soak-report.json", b"{}"),
                           "maintenance": [{"id": name, "elapsed_seconds": 100, "log": samples} for name in names]}
            gate = {"id": identifier, "status": "passed", "identity": {"source_commit": self.source["commit"],
                    "source_tree": self.source["tree"]}, "started_at": "2026-03-01T00:00:00Z", "finished_at": "2026-03-02T00:00:01Z",
                    "host": {"id": "reference", "reservation": {"cpu_count": 2, "disk_bytes": 200 << 30, "memory_bytes": 16 << 30}},
                    "details": details}
            results[identifier] = {"id": identifier, "evidence": self.file(kind + ".json", json.dumps(gate).encode())}
        return results

    def test_report_derives_peaks_latency_counts_and_soak_from_referenced_bytes(self):
        gates = self.gates()
        result = limits.render(self.root, gates, self.source).decode()
        self.assertIn("17 / 20 | 17 / 20 | 17 / 20", result)
        self.assertIn("3 | 100 | 296 | 511", result)
        self.assertIn("1,441 successful operations", result)
        self.assertIn("86,400 seconds", result)
        (self.root / "latency.jsonl").write_text("changed")
        with self.assertRaisesRegex(ValueError, "artifact changed"):
            limits.render(self.root, gates, self.source)

    def test_wrong_source_and_short_soak_fail(self):
        gates = self.gates()
        with self.assertRaisesRegex(ValueError, "selected source"):
            limits.render(self.root, gates, {**self.source, "commit": "f" * 40})
        key = f"ha-soak:{acceptance.REFERENCE}"
        value = acceptance.json_reference(self.root, gates[key]["evidence"])
        value["details"]["duration_seconds"] = 300
        gates[key]["evidence"] = self.file("short.json", json.dumps(value).encode())
        with self.assertRaisesRegex(ValueError, "soak duration"):
            limits.render(self.root, gates, self.source)


if __name__ == "__main__":
    unittest.main()
