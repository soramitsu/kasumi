"""Synthetic counterexamples; these fixtures are never release evidence."""
import copy
import datetime as dt
import hashlib
import io
import json
from pathlib import Path
import py_compile
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import attempt_index
from test_benchmark_matrix_owned import BOUNDS, CONFIRMED, DEADLINE, FOUND, PAUSE, load_records, step
import verify_release_acceptance as acceptance


def end(steps):
    return steps[-1]["offset_ns"] + steps[-1]["elapsed_ns"]


def resends(first, pauses):
    """An uncertain first attempt, then one absent lookup, backoff and uncertain
    resend per pause (milliseconds), settled by a found receipt."""
    steps, at = [first], end([first])
    for pause in pauses:
        steps += [step("lookup", at, 20, "absent"), step("backoff", at + 20, pause * 1_000_000, "slept"),
                  step("send", at + 20 + pause * 1_000_000, 30, "uncertain", "UNAVAILABLE", "leader lost")]
        at = end(steps)
    return steps + [step("lookup", at, 20, "found")]


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="acceptance-unit-fixture-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def file(self, name, contents=b"synthetic unit fixture\n"):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
        return {"path": name, "sha256": acceptance.sha256(path), "bytes": len(contents)}

    def value(self, name, value):
        return self.file(name, json.dumps(value, sort_keys=True).encode())

    def lines(self, name, values):
        return self.file(name, b"".join(json.dumps(value).encode() + b"\n" for value in values))

    def indexed_attempt(self, attempt_id, processes, status="failed", dispatch_boundary=True):
        started = "2026-01-02T00:00:00+00:00"
        finished = "2026-01-02T00:00:10+00:00"
        output = self.root / (attempt_id + "-output")
        attempt_index.create(self.root, "acceptance-unit-journal", "acceptance-unit-host",
                             acceptance.REFERENCE)
        attempt_index.begin(self.root, attempt_id, "repeatable-assembly", output, started)
        output.mkdir()
        outcome = {
            "schema": "kasumi-owned-repeatable-assembly-v1",
            "custody_root": str(output.resolve()),
            "attempt_id": attempt_id, "status": status,
            "started_at": started, "finished_at": finished}
        if dispatch_boundary != "missing":
            outcome["dispatch_started"] = dispatch_boundary
        evidence = self.value(attempt_id + "-output/launcher.json", outcome)
        record = {"schema": acceptance.SCHEMA, "id": attempt_id, "status": status,
                  "evidence": evidence, "started_at": started,
                  "finished_at": finished, "domain_observation": None,
                  "processes": processes}
        terminal = attempt_index.finish(self.root, attempt_id, record)
        return evidence, terminal["receipt"]

    def measurement(self, count=3):
        return {"name": "unit-workload", "requested_operations": count, "attempted_operations": count,
                "successful_operations": count, "failed_operations": 0, "unattempted_operations": 0,
                "samples": self.lines("samples.jsonl", [{"sequence": i, "elapsed_ns": i + 1, "status": "passed"}
                                                        for i in range(count)])}

    def process(self):
        executable = self.file("executables/cargo")
        cleanup = {"group": 123, "before": [], "after": [], "signals": [], "errors": [],
                   "drained": True, "process_returncode": 0}
        receipt = {"status": "passed", "outputs_stable": True, "command": ["/unit/cargo", "build"],
                   "executable": {"path": "/unit/cargo", "sha256": executable["sha256"]},
                   "exit_code": 0, "process_exit_code": 0, "timeout_seconds": 100, "timed_out": False,
                   "received_signals": [], "error": None, "process_group": 123,
                   "cleanup": cleanup, "duration_seconds": 5}
        process = {"id": "unit-process", "receipt": self.value("process.json", receipt),
                   "log": self.file("process.log"), "executable": executable}
        return process, receipt

    def admin_readback(self):
        """Synthetic shape only; no native client, tenant, or release was run."""
        incarnation = "00000000-0000-4000-8000-000000000001"
        config = self.value("inputs/admin-client.json", {"endpoint": "https://unit.invalid:9445"})
        policy_request = self.value("inputs/policy-request.json", {
            "tenant": "unit-tenant", "expected_incarnation": incarnation})
        schema_request = self.value("inputs/schema-request.json", {"selection": "all"})
        policy = {"grants": [{"principal": "unit-reader", "collection": "payments", "actions": ["read"]}],
                  "strict_read_audit": True}
        definition = {"name": "payments", "write_mode": "append_only",
                      "retention_class": "operational", "schema": {"type": "object"},
                      "indexes": [], "strict_read_audit": True}
        expected = {"admin_config_sha256": config["sha256"], "tenant": "unit-tenant",
                    "incarnation": incarnation, "policy": policy, "limits": {"max_documents": 10},
                    "collections": {"payments": definition}}
        policy_snapshot = {"tenant": "unit-tenant", "incarnation": incarnation,
                           "revision": 8, "policy_epoch": 3, "schema_epoch": 4,
                           "policy": policy, "limits": expected["limits"]}
        schema_snapshot = {"incarnation": incarnation, "revision": 9,
                           "policy_epoch": 3, "schema_epoch": 4,
                           "collections": {"payments": {"definition": definition,
                                                        "data_epoch": 2, "archived_document_count": 0}}}
        executable = self.file("executables/kasumictl")
        witness = {"admin_config": config, "policy_request": policy_request,
                   "schema_request": schema_request, "policy_before": "policy-before",
                   "schema": "schema", "policy_after": "policy-after"}
        processes = []
        for name, operation, request, response in (
                ("policy-before", "read-policy-limits", policy_request, policy_snapshot),
                ("schema", "read-schema", schema_request, schema_snapshot),
                ("policy-after", "read-policy-limits", policy_request,
                 {**policy_snapshot, "revision": 10})):
            receipt = {"working_directory": str(self.root.resolve()),
                       "executable": {"path": "/unit/kasumictl", "sha256": executable["sha256"]},
                       "command": ["/unit/kasumictl", "--config", str(self.root.resolve() / config["path"]),
                                   operation, str(self.root.resolve() / request["path"])],
                       "status": "passed", "outputs_stable": True, "exit_code": 0}
            processes.append({"id": name, "receipt": self.value("admin/" + name + ".receipt.json", receipt),
                              "log": self.value("admin/" + name + ".stdout.json", response),
                              "executable": executable})
        return witness, processes, {"kasumictl": executable["sha256"]}, expected

    def test_permanent_sessions_use_the_adopted_floor_and_four_authentic_former_counts(self):
        log = self.file("component.log")
        counts = [{"id": key, "former_limit": limit, "observed": limit + 1, "log": log}
                  for key, limit in acceptance.PERMANENT_HISTORY_LIMITS.items()]
        session = {"id": "sessions", "acceptance_floor": 100_001, "observed": 100_001, "log": log}
        acceptance.check_lifetime_counts(self.root, [*counts, session])
        for changed in ({"observed": 100_000}, {"acceptance_floor": 256},
                        {"former_limit": 65_536}, {"observed": True}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                acceptance.check_lifetime_counts(self.root, [*counts, {**session, **changed}])
        for i, historical in enumerate(counts):
            for change in ({"former_limit": 1}, {"observed": historical["former_limit"]}):
                with self.subTest(category=historical["id"], change=change), self.assertRaises(ValueError):
                    acceptance.check_lifetime_counts(self.root, [
                        *counts[:i], {**historical, **change}, *counts[i + 1:], session])

    def test_native_admin_readback_requires_candidate_processes_and_exact_pinned_state(self):
        witness, processes, binaries, expected = self.admin_readback()
        acceptance.check_native_admin_readback(self.root, witness, processes, binaries, expected)

        def rejected(change):
            witness, processes, binaries, expected = self.admin_readback()
            change(witness, processes, binaries, expected)
            with self.assertRaises(ValueError):
                acceptance.check_native_admin_readback(self.root, witness, processes, binaries, expected)

        def response(process, change):
            value = acceptance.json_reference(self.root, process["log"])
            change(value)
            process["log"] = self.value(process["log"]["path"], value)

        def receipt(process, change):
            value = acceptance.json_reference(self.root, process["receipt"])
            change(value)
            process["receipt"] = self.value(process["receipt"]["path"], value)

        rejected(lambda w, p, b, e: response(p[0], lambda v: v.update(tenant="other")))
        rejected(lambda w, p, b, e: response(p[1], lambda v: v.update(incarnation="other")))
        rejected(lambda w, p, b, e: response(p[0], lambda v: v["policy"]["grants"].append(
            {"principal": "unit-attacker", "collection": None, "actions": ["admin"]})))
        rejected(lambda w, p, b, e: response(p[2], lambda v: v["policy"]["grants"].clear()))
        rejected(lambda w, p, b, e: response(p[2], lambda v: v["limits"].update(max_documents=11)))
        rejected(lambda w, p, b, e: response(p[1], lambda v: v["collections"]["payments"]
                 ["definition"].update(write_mode="mutable")))
        rejected(lambda w, p, b, e: response(p[1], lambda v: v.update(schema_epoch=5)))
        rejected(lambda w, p, b, e: response(p[2], lambda v: v.update(policy_epoch=4)))
        rejected(lambda w, p, b, e: response(p[1], lambda v: v.update(revision=11)))
        rejected(lambda w, p, b, e: response(p[1], lambda v: v["collections"].clear()))
        rejected(lambda w, p, b, e: e.update(admin_config_sha256="0" * 64))
        rejected(lambda w, p, b, e: w.update(policy_request=self.value(
            "inputs/wrong-policy-request.json", {"tenant": "other", "expected_incarnation": e["incarnation"]})))
        rejected(lambda w, p, b, e: w.update(schema_request=self.value(
            "inputs/wrong-schema-request.json", {"collections": [{"payments": True}]})))
        for request in ({"collections": ["payments"]},
                        {"selection": "named", "collections": ["payments"]},
                        {"selection": "all", "collections": ["payments"]}):
            rejected(lambda w, p, b, e: w.update(schema_request=self.value(
                "inputs/partial-schema-request.json", request)))
        rejected(lambda w, p, b, e: b.update(kasumictl="0" * 64))
        rejected(lambda w, p, b, e: p[0].update(executable=self.file(
            "executables/substitute", b"different executable bytes")))
        rejected(lambda w, p, b, e: receipt(p[0], lambda v: v["command"].__setitem__(0, "/unit/other")))
        rejected(lambda w, p, b, e: receipt(p[0], lambda v: v["command"].__setitem__(2, "/tmp/other.json")))
        rejected(lambda w, p, b, e: receipt(p[0], lambda v: v["command"].__setitem__(4, "/tmp/other.json")))
        def alternate_working_tree(w, p, b, e):
            def rewrite(value):
                value["working_directory"] = "/alternate"
                value["command"][2] = "/alternate/inputs/admin-client.json"
                value["command"][4] = "/alternate/inputs/policy-request.json"
            receipt(p[0], rewrite)
        rejected(alternate_working_tree)
        rejected(lambda w, p, b, e: receipt(p[0], lambda v: v["command"].__setitem__(3, "set-policy")))
        rejected(lambda w, p, b, e: w.update(policy_after="policy-before"))
        rejected(lambda w, p, b, e: response(p[0], lambda v: v["policy"]["grants"]
                 .append(copy.deepcopy(v["policy"]["grants"][0]))))
        rejected(lambda w, p, b, e: response(p[0], lambda v: v["policy"].update(strict_read_audit=1)))
        rejected(lambda w, p, b, e: response(p[0], lambda v: v.update(revision=True)))

    def host(self):
        return {"id": "same-physical-host", "physical_machine": "aarch64", "execution_machine": "aarch64",
                "emulated": False, "reservation": {"id": "unit-reservation", "starts_at": "2026-01-01T00:00:00+00:00",
                    "ends_at": "2026-01-04T00:00:00+00:00", "cpu_count": 4,
                    "memory_bytes": 16 << 30, "disk_bytes": 128 << 30},
                "preflight": self.value("host.json", {"schema": 3, "os": "Linux", "machine": "aarch64",
                    "requested_target": acceptance.REFERENCE,
                    "errors": [], "translated": False, "effective_memory_bytes": 16 << 30}),
                "attestation": self.file("host-attestation.txt")}

    def capacity(self):
        size = 4 << 30
        plan = {"run_id": "00000000-0000-0000-0000-000000000001", "collection": "capacity",
                "seed_sha256": "b" * 64, "documents": 4096, "document_bytes": 1 << 20,
                "batch_documents": 3}
        batches = [{"first": first, "documents": min(3, 4096 - first),
                    "canonical_bytes": min(3, 4096 - first) << 20,
                    "expected_sha256": "a" * 64, "observed_sha256": "a" * 64}
                   for first in range(0, 4096, 3)]
        integrity = self.lines("integrity.jsonl", batches)
        verify_start = {"event": "started", "format": 1, "mode": "verify", "corpus": plan,
                        "expected_canonical_bytes": size, "endpoint": "https://localhost:9444",
                        "configuration_sha256": "1" * 64, "executable_sha256": "d" * 64,
                        "os": "linux", "architecture": "aarch64", "credential_binding_claims": {},
                        "credential_binding_scope": "fixture", "scope": "fixture", "generator": "fixture"}
        prefixes = [r["first"] + r["documents"] for r in batches]
        verification = self.lines("verification.jsonl", [verify_start,
            *[{"event": "verified_prefix", "documents": n, "canonical_bytes": n << 20} for n in prefixes],
            {"event": "passed", "documents": 4096, "canonical_bytes": size, "expected_sha256": "f" * 64,
             "observed_sha256": "f" * 64, "integrity_sha256": integrity["sha256"]}])
        limits = {"rss_bytes": 1 << 30, "allocated_disk_bytes": 8 << 30, "maintenance_workspace_bytes": 64 << 20}
        resources = self.lines("resources.jsonl", [{"elapsed_seconds": i, **limits} for i in (0, 1)])
        compression_log = self.lines("compression.jsonl", [
            {"event": "started", "format": 1, "mode": "measure", "algorithm": "gzip-9",
             "configuration_sha256": "c" * 64, "executable_sha256": "d" * 64, "os": "linux",
             "architecture": "aarch64", "expected_canonical_bytes": size, "corpus": plan},
            {"event": "measured", "documents": 4096, "algorithm": "gzip-9", "input_bytes": size,
             "output_bytes": size * 4 // 5, "canonical_sha256": "a" * 64, "gzip_sha256": "e" * 64,
             "expected_sha256": "f" * 64, "seconds": 100.0}])
        return {"corpus": {"documents": 4096, "canonical_bytes": size, "seed_sha256": "b" * 64,
                    "compression": {"algorithm": "gzip-9", "input_bytes": size, "output_bytes": size * 4 // 5,
                                    "log": compression_log}},
                "operations": [{"id": name, "integrity": integrity, "verification": verification, "resources": resources,
                    "limits": limits.copy(), "read_retention_budget_bytes": 64 << 20}
                    for name in sorted(acceptance.SCENARIOS["capacity-ha"])]}

    def soak(self):
        return {"duration_seconds": 86400, "heartbeats": self.lines("heartbeats.jsonl", [
                    {"elapsed_seconds": i * 60, "successful_operations": i,
                     "unexpected_errors": 0, "integrity_mismatches": 0} for i in range(1441)]),
                "maintenance": [{"id": name, "elapsed_seconds": 3600, "log": self.file(name + ".log")}
                                for name in sorted(acceptance.SCENARIOS["ha-soak"])],
                "report": self.file("soak-report.json")}

    def test_json_rejects_duplicate_keys_and_nonfinite_values(self):
        for value in ('{"schema":1,"schema":2}', '{"value":NaN}', '{"value":Infinity}'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                acceptance.decode(value)

    def test_references_reject_aliases_escape_symlinks_and_changed_content(self):
        ref = self.file("owned/file")
        acceptance.reference(self.root, ref)
        for path in ("/etc/passwd", "../file", "owned/../owned/file", "./owned/file", "owned//file", "owned\\file", "."):
            with self.subTest(path=path), self.assertRaises(ValueError):
                acceptance.reference(self.root, {**ref, "path": path})
        (self.root / "link").symlink_to(self.root / "owned", target_is_directory=True)
        with self.assertRaises(ValueError):
            acceptance.reference(self.root, {**ref, "path": "link/file"})
        (self.root / "owned/file").write_bytes(b"changed")
        with self.assertRaises(ValueError):
            acceptance.reference(self.root, ref)

    def test_source_deliverables_cannot_be_omitted_or_substituted(self):
        files = {}
        artifacts = {}
        for artifact_id, source_name in acceptance.SOURCE_DELIVERABLES.items():
            ref = self.file("frozen/" + source_name, (source_name + "\n").encode())
            files[source_name] = {"sha256": ref["sha256"], "bytes": ref["bytes"],
                                  "executable": False}
            artifacts[artifact_id] = {"id": artifact_id, "file": ref}
        acceptance.check_source_deliverables(files, artifacts)
        omitted = dict(files)
        omitted.pop("LICENSE")
        with self.assertRaisesRegex(ValueError, "omits required deliverable: LICENSE"):
            acceptance.check_source_deliverables(omitted, artifacts)
        replaced = copy.deepcopy(artifacts)
        replaced["notice"]["file"] = self.file("substituted-NOTICE", b"different notice\n")
        with self.assertRaisesRegex(ValueError, "differs from frozen source: notice"):
            acceptance.check_source_deliverables(files, replaced)

    def test_sample_stream_is_complete_contiguous_and_successful(self):
        measurement = self.measurement()
        acceptance.check_samples(self.root, measurement)
        for change in ("failed", "unattempted", "short", "duplicate", "extra", "bool", "zero-duration", "truncated"):
            with self.subTest(change=change):
                value = self.measurement()
                if change == "failed":
                    value["failed_operations"] = 1
                elif change == "unattempted":
                    value["unattempted_operations"] = 1
                elif change == "bool":
                    value["successful_operations"] = True
                elif change == "truncated":
                    value["samples"] = self.file("samples.jsonl", b'{"sequence":0}')
                else:
                    rows = list(acceptance.rows(self.root, value["samples"]))
                    if change == "short":
                        rows.pop()
                    elif change == "duplicate":
                        rows[1]["sequence"] = 0
                    elif change == "extra":
                        rows.append({"sequence": 3, "elapsed_ns": 1, "status": "passed"})
                    else:
                        rows[0]["elapsed_ns"] = 0
                    value["samples"] = self.lines("samples.jsonl", rows)
                with self.assertRaises(ValueError):
                    acceptance.check_samples(self.root, value)

    def test_fixed_benchmark_roster_cannot_reduce_documents_tenants_or_protocols(self):
        cases = []
        for mode in acceptance.MODES:
            expected = set(acceptance.BASE_WORKLOADS)
            if mode == "raw":
                expected = {"raw_hashmap_borrowed_lookup"}
            elif mode == "text":
                expected |= {"text_english_Phrase_complete_pages", "text_english_Prefix_complete_pages",
                             "text_english_Fuzzy_complete_pages", "text_japanese_Terms_complete_pages"}
            elif mode == "network":
                expected = {protocol + ":" + name for protocol in ("grpc", "mcp") for name in acceptance.NETWORK_WORKLOADS}
            for tenants in acceptance.TENANTS:
                cases.append({"id": f"{mode}-{tenants}", "mode": mode, "tenants": tenants, "documents": 1_000_000,
                              "provider": "none" if mode == "raw" else "production",
                              "workloads": [{"name": name} for name in sorted(expected)]}
                             | ({} if mode == "raw" else {"load": {}}))
        # This test isolates roster validation. Raw sample and corpus load
        # validation are exercised separately with retained JSONL bytes.
        with patch.object(acceptance, "check_samples") as samples, \
                patch.object(acceptance, "check_load_summary") as loads:
            acceptance.check_benchmarks(self.root, {"cases": cases})
            self.assertEqual(samples.call_count, 99)
            self.assertEqual(loads.call_count, 12)
            for change in ("missing-case", "duplicate-case", "short", "fixture", "missing-workload", "wrong-tenants",
                           "missing-load", "raw-load"):
                value = copy.deepcopy(cases)
                if change == "missing-case":
                    value.pop()
                elif change == "duplicate-case":
                    value.append(value[0])
                elif change == "short":
                    value[0]["documents"] = 999999
                elif change == "fixture":
                    value[-1]["provider"] = "fixture"
                elif change == "missing-workload":
                    value[-1]["workloads"].pop()
                elif change == "missing-load":
                    del value[-1]["load"]
                elif change == "raw-load":
                    value[0]["load"] = {}
                else:
                    value[-1]["tenants"] = 100
                with self.subTest(change=change), self.assertRaises(ValueError):
                    acceptance.check_benchmarks(self.root, {"cases": value})

    def corpus_load(self, records, bounds=BOUNDS, tenants=2, documents=5):
        ref = self.lines("load-batches.jsonl", records)
        return acceptance.check_load(self.root, ref, bounds, tenants, documents)

    def test_corpus_load_recomputes_coverage_resolution_and_recovery_cost(self):
        clean = load_records(["a", "b"], 5, "run")
        summary, order, scopes, prefix = self.corpus_load(clean)
        self.assertEqual((order, prefix), (["a", "b"], "run"))
        self.assertEqual(scopes["b"], {"tenant": "b", "incarnation": "incarnation-b", "principal": "bench-app"})
        self.assertEqual({k: summary[k] for k in ("batches", "documents", "canonical_bytes", "affected_batches",
                                                  "first_attempt_deadline_misses", "resends", "lookups", "unresolved")},
                         {"batches": 2, "documents": 5, "canonical_bytes": 5120, "affected_batches": 0,
                          "first_attempt_deadline_misses": 0, "resends": 0, "lookups": 0, "unresolved": 0})
        self.assertEqual(summary["first_attempt_deadline_miss_rate"], 0.0)
        # Several batches per tenant, one found before resend and one confirmed after.
        with patch.object(acceptance, "LOAD_BATCH_DOCUMENTS", 2):
            records = load_records(["a", "b"], 9, "run", {1: FOUND, 3: CONFIRMED}, size=2)
            summary = self.corpus_load(records, {**BOUNDS, "maximum_affected_batches": 2}, documents=9)[0]
            self.assertEqual({k: summary[k] for k in ("batches", "documents", "affected_batches",
                                                      "receipt_found_before_resend", "commit_confirmed_after_resend",
                                                      "first_attempt_deadline_misses", "resends", "lookups")},
                             {"batches": 5, "documents": 9, "affected_batches": 2, "receipt_found_before_resend": 1,
                              "commit_confirmed_after_resend": 1, "first_attempt_deadline_misses": 2,
                              "resends": 1, "lookups": 3})
            self.assertEqual(summary["first_attempt_deadline_miss_rate"], 2 / 5)
            self.assertEqual(summary["first_attempt_ns"], {"p50": 54, "p99": 10_000, "max": 10_000})
            self.assertEqual(summary["end_to_end_ns"], {"p50": 54, "p99": 10_070 + PAUSE, "max": 10_070 + PAUSE})
            last = records[-1]
            self.assertEqual(summary["wall_ns"], last["started_ns"] + last["elapsed_ns"] + last["effects_elapsed_ns"])
            self.assertEqual(summary["documents_per_second"], 9 * 1e9 / summary["wall_ns"])
            with self.assertRaisesRegex(ValueError, "exceed the declared bound"):
                self.corpus_load(records, documents=9)

    def test_corpus_load_rejects_incomplete_unsettled_or_overclaimed_batches(self):
        base = load_records(["a", "b"], 5, "run", {1: CONFIRMED})
        self.corpus_load(base)

        def label(rows):
            rows[1]["resolution"] = acceptance.LOAD_FOUND_BEFORE_RESEND

        def bare_counter(rows):
            rows[1]["effects"] = [{"duplicate_commits": 0}] * 2

        def other_version(rows):
            rows[1]["effects"][0]["version"] += 1

        def other_digest(rows):
            rows[1]["receipt"]["request_digest"] = rows[1]["request_digest"] = "0" * 64

        def other_scope(rows):
            rows[1]["receipt"]["scope"] = {**rows[1]["scope"], "incarnation": "restored"}

        def partial_versions(rows):
            rows[1]["receipt"]["versions"].pop("/docs/1")

        def unresolved(rows):
            rows[1].update(resolution="unresolved", failure="outcome unresolved after 4 sends")

        def resend_without_lookup(rows):
            rows[1]["steps"] = [rows[1]["steps"][0], step("backoff", 10_000, PAUSE, "slept"),
                                step("send", 10_000 + PAUSE, 30, "committed"), step("lookup", 10_030 + PAUSE, 40, "found")]
            rows[1]["elapsed_ns"] = 10_070 + PAUSE

        def settled_by_refusal(rows):
            # A refused resend is not a terminal success; only a retained receipt is.
            rows[1]["steps"][3:] = [step("send", 10_020 + PAUSE, 30, "refused", "CONFLICT", "exists")]
            rows[1]["elapsed_ns"] = 10_050 + PAUSE

        def too_many_sends(rows):
            # Four resends honour the declared backoff but exceed four sends.
            rows[1]["steps"] = resends(rows[1]["steps"][0], [100, 200, 400, 800])
            rows[1]["elapsed_ns"] = end(rows[1]["steps"])

        def short_backoff(rows):
            rows[1]["steps"][2]["elapsed_ns"] = PAUSE - 1

        def over_budget(rows):
            rows[1]["steps"][-1]["elapsed_ns"] = 60_000 * 1_000_000
            rows[1]["elapsed_ns"] = end(rows[1]["steps"])

        def untyped_uncertain(rows):
            rows[1]["steps"][0]["code"] = None

        def overlap(rows):
            rows[1]["started_ns"] = rows[0]["started_ns"]

        changes = {
            "missing record": lambda rows: rows.pop(),
            "duplicate record": lambda rows: rows.append(dict(rows[-1])),
            "reordered tenants": lambda rows: rows.reverse(),
            "label claims no resend": label,
            "bare duplicate counter": bare_counter,
            "effect at another version": other_version,
            "receipt for other input": other_digest,
            "receipt in another scope": other_scope,
            "partial target-version map": partial_versions,
            "unresolved batch": unresolved,
            "resend before lookup": resend_without_lookup,
            "refusal settles": settled_by_refusal,
            "attempt limit": too_many_sends,
            "backoff shorter than declared": short_backoff,
            "budget": over_budget,
            "untyped uncertain outcome": untyped_uncertain,
            "overlapping batches": overlap,
        }
        for name, change in changes.items():
            rows = copy.deepcopy(base)
            change(rows)
            with self.subTest(change=name), self.assertRaises(ValueError):
                self.corpus_load(rows)
        for bounds in ({**BOUNDS, "attempts": 9}, {**BOUNDS, "maximum_affected_batches": 41},
                       {**BOUNDS, "budget_milliseconds": 900}, {**BOUNDS, "maximum_backoff_milliseconds": 50},
                       {k: v for k, v in BOUNDS.items() if k != "attempts"}, {**BOUNDS, "attempts": True}):
            with self.subTest(bounds=bounds), self.assertRaises(ValueError):
                self.corpus_load(base, bounds)
        load = {**self.corpus_load(base)[0], "records": self.lines("load-batches.jsonl", base)}
        self.assertEqual(acceptance.check_load_summary(self.root, load, 2, 5)["affected_batches"], 1)
        for field, value in (("resends", 0), ("first_attempt_deadline_misses", False), ("unresolved", None)):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "summary differs"):
                acceptance.check_load_summary(self.root, {**load, field: value}, 2, 5)

    def test_corpus_load_enforces_declared_attempts_backoff_and_budget(self):
        base = load_records(["a", "b"], 5, "run", {1: CONFIRMED})

        def resent(pauses, bounds):
            rows = copy.deepcopy(base)
            rows[1]["steps"] = resends(rows[1]["steps"][0], pauses)
            rows[1]["elapsed_ns"] = end(rows[1]["steps"])
            return rows, bounds

        # Backoff doubles from the declared initial delay and is capped at the maximum.
        rows, bounds = resent([100, 200, 400, 800, 1_000], {**BOUNDS, "attempts": 6})
        summary = self.corpus_load(rows, bounds)[0]
        self.assertEqual((summary["resends"], summary["lookups"], summary["commit_confirmed_after_resend"]), (5, 6, 1))
        pauses = [n for n, s in enumerate(rows[1]["steps"]) if s["action"] == "backoff"]
        for index, short in ((pauses[0], PAUSE - 1), (pauses[3], 800_000_000 - 1), (pauses[4], 1_000_000_000 - 1)):
            changed = copy.deepcopy(rows)
            changed[1]["steps"][index]["elapsed_ns"] = short
            with self.subTest(backoff=index), self.assertRaisesRegex(ValueError, "shorter than its declared delay"):
                self.corpus_load(changed, bounds)
        self.corpus_load(*resent([100, 200, 400], BOUNDS))
        with self.assertRaisesRegex(ValueError, "declared attempt limit"):
            self.corpus_load(*resent([100, 200, 400, 800], BOUNDS))
        rows = copy.deepcopy(base)
        rows[1]["steps"][-1]["elapsed_ns"] = BOUNDS["budget_milliseconds"] * 1_000_000
        rows[1]["elapsed_ns"] = end(rows[1]["steps"])
        with self.assertRaisesRegex(ValueError, "declared budget"):
            self.corpus_load(rows)

    def test_corpus_batch_digest_matches_the_driver(self):
        # crates/kasumi-bench/src/corpus_load_tests.rs pins the same vectors.
        self.assertEqual(acceptance.corpus_batch_digest("unit-load-0", [0, 3], 3),
                         "dd19f062d74cb61fa8d6b56be2619c0c78325842c317d6c25abea052618997da")
        self.assertEqual([hashlib.sha256(acceptance.canonical_json(acceptance.corpus_body(n, 3))).hexdigest()
                          for n in (0, 3)],
                         ["224169d68453ee4cc5a0461aa6d44ee016a711e5bfab723f74785e25aaa9a560",
                          "25af119de508f39cf6e36570ed791d713f2856c46a3e308b1d6f41a08ab36f8b"])
        self.assertEqual(len(acceptance.canonical_json(acceptance.corpus_body(999_999, 1))), 1024)

    def test_benchmark_processes_bind_the_driver_embedding_the_qualified_daemon(self):
        daemon, driver = "d" * 64, "e" * 64
        bench = "path+file:///build/source/crates/kasumi-bench#0.1.0"
        packages = {"path+file:///build/source/crates/kasumi-server#0.1.0": {"features": [], "targets": []},
                    "registry+https://github.com/rust-lang/crates.io-index#tokio@1.48.0": {
                        "features": ["full"], "targets": []}}

        def candidate(change=None):
            production = {"name": "production", "compiled_packages": copy.deepcopy(packages), "executables": {
                "release/kasumid": {"target": "kasumid", "test": False, "sha256": daemon, "package_id": "server"}}}
            network = {"name": "network-driver",
                       "compiled_packages": {**copy.deepcopy(packages), bench: {"features": ["installed-embedded"],
                                                                                "targets": []}},
                       "executables": {"release/kasumi-bench-network": {
                           "target": "kasumi-bench-network", "test": False, "sha256": driver, "package_id": bench}}}
            if change:
                change(production, network)
            return {"primary": {"functional": self.value("functional/evidence.json",
                                                         {"gates": [production, network]})}}

        processes = [{"id": "local-1", "executable": {"sha256": driver}},
                     {"id": "raw-1", "executable": {"sha256": driver}}]
        acceptance.check_benchmark_processes(self.root, processes, candidate(), {"kasumid": daemon})
        refusals = {
            "kasumid process": (processes + [{"id": "daemon", "executable": {"sha256": daemon}}], None),
            "no processes": ([], None),
            "other daemon": (processes, lambda p, n: p["executables"]["release/kasumid"].update(sha256="f" * 64)),
            "feature differs": (processes, lambda p, n: n["compiled_packages"][next(iter(packages))].update(
                features=["test-utils"])),
            "extra package": (processes, lambda p, n: n["compiled_packages"].update({"fixture": {"features": []}})),
            "missing package": (processes, lambda p, n: n["compiled_packages"].pop(next(iter(packages)))),
            "test driver": (processes, lambda p, n: n["executables"]["release/kasumi-bench-network"].update(test=True)),
        }
        for name, (inventory, change) in refusals.items():
            with self.subTest(change=name), self.assertRaises(ValueError):
                acceptance.check_benchmark_processes(self.root, inventory, candidate(change), {"kasumid": daemon})

    def test_capacity_replays_original_measurement_before_accepting_reported_counts(self):
        for change in ("extra-event", "short", "different-output", "different-seed", "missing-digest"):
            with self.subTest(change=change):
                corpus = self.capacity()["corpus"]
                events = list(acceptance.rows(self.root, corpus["compression"]["log"]))
                if change == "extra-event":
                    events.append(events[-1])
                elif change == "short":
                    events.pop()
                elif change == "different-output":
                    events[-1]["output_bytes"] -= 1
                elif change == "different-seed":
                    events[0]["corpus"]["seed_sha256"] = "a" * 64
                else:
                    del events[-1]["gzip_sha256"]
                corpus["compression"]["log"] = self.lines("changed-compression.jsonl", events)
                with self.assertRaises(ValueError):
                    acceptance.replay_capacity_measurement(self.root, corpus)

    def test_capacity_verification_binds_original_prefixes_driver_and_measured_framed_digest(self):
        value = self.capacity()
        measured = acceptance.replay_capacity_measurement(self.root, value["corpus"])
        op = value["operations"][0]
        measured[0]["corpus"]["batch_documents"] = 1
        acceptance.check_integrity(self.root, op, measured)
        original = list(acceptance.rows(self.root, op["verification"]))
        for row, key, replacement in ((0, "executable_sha256", "3" * 64), (1, "documents", 2),
                                      (-1, "observed_sha256", "a" * 64),
                                      (-1, "integrity_sha256", "b" * 64)):
            with self.subTest(key=key):
                events = [dict(item) for item in original]
                events[row][key] = replacement
                op["verification"] = self.lines("changed-verification.jsonl", events)
                with self.assertRaises(ValueError):
                    acceptance.check_integrity(self.root, op, measured)

    def test_capacity_must_exceed_three_gib_and_cover_every_operation(self):
        value = self.capacity()
        acceptance.check_capacity(self.root, value, "capacity-ha")
        for change in ("exactly-3gib", "compressible", "missing-operation", "duplicate-operation", "large-workspace",
                       "large-retention", "sampled-integrity", "wrong-digest", "unknown-resource"):
            value = self.capacity()
            if change == "exactly-3gib":
                value["corpus"]["canonical_bytes"] = 3 << 30
            elif change == "compressible":
                value["corpus"]["compression"]["output_bytes"] = 1 << 30
            elif change == "missing-operation":
                value["operations"].pop()
            elif change == "duplicate-operation":
                value["operations"].append(value["operations"][0])
            elif change == "large-workspace":
                value["operations"][0]["limits"]["maintenance_workspace_bytes"] = 4 << 30
            elif change == "large-retention":
                value["operations"][0]["read_retention_budget_bytes"] = 4 << 30
            elif change == "unknown-resource":
                value["operations"][0]["limits"]["rss_bytes"] = None
            else:
                batches = list(acceptance.rows(self.root, value["operations"][0]["integrity"]))
                if change == "sampled-integrity":
                    batches.pop()
                else:
                    batches[0]["observed_sha256"] = "c" * 64
                value["operations"][0]["integrity"] = self.lines("altered-integrity.jsonl", batches)
            with self.subTest(change=change), self.assertRaises(ValueError):
                acceptance.check_capacity(self.root, value, "capacity-ha")

    def test_soak_requires_real_full_interval_unbroken_workload_and_maintenance(self):
        value = self.soak()
        acceptance.check_soak(self.root, value, 86400)
        for change in ("short", "short-wall", "gap", "stalled", "errors", "integrity", "maintenance", "late-maintenance"):
            value = self.soak()
            elapsed = 86400
            if change == "short":
                value["duration_seconds"] = 86399
            elif change == "short-wall":
                elapsed = 60
            elif change == "maintenance":
                value["maintenance"].pop()
            elif change == "late-maintenance":
                value["maintenance"][0]["elapsed_seconds"] = 86401
            else:
                heartbeats = list(acceptance.rows(self.root, value["heartbeats"]))
                if change == "gap":
                    heartbeats.pop(5)
                elif change == "stalled":
                    heartbeats[5]["successful_operations"] = heartbeats[4]["successful_operations"]
                elif change == "errors":
                    heartbeats[5]["unexpected_errors"] = 1
                else:
                    heartbeats[5]["integrity_mismatches"] = 1
                value["heartbeats"] = self.lines("heartbeats.jsonl", heartbeats)
            with self.subTest(change=change), self.assertRaises(ValueError):
                acceptance.check_soak(self.root, value, elapsed)

    def test_process_requires_actual_executable_command_binding_and_clean_drain(self):
        process, _ = self.process()
        self.assertEqual(acceptance.check_processes(self.root, [process], 10), 5)
        for change in ("unrelated-command", "different-executable", "retained-substitute",
                       "no-executable", "still-running", "forced-stop", "signal", "timeout", "duration"):
            process, receipt = self.process()
            if change == "unrelated-command":
                receipt["command"] = ["/usr/bin/true"]
            elif change == "different-executable":
                receipt["executable"]["sha256"] = "0" * 64
            elif change == "retained-substitute":
                process["executable"] = self.file("different-executable", b"substituted bytes\n")
            elif change == "no-executable":
                del receipt["executable"]
            elif change == "still-running":
                receipt["cleanup"]["after"] = [{"pid": 123}]
            elif change == "forced-stop":
                receipt["cleanup"]["signals"] = ["SIGKILL"]
            elif change == "signal":
                receipt["received_signals"] = [15]
            elif change == "timeout":
                receipt["timed_out"] = True
            else:
                receipt["duration_seconds"] = 20
            process["receipt"] = self.value("process.json", receipt)
            with self.subTest(change=change), self.assertRaises(ValueError):
                acceptance.check_processes(self.root, [process], 10)

    def test_native_host_requires_real_architecture_and_covering_reservation(self):
        started = dt.datetime(2026, 1, 2, tzinfo=dt.timezone.utc)
        finished = started + dt.timedelta(hours=24)
        acceptance.check_host(self.root, self.host(), acceptance.REFERENCE, started, finished)
        for change in ("emulated", "wrong-architecture", "short-reservation", "missing-memory"):
            host = self.host()
            if change == "emulated":
                host["emulated"] = True
            elif change == "wrong-architecture":
                host["physical_machine"] = "x86_64"
            elif change == "short-reservation":
                host["reservation"]["ends_at"] = "2026-01-02T01:00:00+00:00"
            else:
                host["reservation"]["memory_bytes"] = None
            with self.subTest(change=change), self.assertRaises(ValueError):
                acceptance.check_host(self.root, host, acceptance.REFERENCE, started, finished)

    def test_native_host_rejects_preflight_from_another_platform(self):
        started = dt.datetime(2026, 1, 2, tzinfo=dt.timezone.utc)
        finished = started + dt.timedelta(hours=1)
        for target, system, machine in ((acceptance.REFERENCE, "Linux", "aarch64"),
                                        ("x86_64-unknown-linux-gnu", "Linux", "x86_64"),
                                        ("aarch64-apple-darwin", "Darwin", "arm64")):
            host = self.host()
            host["physical_machine"] = "x86_64" if target.startswith("x86_64") else "aarch64"
            host["execution_machine"] = host["physical_machine"]
            preflight = acceptance.json_reference(self.root, host["preflight"])
            preflight.update(os=system, machine=machine, requested_target=target)
            host["preflight"] = self.value("host.json", preflight)
            with self.subTest(target=target, change="valid"):
                acceptance.check_host(self.root, host, target, started, finished)
            other_os, other_machine = ("Linux", "x86_64") if target == acceptance.REFERENCE else ("Linux", "aarch64")
            wrong = {**preflight, "os": other_os, "machine": other_machine}
            host["preflight"] = self.value("host.json", wrong)
            with self.subTest(target=target, change="another-supported-target"), self.assertRaisesRegex(
                    ValueError, "native host preflight platform differs"):
                acceptance.check_host(self.root, host, target, started, finished)
            for field, value in (("machine", "other"), ("os", "Other"),
                                 ("machine", None), ("os", None)):
                wrong = dict(preflight)
                wrong[field] = value
                host["preflight"] = self.value("host.json", wrong)
                with self.subTest(target=target, change=field, value=value), self.assertRaisesRegex(
                        ValueError, "native host preflight platform differs"):
                    acceptance.check_host(self.root, host, target, started, finished)
            # Schema 2 never looked for Linux translation; an unchecked or
            # translated host cannot qualify whatever architecture it reports.
            for change in ({"schema": 2}, {"translated": None}, {"translated": True}):
                host["preflight"] = self.value("host.json", {**preflight, **change})
                with self.subTest(target=target, change=change), self.assertRaisesRegex(
                        ValueError, "native host preflight failed"):
                    acceptance.check_host(self.root, host, target, started, finished)

    def test_ha_topology_needs_nine_distinct_owned_processes_and_certificates(self):
        binaries = {"kasumid": "a" * 64, "kasumi-authority": "b" * 64}
        topology, processes = [], []
        for index, role in enumerate(("data", "control", "authority")):
            for member in range(3):
                name = f"{role}-{member}"
                topology.append({"id": name, "role": role, "group": role, "certificate_sha256": f"{index * 3 + member:064x}", "process_id": name})
                processes.append({"id": name, "executable": {"sha256": binaries["kasumi-authority" if role == "authority" else "kasumid"]}})
        acceptance.check_topology(topology, processes, binaries, "required")
        acceptance.check_topology(topology, processes, binaries, "permitted")
        acceptance.check_topology([], processes, binaries, "permitted")
        acceptance.check_topology([], processes, binaries, "forbidden")
        with self.assertRaisesRegex(ValueError, "unexpected HA topology"):
            acceptance.check_topology(topology, processes, binaries, "forbidden")
        with self.assertRaisesRegex(ValueError, "three separate three-member groups"):
            acceptance.check_topology([], processes, binaries, "required")
        with self.assertRaisesRegex(ValueError, "unknown HA topology policy"):
            acceptance.check_topology(topology, processes, binaries, True)
        # Domains whose scenarios involve replicas or membership cannot pass
        # without the topology; no domain is both required and merely permitted.
        self.assertLessEqual(acceptance.TOPOLOGY_REQUIRED | acceptance.TOPOLOGY_PERMITTED,
                             set(acceptance.SCENARIOS))
        self.assertFalse(acceptance.TOPOLOGY_REQUIRED & acceptance.TOPOLOGY_PERMITTED)
        self.assertLessEqual({"audit-retention", "observability", "concurrency", "ha-soak"},
                             acceptance.TOPOLOGY_REQUIRED)
        for change in ("two-members", "shared-process", "shared-certificate", "shared-group", "wrong-binary"):
            nodes, owned = copy.deepcopy(topology), copy.deepcopy(processes)
            if change == "two-members":
                nodes.pop()
            elif change == "shared-process":
                nodes[1]["process_id"] = nodes[0]["process_id"]
            elif change == "shared-certificate":
                nodes[1]["certificate_sha256"] = nodes[0]["certificate_sha256"]
            elif change == "shared-group":
                for node in nodes:
                    node["group"] = "same"
            else:
                owned[0]["executable"]["sha256"] = "c" * 64
            with self.subTest(change=change), self.assertRaises(ValueError):
                acceptance.check_topology(nodes, owned, binaries, "required")

    def test_archives_reject_duplicate_traversal_and_link_members(self):
        for change in ("duplicate", "escape", "symlink"):
            archive = self.root / "unsafe.tar"
            with tarfile.open(archive, "w") as output:
                entry = tarfile.TarInfo("root/file")
                entry.size = 1
                output.addfile(entry, io.BytesIO(b"x"))
                if change == "escape":
                    entry = tarfile.TarInfo("root/../../escape")
                elif change == "symlink":
                    entry = tarfile.TarInfo("root/link")
                    entry.type = tarfile.SYMTYPE
                    entry.linkname = "/etc/passwd"
                output.addfile(entry, io.BytesIO(b"x") if entry.isfile() else None)
            with self.subTest(change=change), self.assertRaises(ValueError):
                acceptance.archive_inventory(archive)

    def test_only_domains_with_a_real_runner_are_registered(self):
        self.assertEqual(set(acceptance.DOMAIN_ADAPTERS),
                         {"ha-faults", "recovery", "capacity-ha", "capacity-standalone", "audit-retention", "key-retention", "benchmark-matrix", "concurrency", "observability", "correctness", "repeatable-assembly", "dependency-review", "ha-soak", "oci-smoke", "package-smoke", "systemd-smoke", "installed", "providers", "backup-cleanup"})
        self.assertLessEqual(set(acceptance.DOMAIN_ADAPTERS), set(acceptance.SCENARIOS))
        self.assertEqual(set(acceptance.SCENARIOS), set(attempt_index.DOMAIN_KINDS))
        source = {"README.md": {"sha256": "a" * 64}}
        for kind in sorted(acceptance.SCENARIOS):
            # A frozen README as "runner" and a file saying everything passed.
            record = {"schema": acceptance.SCHEMA, "id": kind + ":" + acceptance.REFERENCE,
                      "status": "passed", "identity": {}, "binaries": {},
                      "configuration_ids": ["unit"],
                      "runner": {"source_path": "README.md", "sha256": "a" * 64},
                      "started_at": "2026-01-02T00:00:00+00:00",
                      "finished_at": "2026-01-03T00:00:00+00:00", "host": {}, "processes": [],
                      "topology": [], "scenarios": [], "artifacts": {},
                      "details": {"report": self.file("opaque-success.txt", b"all checks passed")}}
            gate = {"id": record["id"], "evidence": self.value("opaque.json", record)}
            configs = {"unit": {"file": self.file("unit-config.json")}}
            arguments = (self.root, gate, {}, source, configs, {acceptance.REFERENCE: {}}, {}, {})
            with self.subTest(kind=kind):
                if kind in acceptance.DOMAIN_ADAPTERS:
                    # A registered adapter still refuses an opaque pass.
                    with self.assertRaises((ValueError, KeyError)):
                        acceptance.verify_gate(*arguments)
                else:
                    with self.assertRaisesRegex(ValueError, "adapter is not implemented: " + kind):
                        acceptance.verify_gate(*arguments)

    def service(self, **changes):
        """An owned daemon's terminal receipt as process_ha_owned writes it."""
        executable = self.file("executables/kasumid")
        record = {"schema": acceptance.SERVICE_SCHEMA, "id": "data-1-0001", "name": "data-1",
                  "command": ["/unit/kasumid", "serve", "/unit/config.json"],
                  "executable": {"path": "/unit/kasumid", "sha256": executable["sha256"]},
                  "status": "drained", "process_group": 321, "leader_birth": "linux:1",
                  "timeout_seconds": 93660, "received_signals": [], "fault": None,
                  "stop": {"signal": "SIGTERM", "target": "owned-leader",
                           "elapsed_seconds": 86500, "sent": True},
                  "error": None, "process_exit_code": 0, "outputs_stable": True,
                  "started_elapsed_seconds": 1, "finished_elapsed_seconds": 86501,
                  "duration_seconds": 86500,
                  "cleanup": {"group": 321, "before": [], "after": [], "signals": [],
                              "errors": [], "drained": True, "process_returncode": 0}}
        for path, value in changes.items():
            target = record
            *parents, leaf = path.split("__")
            for parent in parents:
                target = target[parent]
            target[leaf] = value
        return {"id": "data-1-0001", "receipt": self.value("service.json", record),
                "log": self.file("service.log"), "executable": executable}

    def test_daemons_end_by_their_recorded_stop_or_injected_fault_only(self):
        # A daemon cannot "exit zero undisturbed" like a command: it is stopped
        # on request, or killed as the fault its scenario injects.
        self.assertEqual(acceptance.check_processes(self.root, [self.service()], 86600), 86500)
        fault = {"signal": "SIGKILL", "target": "owned-leader", "sent": True,
                 "observation": "/unit/observation", "observation_sha256": "a" * 64}
        acceptance.check_processes(self.root, [self.service(
            fault=fault, stop=None, process_exit_code=-9, cleanup__process_returncode=-9)], 86600)
        acceptance.check_processes(self.root, [self.service(stop__signal="EOF")], 86600)
        for label, changes in (
                ("forced-cleanup", {"cleanup__signals": ["SIGTERM", "SIGKILL"]}),
                ("stop-ignored", {"process_exit_code": -9, "cleanup__process_returncode": -9}),
                ("nonzero-stop", {"process_exit_code": 2, "cleanup__process_returncode": 2}),
                ("crashed-unrecorded", {"stop": None}),
                ("two-causes", {"fault": fault}),
                ("fault-not-sent", {"fault": {**fault, "sent": False}, "stop": None,
                                    "process_exit_code": -9, "cleanup__process_returncode": -9}),
                ("fault-survived", {"fault": fault, "stop": None}),
                ("interrupted", {"received_signals": [15]}),
                ("undrained", {"cleanup__after": [{"pid": 9}]}),
                ("controller-error", {"error": "ValueError('changed')"}),
                ("other-group", {"cleanup__group": 322}),
                ("too-long", {"duration_seconds": 90000})):
            with self.subTest(change=label), self.assertRaises(ValueError):
                acceptance.check_processes(self.root, [self.service(**changes)], 86600)
        # A failed attempt may retain a crashed daemon, but its custody must be terminal.
        crashed = {"stop": None, "process_exit_code": 1, "cleanup__process_returncode": 1,
                   "status": "failed"}
        acceptance.check_processes(self.root, [self.service(**crashed)], 86600, passed=False)
        with self.assertRaisesRegex(ValueError, "has not drained"):
            acceptance.check_processes(self.root, [self.service(
                **crashed, cleanup__drained=False)], 86600, passed=False)
        with self.assertRaisesRegex(ValueError, "actual executable is not bound"):
            acceptance.check_processes(self.root, [self.service(
                executable__sha256="0" * 64)], 86600)

    def test_repeatable_assembly_bridge_binds_exact_selected_primary_receipt(self):
        def fixture(name, consumed=b'{"candidate":"selected"}\n'):
            selected = self.file(name + "/selected/evidence.json", b'{"candidate":"selected"}\n')
            copied = self.file(name + "/owned/assembly/blobs/functional.json", consumed)
            frozen = self.value(name + "/owned/assembly/frozen-inputs.json", {
                "evidence.json": {"identity": {"sha256": copied["sha256"],
                                               "bytes": copied["bytes"], "executable": False},
                                  "file": {**copied, "path": "blobs/functional.json"}}})
            report = self.value(name + "/owned/assembly/attempt.json", {
                "frozen_inputs": {**frozen, "path": "frozen-inputs.json"}})
            launcher = self.value(name + "/owned/launcher.json", {"status": "passed"})
            domain = {"id": "repeatable-assembly:" + acceptance.REFERENCE,
                      "details": {"launcher": launcher, "report": report,
                                  "second_package": {}, "second_source": {}}}
            candidate = {"primary": {"functional": selected}}
            return domain, candidate, copied

        domain, candidate, _ = fixture("valid")
        with patch("repeatable_assembly.domain_adapter") as owned_bridge:
            selected = acceptance.repeatable_assembly_adapter(
                self.root, domain, {}, {}, {}, {acceptance.REFERENCE: candidate})
            owned_bridge.assert_called_once_with(self.root, domain, {}, {}, {})
            # The launcher record is the journaled attempt's own evidence.
            self.assertEqual(selected, "valid/owned/launcher.json")

        wrong_primary = copy.deepcopy(candidate)
        wrong_primary["primary"]["functional"] = self.file(
            "valid/other/evidence.json", b'{"candidate":"unselected"}\n')
        with self.assertRaisesRegex(ValueError, "another primary"):
            acceptance.check_repeatable_assembly_primary(self.root, domain, wrong_primary)

        substituted = copy.deepcopy(domain)
        substituted["details"]["report"] = self.value("valid/other/attempt.json", {})
        with self.assertRaisesRegex(ValueError, "original report"):
            acceptance.check_repeatable_assembly_primary(self.root, substituted, candidate)

        corrupted, selected_candidate, copied = fixture("corrupt")
        (self.root / copied["path"]).write_bytes(b"changed after custody")
        with self.assertRaises(ValueError):
            acceptance.check_repeatable_assembly_primary(self.root, corrupted, selected_candidate)

        different, selected_candidate, _ = fixture("different", b'{"candidate":"other"}\n')
        with self.assertRaisesRegex(ValueError, "another primary"):
            acceptance.check_repeatable_assembly_primary(self.root, different, selected_candidate)

    def test_dependency_review_bridge_binds_exact_selected_primary_receipt(self):
        def fixture(name, consumed=b'{"candidate":"selected"}\n'):
            selected = self.file(name + "/selected/evidence.json", b'{"candidate":"selected"}\n')
            copied = self.file(name + "/owned/review/blobs/" +
                               hashlib.sha256(consumed).hexdigest(), consumed)
            blob = self.root / copied["path"]
            retained = {"path": "blobs/" + copied["sha256"],
                        "sha256": copied["sha256"], "bytes": copied["bytes"]}
            inner = self.value(name + "/owned/review/attempt.json",
                               {"selected_primary": retained})
            launcher = self.value(name + "/owned/launcher.json",
                                  {"inner_report": {**inner, "path": "review/attempt.json"}})
            domain = {"details": {"report": launcher}}
            candidate = {"primary": {"functional": selected}}
            return domain, candidate, retained, blob

        domain, candidate, _, _ = fixture("valid")
        acceptance.check_dependency_review_primary(self.root, domain, candidate)

        wrong = copy.deepcopy(candidate)
        wrong["primary"]["functional"] = self.file("valid/other/evidence.json", b'{"candidate":"other"}\n')
        with self.assertRaisesRegex(ValueError, "another primary"):
            acceptance.check_dependency_review_primary(self.root, domain, wrong)

        different, selected_candidate, _, _ = fixture("different", b'{"candidate":"other"}\n')
        with self.assertRaisesRegex(ValueError, "another primary"):
            acceptance.check_dependency_review_primary(self.root, different, selected_candidate)

        tampered, selected_candidate, _, blob = fixture("tampered")
        blob.write_bytes(b'{"candidate":"changed"}\n')
        with self.assertRaises(ValueError):
            acceptance.check_dependency_review_primary(self.root, tampered, selected_candidate)

        substituted = copy.deepcopy(domain)
        substituted["details"]["report"] = self.value("valid/other/launcher.json", {})
        with self.assertRaises(ValueError):
            acceptance.check_dependency_review_primary(self.root, substituted, candidate)

    def test_dependency_review_adapter_rejects_substituted_runner_process_and_scenarios(self):
        selected = self.file("selected/evidence.json", b'{"selected":true}\n')
        retained = self.file("owned/review/blobs/" + selected["sha256"], b'{"selected":true}\n')
        scan = self.file("owned/review/advisory-scan/stdout.log", b'{"vulnerabilities":{}}\n')
        inner = {"selected_primary": {**retained, "path": "blobs/" + retained["sha256"]},
                 "source": {"commit": "1" * 40, "tree": "2" * 40,
                            "archive_sha256": "3" * 64, "source_files_sha256": None,
                            "lockfile_sha256": "4" * 64},
                 "advisory_scan": {"step": {"process": {
                     "stdout": {**scan, "path": "advisory-scan/stdout.log"}}}}}
        files = {"scripts/run_dependency_review_launcher.py": {"sha256": "a" * 64}}
        source_files = self.value("source-files.json", files)
        inner["source"]["source_files_sha256"] = source_files["sha256"]
        inner_ref = self.value("owned/review/attempt.json", inner)
        native = self.file("native.json")
        advisory = self.file("advisory.json", b"distinct advisory declaration\n")
        receipt = self.file("owned/runner/process.json")
        stdout = self.file("owned/runner/stdout.log")
        executable = self.file("owned/blobs/python")
        launcher = self.value("owned/launcher.json", {
            "inner_report": {**inner_ref, "path": "review/attempt.json"}})
        outcome = {"products": [{"id": "report", "file": {**launcher, "path": "launcher.json"}}]}
        self.value("owned/outcome.json", outcome)
        launch = {"started_at": "2026-09-24T00:00:00+00:00",
                  "finished_at": "2026-09-24T01:00:00+00:00",
                  "evidence_root": str(self.root),
                  "source_files_sha256": source_files["sha256"],
                  "declaration": native, "advisory_declaration": advisory,
                  "inner_report": {**inner_ref, "path": "review/attempt.json"},
                  "runner_process": {
                      "receipt": {**receipt, "path": "runner/process.json"},
                      "stdout": {**stdout, "path": "runner/stdout.log"},
                      "executable": {**executable, "path": "blobs/python"}}}
        identity = {"source_commit": "1" * 40, "source_tree": "2" * 40,
                    "source_archive_sha256": "3" * 64,
                    "source_files_sha256": source_files["sha256"],
                    "lockfile_sha256": "4" * 64}
        scenario = lambda name, log: {"id": name, "status": "passed", "iterations": 1,
                                      "failures": 0, "unattempted": 0, "log": log}
        domain = {"id": "dependency-review:" + acceptance.REFERENCE,
                  "details": {"report": launcher}, "runner": {
                      "source_path": "scripts/run_dependency_review_launcher.py",
                      "sha256": "a" * 64},
                  "started_at": launch["started_at"], "finished_at": launch["finished_at"],
                  "identity": identity, "configuration_ids": ["advisory", "native"],
                  "processes": [{"id": "runner", "receipt": receipt,
                                 "log": stdout, "executable": executable}],
                  "scenarios": [scenario("patch-upstream-tests", inner_ref),
                                scenario("memory-safety-regressions", inner_ref),
                                scenario("advisory-dispositions", scan)]}
        configs = {"advisory": {"file": advisory}, "native": {"file": native}}
        candidates = {acceptance.REFERENCE: {"primary": {"functional": selected}}}
        with patch("run_dependency_review_launcher.verify",
                   return_value={"record": launch, "inner": inner}):
            self.assertEqual(acceptance.dependency_review_adapter(
                self.root, domain, files, configs, {}, candidates), "owned/outcome.json")
            # The journaled outcome must name this exact launcher record.
            self.value("owned/outcome.json", {"products": [{"id": "report", "file": {
                **launcher, "path": "launcher.json", "sha256": "0" * 64}}]})
            with self.assertRaisesRegex(ValueError, "outcome selected another launcher"):
                acceptance.dependency_review_adapter(self.root, domain, files, configs, {}, candidates)
            self.value("owned/outcome.json", outcome)
            for change in ("runner", "config", "process", "scenario", "primary"):
                altered = copy.deepcopy(domain)
                selected_candidates = copy.deepcopy(candidates)
                if change == "runner":
                    altered["runner"]["source_path"] = "README.md"
                elif change == "config":
                    altered["configuration_ids"] = ["native"]
                elif change == "process":
                    altered["processes"][0]["log"] = scan
                elif change == "scenario":
                    altered["scenarios"][2]["log"] = stdout
                else:
                    selected_candidates[acceptance.REFERENCE]["primary"]["functional"] = self.file(
                        "other/evidence.json", b'{"selected":false}\n')
                with self.subTest(change=change), self.assertRaises(ValueError):
                    acceptance.dependency_review_adapter(
                        self.root, altered, files, configs, {}, selected_candidates)
            link = self.root / "owned/unowned-link"
            link.symlink_to(self.root / "source-files.json")
            with self.assertRaisesRegex(ValueError, "custody contains a symlink"):
                acceptance.dependency_review_adapter(self.root, domain, files, configs, {}, candidates)

    def test_manifest_cannot_omit_platform_or_gate_or_duplicate_identifier(self):
        gates = [{"id": name, "evidence": {}} for name in sorted(acceptance.required_gates())]
        for changed in (gates[:-1], gates + [gates[0]], []):
            manifest = {"schema": acceptance.SCHEMA, "source": {}, "candidates": [], "gates": changed,
                        "artifacts": [], "attempts": []}
            ref = self.value("acceptance.json", manifest)
            with patch.object(acceptance, "_CLEAN_SOURCE_EXECUTION", True):
                with self.assertRaises(ValueError):
                    acceptance.verify(self.root / ref["path"], self.root)

    def test_manifest_and_transitive_inputs_cannot_change_during_verification(self):
        for changed in ("acceptance.json", "source-input.rs", "gate.log"):
            with self.subTest(changed=changed):
                refs = {name: self.file(name) for name in ("acceptance.json", "source-input.rs", "gate.log")}

                def inspect_then_mutate(_manifest, _repository, _heads):
                    for ref in refs.values():
                        acceptance.reference(self.root, ref)
                    (self.root / changed).write_bytes(b"unvalidated replacement")
                    return {"status": "passed"}

                # Isolate the final observed-input seal from the domain adapters.
                with patch.object(acceptance, "_CLEAN_SOURCE_EXECUTION", True), \
                        patch.object(acceptance, "verify_inputs", side_effect=inspect_then_mutate):
                    with self.assertRaisesRegex(ValueError, "artifact changed"):
                        acceptance.verify(self.root / "acceptance.json", self.root)

    def test_json_parsing_uses_the_exact_previously_hashed_bytes(self):
        ref = self.value("data.json", {"status": "failed"})
        token = acceptance.OBSERVATIONS.set({})
        self.addCleanup(acceptance.OBSERVATIONS.reset, token)
        path = acceptance.reference(self.root, ref)
        path.write_text('{"status":"passed"}')
        with self.assertRaisesRegex(ValueError, "between verification and parsing"):
            acceptance.read_json(path)

    def test_executing_attempt_and_package_helpers_match_frozen_source(self):
        scripts = Path(acceptance.__file__).resolve().parent
        # The frozen inventory holds every script; whatever local module is
        # loaded, including an adapter's runner, must match it.
        files = {"scripts/" + path.name: {"sha256": acceptance.sha256(path)}
                 for path in scripts.glob("*.py")}
        acceptance.verify_executing_tools(files)
        import domain_run
        self.assertIsNotNone(domain_run)
        for name in ("domain_run.py",):
            with self.subTest(lazily_loaded=name):
                changed = copy.deepcopy(files)
                changed["scripts/" + name]["sha256"] = "0" * 64
                with self.assertRaisesRegex(ValueError, "differs from final source: " + name):
                    acceptance.verify_executing_tools(changed)
                del changed["scripts/" + name]
                with self.assertRaisesRegex(ValueError, "differs from final source: " + name):
                    acceptance.verify_executing_tools(changed)
        for name in ("attempt_index.py", "assembly_inputs.py"):
            with self.subTest(name=name):
                changed = copy.deepcopy(files)
                changed["scripts/" + name]["sha256"] = "0" * 64
                with self.assertRaisesRegex(ValueError, "differs from final source"):
                    acceptance.verify_executing_tools(changed)
        outside = self.file("outside-attempt-index.py")
        with patch.object(acceptance.attempt_index, "__file__", str(self.root / outside["path"])):
            with self.assertRaisesRegex(ValueError, "imported a different helper"):
                acceptance.verify_executing_tools(files)

    def test_final_acceptance_rejects_imported_library_execution(self):
        self.assertFalse(acceptance._CLEAN_SOURCE_EXECUTION)
        with self.assertRaisesRegex(ValueError, "isolated clean-source CLI bootstrap"):
            acceptance.verify(self.root / "absent.json", self.root)

    def test_clean_source_bootstrap_rejects_both_bytecode_cache_formats(self):
        scripts = self.root / "clean-scripts"
        scripts.mkdir()
        for name in acceptance._LOCAL_HELPERS:
            (scripts / (name + ".py")).write_text("VALUE = 1\n")
        flags = SimpleNamespace(isolated=1, no_site=1, dont_write_bytecode=1)
        options = {"flags": flags, "cache_prefix": None, "environment": {},
                   "loaded": {}, "importers": [acceptance.BuiltinImporter,
                                                  acceptance.FrozenImporter,
                                                  acceptance.PathFinder]}
        acceptance.check_clean_source_execution(scripts, **options)
        source = scripts / "attempt_index.py"
        for mode in (py_compile.PycInvalidationMode.TIMESTAMP,
                     py_compile.PycInvalidationMode.UNCHECKED_HASH):
            with self.subTest(mode=mode):
                cached = Path(py_compile.compile(str(source), doraise=True,
                                                 invalidation_mode=mode))
                self.assertTrue(cached.is_file())
                with self.assertRaisesRegex(ValueError, "bytecode cache is present"):
                    acceptance.check_clean_source_execution(scripts, **options)
                cached.unlink()
                cached.parent.rmdir()
        for changed, message in (({"cache_prefix": str(self.root / "other-cache")}, "redirected"),
                                 ({"environment": {"PYTHONPYCACHEPREFIX": ""}}, "redirected"),
                                 ({"loaded": {"attempt_index": object()}}, "before the cache check"),
                                 ({"importers": [object()]}, "untrusted Python importer"),
                                 ({"flags": SimpleNamespace(isolated=0, no_site=1,
                                                            dont_write_bytecode=1)}, "-I -S -B")):
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, message):
                acceptance.check_clean_source_execution(scripts, **{**options, **changed})

    def test_final_source_identity_is_rechecked_and_manifest_hash_is_bound_to_parsed_bytes(self):
        gates = [{"id": name, "evidence": self.value(name + ".json", {"host": {"id": "unit-host"}})}
                 for name in sorted(acceptance.required_gates())]
        manifest = {"schema": acceptance.SCHEMA, "source": {}, "candidates": [], "gates": gates,
                    "artifacts": [], "attempts": []}
        ref = self.value("acceptance.json", manifest)
        first_identity = {"source_commit": "1" * 40}
        with patch.object(acceptance, "_CLEAN_SOURCE_EXECUTION", True), \
                patch.object(acceptance, "check_clean_source_execution"), \
                patch.object(acceptance, "verify_source", return_value=(first_identity, {}, {})) as source, \
                patch.object(acceptance, "verify_candidates", return_value=({}, {})), \
                patch.object(acceptance, "verify_artifacts", return_value={}), \
                patch.object(acceptance, "verify_gate", side_effect=lambda root, gate, *_: (
                    gate["id"].split(":")[0], gate["id"] + "/outcome.json")), \
                patch.object(acceptance, "verify_native_journals") as attempts:
            value = acceptance.verify(self.root / ref["path"], self.root)
            self.assertEqual(value["manifest_sha256"], ref["sha256"])
            # Every gate's journaled attempt is selected under its own kind.
            selected = attempts.call_args.args[2]
            self.assertEqual(len(selected), len(gates))
            self.assertEqual(selected["ha-soak:" + acceptance.REFERENCE + "/outcome.json"],
                             ("ha-soak", acceptance.REFERENCE, "unit-host"))
            self.assertEqual(source.call_count, 2)
            source.side_effect = [(first_identity, {}, {}), ({"source_commit": "2" * 40}, {}, {})]
            with self.assertRaisesRegex(ValueError, "source changed"):
                acceptance.verify(self.root / ref["path"], self.root)
        # One journaled attempt cannot satisfy two gates.
        with patch.object(acceptance, "_CLEAN_SOURCE_EXECUTION", True), \
                patch.object(acceptance, "check_clean_source_execution"), \
                patch.object(acceptance, "verify_source", return_value=(first_identity, {}, {})), \
                patch.object(acceptance, "verify_candidates", return_value=({}, {})), \
                patch.object(acceptance, "verify_artifacts", return_value={}), \
                patch.object(acceptance, "verify_gate", return_value=("ha-soak", "shared/outcome.json")):
            with self.assertRaisesRegex(ValueError, "two gates selected the same journaled attempt"):
                acceptance.verify(self.root / ref["path"], self.root)

    def test_independent_compilation_can_share_host_but_not_build_root_or_environment(self):
        primary = {"build_id": "first", "build_root": "/unit/first", "environment_id": "first-environment"}
        identity = {"source_archive_sha256": self.file("source.tar")["sha256"],
                    "source_files_sha256": self.file("source-files.json")["sha256"]}
        process, receipt = self.process()
        receipt["command"] = ["/unit/cargo", *dict(acceptance.functional_gates(1, "/unit/python"))["production"][1:]]
        receipt["working_directory"] = "/unit/second/source"
        process["receipt"] = self.value("process.json", receipt)
        binaries, artifacts = {}, []
        package_id = "path+file:///unit/second/source/crates/kasumi-server#kasumi-server@0.1.0"
        messages = []
        targets = []
        for name in sorted(acceptance.package.BINARIES):
            header = bytearray(20)
            header[:6] = b"\x7fELF\x02\x01"
            struct.pack_into("<H", header, 18, 183)
            ref = self.file("independent/target/release/" + name, header)
            binaries[name] = ref["sha256"]
            artifacts.append({"name": name, "file": ref})
            target = {"name": name, "kind": ["bin"], "crate_types": ["bin"]}
            targets.append(target)
            messages.append({"reason": "compiler-artifact", "package_id": package_id,
                             "features": [], "target": target, "profile": {"test": False},
                             "executable": "/unit/second/target/release/" + name})
        process["log"] = self.lines("independent-cargo.log", messages)
        record = {"schema": acceptance.SCHEMA, "status": "passed", "identity": identity,
                  "toolchain": acceptance.TOOLCHAIN, "platform": acceptance.REFERENCE, "jobs": 1,
                  "started_at": "2026-01-02T00:00:00+00:00", "finished_at": "2026-01-02T00:00:10+00:00",
                  "build_id": "second", "build_root": "/unit/second", "environment_id": "second-environment",
                  "environment": self.file("environment.json"), "fresh_build_root": True, "host": self.host(),
                  "processes": [process], "compiled_packages": {package_id: {"features": [], "targets": targets}},
                  "binaries": artifacts,
                  "source_archive": self.file("source.tar"), "source_files": self.file("source-files.json")}
        ref = self.value("independent-build.json", record)
        acceptance.check_independent_build(self.root, ref, primary, acceptance.REFERENCE, identity, binaries)
        for change in ("build_root", "environment_id", "fixture", "wrong-command",
                       "different-binary", "invented-inventory", "missing-binary-in-log",
                       "wrong-output-path", "duplicate-binary-in-log", "wrong-source-root"):
            value = copy.deepcopy(record)
            if change in primary:
                value[change] = primary[change]
            elif change == "fixture":
                value["compiled_packages"][package_id]["features"] = ["test-utils"]
                changed = copy.deepcopy(messages)
                changed[0]["features"] = ["test-utils"]
                value["processes"][0]["log"] = self.lines("fixture-cargo.log", changed)
            elif change == "wrong-command":
                wrong = copy.deepcopy(receipt)
                wrong["command"] = ["/unit/cargo", "--version"]
                value["processes"][0]["receipt"] = self.value("unrelated-build-process.json", wrong)
            elif change == "invented-inventory":
                value["compiled_packages"][package_id]["targets"].pop()
            elif change == "missing-binary-in-log":
                value["processes"][0]["log"] = self.lines("missing-binary-cargo.log", messages[:-1])
            elif change == "wrong-output-path":
                changed = copy.deepcopy(messages)
                changed[0]["executable"] = "/unit/first/target/release/" + changed[0]["target"]["name"]
                value["processes"][0]["log"] = self.lines("wrong-output-cargo.log", changed)
            elif change == "duplicate-binary-in-log":
                value["processes"][0]["log"] = self.lines("duplicate-binary-cargo.log", [*messages, messages[0]])
            elif change == "wrong-source-root":
                wrong = copy.deepcopy(receipt)
                wrong["working_directory"] = "/unit/first/source"
                value["processes"][0]["receipt"] = self.value("wrong-source-process.json", wrong)
            else:
                value["binaries"][0]["file"] = self.file("different-binary", bytes(header) + b"changed")
            ref = self.value("independent-build.json", value)
            with self.subTest(change=change), self.assertRaises(ValueError):
                acceptance.check_independent_build(self.root, ref, primary, acceptance.REFERENCE, identity, binaries)

    def test_failure_history_is_preserved_and_cannot_be_selected_as_success(self):
        process, receipt = self.process()
        receipt.update(status="failed", exit_code=7, process_exit_code=7)
        receipt["cleanup"]["process_returncode"] = 7
        process["receipt"] = self.value("process.json", receipt)
        evidence, ref = self.indexed_attempt("failed-1", [process])
        attempts = [{"id": "failed-1", "receipt": ref}]
        acceptance.verify_attempts(self.root, attempts, {})
        with self.assertRaisesRegex(ValueError, "selected attempt failed"):
            acceptance.verify_attempts(self.root, attempts, {evidence["path"]: None})
        with self.assertRaisesRegex(ValueError, "omitted an on-disk or selected attempt"):
            acceptance.verify_attempts(self.root, attempts, {"unjournaled/outcome.json": None})
        self.indexed_attempt("omitted-2", [process])
        with self.assertRaisesRegex(ValueError, "omits a native attempt"):
            acceptance.verify_attempts(self.root, attempts, {})
        self.value("attempts/omitted/attempt.json", {})
        with self.assertRaises(ValueError):
            acceptance.verify_attempts(self.root, attempts, {})

    def test_native_journals_preserve_failures_and_verify_every_anchored_host(self):
        bundle = self.root / "bundle"
        journals, anchors = [], []
        for target in acceptance.PLATFORMS:
            native = self.root / target
            native.mkdir()
            attempt_index.create(native, target, "host-" + target, target)
            output = native / "build"
            attempt_index.begin(native, target, "independent-build", output, "2026-01-01T00:00:00Z")
            output.mkdir()
            attempt_index.finish_outcome(native, target, "failed", "2026-01-01T00:00:01Z",
                                         products={}, processes=[], dispatch_started=False)
            dest = bundle / "native-attempts" / target
            shutil.copytree(native, dest)
            journals.append({"id": target, "journal": attempt_index.file_ref(bundle, dest / "attempts/index.jsonl")})
            anchors.append({"original_root": str(native.resolve()), "head": attempt_index.head(native)})
        heads = self.root / "operator-heads.json"
        heads.write_text(json.dumps(anchors))
        acceptance.verify_native_journals(bundle, journals, {}, heads)
        target = acceptance.REFERENCE
        path = f"native-attempts/{target}/build/outcome.json"
        for host, reason in [("host-" + target, "selected attempt failed"), ("other", "another host")]:
            with self.assertRaisesRegex(ValueError, reason):
                acceptance.verify_native_journals(bundle, journals, {path: ("independent-build", target, host)}, heads)
        with self.assertRaisesRegex(ValueError, "roster differs"):
            acceptance.verify_native_journals(bundle, journals[:-1], {}, heads)
        anchors[0]["head"]["sha256"] = "0" * 64
        heads.write_text(json.dumps(anchors))
        with self.assertRaisesRegex(ValueError, "differs from its anchor"):
            acceptance.verify_native_journals(bundle, journals, {}, heads)

    def test_selected_independent_record_binds_native_products_after_transport(self):
        native = self.root / "host"
        native.mkdir()
        attempt_index.create(native, "mac", "mac-host", "aarch64-apple-darwin")
        output = native / "build"
        attempt_index.begin(native, "independent", "independent-build", output, "2026-01-02T00:00:00Z")
        output.mkdir()
        with patch.object(self, "root", native):
            process, _ = self.process()
        products = {}
        binaries = []
        for name in sorted(acceptance.package.BINARIES):
            path = output / "target" / "release" / name
            path.parent.mkdir(exist_ok=True, parents=True)
            path.write_bytes(name.encode())
            products[name] = path.relative_to(output).as_posix()
            ref = attempt_index.file_ref(native, path)
            binaries.append({"name": name, "file": {**ref, "path": "native-attempts/mac/" + ref["path"]}})
        proof = output / "build.json"
        proof.write_text(json.dumps({"binaries": binaries}))
        attempt_index.finish_outcome(native, "independent", "passed", "2026-01-02T00:00:10Z",
                                     products=products, processes=[process], dispatch_started=True,
                                     build_evidence="build.json")
        dest = self.root / "bundle/native-attempts/mac"
        shutil.copytree(native, dest)
        ref = attempt_index.file_ref(dest, dest / "attempts/independent/attempt.json")
        retained = [{"id": "independent", "receipt": ref}]
        args = {"head": attempt_index.head(native), "original_root": str(native.resolve())}
        acceptance.verify_attempts(dest, retained, {"build/build.json": "independent-build"}, **args)
        with self.assertRaisesRegex(ValueError, "omitted an on-disk or selected attempt"):
            acceptance.verify_attempts(dest, retained, {"build/outcome.json": "independent-build"}, **args)
        wrong = {**args, "original_root": str(dest)}
        with self.assertRaisesRegex(ValueError, "differs from original outcome"):
            acceptance.verify_attempts(dest, retained, {}, **wrong)

    def test_isolated_cli_shares_observations_with_imported_domain_adapters(self):
        scripts = Path(acceptance.__file__).resolve().parent
        program = """import runpy, sys
path = sys.argv[1]
sys.argv = [path, '--help']
try:
    runpy.run_path(path, run_name='__main__')
except SystemExit as exit:
    assert exit.code == 0
import verify_release_acceptance as verifier
import run_benchmark_matrix_owned as benchmark
assert verifier._CLEAN_SOURCE_EXECUTION and benchmark.acceptance is verifier
"""
        # CLI acceptance requires a source tree without bytecode. Development
        # test discovery may have populated the checkout's scripts directory.
        frozen = self.root / "source/scripts"
        shutil.copytree(scripts, frozen, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        subprocess.run([sys.executable, "-I", "-B", "-S", "-c", program,
                        frozen / "verify_release_acceptance.py"], check=True, capture_output=True)

    def test_rebased_reference_preserves_original_observation(self):
        ref = self.value("custody/evidence.json", {"result": 1})
        token = acceptance.OBSERVATIONS.set({})
        self.addCleanup(acceptance.OBSERVATIONS.reset, token)
        acceptance.reference(self.root / "custody", {**ref, "path": "evidence.json"})
        path = acceptance.reference(self.root, ref)
        self.assertEqual(acceptance.read_json(path), {"result": 1})
        path.write_bytes(b"{}")
        with self.assertRaisesRegex(ValueError, "between verification and parsing"):
            acceptance.read_json(path)

    def test_attempt_census_rejects_unfinished_and_aliased_entries(self):
        process, receipt = self.process()
        receipt.update(status="failed", exit_code=7, process_exit_code=7)
        receipt["cleanup"]["process_returncode"] = 7
        process["receipt"] = self.value("process.json", receipt)
        _, original = self.indexed_attempt("failed-1", [process])
        retained = [{"id": "failed-1", "receipt": original}]
        acceptance.verify_attempts(self.root, retained, {})

        unfinished = self.root / "attempts/started-but-unfinished"
        unfinished.mkdir()
        (unfinished / "runner.log").write_text("interrupted before terminal receipt\n")
        with self.assertRaisesRegex(ValueError, "no regular terminal receipt"):
            acceptance.verify_attempts(self.root, retained, {})
        (unfinished / "runner.log").unlink()
        unfinished.rmdir()

        stray = self.root / "attempts/stray-file"
        stray.write_text("failed launch\n")
        with self.assertRaisesRegex(ValueError, "unowned entry"):
            acceptance.verify_attempts(self.root, retained, {})
        stray.unlink()

        alias = self.root / "attempts/aliased-attempt"
        alias.symlink_to(self.root / "attempts/failed-1", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "unowned entry"):
            acceptance.verify_attempts(self.root, retained, {})
        alias.unlink()

        linked_receipt = self.root / "attempts/linked-receipt"
        linked_receipt.mkdir()
        (linked_receipt / "attempt.json").symlink_to(self.root / original["path"])
        with self.assertRaisesRegex(ValueError, "no regular terminal receipt"):
            acceptance.verify_attempts(self.root, retained, {})

    def test_failed_attempt_cannot_claim_drain_of_another_process_group(self):
        process, receipt = self.process()
        receipt.update(status="failed", exit_code=7, process_exit_code=7)
        receipt["cleanup"]["process_returncode"] = 7
        process["receipt"] = self.value("process.json", receipt)
        acceptance.check_processes(self.root, [process], 10, passed=False)
        for change in ("wrong-group", "boolean-group", "missing-group", "wrong-returncode",
                       "boolean-exit-code", "missing-cleanup"):
            wrong = copy.deepcopy(receipt)
            if change == "wrong-group":
                wrong["cleanup"]["group"] = 999
            elif change == "boolean-group":
                wrong["process_group"] = 1
                wrong["cleanup"]["group"] = True
            elif change == "missing-group":
                del wrong["process_group"]
            elif change == "wrong-returncode":
                wrong["cleanup"]["process_returncode"] = 8
            elif change == "boolean-exit-code":
                wrong["process_exit_code"] = False
                wrong["cleanup"]["process_returncode"] = 0
            else:
                wrong["cleanup"] = None
            process["receipt"] = self.value("process.json", wrong)
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "process ownership has not drained"):
                acceptance.check_processes(self.root, [process], 10, passed=False)

    def test_missing_native_attempt_index_rejects_acceptance(self):
        process, receipt = self.process()
        receipt.update(status="failed", exit_code=7, process_exit_code=7)
        receipt["cleanup"]["process_returncode"] = 7
        process["receipt"] = self.value("process.json", receipt)
        _, ref = self.indexed_attempt("failed-1", [process])
        (self.root / "attempts/index.jsonl").unlink()
        with self.assertRaises(FileNotFoundError):
            acceptance.verify_attempts(self.root, [{"id": "failed-1", "receipt": ref}], {})

    def test_owned_dispatch_boundary_is_explicit_without_legacy_or_boolean_aliases(self):
        original_root = self.root
        for index, boundary in enumerate(("missing", None, 0, 1, "false", False, True)):
            with self.subTest(boundary=boundary):
                self.root = original_root / ("boundary-" + str(index))
                self.root.mkdir()
                process, receipt = self.process()
                receipt.update(status="failed", exit_code=7, process_exit_code=7)
                receipt["cleanup"]["process_returncode"] = 7
                process["receipt"] = self.value("process.json", receipt)
                _, ref = self.indexed_attempt("failed-1", [process], dispatch_boundary=boundary)
                retained = [{"id": "failed-1", "receipt": ref}]
                # Each wrong boundary is the original indexed outcome, with
                # all file hashes and the terminal journal rebuilt around it.
                if boundary is True:
                    acceptance.verify_attempts(self.root, retained, {})
                else:
                    with self.assertRaisesRegex(ValueError, "dispatch boundary|claims child processes"):
                        acceptance.verify_attempts(self.root, retained, {})
        self.root = original_root


if __name__ == "__main__":
    unittest.main()
