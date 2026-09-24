"""Synthetic counterexamples; these fixtures are never release evidence."""
import copy
import datetime as dt
import io
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import verify_release_acceptance as acceptance


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

    def host(self):
        return {"id": "same-physical-host", "physical_machine": "aarch64", "execution_machine": "aarch64",
                "emulated": False, "reservation": {"id": "unit-reservation", "starts_at": "2026-01-01T00:00:00+00:00",
                    "ends_at": "2026-01-04T00:00:00+00:00", "cpu_count": 4,
                    "memory_bytes": 16 << 30, "disk_bytes": 128 << 30},
                "preflight": self.value("host.json", {"schema": 2, "os": "Linux", "machine": "aarch64",
                    "requested_target": acceptance.REFERENCE,
                    "errors": [], "translated": False, "effective_memory_bytes": 16 << 30}),
                "attestation": self.file("host-attestation.txt")}

    def capacity(self):
        size = 4 << 30
        integrity = self.lines("integrity.jsonl", [{"first": first, "documents": 256,
            "canonical_bytes": 256 << 20, "expected_sha256": "a" * 64, "observed_sha256": "a" * 64}
            for first in range(0, 4096, 256)])
        limits = {"rss_bytes": 1 << 30, "allocated_disk_bytes": 8 << 30, "maintenance_workspace_bytes": 64 << 20}
        resources = self.lines("resources.jsonl", [{"elapsed_seconds": i, **limits} for i in (0, 1)])
        return {"corpus": {"documents": 4096, "canonical_bytes": size, "seed_sha256": "b" * 64,
                    "compression": {"algorithm": "gzip-9", "input_bytes": size, "output_bytes": size * 4 // 5,
                                    "log": self.file("compression.log")}},
                "operations": [{"id": name, "integrity": integrity, "resources": resources,
                    "limits": limits.copy(), "read_retention_budget_bytes": 64 << 20}
                    for name in sorted(acceptance.SCENARIOS["capacity-ha"])]}

    def soak(self):
        return {"duration_seconds": 86400, "heartbeats": self.lines("heartbeats.jsonl", [
                    {"elapsed_seconds": i * 60, "successful_operations": i,
                     "unexpected_errors": 0, "integrity_mismatches": 0} for i in range(1441)]),
                "maintenance": [{"id": name, "elapsed_seconds": 3600, "log": self.file(name + ".log")}
                                for name in sorted(acceptance.SCENARIOS["ha-soak"])]}

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
                              "workloads": [{"name": name} for name in sorted(expected)]})
        # This test isolates roster validation. Raw sample validation is exercised
        # separately with retained JSONL bytes, including truncation/duplicates.
        with patch.object(acceptance, "check_samples") as samples:
            acceptance.check_benchmarks(self.root, {"cases": cases})
            self.assertEqual(samples.call_count, 99)
            for change in ("missing-case", "duplicate-case", "short", "fixture", "missing-workload", "wrong-tenants"):
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
                else:
                    value[-1]["tenants"] = 100
                with self.subTest(change=change), self.assertRaises(ValueError):
                    acceptance.check_benchmarks(self.root, {"cases": value})

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
        for change in ("unrelated-command", "different-executable", "no-executable", "still-running", "forced-stop", "signal", "timeout", "duration"):
            process, receipt = self.process()
            if change == "unrelated-command":
                receipt["command"] = ["/usr/bin/true"]
            elif change == "different-executable":
                receipt["executable"]["sha256"] = "0" * 64
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
            legacy = dict(preflight)
            legacy["schema"] = 1
            host["preflight"] = self.value("host.json", legacy)
            with self.subTest(target=target, change="old-schema"), self.assertRaisesRegex(
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
        acceptance.check_topology(topology, processes, binaries, required=True)
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
                acceptance.check_topology(nodes, owned, binaries, required=True)

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

    def test_unimplemented_domain_adapters_reject_frozen_readme_and_opaque_passes(self):
        self.assertEqual(acceptance.DOMAIN_ADAPTERS, {})
        source = {"README.md": {"sha256": "a" * 64}}
        for kind in acceptance.SCENARIOS:
            record = {"schema": acceptance.SCHEMA, "id": kind + ":" + acceptance.REFERENCE,
                      "status": "passed", "runner": {"source_path": "README.md", "sha256": "a" * 64},
                      "details": {"report": self.file("opaque-success.txt", b"all checks passed")}}
            gate = {"id": record["id"], "evidence": self.value("opaque.json", record)}
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "adapter is not implemented"):
                acceptance.verify_gate(self.root, gate, {}, source, {}, {}, {}, {})

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
            acceptance.repeatable_assembly_adapter(self.root, domain, {}, {}, {},
                                                    {acceptance.REFERENCE: candidate})
            owned_bridge.assert_called_once_with(self.root, domain, {}, {}, {})

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

    def test_manifest_cannot_omit_platform_or_gate_or_duplicate_identifier(self):
        gates = [{"id": name, "evidence": {}} for name in sorted(acceptance.required_gates())]
        for changed in (gates[:-1], gates + [gates[0]], []):
            manifest = {"schema": acceptance.SCHEMA, "source": {}, "candidates": [], "gates": changed,
                        "artifacts": [], "attempts": []}
            ref = self.value("acceptance.json", manifest)
            with self.assertRaises(ValueError):
                acceptance.verify(self.root / ref["path"], self.root)

    def test_manifest_and_transitive_inputs_cannot_change_during_verification(self):
        for changed in ("acceptance.json", "source-input.rs", "gate.log"):
            with self.subTest(changed=changed):
                refs = {name: self.file(name) for name in ("acceptance.json", "source-input.rs", "gate.log")}

                def inspect_then_mutate(_manifest, _repository):
                    for ref in refs.values():
                        acceptance.reference(self.root, ref)
                    (self.root / changed).write_bytes(b"unvalidated replacement")
                    return {"status": "passed"}

                # Isolate the final observed-input seal from domain adapters,
                # which deliberately cannot yet produce a passing release.
                with patch.object(acceptance, "verify_inputs", side_effect=inspect_then_mutate):
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

    def test_final_source_identity_is_rechecked_and_manifest_hash_is_bound_to_parsed_bytes(self):
        gates = [{"id": name, "evidence": {"path": name + ".json"}}
                 for name in sorted(acceptance.required_gates())]
        manifest = {"schema": acceptance.SCHEMA, "source": {}, "candidates": [], "gates": gates,
                    "artifacts": [], "attempts": []}
        ref = self.value("acceptance.json", manifest)
        first_identity = {"source_commit": "1" * 40}
        with patch.object(acceptance, "verify_source", return_value=(first_identity, {}, {})) as source, \
                patch.object(acceptance, "verify_candidates", return_value=({}, {})), \
                patch.object(acceptance, "verify_artifacts", return_value={}), \
                patch.object(acceptance, "verify_gate"), patch.object(acceptance, "verify_attempts"):
            value = acceptance.verify(self.root / ref["path"], self.root)
            self.assertEqual(value["manifest_sha256"], ref["sha256"])
            self.assertEqual(source.call_count, 2)
            source.side_effect = [(first_identity, {}, {}), ({"source_commit": "2" * 40}, {}, {})]
            with self.assertRaisesRegex(ValueError, "source changed"):
                acceptance.verify(self.root / ref["path"], self.root)

    def test_independent_compilation_can_share_host_but_not_build_root_or_environment(self):
        primary = {"build_id": "first", "build_root": "/unit/first", "environment_id": "first-environment"}
        identity = {"source_archive_sha256": self.file("source.tar")["sha256"],
                    "source_files_sha256": self.file("source-files.json")["sha256"]}
        process, receipt = self.process()
        receipt["command"] = ["/unit/cargo", *dict(acceptance.functional_gates(1, "/unit/python"))["production"][1:]]
        process["receipt"] = self.value("process.json", receipt)
        binaries, artifacts = {}, []
        for name in acceptance.package.BINARIES:
            header = bytearray(20)
            header[:6] = b"\x7fELF\x02\x01"
            struct.pack_into("<H", header, 18, 183)
            ref = self.file("independent/" + name, header)
            binaries[name] = ref["sha256"]
            artifacts.append({"name": name, "file": ref})
        record = {"schema": acceptance.SCHEMA, "status": "passed", "identity": identity,
                  "toolchain": acceptance.TOOLCHAIN, "platform": acceptance.REFERENCE, "jobs": 1,
                  "started_at": "2026-01-02T00:00:00+00:00", "finished_at": "2026-01-02T00:00:10+00:00",
                  "build_id": "second", "build_root": "/unit/second", "environment_id": "second-environment",
                  "environment": self.file("environment.json"), "fresh_build_root": True, "host": self.host(),
                  "processes": [process], "compiled_packages": {"unit-package": {"features": []}}, "binaries": artifacts,
                  "source_archive": self.file("source.tar"), "source_files": self.file("source-files.json")}
        ref = self.value("independent-build.json", record)
        acceptance.check_independent_build(self.root, ref, primary, acceptance.REFERENCE, identity, binaries)
        for change in ("build_root", "environment_id", "fixture", "wrong-command", "different-binary"):
            value = copy.deepcopy(record)
            if change in primary:
                value[change] = primary[change]
            elif change == "fixture":
                value["compiled_packages"]["unit-package"]["features"] = ["test-utils"]
            elif change == "wrong-command":
                wrong = copy.deepcopy(receipt)
                wrong["command"] = ["/unit/cargo", "--version"]
                value["processes"][0]["receipt"] = self.value("unrelated-build-process.json", wrong)
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
        evidence = self.file("failed-result.json")
        attempt = {"schema": acceptance.SCHEMA, "id": "failed-1", "status": "failed", "evidence": evidence,
                   "started_at": "2026-01-02T00:00:00+00:00", "finished_at": "2026-01-02T00:00:10+00:00", "processes": [process]}
        ref = self.value("attempts/failed-1/attempt.json", attempt)
        attempts = [{"id": "failed-1", "receipt": ref}]
        acceptance.verify_attempts(self.root, attempts, set())
        with self.assertRaises(ValueError):
            acceptance.verify_attempts(self.root, attempts, {evidence["path"]})
        self.value("attempts/omitted/attempt.json", attempt)
        with self.assertRaises(ValueError):
            acceptance.verify_attempts(self.root, attempts, set())

    def test_failed_attempt_cannot_claim_drain_of_another_process_group(self):
        process, receipt = self.process()
        receipt.update(status="failed", exit_code=7, process_exit_code=7)
        receipt["cleanup"]["process_returncode"] = 7
        evidence = self.file("failed-result.json")
        attempt = {"schema": acceptance.SCHEMA, "id": "failed-1", "status": "failed", "evidence": evidence,
                   "started_at": "2026-01-02T00:00:00+00:00", "finished_at": "2026-01-02T00:00:10+00:00",
                   "processes": [process]}
        process["receipt"] = self.value("process.json", receipt)
        ref = self.value("attempts/failed-1/attempt.json", attempt)
        acceptance.verify_attempts(self.root, [{"id": "failed-1", "receipt": ref}], set())
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
            ref = self.value("attempts/failed-1/attempt.json", attempt)
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "process ownership has not drained"):
                acceptance.verify_attempts(self.root, [{"id": "failed-1", "receipt": ref}], set())


if __name__ == "__main__":
    unittest.main()
