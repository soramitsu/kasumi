#!/usr/bin/env python3
"""Derive a capacity/workload report from one recorded benchmark matrix.

Missing observations stay null. Shared runtime footprints are referenced by ID;
API-layer rows must never be summed. This does not estimate a maximum capacity.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

LAYERS = {
    "raw_hashmap": ("raw", ["raw_hashmap_borrowed_lookup"]),
    "embedded_access": ("local", ["embedded_authorized_owned_point_get", "embedded_authorized_shared_point_get", "structured_indexed_equality"]),
    "local_durable_writes": ("local", ["durable_single_document_write", "read_heavy_90_read_10_write", "balanced_50_read_50_write"]),
    "replicated_durable_access": ("replicated", None),
    "authenticated_grpc": ("network", None),
    "authenticated_mcp": ("network", None),
}


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def report(directory):
    manifest = json.loads((directory / "matrix.json").read_text())
    counts = [int(value) for value in manifest["options"]["tenants"].split(",")]
    documents = manifest["options"]["documents"]
    completed = {case["name"]: case for case in manifest.get("cases", []) if case.get("status") == "passed"}
    footprints, layers, supplements, issues = [], [], [], []
    observed = {}
    for tenants in counts:
        for mode in ("raw", "local", "replicated", "text", "network"):
            name = f"{mode}-{tenants}"
            path = directory / f"{name}.json"
            if not path.exists():
                issues.append(f"{name}: no result file")
                continue
            source = json.loads(path.read_text())
            network = mode == "network"
            fixture = source.get("fixture", {}) if network else next((case for case in source.get("cases", []) if case.get("mode") == mode and case.get("tenants") == tenants), {})
            if not fixture and not network:
                progress=next((item for item in source.get("progress",[]) if item.get("mode")==mode and item.get("tenants")==tenants),{})
                fixture=dict(progress.get("details",{}))
                fixture["measurements"]=progress.get("measurements",[])
                fixture["stage"]=progress.get("stage")
            failures = list(source.get("failures", []))
            measurements = [item for case in source.get("cases",[]) for item in case.get("measurements",[])] if network else fixture.get("measurements",[])
            failures.extend(f"workload {item['name']} has failed or unattempted samples" for item in measurements if item.get("failed_operations",0) or item.get("unattempted_operations",0))
            if source.get("fixture_error"):
                failures.append(source["fixture_error"])
            matches = fixture.get("documents") == documents and fixture.get("tenants") == tenants
            expected = completed.get(name, {}).get("result_sha256")
            verified = expected == digest(path) and bool(expected)
            binaries = manifest.get("executable_sha256", {})
            executable_matches = source.get("executable_sha256") == binaries.get("target/release/kasumi-bench-network" if network else "target/release/kasumi-bench")
            if network:
                executable_matches &= fixture.get("server_executable_sha256") == binaries.get("target/release/kasumid")
            qualified = matches and verified and executable_matches and not failures
            if not qualified:
                issues.append(f"{name}: incomplete, mismatched, or not bound to matrix result/executable hashes; observed values are not used for overhead derivation")
            replicas = 3 if mode == "replicated" else 1
            # New fixtures declare this explicitly. Older embedded results predate
            # the independent security store; do not retrofit costs into evidence.
            security_stores = fixture.get("security_audit_stores", 1 if network else 0)
            resident = fixture.get("server_resident_rss_bytes" if network else "resident_rss_bytes")
            payload = documents * fixture.get("payload_bytes_each", 0) if network else fixture.get("payload_bytes")
            footprint = {
                "id": name, "source_file": path.name, "result_sha256": digest(path),
                "completed_and_identity_verified": qualified,
                "deployment": mode, "documents": fixture.get("documents"), "tenants": fixture.get("tenants"),
                "replicas_per_tenant": replicas,
                "resident_data_raft_groups": 0 if mode == "raw" else tenants * replicas,
                "resident_control_raft_groups": 1 if network else 0,
                "service_security_store_count": security_stores,
                "additional_service_security_store": security_stores > 0,
                "baseline_rss_bytes": fixture.get("baseline_rss_bytes"),
                "empty_groups_rss_bytes": fixture.get("server_empty_rss_bytes" if network else "empty_rss_bytes"),
                "empty_indexes_rss_bytes": fixture.get("server_empty_index_rss_bytes" if network else "empty_index_rss_bytes"),
                "loaded_rss_bytes": resident,
                "after_workload_rss_bytes": fixture.get("server_after_workload_rss_bytes" if network else "after_workload_rss_bytes"),
                "after_recovery_rss_bytes": fixture.get("server_after_recovery_rss_bytes" if network else "after_recovery_rss_bytes"),
                "process_lifetime_peak_rss_bytes": None if network else fixture.get("peak_rss_bytes"),
                "disk_file_bytes": fixture.get("server_disk_bytes" if network else "disk_bytes"),
                "unique_logical_payload_bytes": payload,
                "loaded_rss_per_unique_payload_byte": resident / payload if resident is not None and payload else None,
                "loaded_rss_per_resident_payload_byte": resident / (payload * replicas) if resident is not None and payload else None,
                "open_seconds": fixture.get("runtime_open_seconds" if network else "open_seconds"),
                "collection_setup_seconds": fixture.get("collection_setup_seconds"),
                "load_seconds": fixture.get("load_seconds"),
                "clean_shutdown_seconds": fixture.get("shutdown_seconds"),
                "clean_recovery_seconds": fixture.get("recovery_seconds"),
                "sampling_scope": "kasumid process only; benchmark client, issuer, OpenBao are excluded and available in host-samples.jsonl" if network else "entire harness process including all voters and driver allocations",
            }
            footprints.append(footprint)
            observed[(mode, tenants)] = source, fixture, footprint
        for layer, (mode, selected) in LAYERS.items():
            found = observed.get((mode, tenants))
            measures = []
            if found:
                source, fixture, _ = found
                if mode == "network":
                    protocol = "grpc" if layer == "authenticated_grpc" else "mcp"
                    case = next((case for case in source.get("cases", []) if case.get("protocol") == protocol), {})
                    measures = case.get("measurements", [])
                else:
                    measures = fixture.get("measurements", [])
                if selected is not None:
                    measures = [item for item in measures if item["name"] in selected]
            layers.append({"layer": layer, "tenants": tenants, "footprint_id": f"{mode}-{tenants}", "measurements": measures, "status": "observed_with_failures" if any(item.get("failed_operations",0) or item.get("unattempted_operations",0) for item in measures) else ("observed" if measures else "not_measured")})
        found = observed.get(("text", tenants))
        supplements.append({"workload": "english_japanese_indexed_text", "tenants": tenants, "footprint_id": f"text-{tenants}", "measurements": found[1].get("measurements", []) if found else [], "status": "observed" if found else "not_measured"})
    overhead = []
    for footprint in footprints:
        mode, tenants = footprint["deployment"], footprint["tenants"]
        baseline = observed.get((mode, 1))
        if tenants is None or tenants <= 1 or not footprint["completed_and_identity_verified"] or not baseline or not baseline[2]["completed_and_identity_verified"]:
            continue
        for stage in ("empty_groups_rss_bytes", "empty_indexes_rss_bytes"):
            one, many = baseline[2][stage], footprint[stage]
            if one is None or many is None:
                continue
            delta = (many - one) / (tenants - 1)
            overhead.append({"deployment": mode, "tenant_count": tenants, "stage": stage, "additional_tenant_rss_bytes": delta, "additional_resident_voter_rss_bytes": None if mode == "raw" else delta / footprint["replicas_per_tenant"], "method": "Difference from independent one-tenant process / additional tenants. This includes all associated runtime, policy, KMS, audit and index overhead; allocator/OS noise can produce negative estimates. It is not an isolated Raft allocation measurement."})
    return {
        "format": 1, "matrix_status": manifest.get("status"), "source_sha256": manifest.get("source_sha256"),
        "passed_quietness_screening": manifest.get("passed_quietness_screening", False),
        "host_load_violation_counts": manifest.get("host_load_violation_counts", {}),
        "configured_documents": documents, "configured_tenants": counts,
        "footprints": footprints, "layers": layers, "supplemental_workloads": supplements,
        "tenant_overhead_estimates": overhead, "issues": issues,
        "limits": [
            "One sequential closed-loop observation per workload; no saturation throughput, confidence interval, or launch SLA is inferred.",
            "API-layer rows share footprints. Never sum embedded/local or native/MCP footprint references.",
            "Service security-audit stores are shared per node, included in memory/key/disk observations, and counted separately from tenant/control Raft groups. Older results without declared counts retain their original fixture attribution.",
            "Resident/payload ratios include whole-process infrastructure and replicated copies, not just document heap overhead.",
            "RSS snapshots and five-second host samples can miss transient peaks; network process-lifetime peak is not measured here.",
            "Shutdown is timed separately through complete database closure or successful server process exit. Recovery starts after shutdown and covers reopen/spawn through verified reads; final cleanup is excluded. OpenBao and issuer remain running for network restart. These are not crash/power-loss measurements.",
            "Three voters are in one process on one host. Independent failure domains and remote network latency are not measured.",
            "An observed fit does not establish maximum capacity; budgets require headroom for staged indexes, snapshots, cursors, receipts, auditing, background work and OS memory.",
        ],
    }


def markdown(value):
    lines = ["# Measured capacity", "", f"Matrix outcome: `{value['matrix_status']}`. Quietness screening passed: `{value['passed_quietness_screening']}`.", "", "Footprints are shared between API layers and must not be added together. Missing values mean not measured.", "", "| Deployment | Tenants | Empty groups MiB | Empty indexes MiB | Loaded MiB | After work MiB | Shutdown s | Recovery s |", "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for row in value["footprints"]:
        def mib(key):
            number = row[key]
            return "—" if number is None else f"{number / 2**20:.2f}"
        shutdown, recovery = row["clean_shutdown_seconds"], row["clean_recovery_seconds"]
        lines.append(f"| {row['deployment']} | {row['tenants']} | {mib('empty_groups_rss_bytes')} | {mib('empty_indexes_rss_bytes')} | {mib('loaded_rss_bytes')} | {mib('after_workload_rss_bytes')} | {'—' if shutdown is None else f'{shutdown:.3f}'} | {'—' if recovery is None else f'{recovery:.3f}'} |")
    lines.extend(["", "The JSON report contains all six API layers, workload sample counts, latency, throughput, source/result identities, and qualified tenant-overhead estimates.", ""])
    for item in value["limits"] + value["issues"]:
        lines.append(f"- {item}")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("matrix_directory", type=Path)
    options = parser.parse_args()
    value = report(options.matrix_directory)
    (options.matrix_directory / "capacity.json").write_text(json.dumps(value, indent=2) + "\n")
    (options.matrix_directory / "capacity.md").write_text(markdown(value))
    print(options.matrix_directory / "capacity.json")


if __name__ == "__main__":
    main()
