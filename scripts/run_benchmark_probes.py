#!/usr/bin/env python3
"""Collect complete raw-map cases and optionally measure configured live network endpoints."""
import argparse
import json
import os
from pathlib import Path
import sys

if __name__ == "__main__":
    scripts = Path(__file__).resolve().parent
    if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode
            and sys.pycache_prefix is None and "PYTHONPYCACHEPREFIX" not in os.environ):
        raise SystemExit("benchmark probes require Python -I -B -S")
    if any(p.name == "__pycache__" or p.suffix in {".pyc", ".pyo"}
           or (p.suffix == ".py" and p.is_symlink()) for p in scripts.rglob("*")):
        raise SystemExit("benchmark probes require source-only Python imports")
    sys.path.insert(0, str(scripts))

import domain_run
import package_release as package
import repeatable_assembly as owned
import verify_release_acceptance as acceptance
from domain_run import require

RUNNER = "scripts/run_benchmark_probes.py"
DOCUMENTS = 1_000_000
OPERATIONS = 1000


def driver(evidence, functional):
    gate, = (gate for gate in functional["gates"] if gate["name"] == "network-driver")
    matches = [(path, record["sha256"]) for path, record in gate["executables"].items()
               if record["target"] == "kasumi-bench-network" and record["test"] is False]
    require(len(matches) == 1, "primary production network benchmark missing or ambiguous")
    path, digest = matches[0]
    return package.verify_file(evidence / "target", path, digest), digest


def project(root, name, native, operations, destination, replay=False):
    require(native["name"] == name and native["failed_attempts"] == [], "benchmark workload failed or changed")
    counts = {key: native[key] for key in ("requested_operations", "attempted_operations", "successful_operations",
                                          "failed_operations", "unattempted_operations")}
    rows = native.get("successful_elapsed_ns")
    require(isinstance(rows, list) and len(rows) == operations
            and all(type(n) is int and n > 0 for n in rows)
            and all(type(n) is int for n in counts.values())
            and list(counts.values()) == [operations, operations, operations, 0, 0],
            "native benchmark lost, repeated or failed operations")
    ordered = sorted(rows)
    latency = native["latency"]
    require(latency["operations"] == operations and type(latency["operations"]) is int
            and latency["p50_microseconds"] == ordered[(operations * 50 + 99) // 100 - 1] / 1000
            and latency["p99_microseconds"] == ordered[(operations * 99 + 99) // 100 - 1] / 1000
            and latency["max_microseconds"] == ordered[-1] / 1000, "native percentiles and sample stream differ")
    expected_rows = ({"sequence": number, "elapsed_ns": elapsed, "status": "passed"} for number, elapsed in enumerate(rows))
    if replay:
        require(list(acceptance.rows(root, owned.ref(root, destination))) == list(expected_rows),
                "retained rows differ from native operation durations")
    else:
        with destination.open("x") as stream:
            for row in expected_rows:
                stream.write(json.dumps(row) + "\n")
    measurement = {"name": name, **counts, "samples": owned.ref(root, destination)}
    acceptance.check_samples(root, measurement, minimum=operations)
    return measurement


def raw_case(root, report, digest, tenants, documents=DOCUMENTS, operations=OPERATIONS, replay=False):
    acceptance.exact(report, {"format", "tenants", "documents", "payload_bytes", "provider",
                              "measurement", "executable_sha256"}, "original raw map report")
    require(report["format"] == "kasumi-raw-matrix-v1" and report["executable_sha256"] == digest
            and type(report["tenants"]) is int and report["tenants"] == tenants
            and type(report["documents"]) is int and report["documents"] == documents
            and type(report["payload_bytes"]) is int and report["payload_bytes"] == documents * 1024
            and report["provider"] == "none", "wrong raw executable or incomplete corpus")
    name = "raw-" + str(tenants)
    measured = project(root, "raw_hashmap_borrowed_lookup", report["measurement"], operations, root / (name + ".jsonl"), replay)
    return {"id": name, "mode": "raw", "tenants": tenants, "documents": documents,
            "provider": "none", "workloads": [measured]}


def network_inputs(config, tenants):
    acceptance.exact(config, {"cases"}, "live network configuration")
    protocols = {}
    for case in config["cases"]:
        protocol = case["protocol"]
        targets = case["targets"]
        require(protocol in ("grpc", "mcp") and protocol not in protocols
                and case["name"] == protocol and case["operations"] == OPERATIONS and type(case["operations"]) is int
                and len(targets) == tenants and len({t["token_file"] for t in targets}) == tenants
                and all(t.get("query") is not None and Path(t["token_file"]).is_absolute()
                        and t.get("mutation_body") and Path(t["mutation_body"]).is_absolute() for t in targets)
                and all(Path(case[k]).is_absolute() for k in ("ca_pem", "client_certificate_pem", "client_private_key_pem")
                        if case.get(k) is not None), "network plan omits dedicated inputs or rewrites relative credentials")
        protocols[protocol] = case
    require(set(protocols) == {"grpc", "mcp"}, "both live protocols are required")
    return protocols


def network_samples(root, original, protocols, digest, tenants, replay=False):
    require(original["format"] == 1 and original["executable_sha256"] == digest and not original["failures"],
            "live network driver failed or changed")
    by_protocol = acceptance.unique(original["cases"], "protocol", "network protocols")
    require(set(by_protocol) == set(protocols), "missing live protocol results")
    readings = []
    for protocol, case in sorted(by_protocol.items()):
        require(case["name"] == protocol and case["phase"] == "completed"
                and case["endpoint"] == protocols[protocol]["endpoint"]
                and case["credentials"] == tenants == case["configured_targets"], "actual live endpoint or credential roster differs")
        measurements = acceptance.unique(case["measurements"], "name", "network measurements")
        require(set(measurements) == acceptance.NETWORK_WORKLOADS, "network workload roster differs")
        for name, native in sorted(measurements.items()):
            measured = project(root, name, native, OPERATIONS, root / f"network-{tenants}-{protocol}-{name}.jsonl", replay)
            measured["name"] = protocol + ":" + name
            readings.append(measured)
    return readings


def execute(run, configurations):
    run.bind()
    path, digest = driver(run.evidence, owned.read(run.evidence / "evidence.json"))
    plans = {}
    if configurations:
        require(len(configurations) == len(acceptance.TENANTS), "supply 1/100/1000 configurations in that order")
        for tenants, config in zip(acceptance.TENANTS, configurations):
            retained = run.configuration(f"network-{tenants}", config)
            plans[tenants] = retained, network_inputs(owned.read(retained), tenants)
    details = {"raw_cases": [], "network_workloads": [], "native_reports": []}
    run.report["details"] = details

    def measure(name, output, command, timeout):
        try:
            run.command(name, command, timeout, scenario=name)
        finally:
            if output.is_file():
                details["native_reports"].append(owned.ref(run.output, output))
                run.save()
        require(run.report["processes"][-1]["executable"]["sha256"] == digest, "another driver ran")

    for tenants in acceptance.TENANTS:
        name = "raw-" + str(tenants)
        output = run.output / (name + ".native.json")
        measure(name, output, [str(path), "--raw-baseline", str(tenants), str(DOCUMENTS), str(OPERATIONS), str(output)], 7200)
        details["raw_cases"].append(raw_case(run.output, owned.read(output), digest, tenants))
        if tenants in plans:
            name = "network-" + str(tenants)
            config, protocols = plans[tenants]
            output = run.output / (name + ".native.json")
            measure(name, output, [str(path), str(config), str(output), "--allow-writes", "--retain-samples"], 14400)
            details["network_workloads"].append({"tenants": tenants,
                "workloads": network_samples(run.output, owned.read(output), protocols, digest, tenants)})
    # Network credentials prove neither distinct tenants nor the installed corpus/provider.
    details["unqualified_cases"] = sorted(acceptance.SCENARIOS["benchmark-matrix"] - {c["id"] for c in details["raw_cases"]})
    run.passed(details)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("evidence", "output", "journal"):
        parser.add_argument("--" + key, type=Path, required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--network-config", type=Path, action="append", default=[])
    args = parser.parse_args()
    with domain_run.Run("benchmark-matrix", RUNNER, (), args.evidence, args.output, args.journal,
                        args.attempt_id, {"network_configs": [str(path) for path in args.network_config]},
                        domain_run.REHEARSAL) as run:
        execute(run, args.network_config)
