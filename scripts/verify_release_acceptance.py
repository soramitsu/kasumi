#!/usr/bin/env python3
"""Verify complete first-release evidence, independently of candidate packaging.

Read-only: never creates passing evidence, drops failures, runs workloads, or
repairs a manifest. See docs/release-acceptance-manifest.md for the trust boundary
and the domain runner work that remains necessary to produce these receipts.
"""
from __future__ import annotations

import argparse
import contextvars
import datetime as dt
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tempfile

import package_release as package
from release_gate import TOOLCHAIN, functional_gates, sha256

SCHEMA = "kasumi-release-acceptance-v1"
# Registrations must be reviewed code in the frozen source: each adapter owns a
# fixed runner path, reconstructs its exact command from verified inputs, and
# validates the runner's domain-specific outcomes. No current runner implements
# the complete final-release domain contracts. Deliberately accept none until
# those adapters exist; an opaque report and asserted scenario labels cannot
# certify a release. There is no CLI/manifest switch to override this registry.
DOMAIN_ADAPTERS = {}
OBSERVATIONS = contextvars.ContextVar("release_acceptance_observations", default=None)
PLATFORMS = tuple(sorted(package.TARGETS))
LINUX = tuple(target for target in PLATFORMS if "linux" in target)
REFERENCE = "aarch64-unknown-linux-gnu"
MIN_CORPUS = 3 << 30
SOAK_SECONDS = 86400
MAX_JSON_BYTES = 16 << 20
MODES = ("raw", "local", "replicated", "text", "network")
TENANTS = (1, 100, 1000)
BASE_WORKLOADS = {
    "embedded_authorized_owned_point_get", "embedded_authorized_shared_point_get",
    "durable_single_document_write", "read_heavy_90_read_10_write",
    "balanced_50_read_50_write", "structured_indexed_equality",
}
NETWORK_WORKLOADS = {"authenticated_point_get", "durable_single_document_write",
                     "read_heavy_90_read_10_write", "balanced_50_read_50_write",
                     "authenticated_query_complete_pages"}
CAPACITY_OPERATIONS = {"snapshot", "compaction", "restart", "filesystem-backup",
                       "filesystem-restore", "s3-backup", "s3-restore", "retained-read-pressure"}
RECOVERY_PHASES = {"preparation", "materialization", "initialization", "source-fencing",
                   "activation", "confirmation", "route-publication"}
DELETION_PHASES = {"permanent-stop", "issuer-drain", "gate-closure", "worker-drain",
                   "storage-drain", "exact-deletion", "parent-sync", "durable-evidence"}
SCENARIOS = {
    "correctness": {"allocation-boundaries", "publication-boundaries", "transaction-rollback",
                    "owner-failure", "interrupted-repair", "interrupted-close",
                    "interrupted-compaction", "generation-publication", "pinned-reader-reclamation",
                    "cancellation", "child-panic", "response-revocation", "cleanup-sync-failure"},
    "installed": {"offline-initialize", "native-mtls", "mcp", "one-hour-jwt", "renewal",
                  "revocation", "wrapping-rotation", "signer-rotation", "certificate-rotation",
                  "invalid-tls-replacement", "restart", "backup", "restore",
                  "operator-key-backup", "exclusive-stopped-admin-recovery", "oauth-discovery"},
    "providers": {"real-openbao", "real-minio", "credential-refresh", "provider-restart"},
    "ha-faults": {"leader-loss", "partition", "lease-length-outage", "fresh-admission",
                  "learner-catchup", "voter-replacement-under-load", "endpoint-trust-rotation"},
    "recovery": {f"{phase}-{fault}" for phase in RECOVERY_PHASES | DELETION_PHASES
                 for fault in ("crash", "cancellation")} | {
                     "absent-source-quorum", "independent-source-target-authorization",
                     "single-activation-winner", "forward-after-activation", "physical-bindings",
                     "unrelated-file-isolation"},
    "audit-retention": {"hot-budget-crossing", "verified-contiguous-archives", "archive-outage",
                        "replica-dependency-before-prune", "replacement-dependencies",
                        "permanent-identity-lifetime-ceiling"},
    "backup-cleanup": {"completion-uncertainty", "abort-resolution", "repeated-namespace-cleanup",
                       "late-upload", "completed-backup-isolation", "archive-isolation",
                       "permanent-tombstones"},
    "key-retention": {"exact-historical-resolution", "recovery-provider-bindings", "paged-coverage",
                      "incomplete-dependency-rejection", "race-safe-retirement"},
    "observability": {"protected-health", "protected-readiness", "protected-metrics",
                      "structured-logs", "physical-capacity", "archive-backlog", "backup-outcomes",
                      "authority-health", "membership-maintenance", "recovery-phases",
                      "membership-epoch-coverage", "more-than-128-groups"},
    "concurrency": {"reads-writes", "backup-writes", "snapshot-writes", "membership-writes"},
    "ha-soak": {"credential-renewal", "archival", "backup", "membership-maintenance"},
    "package-smoke": {"fresh-install", "initialize", "native", "mcp", "restart", "clean-stop"},
    "oci-smoke": {"load-image", "fresh-install", "native", "mcp", "restart", "clean-stop"},
    "systemd-smoke": {"install-units", "start-data", "start-authority", "restart", "clean-stop"},
    "repeatable-assembly": {"assembly-a", "assembly-b"},
    "dependency-review": {"patch-upstream-tests", "memory-safety-regressions", "advisory-dispositions"},
    "capacity-standalone": CAPACITY_OPERATIONS,
    "capacity-ha": CAPACITY_OPERATIONS | {"follower-replacement"},
    "benchmark-matrix": {f"{mode}-{tenants}" for mode in MODES for tenants in TENANTS},
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def exact(value, fields, label):
    require(isinstance(value, dict) and set(value) == set(fields), label + " fields differ from contract")


def uint(value, label, minimum=0):
    require(type(value) is int and minimum <= value <= (1 << 64) - 1, label + " is not a bounded integer")
    return value


def number(value, label, minimum=0):
    require(type(value) in (int, float) and math.isfinite(value) and value >= minimum,
            label + " is not a finite number in range")
    return value


def checksum(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "invalid SHA256")
    return value


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode()).hexdigest()


def unique(items, field, label):
    require(isinstance(items, list), label + " must be a list")
    result = {}
    for item in items:
        require(isinstance(item, dict) and isinstance(item.get(field), str), label + " identifier missing")
        key = item[field]
        require(key and key not in result, label + " duplicate/empty identifier: " + key)
        result[key] = item
    return result


def object_pairs(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON key: " + key)
        value[key] = item
    return value


def decode(value):
    return json.loads(value, object_pairs_hook=object_pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite JSON: " + value)))


def read_json(path):
    with path.open("rb") as stream:
        data = stream.read(MAX_JSON_BYTES + 1)
    require(len(data) <= MAX_JSON_BYTES, "JSON exceeds work limit")
    observations = OBSERVATIONS.get()
    if observations is not None:
        observed = observations.get(str(path.absolute()))
        if observed is not None:
            require(hashlib.sha256(data).hexdigest() == observed[2]["sha256"]
                    and len(data) == observed[2]["bytes"], "JSON changed between verification and parsing")
    return decode(data)


def relative_path(value):
    require(isinstance(value, str) and value and "\\" not in value, "invalid relative path")
    path = PurePosixPath(value)
    require(not path.is_absolute() and ".." not in path.parts and path.as_posix() == value
            and value != ".", "unsafe or noncanonical file reference")
    return value


def reference(root, ref):
    exact(ref, {"path", "sha256", "bytes"}, "file reference")
    path = package.verify_file(root, relative_path(ref["path"]), checksum(ref["sha256"]))
    require(path.stat().st_size == uint(ref["bytes"], "file length"), "file length changed")
    observations = OBSERVATIONS.get()
    if observations is not None:
        key = str(path.absolute())
        previous = observations.get(key)
        require(previous is None or previous[2] == ref, "input identity changed during verification")
        observations[key] = (root, path, dict(ref))
    return path


def json_reference(root, ref):
    return read_json(reference(root, ref))


def rows(root, ref):
    with reference(root, ref).open("rb") as stream:
        while line := stream.readline((1 << 20) + 1):
            require(len(line) <= 1 << 20 and line.endswith(b"\n"), "oversized/truncated JSONL row")
            yield decode(line)


def required_gates():
    result = {(kind, REFERENCE) for kind in SCENARIOS
              if kind not in {"installed", "package-smoke", "oci-smoke", "systemd-smoke", "repeatable-assembly"}}
    result |= {(kind, target) for target in PLATFORMS
               for kind in ("installed", "package-smoke", "repeatable-assembly")}
    result |= {(kind, target) for target in LINUX for kind in ("oci-smoke", "systemd-smoke")}
    return {kind + ":" + target for kind, target in result}


def required_artifacts():
    result = {"source", "checksums", "license", "notice", "contribution", "security", "installation",
              "maintenance", "recovery", "operating-limits", "systemd-data", "systemd-authority"}
    result |= {kind + ":" + target for target in PLATFORMS
               for kind in ("package", "dependency-sbom", "third-party-notices")}
    result |= {kind + ":" + target for target in LINUX for kind in ("oci", "image-sbom")}
    return result


def timestamp(value):
    require(isinstance(value, str), "timestamp is missing")
    parsed = dt.datetime.fromisoformat(value)
    require(parsed.tzinfo is not None and parsed.utcoffset() == dt.timedelta(), "timestamp must use UTC")
    return parsed


def check_samples(root, measurement, minimum=1):
    exact(measurement, {"name", "requested_operations", "attempted_operations", "successful_operations",
                        "failed_operations", "unattempted_operations", "samples"}, "measurement")
    count = uint(measurement["requested_operations"], "requested operations", minimum)
    require(measurement["attempted_operations"] == count and measurement["successful_operations"] == count
            and type(measurement["attempted_operations"]) is int
            and type(measurement["successful_operations"]) is int
            and measurement["failed_operations"] == 0 and type(measurement["failed_operations"]) is int
            and measurement["unattempted_operations"] == 0 and type(measurement["unattempted_operations"]) is int,
            "failed, unattempted or missing workload samples")
    seen = 0
    for row in rows(root, measurement["samples"]):
        exact(row, {"sequence", "elapsed_ns", "status"}, "sample")
        require(type(row["sequence"]) is int and row["sequence"] == seen and row["status"] == "passed",
                "sample gap, duplicate, or failure")
        uint(row["elapsed_ns"], "sample duration", 1)
        seen += 1
        require(seen <= count, "extra workload samples")
    require(seen == count, "shortened workload sample stream")


def check_benchmarks(root, details):
    exact(details, {"cases"}, "benchmark details")
    cases = unique(details["cases"], "id", "benchmark cases")
    require(set(cases) == SCENARIOS["benchmark-matrix"], "all fifteen benchmark cases are required")
    for name, case in cases.items():
        exact(case, {"id", "mode", "tenants", "documents", "provider", "workloads"}, "benchmark case")
        mode, tenants = name.rsplit("-", 1)
        require(case["mode"] == mode and case["tenants"] == int(tenants)
                and type(case["tenants"]) is int and case["documents"] == 1_000_000
                and type(case["documents"]) is int, "benchmark case is shortened or mislabeled")
        require(case["provider"] == ("none" if mode == "raw" else "production"),
                "fixture providers cannot qualify production benchmarks")
        workloads = unique(case["workloads"], "name", "benchmark workloads")
        expected = {"raw_hashmap_borrowed_lookup"} if mode == "raw" else BASE_WORKLOADS
        if mode == "text":
            expected = BASE_WORKLOADS | {"text_english_Phrase_complete_pages", "text_english_Prefix_complete_pages",
                                         "text_english_Fuzzy_complete_pages", "text_japanese_Terms_complete_pages"}
        if mode == "network":
            expected = {protocol + ":" + work for protocol in ("grpc", "mcp") for work in NETWORK_WORKLOADS}
        require(set(workloads) == expected, "benchmark workload set is incomplete")
        for measurement in workloads.values():
            check_samples(root, measurement, minimum=1000)


def check_integrity(root, ref, documents, expected_bytes):
    count = size = 0
    for row in rows(root, ref):
        exact(row, {"first", "documents", "canonical_bytes", "expected_sha256", "observed_sha256"}, "integrity batch")
        require(type(row["first"]) is int and row["first"] == count, "integrity gap or duplicate batch")
        batch = uint(row["documents"], "integrity documents", 1)
        require(batch <= 256, "integrity verification is not bounded")
        count += batch
        size += uint(row["canonical_bytes"], "integrity bytes", 1)
        require(checksum(row["expected_sha256"]) == row["observed_sha256"], "integrity mismatch")
        require(count <= documents and size <= expected_bytes, "integrity exceeds corpus")
    require(count == documents and size == expected_bytes, "integrity verification is not exhaustive")


def check_capacity(root, details, kind):
    exact(details, {"corpus", "operations"}, "capacity details")
    corpus = details["corpus"]
    exact(corpus, {"documents", "canonical_bytes", "seed_sha256", "compression"}, "capacity corpus")
    documents = uint(corpus["documents"], "corpus documents", 1)
    size = uint(corpus["canonical_bytes"], "corpus bytes", MIN_CORPUS + 1)
    checksum(corpus["seed_sha256"])
    compression = corpus["compression"]
    exact(compression, {"algorithm", "input_bytes", "output_bytes", "log"}, "compression measurement")
    require(compression["algorithm"] == "gzip-9" and compression["input_bytes"] == size,
            "compression must measure the full exact corpus with gzip-9")
    compressed = uint(compression["output_bytes"], "compressed bytes", 1)
    require(compressed * 4 >= size * 3, "corpus is too compressible (minimum ratio 0.75)")
    reference(root, compression["log"])
    operations = unique(details["operations"], "id", "capacity operations")
    require(set(operations) == SCENARIOS[kind], "capacity operation coverage is incomplete")
    for operation in operations.values():
        exact(operation, {"id", "integrity", "resources", "limits", "read_retention_budget_bytes"}, "capacity operation")
        check_integrity(root, operation["integrity"], documents, size)
        limits = operation["limits"]
        exact(limits, {"rss_bytes", "allocated_disk_bytes", "maintenance_workspace_bytes"}, "resource limits")
        for key, value in limits.items():
            uint(value, key, 1)
        require(limits["maintenance_workspace_bytes"] <= size // 4, "maintenance workspace is not bounded below corpus size")
        retention = uint(operation["read_retention_budget_bytes"], "read retention budget", 1)
        require(retention <= size // 4, "retained-read budget must be substantially smaller than corpus")
        count = 0
        previous = -1
        for sample in rows(root, operation["resources"]):
            exact(sample, {"elapsed_seconds", *limits}, "resource sample")
            observed = number(sample["elapsed_seconds"], "resource sample time")
            require(observed > previous, "resource samples are unordered")
            previous = observed
            for key, ceiling in limits.items():
                require(uint(sample[key], key) <= ceiling, "measured resource exceeds admitted limit")
            count += 1
        require(count >= 2, "resource peaks require multiple actual samples")


def check_soak(root, details, elapsed):
    exact(details, {"duration_seconds", "heartbeats", "maintenance"}, "soak details")
    duration = number(details["duration_seconds"], "soak duration", SOAK_SECONDS)
    require(elapsed >= duration, "soak duration exceeds observed wall time")
    previous = None
    operations = 0
    count = 0
    for row in rows(root, details["heartbeats"]):
        exact(row, {"elapsed_seconds", "successful_operations", "unexpected_errors", "integrity_mismatches"}, "soak heartbeat")
        current = number(row["elapsed_seconds"], "heartbeat time")
        require((previous is None and current == 0) or
                (previous is not None and 0 < current - previous <= 60), "soak heartbeat gap")
        require(row["unexpected_errors"] == 0 and type(row["unexpected_errors"]) is int
                and row["integrity_mismatches"] == 0 and type(row["integrity_mismatches"]) is int,
                "soak has unexpected errors or integrity mismatches")
        now_operations = uint(row["successful_operations"], "soak operations")
        require(previous is None or now_operations > operations, "soak workload stopped between heartbeats")
        operations, previous, count = now_operations, current, count + 1
    require(count >= 1441 and previous == duration, "shortened or incomplete soak observations")
    maintenance = unique(details["maintenance"], "id", "soak maintenance")
    require(set(maintenance) == SCENARIOS["ha-soak"], "soak maintenance coverage missing")
    for event in maintenance.values():
        exact(event, {"id", "elapsed_seconds", "log"}, "soak maintenance event")
        require(0 < number(event["elapsed_seconds"], "maintenance time") < duration,
                "maintenance did not occur during soak")
        reference(root, event["log"])


def check_host(root, host, target, started, finished):
    exact(host, {"id", "physical_machine", "execution_machine", "emulated", "reservation", "preflight", "attestation"}, "native host")
    machine = "x86_64" if target.startswith("x86_64") else "aarch64"
    require(isinstance(host["id"], str) and host["id"] and host["physical_machine"] == machine
            and host["execution_machine"] == machine and host["emulated"] is False,
            "native host architecture is missing or emulated")
    preflight = json_reference(root, host["preflight"])
    require(preflight.get("schema") == 1 and preflight.get("requested_target") == target
            and preflight.get("errors") == [] and preflight.get("translated") in (None, False),
            "native host preflight failed")
    require(uint(preflight.get("effective_memory_bytes"), "host memory") >= 15 << 30,
            "insufficient native functional memory")
    reference(root, host["attestation"])
    reservation = host["reservation"]
    exact(reservation, {"id", "starts_at", "ends_at", "cpu_count", "memory_bytes", "disk_bytes"}, "host reservation")
    require(reservation["id"] and timestamp(reservation["starts_at"]) <= started
            and timestamp(reservation["ends_at"]) >= finished, "reservation does not cover execution")
    uint(reservation["cpu_count"], "reserved CPUs", 1)
    uint(reservation["memory_bytes"], "reserved memory", 15 << 30)
    uint(reservation["disk_bytes"], "reserved disk", 64 << 30)


def check_processes(root, processes, elapsed, passed=True):
    processes = unique(processes, "id", "owned processes")
    require(processes, "missing process custody")
    longest = 0
    for process in processes.values():
        exact(process, {"id", "receipt", "log", "executable"}, "owned process")
        reference(root, process["log"])
        reference(root, process["executable"])
        record = json_reference(root, process["receipt"])
        executable = record.get("executable")
        exact(executable, {"path", "sha256"}, "executed process identity")
        require(isinstance(executable["path"], str) and Path(executable["path"]).is_absolute()
                and checksum(executable["sha256"]) == process["executable"]["sha256"],
                "actual executable is not bound to retained executable bytes")
        command = record.get("command")
        require(isinstance(command, list) and command and all(isinstance(arg, str) for arg in command)
                and command[0] == executable["path"], "process command differs from executed identity")
        require(record.get("status") in ("passed", "failed") and record.get("outputs_stable") is True,
                "process is not terminal with stable output")
        cleanup = record.get("cleanup", {})
        require(cleanup.get("drained") is True and cleanup.get("after") == []
                and cleanup.get("errors") == [] and type(cleanup.get("process_returncode")) is int,
                "process ownership has not drained")
        if passed:
            gate = {"command": command, "process": process["receipt"]["path"],
                    "process_sha256": process["receipt"]["sha256"], "process_cleanup": cleanup,
                    "timeout_seconds": record.get("timeout_seconds"), "timed_out": record.get("timed_out"),
                    "received_signals": record.get("received_signals"), "process_error": record.get("error")}
            number(record.get("timeout_seconds"), "original process deadline", 1)
            package.verify_process_receipt(root, gate, record["timeout_seconds"])
        duration = number(record.get("duration_seconds"), "process elapsed time")
        require(duration <= elapsed + 1, "process duration exceeds attempt wall time")
        longest = max(longest, duration)
    return longest


def check_topology(topology, processes, binaries, required):
    nodes = unique(topology, "id", "HA members")
    if not required:
        require(not nodes, "unexpected HA topology for this gate")
        return
    require(len(nodes) == 9, "HA acceptance requires three separate three-member groups")
    owned = unique(processes, "id", "HA processes")
    roles = {role: [] for role in ("data", "control", "authority")}
    groups, certificates, process_ids = set(), set(), set()
    for node in nodes.values():
        exact(node, {"id", "role", "group", "certificate_sha256", "process_id"}, "HA member")
        require(node["role"] in roles and isinstance(node["group"], str) and node["group"], "invalid HA group")
        process_id = node["process_id"]
        require(process_id in owned and process_id not in process_ids, "HA members must be separate owned processes")
        process_ids.add(process_id)
        certificate = checksum(node["certificate_sha256"])
        require(certificate not in certificates, "HA TLS identities are not distinct")
        certificates.add(certificate)
        binary = "kasumi-authority" if node["role"] == "authority" else "kasumid"
        require(owned[process_id]["executable"]["sha256"] == binaries[binary], "HA member did not execute candidate bytes")
        roles[node["role"]].append(node["group"])
    for members in roles.values():
        require(len(members) == 3 and len(set(members)) == 1 and members[0] not in groups,
                "data, Control and authority groups must each contain exactly three members")
        groups.add(members[0])


def archive_inventory(path, strip_root=True):
    """Stream hashes without extracting executable archives or trusting links."""
    result = {}
    all_names = set()
    prefix = None
    with tarfile.open(path, "r:*") as archive:
        for member in archive:
            name = relative_path(member.name.rstrip("/") if member.isdir() else member.name)
            require(name not in all_names, "duplicate archive member")
            all_names.add(name)
            parts = PurePosixPath(name).parts
            prefix = prefix or parts[0]
            require((not strip_root or parts[0] == prefix) and (member.isdir() or member.isfile()), "unsafe archive member")
            if member.isdir():
                continue
            require(not strip_root or len(parts) > 1, "archive lacks single root directory")
            with archive.extractfile(member) as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            result["/".join(parts[1:] if strip_root else parts)] = {
                "sha256": digest, "bytes": member.size, "executable": bool(member.mode & 0o111)}
    require(result, "empty archive")
    return result


def verify_source(root, manifest, repository):
    source = manifest["source"]
    exact(source, {"commit", "tree", "archive", "files", "lockfile_sha256", "patches_sha256", "configurations"}, "source")
    for key in ("commit", "tree"):
        require(isinstance(source[key], str) and re.fullmatch(r"[0-9a-f]{40}", source[key]), "invalid Git identity")
    def git(*args):
        return subprocess.check_output(["git", "-C", str(repository), *args], text=True).strip()
    require(git("rev-parse", "HEAD") == source["commit"] and
            git("rev-parse", "HEAD^{tree}") == source["tree"], "acceptance must run at exact frozen Git revision")
    require(not git("status", "--porcelain", "--untracked-files=all"), "final source checkout is not clean")
    archive = reference(root, source["archive"])
    files = json_reference(root, source["files"])
    with tempfile.TemporaryDirectory(prefix="kasumi-acceptance-source-") as temporary:
        original = Path(temporary) / "source.tar"
        subprocess.run(["git", "-C", str(repository), "archive", "--format=tar", "--output=" + str(original),
                        source["commit"]], check=True)
        require(sha256(original) == sha256(archive), "source archive is not the exact Git archive")
    require(files == archive_inventory(archive, strip_root=False), "source inventory differs from actual Git archive")
    require(isinstance(files, dict) and files.get("Cargo.lock", {}).get("sha256") == checksum(source["lockfile_sha256"]),
            "source lockfile hash differs")
    patches = {name: entry for name, entry in files.items() if name.startswith("vendor/")}
    require(patches and canonical_hash(patches) == checksum(source["patches_sha256"]), "patch inventory differs")
    configs = unique(source["configurations"], "id", "configurations")
    require(configs, "configuration hashes are missing")
    for config in configs.values():
        exact(config, {"id", "file"}, "configuration")
        reference(root, config["file"])
    identity = {"source_commit": source["commit"], "source_tree": source["tree"],
                "source_archive_sha256": source["archive"]["sha256"], "source_files_sha256": source["files"]["sha256"],
                "lockfile_sha256": source["lockfile_sha256"], "patches_sha256": source["patches_sha256"],
                "configurations_sha256": canonical_hash({key: value["file"]["sha256"] for key, value in configs.items()})}
    for tool in ("verify_release_acceptance.py", "package_release.py", "release_gate.py", "gate_process.py"):
        require(files.get("scripts/" + tool, {}).get("sha256") == sha256(Path(__file__).parent / tool),
                "executing verifier differs from final source: " + tool)
    return identity, files, configs


def verify_candidates(root, manifest, identity):
    candidates = unique(manifest["candidates"], "platform", "native candidates")
    require(set(candidates) == set(PLATFORMS), "all three native candidates and independent builds are required")
    binaries = {}
    for target, candidate in candidates.items():
        exact(candidate, {"platform", "primary", "independent"}, "candidate")
        build = candidate["primary"]
        exact(build, {"functional", "host", "build_id", "build_root", "environment_id", "fresh_build_root"}, "candidate build")
        require(build["build_id"] and build["fresh_build_root"] is True and build["environment_id"]
                and isinstance(build["build_root"], str) and Path(build["build_root"]).is_absolute(),
                "primary build custody missing")
        evidence_path = reference(root, build["functional"])
        record, _, actual_target, actual_binaries = package.verify_evidence(evidence_path.parent)
        require(evidence_path.name == "evidence.json" and actual_target == target, "candidate platform mismatch")
        # Reject duplicate keys before the existing verifier's ordinary JSON reads.
        require(read_json(evidence_path) == record, "ambiguous functional evidence")
        # Retain every transitive input checked by the candidate verifier for a
        # final recheck. A concurrent replacement cannot be certified by hashing
        # only the top-level evidence file after its children were inspected.
        evidence_root = evidence_path.parent
        interpreter = record["python_executable"]
        child = package.owned_file(evidence_root, interpreter["artifact"])
        reference(evidence_root, {"path": interpreter["artifact"], "sha256": interpreter["sha256"],
                                  "bytes": child.stat().st_size})
        archive = package.owned_file(evidence_root, "source.tar")
        reference(evidence_root, {"path": "source.tar", "sha256": record["source_archive_sha256"],
                                  "bytes": archive.stat().st_size})
        for gate in record["gates"]:
            for field in ("log", "process", "resources"):
                child = package.owned_file(evidence_root, gate[field])
                ref = {"path": gate[field], "sha256": gate[field + "_sha256"], "bytes": child.stat().st_size}
                reference(evidence_root, ref)
                if field != "log":
                    read_json(child)
            for relative, executable in gate.get("executables", {}).items():
                child = package.owned_file(evidence_root / "target", relative)
                reference(evidence_root / "target", {"path": relative, "sha256": executable["sha256"], "bytes": child.stat().st_size})
        inventory_path = package.owned_file(evidence_root, "source-files.json")
        reference(evidence_root, {"path": "source-files.json", "sha256": record["source_files_sha256"],
                                  "bytes": inventory_path.stat().st_size})
        for relative, entry in read_json(inventory_path).items():
            reference(evidence_root / "source", {"path": relative, "sha256": entry["sha256"], "bytes": entry["bytes"]})
        for field in ("source_commit", "source_tree", "source_archive_sha256", "source_files_sha256", "lockfile_sha256"):
            require(record.get(field) == identity[field], "candidate source mismatch: " + field)
        start, end = timestamp(record["started_at"]), timestamp(record["finished_at"])
        require(end > start, "functional run has no elapsed interval")
        check_host(root, build["host"], target, start, end)
        require(record.get("toolchain") == TOOLCHAIN, "candidate toolchain mismatch")
        binaries[target] = {name: digest for name, (_, digest) in actual_binaries.items()}
        check_independent_build(root, candidate["independent"], build, target, identity, binaries[target])
    return candidates, binaries


def check_independent_build(root, ref, primary, target, identity, binaries):
    """A second isolated compilation; it need not repeat every functional test."""
    record = json_reference(root, ref)
    exact(record, {"schema", "status", "identity", "toolchain", "platform", "jobs", "started_at", "finished_at",
                   "build_id", "build_root", "environment_id", "environment", "fresh_build_root", "host",
                   "processes", "compiled_packages", "binaries", "source_archive", "source_files"}, "independent build")
    require(record["schema"] == SCHEMA and record["status"] == "passed" and record["identity"] == identity
            and record["platform"] == target and record["toolchain"] == TOOLCHAIN, "independent build identity differs")
    for key in ("build_id", "build_root", "environment_id"):
        require(isinstance(record[key], str) and record[key] and record[key] != primary[key],
                "independent compilation reused primary " + key)
    require(Path(record["build_root"]).is_absolute() and record["fresh_build_root"] is True,
            "independent compilation lacks an isolated empty build root")
    reference(root, record["environment"])
    for name in ("source_archive", "source_files"):
        reference(root, record[name])
        require(record[name]["sha256"] == identity[name + "_sha256"], "independent build input differs")
    start, end = timestamp(record["started_at"]), timestamp(record["finished_at"])
    require(end > start, "independent compilation has no elapsed interval")
    check_host(root, record["host"], target, start, end)
    check_processes(root, record["processes"], (end - start).total_seconds())
    require(len(record["processes"]) == 1, "independent compilation must retain its one Cargo command")
    process = json_reference(root, record["processes"][0]["receipt"])
    jobs = uint(record["jobs"], "independent build concurrency", 1)
    require(jobs <= 64, "independent build concurrency exceeds contract")
    command = dict(functional_gates(jobs, sys.executable))["production"]
    require(Path(process["command"][0]).name == "cargo" and process["command"][1:] == command[1:],
            "independent build did not invoke exact fixture-free production compilation")
    compiled = record["compiled_packages"]
    require(isinstance(compiled, dict) and compiled, "independent compilation dependency inventory missing")
    for item in compiled.values():
        require(isinstance(item, dict) and isinstance(item.get("features"), list)
                and not set(item["features"]) & {"test-utils", "embedded-fixture", "loopback-fixture"},
                "independent production compilation contains fixture capabilities")
    actual = unique(record["binaries"], "name", "independent binaries")
    require(set(actual) == package.BINARIES, "independent production executable set is incomplete")
    for name, artifact in actual.items():
        exact(artifact, {"name", "file"}, "independent binary")
        path = reference(root, artifact["file"])
        package.verify_architecture(path, target)
        require(artifact["file"]["sha256"] == binaries[name], "independent build binary hashes differ")


def verify_artifacts(root, manifest, source_files, candidates, binaries):
    artifacts = unique(manifest["artifacts"], "id", "deliverables")
    require(set(artifacts) == required_artifacts(), "release deliverables roster differs")
    for artifact in artifacts.values():
        exact(artifact, {"id", "file"}, "deliverable")
        require(reference(root, artifact["file"]).stat().st_size > 0, "empty deliverable")
    for target in PLATFORMS:
        contents = archive_inventory(reference(root, artifacts["package:" + target]["file"]))
        for name, digest in binaries[target].items():
            require(contents.get("bin/" + name, {}).get("sha256") == digest, "package binary differs from qualified candidate")
        for member in ("LICENSE", "NOTICE", "SECURITY.md", "CONTRIBUTING.md",
                       "systemd/kasumid.service", "systemd/kasumi-authority.service"):
            source_name = "release/" + member if member.startswith("systemd/") else member
            require(contents.get(member) == source_files.get(source_name), "package omitted or changed source deliverable: " + member)
        for kind, member in (("dependency-sbom", "sbom.spdx.json"), ("third-party-notices", "THIRD-PARTY-NOTICES.json")):
            require(contents.get(member, {}).get("sha256") == artifacts[kind + ":" + target]["file"]["sha256"],
                    "packaged SBOM/notices differ from delivered bytes")
        require("provenance.json" in contents, "package provenance missing")
        with tarfile.open(reference(root, artifacts["package:" + target]["file"]), "r:*") as archive:
            provenance = [member for member in archive if member.name.endswith("/provenance.json")]
            require(len(provenance) == 1 and provenance[0].size <= MAX_JSON_BYTES, "ambiguous package provenance")
            record = decode(archive.extractfile(provenance[0]).read())
            require(record.get("executables") == binaries[target] and record.get("target") == target
                    and record.get("functional_evidence_sha256") == candidates[target]["primary"]["functional"]["sha256"],
                    "package provenance is not bound to candidate")
    require(archive_inventory(reference(root, artifacts["source"]["file"])) == source_files,
            "delivered source archive differs from frozen source")
    checksums = reference(root, artifacts["checksums"]["file"]).read_text().splitlines()
    expected = {artifact["file"]["sha256"] + "  " + artifact["file"]["path"]
                for key, artifact in artifacts.items() if key != "checksums"}
    require(len(checksums) == len(expected) and set(checksums) == expected, "checksums are incomplete or duplicated")
    return artifacts


def verify_gate(root, gate, identity, files, configs, binaries, artifacts):
    exact(gate, {"id", "evidence"}, "acceptance gate")
    kind, target = gate["id"].split(":", 1)
    adapter = DOMAIN_ADAPTERS.get(kind)
    require(adapter is not None, "final-release domain evidence adapter is not implemented: " + kind)
    record = json_reference(root, gate["evidence"])
    exact(record, {"schema", "id", "status", "identity", "binaries", "configuration_ids", "runner",
                   "started_at", "finished_at", "host", "processes", "topology", "scenarios", "details", "artifacts"}, "domain gate")
    require(record["schema"] == SCHEMA and record["status"] == "passed" and record["id"] == gate["id"],
            "domain gate did not pass exact contract")
    require(record["identity"] == identity and record["binaries"] == binaries[target], "domain candidate/source identity mismatch")
    config_ids = record["configuration_ids"]
    require(isinstance(config_ids, list) and config_ids and all(isinstance(key, str) for key in config_ids)
            and len(config_ids) == len(set(config_ids)) and set(config_ids) <= set(configs), "domain configuration identities missing or duplicated")
    runner = record["runner"]
    exact(runner, {"source_path", "sha256"}, "domain runner")
    require(files.get(relative_path(runner["source_path"]), {}).get("sha256") == checksum(runner["sha256"]),
            "domain runner is not frozen source")
    # A future registered adapter must additionally bind its exact invocation
    # and independently validate semantic outcomes. This cannot be replaced by
    # checking that some arbitrary file happens to be in the source inventory.
    adapter(root, record, files, configs, artifacts)
    started, finished = timestamp(record["started_at"]), timestamp(record["finished_at"])
    elapsed = (finished - started).total_seconds()
    require(elapsed > 0, "domain gate elapsed time missing")
    check_host(root, record["host"], target, started, finished)
    longest = check_processes(root, record["processes"], elapsed)
    check_topology(record["topology"], record["processes"], binaries[target],
                   kind in {"ha-faults", "recovery", "capacity-ha", "ha-soak"})
    if kind not in {"correctness", "dependency-review", "repeatable-assembly"}:
        require(binaries[target]["kasumid"] in {process["executable"]["sha256"] for process in record["processes"]},
                "domain process inventory does not contain the qualified daemon")
    scenarios = unique(record["scenarios"], "id", "domain scenarios")
    require(set(scenarios) == SCENARIOS[kind], "domain scenario roster differs: " + kind)
    for scenario in scenarios.values():
        exact(scenario, {"id", "status", "iterations", "failures", "unattempted", "log"}, "scenario")
        require(scenario["status"] == "passed" and scenario["failures"] == 0 and scenario["unattempted"] == 0
                and type(scenario["failures"]) is int and type(scenario["unattempted"]) is int,
                "failed or unattempted domain scenario")
        uint(scenario["iterations"], "scenario iterations", 3 if scenario["id"] in
             {"archive-outage", "late-upload", "repeated-namespace-cleanup"} else 1)
        reference(root, scenario["log"])
    consumed = record["artifacts"]
    require(isinstance(consumed, dict) and all(key in artifacts and value == artifacts[key]["file"]["sha256"]
                                            for key, value in consumed.items()), "gate consumed a different artifact")
    expected_artifacts = {
        "package-smoke": {"package:" + target}, "oci-smoke": {"oci:" + target, "image-sbom:" + target},
        "systemd-smoke": {"systemd-data", "systemd-authority", "package:" + target},
        "repeatable-assembly": {"package:" + target, "source"},
    }.get(kind, set())
    require(set(consumed) == expected_artifacts, "gate artifact coverage is incomplete")
    details = record["details"]
    if kind == "benchmark-matrix":
        check_benchmarks(root, details)
    elif kind.startswith("capacity-"):
        check_capacity(root, details, kind)
    elif kind == "ha-soak":
        check_soak(root, details, elapsed)
        require(longest >= details["duration_seconds"], "soak has no process retained for full duration")
    elif kind == "concurrency":
        exact(details, {"workloads"}, "concurrent workloads")
        workloads = unique(details["workloads"], "name", "concurrent workloads")
        require(set(workloads) == SCENARIOS[kind], "concurrent workload roster differs")
        for work in workloads.values():
            exact(work, {"name", "workers", "peak_inflight", "measurement"}, "concurrent workload")
            workers = uint(work["workers"], "concurrent workers", 2)
            require(2 <= uint(work["peak_inflight"], "observed concurrent operations") <= workers,
                    "workload did not execute concurrently")
            require(work["measurement"].get("name") == work["name"], "concurrent sample binding differs")
            check_samples(root, work["measurement"], minimum=1000)
    elif kind == "repeatable-assembly":
        exact(details, {"second_package", "second_source"}, "repeated assembly")
        for field, artifact_id in (("second_package", "package:" + target), ("second_source", "source")):
            reference(root, details[field])
            require(details[field]["path"] != artifacts[artifact_id]["file"]["path"] and
                    details[field]["sha256"] == artifacts[artifact_id]["file"]["sha256"], "assembly was not independently repeated byte-for-byte")
    elif kind == "ha-faults":
        exact(details, {"lease_seconds", "outage_seconds", "report"}, "HA fault details")
        require(number(details["outage_seconds"], "lease outage", 1) >
                number(details["lease_seconds"], "lease lifetime", 1), "HA outage did not exceed actual lease")
        reference(root, details["report"])
    elif kind == "recovery":
        exact(details, {"source_voters", "available_source_voters", "activation_winners", "report"}, "recovery details")
        voters = uint(details["source_voters"], "source voters", 3)
        require(uint(details["available_source_voters"], "available source voters") < voters // 2 + 1,
                "recovery did not exercise absent source quorum")
        require(details["activation_winners"] == 1 and type(details["activation_winners"]) is int,
                "recovery has no unique activation winner")
        reference(root, details["report"])
    elif kind == "providers":
        exact(details, {"services", "report"}, "provider details")
        services = unique(details["services"], "id", "actual provider services")
        require(set(services) == {"openbao", "minio"}, "real OpenBao and MinIO are required")
        owned = unique(record["processes"], "id", "provider processes")
        for service in services.values():
            exact(service, {"id", "version", "executable", "process_id"}, "provider service")
            reference(root, service["executable"])
            require(service["version"] and service["process_id"] in owned and
                    owned[service["process_id"]]["executable"] == service["executable"],
                    "provider service executable/process identity is missing")
        reference(root, details["report"])
    elif kind == "audit-retention":
        exact(details, {"maximum_segment_bytes", "maintenance_start_percent", "maintenance_target_percent",
                        "lifetime_counts", "report"}, "audit retention details")
        require(uint(details["maximum_segment_bytes"], "encrypted archive segment", 1) <= 8 << 20
                and details["maintenance_start_percent"] == 75 and details["maintenance_target_percent"] == 50,
                "audit segment/maintenance contract differs")
        counts = unique(details["lifetime_counts"], "id", "permanent record lifetime counts")
        require(set(counts) == {"commands", "receipts", "incarnations", "lifecycle", "sessions"},
                "permanent history lifetime coverage is incomplete")
        for count in counts.values():
            exact(count, {"id", "former_limit", "observed", "log"}, "lifetime crossing")
            require(uint(count["observed"], "observed records", 1) > uint(count["former_limit"], "former ceiling", 1),
                    "former lifetime ceiling was not crossed")
            reference(root, count["log"])
        reference(root, details["report"])
    elif kind == "key-retention":
        exact(details, {"maximum_page_entries", "coverage_complete", "report"}, "key retention details")
        require(uint(details["maximum_page_entries"], "key retention page", 1) <= 256
                and details["coverage_complete"] is True, "authoritative key retention coverage is incomplete/unbounded")
        reference(root, details["report"])
    elif kind == "observability":
        exact(details, {"groups", "membership_epoch", "covered_epoch", "coverage_complete", "report"}, "observability details")
        uint(details["groups"], "readiness groups", 129)
        require(uint(details["membership_epoch"], "membership epoch", 1) == details["covered_epoch"]
                and type(details["covered_epoch"]) is int and details["coverage_complete"] is True,
                "readiness lacks complete current membership coverage")
        reference(root, details["report"])
    else:
        # Semantic scenario evaluators belong to frozen domain runners, not a
        # user-supplied list of waived checks. Retain their full machine report.
        exact(details, {"report"}, "domain details")
        reference(root, details["report"])


def verify_attempts(root, attempts, selected):
    indexed = unique(attempts, "id", "retained attempts")
    require(indexed, "attempt history is missing")
    paths = set()
    selected_paths = set()
    for name, attempt in indexed.items():
        exact(attempt, {"id", "receipt"}, "retained attempt")
        relative_path(name)
        require("/" not in name and attempt["receipt"]["path"] == "attempts/" + name + "/attempt.json",
                "attempt receipt is outside its permanent namespace")
        record = json_reference(root, attempt["receipt"])
        exact(record, {"schema", "id", "status", "evidence", "started_at", "finished_at", "processes"}, "attempt receipt")
        require(record["schema"] == SCHEMA and record["id"] == name and
                record["status"] in {"passed", "failed", "interrupted"}, "attempt has no retained terminal result")
        reference(root, record["evidence"])
        selected_paths.add(record["evidence"]["path"])
        elapsed = (timestamp(record["finished_at"]) - timestamp(record["started_at"])).total_seconds()
        check_processes(root, record["processes"], elapsed, passed=record["status"] == "passed")
        if record["evidence"]["path"] in selected:
            require(record["status"] == "passed", "selected attempt failed")
        paths.add(attempt["receipt"]["path"])
    actual = {path.relative_to(root).as_posix() for path in (root / "attempts").glob("*/attempt.json")}
    require(actual == paths and selected <= selected_paths, "attempt history omitted an on-disk or selected attempt")


def verify(manifest_path, repository):
    observations = {}
    token = OBSERVATIONS.set(observations)
    try:
        result = verify_inputs(manifest_path, repository)
        for root, _, ref in tuple(observations.values()):
            reference(root, ref)
        return result
    finally:
        OBSERVATIONS.reset(token)


def verify_inputs(manifest_path, repository):
    root = manifest_path.parent.resolve(strict=True)
    path = package.owned_file(root, manifest_path.name)
    with path.open("rb") as stream:
        data = stream.read(MAX_JSON_BYTES + 1)
    require(len(data) <= MAX_JSON_BYTES, "manifest exceeds work limit")
    manifest_digest = hashlib.sha256(data).hexdigest()
    reference(root, {"path": path.name, "sha256": manifest_digest, "bytes": len(data)})
    manifest = decode(data)
    exact(manifest, {"schema", "source", "candidates", "gates", "artifacts", "attempts"}, "acceptance manifest")
    require(manifest["schema"] == SCHEMA, "unsupported acceptance manifest schema")
    gates = unique(manifest["gates"], "id", "acceptance gates")
    require(set(gates) == required_gates(), "fixed complete release gate roster is required")
    identity, files, configs = verify_source(root, manifest, repository.resolve(strict=True))
    candidates, binaries = verify_candidates(root, manifest, identity)
    artifacts = verify_artifacts(root, manifest, files, candidates, binaries)
    for gate in gates.values():
        verify_gate(root, gate, identity, files, configs, binaries, artifacts)
    selected = {gate["evidence"]["path"] for gate in gates.values()}
    selected |= {candidate["primary"]["functional"]["path"] for candidate in candidates.values()}
    selected |= {candidate["independent"]["path"] for candidate in candidates.values()}
    verify_attempts(root, manifest["attempts"], selected)
    require(verify_source(root, manifest, repository.resolve(strict=True))[0] == identity,
            "frozen source changed during verification")
    return {"schema": SCHEMA, "status": "passed", "manifest_sha256": manifest_digest,
            "identity": identity, "domain_gates": len(gates),
            "native_functional_gates": len(PLATFORMS) * len(functional_gates(1, sys.executable))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.manifest.resolve(strict=True), args.repository), sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError, tarfile.TarError) as error:
        print("Release acceptance rejected: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
