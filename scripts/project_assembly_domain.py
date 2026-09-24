#!/usr/bin/env python3
"""Project checked assembly facts without publishing release acceptance.

This post-download rendezvous collects raw assembly transport bytes, joins them to
one caller-selected primary, and retains explicit host/attempt claims. Its
receipt is permanently *unqualified*: it does not authenticate those claims,
prove complete attempt history, or satisfy a final domain gate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tarfile

import package_release as package
import repeatable_assembly as assembly
from release_gate import sha256
import run_repeatable_assembly_owned as owned
import transport_assembly_evidence as transport
import verify_release_acceptance as acceptance

SCHEMA = "kasumi-repeatable-assembly-domain-projection-v1"
RESERVATION_SCHEMA = "kasumi-assembly-reservation-claim-v1"
ATTEMPT_SCHEMA = "kasumi-assembly-attempt-claim-v1"
SOURCE_PATH = "scripts/project_assembly_domain.py"
ATTEMPT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
MAX_CLAIM_BYTES = acceptance.MAX_JSON_BYTES


def require(value, message):
    if not value:
        raise ValueError(message)


def bounded_file(path, label):
    path = transport.rooted(path, file=True)
    require(0 < path.stat().st_size <= MAX_CLAIM_BYTES, label + " is empty or exceeds byte limit")
    return path


def read_reservation(path, attempt_id):
    path = bounded_file(path, "reservation claim")
    data = path.read_bytes()
    value = acceptance.decode(data)
    acceptance.exact(value, {"schema", "attempt_id", "host_id", "target", "starts_at",
                             "ends_at", "cpu_count", "memory_bytes", "disk_bytes"},
                     "assembly reservation claim")
    require(value["schema"] == RESERVATION_SCHEMA and value["attempt_id"] == attempt_id
            and isinstance(value["host_id"], str) and value["host_id"],
            "reservation does not identify this claimed attempt and host")
    require(value["target"] in package.TARGETS,
            "reservation does not identify a supported target")
    require(acceptance.timestamp(value["ends_at"]) > acceptance.timestamp(value["starts_at"]),
            "reservation interval is empty")
    acceptance.uint(value["cpu_count"], "claimed reserved CPUs", 1)
    acceptance.uint(value["memory_bytes"], "claimed reserved memory", 15 << 30)
    acceptance.uint(value["disk_bytes"], "claimed reserved disk", 64 << 30)
    require(transport.canonical(value) == data, "reservation claim is not canonical")
    return path, data, value


def read_attempt_claim(path, attempt_id):
    path = bounded_file(path, "attempt registry claim")
    data = path.read_bytes()
    value = acceptance.decode(data)
    acceptance.exact(value, {"schema", "attempt_id", "registry_id", "sequence",
                             "previous_sha256", "issued_at", "target", "source_commit"},
                     "attempt registry claim")
    require(value["schema"] == ATTEMPT_SCHEMA and value["attempt_id"] == attempt_id
            and isinstance(value["registry_id"], str) and value["registry_id"],
            "attempt registry claim does not identify this attempt")
    acceptance.uint(value["sequence"], "claimed attempt sequence", 1)
    acceptance.checksum(value["previous_sha256"])
    acceptance.timestamp(value["issued_at"])
    require(value["target"] in package.TARGETS
            and isinstance(value["source_commit"], str)
            and re.fullmatch(r"[0-9a-f]{40}", value["source_commit"]),
            "attempt registry claim target or source is malformed")
    require(transport.canonical(value) == data,
            "attempt registry claim is not canonical")
    return path, data, value


def copy_claim(source, destination, expected_sha256):
    data = bounded_file(source, "claimed file").read_bytes()
    require(hashlib.sha256(data).hexdigest() == expected_sha256,
            "claim changed before retention")
    with destination.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    require(sha256(destination) == expected_sha256,
            "retained claim differs from original bytes")
    transport.functional_transport.sync_directory(destination.parent)
    return {"path": "claims/" + destination.name,
            "sha256": expected_sha256, "bytes": len(data)}


def project(archive, producer, producer_sha256, max_bytes, selected_primary,
            host_attestation, reservation, attempt_id, attempt_record, output):
    """Only publish a non-acceptance projection after independent raw readback."""
    require(isinstance(attempt_id, str) and ATTEMPT_ID.fullmatch(attempt_id),
            "attempt claim identifier is malformed")
    transport.cap(max_bytes)
    archive = transport.rooted(archive, file=True)
    producer = transport.rooted(producer, file=True)
    selected = bounded_file(selected_primary, "selected primary receipt")
    attestation = bounded_file(host_attestation, "host attestation claim")
    reservation, reservation_data, reservation_claim = read_reservation(reservation, attempt_id)
    attempt_record, attempt_data, attempt_claim = read_attempt_claim(attempt_record, attempt_id)
    require(len({archive, producer, selected, attestation, reservation, attempt_record}) == 6,
            "projection inputs are aliased")
    require(selected.name == "evidence.json" and selected.parent.is_dir(),
            "selected primary is not an original functional receipt")
    output = transport.fresh(output, (archive, producer, selected.parent, attestation,
                                      reservation, attempt_record))
    selected_sha = sha256(selected)
    attestation_sha = sha256(attestation)
    reservation_sha = hashlib.sha256(reservation_data).hexdigest()
    attempt_sha = hashlib.sha256(attempt_data).hexdigest()
    selected_record = acceptance.read_json(selected)
    verified_record, _, selected_target, _ = package.verify_evidence(selected.parent)
    require(selected_record == verified_record and selected_record.get("status") == "passed",
            "selected primary functional evidence did not verify")
    output.mkdir(mode=0o700)
    output.chmod(0o700)
    transport.functional_transport.sync_directory(output.parent)
    collected = transport.collect(archive, producer, producer_sha256,
                                  max_bytes, output / "collection")
    require(collected["schema"] == transport.COLLECTOR_SCHEMA
            and collected["status"] == "passed", "assembly collection is not passing transport")
    identity = collected["identity"]
    require(identity["target"] == selected_target == reservation_claim["target"]
            == attempt_claim["target"]
            and identity["functional_sha256"] == selected_sha
            and identity["source_commit"] == verified_record["source_commit"]
            == attempt_claim["source_commit"]
            and identity["source_tree"] == verified_record["source_tree"],
            "assembly, selected primary and reservation claim target/source differ")
    original = output / "collection" / "assembly"
    launcher = original / "launcher.json"
    verified = owned.verify(original, assembly.ref(original, launcher))
    record = verified["record"]
    inner = verified["inner"]
    inner_root = original / "assembly"
    source_files = assembly.read(assembly.check_ref(
        inner_root, inner["frozen"]["source-files.json"]["file"]))
    require(source_files.get(SOURCE_PATH, {}).get("sha256") == sha256(__file__),
            "projection implementation differs from frozen original source")
    require(identity["launcher_sha256"] == sha256(launcher)
            and acceptance.timestamp(reservation_claim["starts_at"])
            <= acceptance.timestamp(record["started_at"])
            and acceptance.timestamp(reservation_claim["ends_at"])
            >= acceptance.timestamp(record["finished_at"])
            and acceptance.timestamp(attempt_claim["issued_at"])
            <= acceptance.timestamp(record["started_at"]),
            "launcher identity or claimed reservation interval differs")
    archives = {}
    for name in inner["archives"]:
        first = inner_root / "assembly-a-output" / name
        second = inner_root / "assembly-b-output" / name
        require(sha256(first) == sha256(second), "repeated archive bytes differ")
        archives[name] = {"first_sha256": sha256(first), "second_sha256": sha256(second),
                          "first_bytes": first.stat().st_size, "second_bytes": second.stat().st_size}
    require(len(archives) == 2, "assembly did not yield its exact two archive kinds")
    claims = output / "claims"
    claims.mkdir(mode=0o700)
    claim_files = {
        "selected_primary": copy_claim(selected, claims / "selected-primary.json", selected_sha),
        "host_attestation": copy_claim(attestation, claims / "host-attestation", attestation_sha),
        "reservation": copy_claim(reservation, claims / "reservation.json", reservation_sha),
        "attempt_record": copy_claim(attempt_record, claims / "attempt-record.json", attempt_sha),
    }
    require(sha256(selected) == selected_sha and sha256(attestation) == attestation_sha
            and sha256(reservation) == reservation_sha
            and sha256(attempt_record) == attempt_sha
            and sha256(archive) == collected["archive"]["sha256"]
            and sha256(producer) == acceptance.checksum(producer_sha256),
            "projection inputs changed before publication")
    receipt_path = output / "collection" / "receipt.json"
    manifest_path = output / "collection" / "manifest.json"
    manifest = acceptance.read_json(manifest_path)
    observed = transport.census(original, max_bytes)
    require(acceptance.read_json(receipt_path) == collected
            and sha256(manifest_path) == collected["manifest_sha256"]
            and all(observed[key] == manifest[key] for key in
                    ("root_mode", "directories", "files", "file_count",
                     "directory_count", "total_bytes")),
            "collected assembly changed before projection publication")
    projection = {
        "schema": SCHEMA, "status": "unqualified",
        "derived": {
            "target": identity["target"], "source_commit": identity["source_commit"],
            "source_tree": identity["source_tree"], "functional_sha256": selected_sha,
            "launcher_sha256": identity["launcher_sha256"],
            "report_sha256": sha256(inner_root / "attempt.json"),
            "started_at": record["started_at"], "finished_at": record["finished_at"],
            "archives": archives, "projection_source_sha256": sha256(__file__),
            "collector_receipt_sha256": sha256(receipt_path),
            "supplied_producer_sha256": acceptance.checksum(producer_sha256),
            "raw_archive_sha256": collected["archive"]["sha256"],
        },
        "unverified_claims": {
            "attempt_id": attempt_id, "host_id": reservation_claim["host_id"],
            "reservation": reservation_claim, "attempt_record": attempt_claim,
            "files": claim_files,
            "authenticated_host": False, "durable_attempt_completeness": False,
            "selected_by_final_manifest": False,
        },
    }
    transport.publish(output / "projection.json", projection)
    return projection


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--producer-manifest", required=True, type=Path)
    parser.add_argument("--producer-sha256", required=True)
    parser.add_argument("--max-bytes", required=True, type=int)
    parser.add_argument("--selected-primary", required=True, type=Path)
    parser.add_argument("--host-attestation", required=True, type=Path)
    parser.add_argument("--reservation", required=True, type=Path)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--attempt-record", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = project(args.archive, args.producer_manifest, args.producer_sha256,
                         args.max_bytes, args.selected_primary, args.host_attestation,
                         args.reservation, args.attempt_id, args.attempt_record, args.output)
        print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        print("assembly domain projection rejected: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
