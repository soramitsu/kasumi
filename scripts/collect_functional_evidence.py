#!/usr/bin/env python3
"""Read back one downloaded native functional tar under external identities.

This is a local evidence collector, not release acceptance. A success receipt
is published only after the existing exporter verifies and restores every byte.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

import export_functional_evidence as exporter
import package_release as package
from release_gate import TOOLCHAIN, sha256
import verify_release_acceptance as acceptance


SCHEMA = "kasumi-functional-evidence-collection-v1"
SHA1 = re.compile(r"[0-9a-f]{40}\Z")


def require(value, message):
    if not value:
        raise ValueError(message)


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_receipt(path, value):
    """Make the owned, canonical success marker the last durable write."""
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    require(len(data) <= acceptance.MAX_JSON_BYTES, "collector receipt exceeds JSON limit")
    pending = path.with_suffix(path.suffix + ".pending")
    with pending.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    pending.replace(path)
    sync_directory(path.parent)


def read_producer(path, expected_sha256):
    """Read one independently downloaded, digest-bound native producer record."""
    expected_sha256 = acceptance.checksum(expected_sha256)
    path = Path(path)
    require(path.is_absolute() and not path.is_symlink()
            and stat.S_ISREG(path.stat().st_mode),
            "producer record is not an owned absolute regular file")
    path = path.resolve(strict=True)
    with path.open("rb") as stream:
        data = stream.read(acceptance.MAX_JSON_BYTES + 1)
    require(len(data) <= acceptance.MAX_JSON_BYTES
            and hashlib.sha256(data).hexdigest() == expected_sha256,
            "producer record length or external digest differs")
    record = acceptance.decode(data)
    acceptance.exact(record, {"schema", "status", "target", "source", "run",
                              "transport", "exporter_sha256"}, "functional producer")
    require(record["schema"] == exporter.PRODUCER_SCHEMA and record["status"] == "passed"
            and record["target"] in package.TARGETS,
            "functional producer is not a passed native record")
    source = record["source"]
    acceptance.exact(source, {"commit", "tree", "archive_sha256", "files_sha256",
                              "lockfile_sha256"}, "functional producer source")
    require(isinstance(source["commit"], str) and SHA1.fullmatch(source["commit"])
            and isinstance(source["tree"], str) and SHA1.fullmatch(source["tree"]),
            "functional producer Git identity is malformed")
    for key in ("archive_sha256", "files_sha256", "lockfile_sha256"):
        acceptance.checksum(source[key])
    run = record["run"]
    acceptance.exact(run, {"evidence_sha256", "started_at", "finished_at"},
                     "functional producer run")
    acceptance.checksum(run["evidence_sha256"])
    require(acceptance.timestamp(run["finished_at"]) > acceptance.timestamp(run["started_at"]),
            "functional producer has no positive UTC interval")
    transport = record["transport"]
    acceptance.exact(transport, {"archive_name", "archive_sha256", "archive_bytes",
                                 "manifest_sha256", "max_bytes", "file_count", "total_bytes"},
                     "functional producer transport")
    require(isinstance(transport["archive_name"], str)
            and acceptance.relative_path(transport["archive_name"]) == transport["archive_name"]
            and "/" not in transport["archive_name"],
            "functional producer archive name is malformed")
    acceptance.checksum(transport["archive_sha256"])
    acceptance.checksum(transport["manifest_sha256"])
    acceptance.uint(transport["archive_bytes"], "producer archive length", 1)
    acceptance.uint(transport["max_bytes"], "producer byte cap", 1)
    acceptance.uint(transport["file_count"], "producer file count", 1)
    acceptance.uint(transport["total_bytes"], "producer payload length", 1)
    require(transport["archive_bytes"] <= transport["max_bytes"]
            and transport["total_bytes"] <= transport["max_bytes"],
            "functional producer exceeds its declared byte cap")
    require(acceptance.checksum(record["exporter_sha256"]) == sha256(exporter.__file__),
            "collector exporter differs from frozen native producer")
    require((json.dumps(record, indent=2, sort_keys=True) + "\n").encode() == data,
            "functional producer record is not canonical")
    return path, data, record


def collect(archive, producer_manifest, producer_sha256, max_bytes, output):
    """Verify one complete tar against a separately retained native producer."""
    require(type(max_bytes) is int and 0 < max_bytes <= (1 << 64) - 1,
            "an explicit positive collector byte cap is required")
    producer_path, producer_data, producer = read_producer(producer_manifest, producer_sha256)
    transport = producer["transport"]
    source = producer["source"]
    run = producer["run"]
    effective_max_bytes = min(max_bytes, transport["max_bytes"])
    archive = Path(archive)
    output = Path(output)
    require(archive.is_absolute() and output.is_absolute(), "collector paths must be absolute")
    require(not archive.is_symlink() and stat.S_ISREG(archive.stat().st_mode),
            "downloaded archive is not an owned regular file")
    archive = archive.resolve(strict=True)
    output = output.resolve()
    require(archive != producer_path and archive.name == transport["archive_name"]
            and archive.stat().st_size == transport["archive_bytes"],
            "downloaded tar differs from producer record")
    require(not output.exists() and not archive.is_relative_to(output)
            and not output.is_relative_to(archive)
            and not producer_path.is_relative_to(output)
            and not output.is_relative_to(producer_path),
            "collector output must be fresh and separate")
    require(output.parent.is_dir(), "collector output parent is absent")
    output.mkdir(mode=0o700)
    output.chmod(0o700)
    sync_directory(output.parent)
    readback = output / "readback"
    manifest = exporter.check_transport(archive, transport["archive_sha256"],
                                        transport["manifest_sha256"], effective_max_bytes, readback)
    require(exporter.verify(readback, transport["manifest_sha256"]) == manifest,
            "collector readback differs from transported manifest")
    require(manifest["target"] == producer["target"]
            and manifest["source_evidence_sha256"] == run["evidence_sha256"]
            and manifest["max_bytes"] == transport["max_bytes"]
            and manifest["file_count"] == transport["file_count"]
            and manifest["total_bytes"] == transport["total_bytes"],
            "functional target or run identity differs")
    evidence_path = package.owned_file(readback / "run", "evidence.json")
    require(sha256(evidence_path) == run["evidence_sha256"], "functional run identity differs")
    record = acceptance.read_json(evidence_path)
    require(isinstance(record, dict) and record.get("schema") == 1
            and record.get("status") == "passed" and record.get("toolchain") == TOOLCHAIN
            and record.get("source_commit") == source["commit"]
            and record.get("source_tree") == source["tree"]
            and record.get("source_archive_sha256") == source["archive_sha256"]
            and record.get("source_files_sha256") == source["files_sha256"]
            and record.get("lockfile_sha256") == source["lockfile_sha256"]
            and record.get("started_at") == run["started_at"]
            and record.get("finished_at") == run["finished_at"],
            "functional source identity differs")
    require(acceptance.timestamp(record.get("finished_at"))
            > acceptance.timestamp(record.get("started_at")),
            "functional run has no positive UTC interval")
    require(sha256(archive) == transport["archive_sha256"]
            and sha256(producer_path) == producer_sha256
            and exporter.verify(readback, transport["manifest_sha256"]) == manifest,
            "downloaded archive, producer or readback changed before collection")
    require({path.name for path in output.iterdir()} == {"readback"},
            "collector output contains an unexpected entry")
    producer_copy = output / "producer.json"
    with producer_copy.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(producer_data)
        stream.flush()
        os.fsync(stream.fileno())
    require(sha256(producer_copy) == producer_sha256,
            "owned producer record differs from external digest")
    sync_directory(output)
    receipt = {"schema": SCHEMA, "status": "passed",
               "archive": {"path": str(archive), "sha256": transport["archive_sha256"],
                           "bytes": archive.stat().st_size},
               "producer": {"path": "producer.json", "sha256": producer_sha256,
                            "bytes": len(producer_data)},
               "manifest": {"path": "readback/manifest.json",
                            "sha256": transport["manifest_sha256"]},
               "readback": "readback/run", "target": producer["target"],
               "source": source,
               "run": run,
               "file_count": manifest["file_count"],
               "total_bytes": manifest["total_bytes"], "max_bytes": effective_max_bytes,
               "collector_sha256": sha256(__file__),
               "exporter_sha256": sha256(exporter.__file__)}
    receipt_path = output / "receipt.json"
    try:
        publish_receipt(receipt_path, receipt)
        require(acceptance.read_json(receipt_path) == receipt,
                "collector success receipt changed during publication")
    except BaseException:
        receipt_path.unlink(missing_ok=True)
        receipt_path.with_suffix(receipt_path.suffix + ".pending").unlink(missing_ok=True)
        sync_directory(output)
        raise
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--producer-manifest", required=True, type=Path)
    parser.add_argument("--producer-sha256", required=True)
    parser.add_argument("--max-bytes", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        receipt = collect(args.archive, args.producer_manifest, args.producer_sha256,
                          args.max_bytes, args.output)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("functional collection failed: " + str(error), file=sys.stderr)
        return 1
    print("functional collection receipt: " + sha256(Path(args.output) / "receipt.json"))
    print("target: " + receipt["target"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
