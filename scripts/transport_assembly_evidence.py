#!/usr/bin/env python3
"""Transport original owned assemblies without declaring release acceptance.

Passing transport requires the successful launcher and frozen functional run.
Failure transport records an unresolved original directory under the expected
workflow context. Downloaded readback requires an external producer digest.
No transport receipt supplies host attestation, a domain result, an
independent build, or a final acceptance manifest.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import tempfile

import export_functional_evidence as functional_transport
import package_release as package
from release_gate import sha256
import repeatable_assembly as assembly
import run_repeatable_assembly_owned as owned
import verify_release_acceptance as acceptance

SCHEMA = "kasumi-assembly-transport-v1"
PRODUCER_SCHEMA = "kasumi-assembly-producer-v1"
COLLECTOR_SCHEMA = "kasumi-assembly-collection-v1"
NATIVE_SCHEMA = "kasumi-assembly-native-transport-v1"
FAILURE_SCHEMA = "kasumi-assembly-failure-transport-v1"
FAILURE_PRODUCER_SCHEMA = "kasumi-assembly-failure-producer-v1"
FAILURE_COLLECTOR_SCHEMA = "kasumi-assembly-failure-collection-v1"
SCRIPT = "scripts/transport_assembly_evidence.py"
MAX_FILES = 200_000
MAX_DIRECTORIES = 200_000
MAX_PATH_BYTES = 4096
CHUNK = 1 << 20


def require(value, message):
    if not value:
        raise ValueError(message)


def cap(value):
    return acceptance.uint(value, "assembly transport byte cap", 1)


def canonical(value):
    data = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
    require(len(data) <= acceptance.MAX_JSON_BYTES, "assembly JSON exceeds work limit")
    return data


def rooted(path, *, file=False):
    path = Path(path)
    require(path.is_absolute() and not path.is_symlink(), "assembly path is not absolute and owned")
    resolved = path.resolve(strict=True)
    require(resolved == path, "assembly path contains a symlink")
    mode = path.stat().st_mode
    require(stat.S_ISREG(mode) if file else stat.S_ISDIR(mode), "assembly path has the wrong type")
    return path


def fresh(path, protected=()):
    path = Path(path)
    require(path.is_absolute() and not path.exists() and path.parent.is_dir()
            and not path.parent.is_symlink() and path.parent.resolve(strict=True) == path.parent,
            "assembly output must be a fresh absolute path")
    require(all(not path.is_relative_to(item) and not item.is_relative_to(path)
                for item in protected), "assembly output overlaps an input")
    return path


def checked_mode(path, directory):
    status = path.lstat()
    require(stat.S_ISDIR(status.st_mode) if directory else stat.S_ISREG(status.st_mode),
            "assembly contains a symlink or special file")
    mode = stat.S_IMODE(status.st_mode)
    allowed = (mode & 0o700) == 0o700 if directory else mode & 0o400 != 0
    require(mode & ~0o777 == 0 and allowed,
            "assembly file or directory mode is unsupported")
    return mode, status.st_size


def census(root, max_bytes, *, require_receipts=True):
    """Inventory every regular file and directory under explicit work bounds."""
    root = rooted(root)
    cap(max_bytes)
    root_mode, _ = checked_mode(root, True)
    files, directories = {}, {}
    total = 0
    stack = [root]
    while stack:
        directory = stack.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                relative = path.relative_to(root).as_posix()
                acceptance.relative_path(relative)
                require(len(relative.encode()) <= MAX_PATH_BYTES
                        and len(path.relative_to(root).parts) <= 64,
                        "assembly path exceeds work limit")
                status = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(status.st_mode):
                    mode, _ = checked_mode(path, True)
                    directories[relative] = mode
                    require(len(directories) <= MAX_DIRECTORIES,
                            "assembly directory count exceeds work limit")
                    stack.append(path)
                elif stat.S_ISREG(status.st_mode):
                    mode, length = checked_mode(path, False)
                    total += length
                    require(len(files) < MAX_FILES and total <= max_bytes,
                            "assembly file count or payload exceeds byte cap")
                    files[relative] = {"sha256": sha256(path), "bytes": length, "mode": mode}
                else:
                    raise ValueError("assembly contains a symlink or special file")
    if require_receipts:
        require(files and "launcher.json" in files and "assembly/attempt.json" in files,
                "assembly is missing its original receipts")
    return {"root_mode": root_mode, "directories": dict(sorted(directories.items())),
            "files": dict(sorted(files.items())), "file_count": len(files),
            "directory_count": len(directories), "total_bytes": total}


def assembly_identity(root, evidence=None):
    """Derive source/target/run identity from the actual semantic verifier."""
    root = rooted(root)
    launcher = package.owned_file(root, "launcher.json")
    verified = owned.verify(root, assembly.ref(root, launcher))
    parsed = verified["inner"]
    inner = root / "assembly"
    frozen = parsed["frozen"]
    original = assembly.check_ref(inner, frozen["evidence.json"]["file"])
    functional = acceptance.read_json(original)
    source_files = assembly.read(assembly.check_ref(inner, frozen["source-files.json"]["file"]))
    require(source_files.get(SCRIPT, {}).get("sha256") == sha256(__file__)
            and source_files.get("scripts/export_functional_evidence.py", {}).get("sha256")
            == sha256(functional_transport.__file__),
            "assembly transport is not the original frozen source")
    if evidence is not None:
        evidence = rooted(evidence)
        require(sha256(package.owned_file(evidence, "evidence.json")) == sha256(original),
                "assembly consumed another original functional run")
    return {"target": parsed["inputs"]["target"],
            "source_commit": functional["source_commit"],
            "source_tree": functional["source_tree"],
            "functional_sha256": sha256(original),
            "launcher_sha256": sha256(launcher)}


def validate_identity(identity):
    acceptance.exact(identity, {"target", "source_commit", "source_tree",
                                "functional_sha256", "launcher_sha256"}, "assembly identity")
    require(identity["target"] in package.TARGETS
            and all(isinstance(identity[key], str)
                    and re.fullmatch(r"[0-9a-f]{40}", identity[key])
                    for key in ("source_commit", "source_tree")),
            "assembly target or Git identity is malformed")
    acceptance.checksum(identity["functional_sha256"])
    acceptance.checksum(identity["launcher_sha256"])
    return identity


def validate_failure_identity(identity):
    acceptance.exact(identity, {"target", "source_commit", "source_tree"},
                     "failed assembly attempt identity")
    require(identity["target"] in package.TARGETS
            and all(isinstance(identity[key], str)
                    and re.fullmatch(r"[0-9a-f]{40}", identity[key])
                    for key in ("source_commit", "source_tree")),
            "failed assembly attempt source or target is malformed")
    return identity


def validate_manifest(data, expected_sha256):
    require(len(data) <= acceptance.MAX_JSON_BYTES
            and hashlib.sha256(data).hexdigest() == acceptance.checksum(expected_sha256),
            "assembly transport manifest digest differs")
    manifest = acceptance.decode(data)
    acceptance.exact(manifest, {"schema", "status", "identity", "root_mode", "directories",
                                "files", "file_count", "directory_count", "total_bytes", "max_bytes"},
                     "assembly transport manifest")
    success = manifest["schema"] == SCHEMA and manifest["status"] == "passed"
    failure = (manifest["schema"] == FAILURE_SCHEMA
               and manifest["status"] in {"failed", "interrupted"})
    require(success or failure, "assembly transport manifest has no typed disposition")
    if success:
        validate_identity(manifest["identity"])
    else:
        validate_failure_identity(manifest["identity"])
    cap(manifest["max_bytes"])
    require(type(manifest["root_mode"]) is int and 0o700 <= manifest["root_mode"] <= 0o777,
            "assembly root mode is unsupported")
    files, directories = manifest["files"], manifest["directories"]
    require(isinstance(files, dict) and (files or failure) and isinstance(directories, dict)
            and len(files) <= MAX_FILES and len(directories) <= MAX_DIRECTORIES
            and not set(files) & set(directories),
            "assembly file or directory roster is malformed")
    total = 0
    for relative, mode in directories.items():
        acceptance.relative_path(relative)
        require(len(relative.encode()) <= MAX_PATH_BYTES
                and len(Path(relative).parts) <= 64 and type(mode) is int
                and mode & ~0o777 == 0 and mode & 0o700 == 0o700,
                "assembly directory identity is malformed")
    for relative, item in files.items():
        acceptance.relative_path(relative)
        acceptance.exact(item, {"sha256", "bytes", "mode"}, "assembly file")
        require(len(relative.encode()) <= MAX_PATH_BYTES
                and len(Path(relative).parts) <= 64
                and type(item["mode"]) is int and item["mode"] & ~0o777 == 0
                and item["mode"] & 0o400 != 0,
                "assembly file mode is malformed")
        acceptance.checksum(item["sha256"])
        total += acceptance.uint(item["bytes"], "assembly file length")
        require(total <= manifest["max_bytes"], "assembly payload exceeds byte cap")
        for parent in Path(relative).parents:
            if str(parent) == ".":
                break
            require(parent.as_posix() in directories, "assembly file parent is absent")
    for relative in directories:
        for parent in Path(relative).parents:
            if str(parent) == ".":
                break
            require(parent.as_posix() in directories, "assembly directory parent is absent")
    require((failure or ("launcher.json" in files and "assembly/attempt.json" in files
                         and "assembly" in directories))
            and type(manifest["file_count"]) is int and manifest["file_count"] == len(files)
            and type(manifest["directory_count"]) is int
            and manifest["directory_count"] == len(directories)
            and type(manifest["total_bytes"]) is int and manifest["total_bytes"] == total
            and total + len(data) <= manifest["max_bytes"],
            "assembly transport coverage or byte accounting differs")
    require(canonical(manifest) == data, "assembly transport manifest is not canonical")
    return manifest


def archive_write(root, manifest_data, archive_path, max_bytes):
    """Write one deterministic raw PAX tar, leaving no success marker on error."""
    root = rooted(root)
    archive_path = fresh(archive_path, (root,))
    descriptor, temporary = tempfile.mkstemp(prefix=".assembly-transport-", suffix=".pending",
                                            dir=archive_path.parent)
    try:
        with os.fdopen(descriptor, "wb") as raw:
            os.fchmod(raw.fileno(), 0o600)
            writer = functional_transport.LimitedWriter(raw, max_bytes)
            with tarfile.open(fileobj=writer, mode="w|", format=tarfile.PAX_FORMAT) as output:
                info = tarfile.TarInfo("manifest.json")
                info.size, info.mode = len(manifest_data), 0o600
                info.uid = info.gid = info.mtime = 0
                output.addfile(info, io.BytesIO(manifest_data))
                manifest = acceptance.decode(manifest_data)
                directory_members = [("assembly/", manifest["root_mode"])]
                directory_members.extend(("assembly/" + relative + "/", mode)
                                         for relative, mode in manifest["directories"].items())
                for name, mode in directory_members:
                    directory = tarfile.TarInfo(name)
                    directory.type = tarfile.DIRTYPE
                    directory.mode = mode
                    directory.uid = directory.gid = directory.mtime = 0
                    output.addfile(directory)
                for relative, identity in manifest["files"].items():
                    path = package.owned_file(root, relative)
                    with path.open("rb") as source:
                        output.addfile(functional_transport.archive_member(
                            "assembly/" + relative, path, identity["mode"]), source)
            raw.flush()
            os.fsync(raw.fileno())
        digest = sha256(temporary)
        check_archive(Path(temporary).absolute(), digest,
                      hashlib.sha256(manifest_data).hexdigest(), max_bytes)
        os.link(temporary, archive_path)
        functional_transport.sync_directory(archive_path.parent)
        return digest
    finally:
        Path(temporary).unlink(missing_ok=True)
        functional_transport.sync_directory(archive_path.parent)


def check_directory_member(member, name, mode):
    acceptance.relative_path(name[:-1])
    pax = member.pax_headers
    needs_path_pax = len(name) > tarfile.LENGTH_NAME or not name.isascii()
    require(isinstance(pax, dict) and set(pax) <= {"path"}
            and ("path" in pax) == needs_path_pax
            and ("path" not in pax or pax["path"] == name),
            "unexpected assembly directory PAX metadata")
    # Python's tar reader canonicalizes directory names by dropping '/'.
    require(member.name == name[:-1] and member.type == tarfile.DIRTYPE
            and not getattr(member, "sparse", None) and not member.linkname
            and member.size == 0 and member.mode == mode
            and member.uid == 0 and member.gid == 0 and member.mtime == 0
            and member.uname == "" and member.gname == "",
            "unsafe or mismatched assembly directory member")


def check_archive(archive_path, archive_sha256, manifest_sha256, max_bytes, output=None):
    """Strictly read one raw tar; optional restoration is into a fresh root."""
    cap(max_bytes)
    archive_path = rooted(archive_path, file=True)
    require(archive_path.stat().st_size <= max_bytes
            and sha256(archive_path) == acceptance.checksum(archive_sha256),
            "assembly archive exceeds cap or differs from native digest")
    restored = fresh(output, (archive_path,)) if output is not None else None
    with tarfile.open(archive_path, "r:") as source:
        entries = iter(source)
        first = next(entries, None)
        require(first is not None and first.name == "manifest.json"
                and first.size <= acceptance.MAX_JSON_BYTES,
                "assembly archive lacks a bounded first manifest")
        functional_transport.check_transport_member(first, "manifest.json", first.size, 0o600)
        with source.extractfile(first) as stream:
            data = stream.read(acceptance.MAX_JSON_BYTES + 1)
        manifest = validate_manifest(data, manifest_sha256)
        require(manifest["max_bytes"] >= archive_path.stat().st_size,
                "assembly archive exceeds its native cap")
        if restored is not None:
            restored.mkdir(mode=0o700)
            restored.chmod(0o700)
            for relative in sorted(manifest["directories"], key=lambda name: (len(Path(name).parts), name)):
                directory = restored / relative
                directory.mkdir(mode=0o700)
                directory.chmod(0o700)
        expected_directories = [("assembly/", manifest["root_mode"])]
        expected_directories.extend(("assembly/" + relative + "/", mode)
                                    for relative, mode in manifest["directories"].items())
        last = first
        for name, mode in expected_directories:
            member = next(entries, None)
            require(member is not None, "assembly archive omitted a directory")
            check_directory_member(member, name, mode)
            last = member
        expected = list(manifest["files"].items())
        count = 0
        for member in entries:
            require(count < len(expected), "assembly archive has an extra member")
            relative, identity = expected[count]
            functional_transport.check_transport_member(
                member, "assembly/" + relative, identity["bytes"], identity["mode"])
            digest = hashlib.sha256()
            length = 0
            with source.extractfile(member) as original:
                if restored is None:
                    while block := original.read(CHUNK):
                        length += len(block)
                        require(length <= identity["bytes"], "assembly file exceeds recorded length")
                        digest.update(block)
                else:
                    path = restored / relative
                    with path.open("xb") as copied:
                        while block := original.read(CHUNK):
                            length += len(block)
                            require(length <= identity["bytes"], "assembly file exceeds recorded length")
                            digest.update(block)
                            copied.write(block)
                        os.fchmod(copied.fileno(), identity["mode"])
                        copied.flush()
                        os.fsync(copied.fileno())
            require(length == identity["bytes"] and digest.hexdigest() == identity["sha256"],
                    "assembly file bytes differ from native manifest")
            count += 1
            last = member
        require(count == len(expected), "assembly archive omitted a file")
        end = last.offset_data + ((last.size + 511) // 512) * 512
    expected_size = ((end + 1024 + 10239) // 10240) * 10240
    require(archive_path.stat().st_size == expected_size, "assembly tar trailer is noncanonical")
    with archive_path.open("rb") as stream:
        stream.seek(end)
        while block := stream.read(CHUNK):
            require(not any(block), "assembly tar trailer contains data")
    require(sha256(archive_path) == archive_sha256,
            "assembly archive changed during readback")
    if restored is not None:
        for relative, mode in sorted(manifest["directories"].items(),
                                     key=lambda item: (-len(Path(item[0]).parts), item[0])):
            (restored / relative).chmod(mode)
            functional_transport.sync_directory(restored / relative)
        restored.chmod(manifest["root_mode"])
        functional_transport.sync_directory(restored)
        observed = census(restored, max_bytes, require_receipts=manifest["schema"] == SCHEMA)
        require(all(observed[key] == manifest[key] for key in
                    ("root_mode", "directories", "files", "file_count", "directory_count", "total_bytes")),
                "assembly readback differs from native inventory")
    return manifest


def publish(path, value):
    path = fresh(path)
    data = canonical(value)
    pending = path.with_suffix(path.suffix + ".pending")
    linked = False
    try:
        with pending.open("xb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(pending, path)
        linked = True
        functional_transport.sync_directory(path.parent)
        require(path.read_bytes() == data, "assembly record changed during publication")
        return hashlib.sha256(data).hexdigest()
    except BaseException:
        if linked:
            path.unlink(missing_ok=True)
        raise
    finally:
        pending.unlink(missing_ok=True)
        functional_transport.sync_directory(path.parent)


def produce(root, evidence, archive, producer, receipt, max_bytes,
            expected_target, expected_commit, expected_tree):
    """Native side: publish transport only after actual owned verification."""
    root, evidence = rooted(root), rooted(evidence)
    cap(max_bytes)
    archive = fresh(archive, (root, evidence))
    producer = fresh(producer, (root, evidence, archive))
    receipt = fresh(receipt, (root, evidence, archive, producer))
    identity = validate_identity(assembly_identity(root, evidence))
    require(identity["target"] == expected_target
            and identity["source_commit"] == expected_commit
            and identity["source_tree"] == expected_tree,
            "assembly differs from expected native source or target")
    observed = census(root, max_bytes)
    manifest = {"schema": SCHEMA, "status": "passed", "identity": identity,
                **observed, "max_bytes": max_bytes}
    data = canonical(manifest)
    manifest_sha = hashlib.sha256(data).hexdigest()
    validate_manifest(data, manifest_sha)
    archive_sha = archive_write(root, data, archive, max_bytes)
    require(census(root, max_bytes) == observed
            and assembly_identity(root, evidence) == identity,
            "original assembly changed during native transport")
    producer_record = {"schema": PRODUCER_SCHEMA, "status": "passed",
                       "identity": identity, "script_sha256": sha256(__file__),
                       "transport": {"archive_name": archive.name, "archive_sha256": archive_sha,
                                     "archive_bytes": archive.stat().st_size,
                                     "manifest_sha256": manifest_sha,
                                     "max_bytes": max_bytes,
                                     "file_count": observed["file_count"],
                                     "directory_count": observed["directory_count"],
                                     "total_bytes": observed["total_bytes"]}}
    producer_sha = publish(producer, producer_record)
    native = {"schema": NATIVE_SCHEMA, "status": "passed",
              "archive": {"name": archive.name, "sha256": archive_sha,
                          "bytes": archive.stat().st_size},
              "producer": {"name": producer.name, "sha256": producer_sha,
                           "bytes": producer.stat().st_size},
              "manifest_sha256": manifest_sha, "identity": identity}
    publish(receipt, native)
    return native


def produce_failure(root, archive, producer, receipt, max_bytes,
                    expected_target, expected_commit, expected_tree):
    """Preserve a failed or interrupted original as raw bytes, never success."""
    root = rooted(root)
    cap(max_bytes)
    archive = fresh(archive, (root,))
    producer = fresh(producer, (root, archive))
    receipt = fresh(receipt, (root, archive, producer))
    identity = validate_failure_identity({"target": expected_target,
                                          "source_commit": expected_commit,
                                          "source_tree": expected_tree})
    # An interrupted launcher may have no JSON or only its initial running
    # receipt. Only an original typed terminal failure earns "failed"; every
    # other state is explicitly unresolved and cannot be selected as success.
    disposition = "interrupted"
    launcher = root / "launcher.json"
    if launcher.is_file() and not launcher.is_symlink():
        try:
            original = acceptance.read_json(launcher)
            if original.get("schema") == owned.SCHEMA and original.get("status") == "failed":
                disposition = "failed"
        except (OSError, ValueError, TypeError):
            pass
    observed = census(root, max_bytes, require_receipts=False)
    manifest = {"schema": FAILURE_SCHEMA, "status": disposition,
                "identity": identity, **observed, "max_bytes": max_bytes}
    data = canonical(manifest)
    manifest_sha = hashlib.sha256(data).hexdigest()
    validate_manifest(data, manifest_sha)
    archive_written = False
    try:
        archive_sha = archive_write(root, data, archive, max_bytes)
        archive_written = True
        require(census(root, max_bytes, require_receipts=False) == observed,
                "failed original assembly changed during native preservation")
        producer_record = {"schema": FAILURE_PRODUCER_SCHEMA, "status": disposition,
                           "identity": identity, "script_sha256": sha256(__file__),
                           "transport": {"archive_name": archive.name, "archive_sha256": archive_sha,
                                         "archive_bytes": archive.stat().st_size,
                                         "manifest_sha256": manifest_sha, "max_bytes": max_bytes,
                                         "file_count": observed["file_count"],
                                         "directory_count": observed["directory_count"],
                                         "total_bytes": observed["total_bytes"]}}
        producer_sha = publish(producer, producer_record)
        native = {"schema": NATIVE_SCHEMA, "status": disposition,
                  "archive": {"name": archive.name, "sha256": archive_sha,
                              "bytes": archive.stat().st_size},
                  "producer": {"name": producer.name, "sha256": producer_sha,
                               "bytes": producer.stat().st_size},
                  "manifest_sha256": manifest_sha, "identity": identity}
        publish(receipt, native)
        return native
    except BaseException:
        # A failed capture has no terminal marker. Its original directory is
        # untouched and the same raw names can be retried by host cleanup.
        if not receipt.exists():
            producer.unlink(missing_ok=True)
            if archive_written:
                archive.unlink(missing_ok=True)
            functional_transport.sync_directory(archive.parent)
            functional_transport.sync_directory(producer.parent)
        raise


def read_producer(path, expected_sha256):
    path = rooted(path, file=True)
    digest = acceptance.checksum(expected_sha256)
    with path.open("rb") as stream:
        data = stream.read(acceptance.MAX_JSON_BYTES + 1)
    require(len(data) <= acceptance.MAX_JSON_BYTES
            and hashlib.sha256(data).hexdigest() == digest,
            "assembly producer differs from external digest")
    record = acceptance.decode(data)
    acceptance.exact(record, {"schema", "status", "identity", "script_sha256", "transport"},
                     "assembly producer")
    success = record["schema"] == PRODUCER_SCHEMA and record["status"] == "passed"
    failure = (record["schema"] == FAILURE_PRODUCER_SCHEMA
               and record["status"] in {"failed", "interrupted"})
    require((success or failure)
            and acceptance.checksum(record["script_sha256"]) == sha256(__file__),
            "assembly producer has no typed disposition or frozen implementation")
    if success:
        validate_identity(record["identity"])
    else:
        validate_failure_identity(record["identity"])
    transport = record["transport"]
    acceptance.exact(transport, {"archive_name", "archive_sha256", "archive_bytes",
                                 "manifest_sha256", "max_bytes", "file_count",
                                 "directory_count", "total_bytes"}, "assembly producer transport")
    require(isinstance(transport["archive_name"], str)
            and acceptance.relative_path(transport["archive_name"]) == transport["archive_name"]
            and "/" not in transport["archive_name"],
            "assembly producer archive name differs")
    acceptance.checksum(transport["archive_sha256"])
    acceptance.checksum(transport["manifest_sha256"])
    for key in ("archive_bytes", "max_bytes", "file_count", "directory_count", "total_bytes"):
        minimum = 1 if key in {"archive_bytes", "max_bytes"} or (success and key in {"file_count", "directory_count"}) else 0
        acceptance.uint(transport[key], "assembly producer " + key, minimum)
    require(transport["archive_bytes"] <= transport["max_bytes"]
            and transport["total_bytes"] <= transport["max_bytes"]
            and canonical(record) == data,
            "assembly producer is not canonical or exceeds cap")
    return path, data, record


def read_native_receipt(path):
    """Type-check the native sidecar before comparing external upload digests."""
    path = rooted(path, file=True)
    with path.open("rb") as stream:
        data = stream.read(acceptance.MAX_JSON_BYTES + 1)
    require(len(data) <= acceptance.MAX_JSON_BYTES, "assembly native receipt exceeds work limit")
    record = acceptance.decode(data)
    acceptance.exact(record, {"schema", "status", "archive", "producer",
                              "manifest_sha256", "identity"}, "assembly native receipt")
    require(record["schema"] == NATIVE_SCHEMA
            and record["status"] in {"passed", "failed", "interrupted"},
            "assembly native transport has no typed disposition")
    if record["status"] == "passed":
        validate_identity(record["identity"])
    else:
        validate_failure_identity(record["identity"])
    acceptance.checksum(record["manifest_sha256"])
    for label in ("archive", "producer"):
        entry = record[label]
        acceptance.exact(entry, {"name", "sha256", "bytes"}, "assembly native " + label)
        require(isinstance(entry["name"], str)
                and acceptance.relative_path(entry["name"]) == entry["name"]
                and "/" not in entry["name"],
                "assembly native artifact name is malformed")
        acceptance.checksum(entry["sha256"])
        acceptance.uint(entry["bytes"], "assembly native artifact length", 1)
    require(canonical(record) == data, "assembly native receipt is not canonical")
    return record


def collect(archive, producer, producer_sha256, max_bytes, output):
    """Download side: no receipt until raw archive and semantics reopen."""
    cap(max_bytes)
    producer_path, producer_data, record = read_producer(producer, producer_sha256)
    transport = record["transport"]
    archive = rooted(archive, file=True)
    require(archive != producer_path and archive.name == transport["archive_name"]
            and archive.stat().st_size == transport["archive_bytes"],
            "downloaded assembly archive differs from producer")
    output = fresh(output, (archive, producer_path))
    output.mkdir(mode=0o700)
    output.chmod(0o700)
    functional_transport.sync_directory(output.parent)
    restored = output / "assembly"
    manifest = check_archive(archive, transport["archive_sha256"],
                             transport["manifest_sha256"],
                             min(max_bytes, transport["max_bytes"]), restored)
    expected_schema = SCHEMA if record["status"] == "passed" else FAILURE_SCHEMA
    require(manifest["schema"] == expected_schema
            and manifest["status"] == record["status"]
            and manifest["identity"] == record["identity"]
            and all(manifest[key] == transport[key] for key in
                    ("file_count", "directory_count", "total_bytes")),
            "assembly producer differs from original archive manifest")
    if record["status"] == "passed":
        require(assembly_identity(restored) == record["identity"],
                "downloaded assembly no longer verifies against original semantics")
    require(sha256(archive) == transport["archive_sha256"]
            and sha256(producer_path) == producer_sha256
            and census(restored, max_bytes,
                       require_receipts=record["status"] == "passed")["files"] == manifest["files"],
            "assembly evidence changed before collector publication")
    with (output / "producer.json").open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(producer_data)
        stream.flush()
        os.fsync(stream.fileno())
    manifest_data = canonical(manifest)
    with (output / "manifest.json").open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(manifest_data)
        stream.flush()
        os.fsync(stream.fileno())
    require(sha256(output / "producer.json") == producer_sha256
            and sha256(output / "manifest.json") == transport["manifest_sha256"],
            "owned assembly readback metadata differs")
    functional_transport.sync_directory(output)
    receipt = {"schema": COLLECTOR_SCHEMA if record["status"] == "passed" else FAILURE_COLLECTOR_SCHEMA,
               "status": record["status"],
               "archive": {"path": str(archive), "sha256": transport["archive_sha256"],
                           "bytes": archive.stat().st_size},
               "producer_sha256": producer_sha256,
               "manifest_sha256": transport["manifest_sha256"],
               "identity": record["identity"], "file_count": transport["file_count"],
               "directory_count": transport["directory_count"],
               "total_bytes": transport["total_bytes"], "collector_sha256": sha256(__file__)}
    publish(output / "receipt.json", receipt)
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    native = commands.add_parser("produce")
    native.add_argument("--assembly", required=True, type=Path)
    native.add_argument("--evidence", required=True, type=Path)
    native.add_argument("--archive", required=True, type=Path)
    native.add_argument("--producer", required=True, type=Path)
    native.add_argument("--receipt", required=True, type=Path)
    native.add_argument("--max-bytes", required=True, type=int)
    native.add_argument("--expected-target", required=True)
    native.add_argument("--expected-source-commit", required=True)
    native.add_argument("--expected-source-tree", required=True)
    failed = commands.add_parser("snapshot-failure")
    failed.add_argument("--assembly", required=True, type=Path)
    failed.add_argument("--archive", required=True, type=Path)
    failed.add_argument("--producer", required=True, type=Path)
    failed.add_argument("--receipt", required=True, type=Path)
    failed.add_argument("--max-bytes", required=True, type=int)
    failed.add_argument("--expected-target", required=True)
    failed.add_argument("--expected-source-commit", required=True)
    failed.add_argument("--expected-source-tree", required=True)
    downloaded = commands.add_parser("collect")
    downloaded.add_argument("--archive", required=True, type=Path)
    downloaded.add_argument("--producer-manifest", required=True, type=Path)
    downloaded.add_argument("--producer-sha256", required=True)
    downloaded.add_argument("--max-bytes", required=True, type=int)
    downloaded.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "produce":
            result = produce(args.assembly, args.evidence, args.archive, args.producer,
                             args.receipt, args.max_bytes, args.expected_target,
                             args.expected_source_commit, args.expected_source_tree)
            print(json.dumps(result, sort_keys=True))
        elif args.command == "snapshot-failure":
            result = produce_failure(args.assembly, args.archive, args.producer,
                                     args.receipt, args.max_bytes, args.expected_target,
                                     args.expected_source_commit, args.expected_source_tree)
            print(json.dumps(result, sort_keys=True))
        else:
            result = collect(args.archive, args.producer_manifest, args.producer_sha256,
                             args.max_bytes, args.output)
            print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        print("assembly transport failed: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
