#!/usr/bin/env python3
"""Export the exact transitive bytes of one passed native functional run.

The export is only functional evidence, not final production acceptance.  An
operator supplies an explicit byte budget; an oversized or incomplete run
cannot produce a passing manifest.  The export keeps the original `run/`
layout so the final acceptance verifier can reopen every referenced byte.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path
import tarfile
import tempfile

import package_release as package
from release_gate import inventory, sha256, write_json
import verify_release_acceptance as acceptance


SCHEMA = "kasumi-functional-evidence-export-v1"
PRODUCER_SCHEMA = "kasumi-functional-producer-v1"
CHUNK = 1 << 20


def require(value, message):
    if not value:
        raise ValueError(message)


def identity(root, relative, digest=None, length=None, executable=None):
    """Reopen a canonical owned regular file and bind its recorded identity."""
    relative = acceptance.relative_path(relative)
    path = package.owned_file(root, relative)
    size = path.stat().st_size
    if length is not None:
        require(size == acceptance.uint(length, relative + " length"), "functional file length differs: " + relative)
    digest = sha256(path) if digest is None else acceptance.checksum(digest)
    acceptance.reference(root, {"path": relative, "sha256": digest, "bytes": size})
    mode = bool(path.stat().st_mode & 0o111)
    if executable is not None:
        require(type(executable) is bool and mode == executable, "functional file mode differs: " + relative)
    return {"sha256": digest, "bytes": size, "executable": mode}


def roster(evidence):
    """Compute and validate every original file the final candidate rechecks."""
    evidence = Path(evidence).resolve(strict=True)
    record = acceptance.read_json(package.owned_file(evidence, "evidence.json"))
    require(isinstance(record, dict) and record.get("schema") == 1 and record.get("status") == "passed",
            "a passed original functional run is required")
    verified, _, target, _ = package.verify_evidence(evidence)
    require(record == verified, "ambiguous original functional receipt")
    source_files = acceptance.read_json(package.owned_file(evidence, "source-files.json"))
    require(isinstance(source_files, dict) and source_files, "original source inventory is absent")
    files = {}

    def add(relative, digest=None, length=None, executable=None):
        value = identity(evidence, relative, digest, length, executable)
        previous = files.setdefault(relative, value)
        require(previous == value, "conflicting functional file identity: " + relative)

    add("evidence.json")
    add("source-files.json", record["source_files_sha256"])
    add("source.tar", record["source_archive_sha256"])
    interpreter = record["python_executable"]
    require(interpreter["artifact"] == "tools/python", "functional interpreter path differs")
    add(interpreter["artifact"], interpreter["sha256"])
    for gate in record["gates"]:
        name = gate["name"]
        for field, suffix in (("log", ".log"), ("process", "-process.json"),
                              ("resources", "-resources.json")):
            relative = gate[field]
            require(relative == name + suffix, "functional gate file path differs: " + name)
            add(relative, gate[field + "_sha256"])
            if field != "log":
                acceptance.read_json(package.owned_file(evidence, relative))
        for relative, executable in gate.get("executables", {}).items():
            relative = acceptance.relative_path(relative)
            require(isinstance(executable, dict), "functional executable identity is malformed")
            add("target/" + relative, executable["sha256"], executable["bytes"], True)
    for relative, value in source_files.items():
        relative = acceptance.relative_path(relative)
        acceptance.exact(value, {"sha256", "bytes", "executable"}, "functional source file")
        add("source/" + relative, value["sha256"], value["bytes"], value["executable"])
    require(acceptance.archive_inventory(package.owned_file(evidence, "source.tar"), strip_root=False) == source_files,
            "original source archive differs from original source inventory")
    require(inventory(evidence / "source") == source_files,
            "original source directory differs from original source inventory")
    return dict(sorted(files.items())), target


def copy_checked(source, destination, expected):
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    digest = hashlib.sha256()
    count = 0
    with source.open("rb") as original, destination.open("xb") as output:
        while block := original.read(CHUNK):
            count += len(block)
            require(count <= expected["bytes"], "functional input grew while exporting: " + str(source))
            digest.update(block)
            output.write(block)
        os.fchmod(output.fileno(), 0o755 if expected["executable"] else 0o644)
        output.flush()
        os.fsync(output.fileno())
    require(count == expected["bytes"] and digest.hexdigest() == expected["sha256"],
            "functional input changed while exporting: " + str(source))


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def export(evidence, output, max_bytes):
    require(type(max_bytes) is int and 0 < max_bytes <= (1 << 64) - 1,
            "an explicit positive export byte budget is required")
    evidence = Path(evidence).resolve(strict=True)
    output = Path(output)
    require(output.is_absolute(), "export output must be absolute")
    output = output.resolve()
    require(not output.exists() and not output.is_relative_to(evidence)
            and not evidence.is_relative_to(output), "export output must be fresh and outside original evidence")
    files, target = roster(evidence)
    total = sum(value["bytes"] for value in files.values())
    manifest = {"schema": SCHEMA, "status": "passed", "target": target,
                "source_evidence_sha256": files["evidence.json"]["sha256"],
                "file_count": len(files), "total_bytes": total, "max_bytes": max_bytes,
                "files": files}
    manifest_size = len((json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode())
    require(manifest_size <= acceptance.MAX_JSON_BYTES and total + manifest_size <= max_bytes,
            "functional export exceeds explicit byte budget")
    output.mkdir(parents=False, exist_ok=False, mode=0o700)
    output.chmod(0o700)
    sync_directory(output.parent)
    exported = output / "run"
    exported.mkdir(mode=0o700)
    exported.chmod(0o700)
    for relative, expected in files.items():
        copy_checked(package.owned_file(evidence, relative), exported / relative, expected)
        require(identity(evidence, relative) == expected, "original functional input changed during export: " + relative)
    copied, copied_target = roster(exported)
    require(copied == files and copied_target == target and inventory(exported) == files,
            "copied functional evidence differs from original roster")
    # A manifest is the success marker: file content, modes, and directory
    # entries must reach stable storage before its atomic/fsynced publication.
    for directory in sorted((path for path in exported.rglob("*") if path.is_dir()),
                            key=lambda path: len(path.parts), reverse=True):
        directory.chmod(0o700)
        sync_directory(directory)
    sync_directory(exported)
    sync_directory(output)
    write_json(output / "manifest.json", manifest)
    return sha256(output / "manifest.json")


def verify(export_root, expected_manifest_sha256):
    """Read back a transported export against an externally retained digest."""
    root = Path(export_root).resolve(strict=True)
    expected = acceptance.checksum(expected_manifest_sha256)
    manifest_path = package.owned_file(root, "manifest.json")
    require(sha256(manifest_path) == expected, "functional export manifest digest differs")
    manifest = acceptance.read_json(manifest_path)
    acceptance.exact(manifest, {"schema", "status", "target", "source_evidence_sha256", "file_count",
                                "total_bytes", "max_bytes", "files"}, "functional export manifest")
    require(manifest["schema"] == SCHEMA and manifest["status"] == "passed",
            "functional export did not pass")
    require({item.name for item in root.iterdir()} == {"manifest.json", "run"},
            "functional export root contains unexpected entries")
    files, target = roster(root / "run")
    require(target == manifest["target"] and files == manifest["files"] and inventory(root / "run") == files,
            "transported functional evidence differs from export manifest")
    require(manifest["source_evidence_sha256"] == files["evidence.json"]["sha256"]
            and type(manifest["file_count"]) is int and manifest["file_count"] == len(files)
            and type(manifest["max_bytes"]) is int and 0 < manifest["max_bytes"] <= (1 << 64) - 1
            and type(manifest["total_bytes"]) is int
            and manifest["total_bytes"] == sum(value["bytes"] for value in files.values())
            and manifest["total_bytes"] + manifest_path.stat().st_size <= manifest["max_bytes"],
            "functional export byte accounting differs")
    return manifest


class LimitedWriter:
    def __init__(self, output, limit):
        self.output = output
        self.limit = limit
        self.count = 0

    def write(self, value):
        require(self.count + len(value) <= self.limit, "functional transport exceeds explicit byte budget")
        written = self.output.write(value)
        require(written == len(value), "short functional transport write")
        self.count += written
        return written


def archive_member(name, path, mode):
    info = tarfile.TarInfo(name)
    info.size = path.stat().st_size
    info.mode = mode
    info.uid = info.gid = info.mtime = 0
    info.uname = info.gname = ""
    return info


def validate_transport_manifest(data, expected_sha256):
    require(len(data) <= acceptance.MAX_JSON_BYTES and hashlib.sha256(data).hexdigest() == expected_sha256,
            "transport manifest length or digest differs")
    manifest = acceptance.decode(data)
    acceptance.exact(manifest, {"schema", "status", "target", "source_evidence_sha256", "file_count",
                                "total_bytes", "max_bytes", "files"}, "functional transport manifest")
    require(manifest["schema"] == SCHEMA and manifest["status"] == "passed"
            and isinstance(manifest["files"], dict) and manifest["files"],
            "transport manifest is not a passed functional export")
    files = manifest["files"]
    for relative, value in files.items():
        acceptance.relative_path(relative)
        acceptance.exact(value, {"sha256", "bytes", "executable"}, "transport file identity")
        acceptance.checksum(value["sha256"])
        acceptance.uint(value["bytes"], "transport file length")
        require(type(value["executable"]) is bool, "transport file mode is invalid")
    require(type(manifest["file_count"]) is int and manifest["file_count"] == len(files)
            and type(manifest["total_bytes"]) is int
            and manifest["total_bytes"] == sum(value["bytes"] for value in files.values())
            and type(manifest["max_bytes"]) is int and 0 < manifest["max_bytes"] <= (1 << 64) - 1
            and manifest["total_bytes"] + len(data) <= manifest["max_bytes"],
            "transport manifest byte accounting differs")
    require((json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode() == data,
            "transport manifest is not canonical")
    return manifest


def check_transport_member(member, name, length, mode):
    acceptance.relative_path(member.name)
    pax = member.pax_headers
    needs_path_pax = len(name) > tarfile.LENGTH_NAME or not name.isascii()
    needs_size_pax = length >= 8 ** 11
    require(isinstance(pax, dict) and set(pax) <= {"path", "size"}
            and ("path" in pax) == needs_path_pax
            and ("size" in pax) == needs_size_pax
            and ("path" not in pax or pax["path"] == name)
            and ("size" not in pax or pax["size"] == str(length)),
            "unexpected functional transport PAX metadata")
    require(member.name == name and member.type in (tarfile.REGTYPE, tarfile.AREGTYPE)
            and not getattr(member, "sparse", None) and not member.linkname
            and member.size == length and member.mode == mode
            and member.uid == 0 and member.gid == 0 and member.mtime == 0
            and member.uname == "" and member.gname == "",
            "unsafe or mismatched functional transport member")


def check_transport(archive_path, expected_archive_sha256, expected_manifest_sha256, max_bytes,
                    output=None):
    """Hash an uncompressed archive, then stream-check and optionally restore it."""
    require(type(max_bytes) is int and 0 < max_bytes <= (1 << 64) - 1,
            "an explicit positive transport byte budget is required")
    archive_path = Path(archive_path)
    require(archive_path.is_absolute() and not archive_path.is_symlink()
            and stat.S_ISREG(archive_path.stat().st_mode), "transport archive is not an owned regular file")
    require(archive_path.stat().st_size <= max_bytes, "functional transport exceeds explicit byte budget")
    expected_archive_sha256 = acceptance.checksum(expected_archive_sha256)
    require(sha256(archive_path) == expected_archive_sha256,
            "functional transport archive digest differs")
    expected_manifest_sha256 = acceptance.checksum(expected_manifest_sha256)
    destination = None
    if output is not None:
        destination = Path(output)
        require(destination.is_absolute(), "transport readback must use an absolute output")
        destination = destination.resolve()
        require(not destination.exists() and not archive_path.is_relative_to(destination),
                "transport readback output must be fresh and outside archive custody")
    with tarfile.open(archive_path, "r:") as source:
        entries = iter(source)
        first = next(entries, None)
        require(first is not None and first.name == "manifest.json" and first.size <= acceptance.MAX_JSON_BYTES,
                "functional transport lacks a bounded first manifest")
        check_transport_member(first, "manifest.json", first.size, 0o600)
        with source.extractfile(first) as stream:
            data = stream.read(acceptance.MAX_JSON_BYTES + 1)
        manifest = validate_transport_manifest(data, expected_manifest_sha256)
        expected = manifest["files"]
        names = ["run/" + name for name in sorted(expected)]
        if destination is not None:
            destination.mkdir(parents=False, exist_ok=False, mode=0o700)
            destination.chmod(0o700)
            sync_directory(destination.parent)
            run = destination / "run"
            run.mkdir(mode=0o700)
            run.chmod(0o700)
        seen = 0
        for member in entries:
            require(seen < len(names), "functional transport has an extra member")
            relative = names[seen]
            value = expected[relative.removeprefix("run/")]
            mode = 0o755 if value["executable"] else 0o644
            check_transport_member(member, relative, value["bytes"], mode)
            digest = hashlib.sha256()
            count = 0
            with source.extractfile(member) as stream:
                if destination is None:
                    while block := stream.read(CHUNK):
                        count += len(block)
                        require(count <= value["bytes"], "transport file exceeds recorded length")
                        digest.update(block)
                else:
                    path = destination / relative
                    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    with path.open("xb") as copied:
                        while block := stream.read(CHUNK):
                            count += len(block)
                            require(count <= value["bytes"], "transport file exceeds recorded length")
                            digest.update(block)
                            copied.write(block)
                        os.fchmod(copied.fileno(), mode)
                        copied.flush()
                        os.fsync(copied.fileno())
            require(count == value["bytes"] and digest.hexdigest() == value["sha256"],
                    "transport file bytes differ from original functional evidence")
            seen += 1
        require(seen == len(names), "functional transport omitted a required file")
    require(sha256(archive_path) == expected_archive_sha256,
            "functional transport archive changed during readback")
    if destination is not None:
        files, target = roster(destination / "run")
        require(files == manifest["files"] and target == manifest["target"]
                and inventory(destination / "run") == files,
                "transport readback differs from verified functional export")
        for directory in sorted((path for path in (destination / "run").rglob("*") if path.is_dir()),
                                key=lambda path: len(path.parts), reverse=True):
            directory.chmod(0o700)
            sync_directory(directory)
        sync_directory(destination / "run")
        sync_directory(destination)
        try:
            write_json(destination / "manifest.json", manifest)
            require(sha256(destination / "manifest.json") == expected_manifest_sha256,
                    "readback manifest changed during publication")
            verify(destination, expected_manifest_sha256)
        except BaseException:
            (destination / "manifest.json").unlink(missing_ok=True)
            (destination / "manifest.json.pending").unlink(missing_ok=True)
            sync_directory(destination)
            raise
    return manifest


def create_transport(export_root, expected_manifest_sha256, destination, max_bytes):
    """Publish one complete, mode-preserving, explicitly bounded tar file."""
    root = Path(export_root).resolve(strict=True)
    manifest = verify(root, expected_manifest_sha256)
    require(type(max_bytes) is int and 0 < max_bytes <= (1 << 64) - 1,
            "an explicit positive transport byte budget is required")
    destination = Path(destination)
    require(destination.is_absolute(), "transport archive path must be absolute")
    destination = destination.resolve()
    require(not destination.exists() and not destination.is_relative_to(root)
            and not root.is_relative_to(destination), "transport archive must be fresh and outside export")
    descriptor, temporary = tempfile.mkstemp(prefix=".functional-transport-", suffix=".pending",
                                            dir=destination.parent)
    try:
        with os.fdopen(descriptor, "wb") as raw:
            writer = LimitedWriter(raw, max_bytes)
            with tarfile.open(fileobj=writer, mode="w|", format=tarfile.PAX_FORMAT) as archive:
                items = [("manifest.json", 0o600)] + [
                    ("run/" + relative, 0o755 if value["executable"] else 0o644)
                    for relative, value in sorted(manifest["files"].items())]
                for name, mode in items:
                    path = package.owned_file(root, name)
                    with path.open("rb") as stream:
                        archive.addfile(archive_member(name, path, mode), stream)
            raw.flush()
            os.fsync(raw.fileno())
        digest = sha256(temporary)
        check_transport(Path(temporary).absolute(), digest, expected_manifest_sha256, max_bytes)
        os.link(temporary, destination)
        sync_directory(destination.parent)
        return digest
    finally:
        Path(temporary).unlink(missing_ok=True)
        sync_directory(destination.parent)


def produce_identity(evidence, export_root, archive, manifest_sha256,
                     archive_sha256, expected_target, expected_commit,
                     expected_tree, max_bytes, output):
    """Publish a separate native-source identity for one verified transport."""
    require(type(max_bytes) is int and 0 < max_bytes <= (1 << 64) - 1,
            "an explicit positive producer byte budget is required")
    manifest_sha256 = acceptance.checksum(manifest_sha256)
    archive_sha256 = acceptance.checksum(archive_sha256)
    require(expected_target in package.TARGETS, "unsupported expected native target")
    require(isinstance(expected_commit, str) and re.fullmatch(r"[0-9a-f]{40}", expected_commit)
            and isinstance(expected_tree, str) and re.fullmatch(r"[0-9a-f]{40}", expected_tree),
            "expected native Git identity is malformed")
    evidence = Path(evidence).resolve(strict=True)
    export_root = Path(export_root).resolve(strict=True)
    archive = Path(archive)
    output = Path(output)
    require(archive.is_absolute() and output.is_absolute(),
            "producer archive and output must be absolute")
    require(not archive.is_symlink() and stat.S_ISREG(archive.stat().st_mode),
            "producer archive is not an owned regular file")
    archive = archive.resolve(strict=True)
    output = output.resolve()
    require(not output.exists() and output.parent.is_dir()
            and not output.is_relative_to(evidence) and not output.is_relative_to(export_root)
            and output != archive, "producer output must be fresh and separate")
    files, target = roster(evidence)
    original = acceptance.read_json(package.owned_file(evidence, "evidence.json"))
    require(sha256(package.owned_file(evidence / "source", "scripts/export_functional_evidence.py"))
            == sha256(__file__), "producer did not execute its frozen source")
    manifest = verify(export_root, manifest_sha256)
    require(manifest["files"] == files and manifest["target"] == target
            and manifest["source_evidence_sha256"] == files["evidence.json"]["sha256"]
            and manifest["max_bytes"] == max_bytes,
            "producer export differs from original native run")
    require(check_transport(archive, archive_sha256, manifest_sha256, max_bytes) == manifest,
            "producer tar differs from original native run")
    require(target == expected_target and original["source_commit"] == expected_commit
            and original["source_tree"] == expected_tree,
            "producer native target or Git identity differs")
    started = acceptance.timestamp(original["started_at"])
    finished = acceptance.timestamp(original["finished_at"])
    require(finished > started, "producer run has no positive UTC interval")
    record = {
        "schema": PRODUCER_SCHEMA, "status": "passed", "target": target,
        "source": {"commit": original["source_commit"], "tree": original["source_tree"],
                   "archive_sha256": original["source_archive_sha256"],
                   "files_sha256": original["source_files_sha256"],
                   "lockfile_sha256": original["lockfile_sha256"]},
        "run": {"evidence_sha256": files["evidence.json"]["sha256"],
                "started_at": original["started_at"],
                "finished_at": original["finished_at"]},
        "transport": {"archive_name": archive.name, "archive_sha256": archive_sha256,
                      "archive_bytes": archive.stat().st_size,
                      "manifest_sha256": manifest_sha256, "max_bytes": max_bytes,
                      "file_count": manifest["file_count"],
                      "total_bytes": manifest["total_bytes"]},
        "exporter_sha256": sha256(__file__),
    }
    data = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
    require(len(data) <= acceptance.MAX_JSON_BYTES, "producer record exceeds JSON limit")
    pending = output.with_suffix(output.suffix + ".pending")
    linked = False
    try:
        with pending.open("xb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(pending, output)
        linked = True
        sync_directory(output.parent)
        require(acceptance.read_json(output) == record and sha256(output) == hashlib.sha256(data).hexdigest(),
                "producer record changed during publication")
        return hashlib.sha256(data).hexdigest()
    except BaseException:
        if linked:
            output.unlink(missing_ok=True)
        raise
    finally:
        pending.unlink(missing_ok=True)
        sync_directory(output.parent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("--evidence", required=True, type=Path)
    create.add_argument("--output", required=True, type=Path)
    create.add_argument("--max-bytes", required=True, type=int)
    check = commands.add_parser("verify")
    check.add_argument("--export", required=True, type=Path)
    check.add_argument("--expected-manifest-sha256", required=True)
    pack = commands.add_parser("archive")
    pack.add_argument("--export", required=True, type=Path)
    pack.add_argument("--expected-manifest-sha256", required=True)
    pack.add_argument("--output", required=True, type=Path)
    pack.add_argument("--max-bytes", required=True, type=int)
    unpack = commands.add_parser("readback")
    unpack.add_argument("--archive", required=True, type=Path)
    unpack.add_argument("--expected-archive-sha256", required=True)
    unpack.add_argument("--expected-manifest-sha256", required=True)
    unpack.add_argument("--output", required=True, type=Path)
    unpack.add_argument("--max-bytes", required=True, type=int)
    producer = commands.add_parser("producer")
    producer.add_argument("--evidence", required=True, type=Path)
    producer.add_argument("--export", required=True, type=Path)
    producer.add_argument("--archive", required=True, type=Path)
    producer.add_argument("--expected-manifest-sha256", required=True)
    producer.add_argument("--expected-archive-sha256", required=True)
    producer.add_argument("--expected-target", required=True)
    producer.add_argument("--expected-source-commit", required=True)
    producer.add_argument("--expected-source-tree", required=True)
    producer.add_argument("--max-bytes", required=True, type=int)
    producer.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.command == "create":
        print(export(args.evidence, args.output, args.max_bytes))
    elif args.command == "verify":
        verify(args.export, args.expected_manifest_sha256)
        print("functional evidence export verified")
    elif args.command == "archive":
        print(create_transport(args.export, args.expected_manifest_sha256, args.output, args.max_bytes))
    elif args.command == "producer":
        print(produce_identity(args.evidence, args.export, args.archive,
                               args.expected_manifest_sha256, args.expected_archive_sha256,
                               args.expected_target, args.expected_source_commit,
                               args.expected_source_tree, args.max_bytes, args.output))
    else:
        check_transport(args.archive, args.expected_archive_sha256,
                        args.expected_manifest_sha256, args.max_bytes, args.output)
        print("functional evidence transport readback verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
