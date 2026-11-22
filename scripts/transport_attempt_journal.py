#!/usr/bin/env python3
"""Transport one complete native attempt journal and admit it only after replay.

A native host's custody root holds its attempt journal and every admitted
output. Final verification reads that root from the evidence bundle at
``native-attempts/<journal id>/`` and replays it against the operator's journal
head and the root's original absolute path.

``produce`` runs beside the original root. It replays the journal with the
acceptance verifier and records which files that verifier opened and which
directories it listed. The archive holds the journal namespace and every
admitted output whole, except compiler work trees: the source extraction and
Cargo target directory that a build's own qualification record places, and any
directory the operator names with ``--omit``. From a work tree it carries only
the files the verifier opened, the listings it read and the files the
qualification record names. The manifest accounts for everything left behind
by count and bytes. Before the producer record exists, the archive is restored
and replayed as a relocated copy.

``admit`` runs beside the bundle. The operator supplies the journal heads file
separately. The archive is restored next to its destination, replayed by the
same verifier against that head and original root, and only then renamed into
place. That rename is the commit. A transfer refused before it leaves a
rejection record and no custody root. A failure after it is reported as
unconfirmed, with exit status 2: the verified root stays, and admitting the
same transfer again confirms it in place. An existing root is never replaced.

Run both with the native Python from the frozen source::

    python3 -I -S -B /frozen/source/scripts/transport_attempt_journal.py produce \\
      --root /native/custody --archive /native/transfer/custody.tar \\
      --producer /native/transfer/custody.producer.json --max-bytes 68719476736 \\
      --omit run/tmp

    python3 -I -S -B /frozen/source/scripts/transport_attempt_journal.py admit \\
      --archive /incoming/custody.tar --producer-manifest /incoming/custody.producer.json \\
      --producer-sha256 <digest carried outside the upload> \\
      --journal-heads /operator/native-journal-heads.json --max-bytes 68719476736 \\
      --output /evidence/native-attempts/<journal id> --record /operator/admissions/<journal id>-1

The journal head is the operator's anchor. This transport cannot certify a head
it did not receive, and it does not authenticate an adversarial producing host.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import sys
import tarfile
import tempfile

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve(strict=True).parent))

import attempt_index
import export_functional_evidence as functional_transport
import package_release as package
from release_gate import sha256
import transport_assembly_evidence as transport
import verify_release_acceptance as acceptance

SCHEMA = "kasumi-native-custody-transport-v1"
PRODUCER_SCHEMA = "kasumi-native-custody-producer-v1"
ADMISSION_SCHEMA = "kasumi-native-custody-admission-v1"
PREFIX = "custody/"
# A domain installation can hold several hundred thousand small files.
MAX_MANIFEST_BYTES = 256 << 20
MAX_FILES = 1_000_000
MAX_DIRECTORIES = 1_000_000
# These kinds select a qualification record, and their outputs hold compiler work trees.
BUILD_KINDS = frozenset({"functional", "independent-build"})
REJECTIONS = (OSError, ValueError, KeyError, TypeError, tarfile.TarError)
require = transport.require


class Reads:
    """Files opened and directories listed beneath one root while a verifier runs."""

    active = []
    installed = False

    def __init__(self, root):
        self.root = os.path.realpath(root)
        self.files, self.listings = set(), set()

    def __enter__(self):
        if not Reads.installed:
            # An audit hook cannot be removed; it is inert while nothing records.
            sys.addaudithook(Reads.audit)
            Reads.installed = True
        Reads.active.append(self)
        return self

    def __exit__(self, *_):
        Reads.active.remove(self)

    @staticmethod
    def audit(event, arguments):
        if not Reads.active or event not in ("open", "os.scandir", "os.listdir"):
            return
        path = arguments[0]
        if isinstance(path, os.PathLike):
            path = os.fspath(path)
        if isinstance(path, bytes):
            path = os.fsdecode(path)
        if not isinstance(path, str):
            return
        path = os.path.realpath(path)
        for reads in Reads.active:
            if path == reads.root or path.startswith(reads.root + os.sep):
                seen = reads.files if event == "open" else reads.listings
                seen.add(Path(os.path.relpath(path, reads.root)).as_posix())


def decode(data):
    return json.loads(data, object_pairs_hook=attempt_index.unique_pairs,
                      parse_constant=attempt_index.reject_constant)


def comparable(facts):
    """What the original and a relocated copy must be judged alike on."""
    return [{key: fact[key] for key in ("id", "kind", "status", "output", "selectable")} for fact in facts]


def require_same(original, relocated):
    changed = [fact["id"] + " (" + str(fact["refusal"]) + ")"
               for fact, before in zip(relocated, original) if comparable([fact]) != comparable([before])]
    require(len(relocated) == len(original) and not changed,
            "the relocated journal is judged differently from its original: " + ", ".join(changed))


def selection_needs(root, journal_id, kind, evidence):
    """Files a final gate rechecks through the kind's own qualification record."""
    if kind == "functional":
        files, _ = functional_transport.roster(evidence.parent)
        base = evidence.parent.relative_to(root).as_posix()
        return {base + "/" + relative for relative in files}
    # The independent record names its inputs by their final bundle paths.
    prefix = "native-attempts/" + journal_id + "/"
    found = set()

    def walk(value):
        if (isinstance(value, dict) and set(value) == {"path", "sha256", "bytes"}
                and isinstance(value["path"], str) and value["path"].startswith(prefix)):
            relative = value["path"][len(prefix):]
            attempt_index.check_ref(root, {**value, "path": relative})
            found.add(relative)
        elif isinstance(value, (dict, list)):
            for item in value.values() if isinstance(value, dict) else value:
                walk(item)

    walk(acceptance.read_json(evidence))
    return found


def judge(root, head, original_root=None):
    """Ask the frozen verifier about every admission in one custody root.

    Returns each attempt's facts, the files a selecting gate would reopen and
    each build's qualification record. The journal must be complete and must
    replay to ``head``.
    """
    root = attempt_index.custody(root)
    entries = attempt_index.replay(root, head=head, original_root=original_root)
    retained = [{"id": name, "receipt": entries[name]["terminal"]["receipt"]} for name in sorted(entries)]

    def verify(selected):
        acceptance.verify_attempts(root, retained, selected, head=head, original_root=original_root)

    verify({})
    facts, passed, records = [], {}, {}
    for name in sorted(entries):
        begin = entries[name]["begin"]
        record = acceptance.read_json(root / entries[name]["terminal"]["receipt"]["path"])
        outcome = acceptance.read_json(root / record["evidence"]["path"])
        selected, evidence = record["evidence"]["path"], None
        if begin["kind"] in BUILD_KINDS and "build_evidence" in outcome:
            selected = records[name] = begin["output"] + "/" + outcome["build_evidence"]["path"]
            evidence = root / selected
        fact = {"id": name, "kind": begin["kind"], "status": record["status"], "output": begin["output"],
                "selectable": False, "refusal": None}
        if record["status"] == "passed":
            passed[name] = (fact, selected, evidence)
        else:
            fact["refusal"] = "the attempt " + record["status"]
        facts.append(fact)
    refused = {}
    try:
        # One replay usually settles every selection; a refusal is then attributed singly.
        verify({selected: fact["kind"] for fact, selected, _ in passed.values()})
    except REJECTIONS:
        for name, (fact, selected, _) in passed.items():
            try:
                verify({selected: fact["kind"]})
            except REJECTIONS as error:
                refused[name] = str(error)
    needed = set()
    for name, (fact, _, evidence) in passed.items():
        if name in refused:
            fact["refusal"] = refused[name]
        elif evidence is None and fact["kind"] in BUILD_KINDS:
            fact["refusal"] = "the build retained no qualification record"
        else:
            try:
                if evidence is not None:
                    needed |= selection_needs(root, head["journal_id"], fact["kind"], evidence)
                fact["selectable"] = True
            except REJECTIONS as error:
                fact["refusal"] = str(error)
    return facts, needed, records


def work_trees(root, facts, records, omit):
    """Directories carried only as far as the verifier reads them.

    A functional run compiles beside its record; an independent build names
    its build root. Each also holds a plain extraction of the retained source
    archive. The operator may name further directories inside admitted outputs.
    """
    trees = set()
    for fact in facts:
        record = records.get(fact["id"])
        if fact["kind"] == "functional":
            base = PurePosixPath(record).parent if record else PurePosixPath(fact["output"])
        elif record:
            build_root = acceptance.read_json(root / record).get("build_root")
            if not isinstance(build_root, str) or not Path(build_root).is_relative_to(root / fact["output"]):
                continue
            base = PurePosixPath(Path(build_root).relative_to(root).as_posix())
        else:
            continue
        trees.update((base / name).as_posix() for name in ("source", "target"))
    outputs = [PurePosixPath(fact["output"]) for fact in facts]
    for relative in omit:
        path = PurePosixPath(attempt_index.relative(relative))
        require(any(output in path.parents for output in outputs),
                "an omitted work tree must lie inside an admitted output: " + relative)
        require((root / relative).is_dir() and not (root / relative).is_symlink(),
                "an omitted work tree is not an original directory: " + relative)
        trees.add(relative)
    return sorted(tree for tree in trees if (root / tree).is_dir() and not (root / tree).is_symlink())


def roster(root, facts, needed, seen, trees):
    """Every original file and directory the transport carries, with its identity."""
    files, directories = {}, {}

    def keep_directory(relative):
        for part in reversed((PurePosixPath(relative), *PurePosixPath(relative).parents)):
            key = part.as_posix()
            if key != "." and key not in directories:
                acceptance.relative_path(key)
                directories[key] = mode(key, True)[0]

    def mode(relative, directory):
        try:
            return transport.checked_mode(root / relative, directory)
        except ValueError:
            raise ValueError("custody entry is a symlink, a special file or has an unsupported mode: "
                             + relative) from None

    def keep_file(relative):
        if relative not in files:
            acceptance.relative_path(relative)
            permissions, length = mode(relative, False)
            keep_directory(PurePosixPath(relative).parent.as_posix())
            files[relative] = {"sha256": sha256(root / relative), "bytes": length, "mode": permissions}

    def keep_children(relative, deep):
        """Preserve one directory's listing; ``deep`` preserves its tree outside work trees."""
        keep_directory(relative)
        with os.scandir(root / relative) as entries:
            for entry in sorted(entries, key=lambda item: item.name):
                child = relative + "/" + entry.name
                if not entry.is_dir(follow_symlinks=False):
                    keep_file(child)
                elif not deep:
                    keep_directory(child)
                elif child not in trees:
                    keep_children(child, True)

    keep_children("attempts", True)
    for fact in facts:
        keep_children(fact["output"], True)
    for relative in sorted(needed):
        keep_file(relative)
    for relative in sorted(seen.files):
        path = root / relative
        if path.is_file() and not path.is_symlink():
            keep_file(relative)
    # A listing the verifier read is evidence of absence as well as presence.
    for relative in sorted(seen.listings):
        if (root / relative).is_dir() and relative != ".":
            keep_children(relative, False)
    return dict(sorted(files.items())), dict(sorted(directories.items()))


def account(root, files, directories):
    """Count the whole original root and summarize what the transport leaves behind."""
    census = {"files": 0, "bytes": 0}
    omitted = []

    def tree(path):
        count = size = 0
        stack = [path]
        while stack:
            with os.scandir(stack.pop()) as entries:
                for entry in entries:
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(entry.path)
                    else:
                        count += 1
                        size += entry.stat(follow_symlinks=False).st_size
        return count, size

    def leave(relative, scope, count, size):
        census["files"] += count
        census["bytes"] += size
        omitted.append({"path": relative, "scope": scope, "files": count, "bytes": size})

    stack = ["."]
    while stack:
        relative = stack.pop()
        count = size = 0
        with os.scandir(root / relative) as entries:
            for entry in sorted(entries, key=lambda item: item.name):
                child = entry.name if relative == "." else relative + "/" + entry.name
                if entry.is_dir(follow_symlinks=False):
                    if child in directories:
                        stack.append(child)
                    else:
                        leave(child, "tree", *tree(entry.path))
                elif child in files:
                    census["files"] += 1
                    census["bytes"] += files[child]["bytes"]
                else:
                    count += 1
                    size += entry.stat(follow_symlinks=False).st_size
        if count:
            leave(relative, "children", count, size)
    return census, sorted(omitted, key=lambda item: (item["path"], item["scope"]))


def validate_manifest(data, expected_sha256):
    require(len(data) <= MAX_MANIFEST_BYTES
            and hashlib.sha256(data).hexdigest() == acceptance.checksum(expected_sha256),
            "native custody manifest digest differs")
    manifest = decode(data)
    acceptance.exact(manifest, {"schema", "status", "head", "original_root", "attempts", "work_trees",
                                "census", "omitted", "root_mode", "directories", "files", "file_count",
                                "directory_count", "total_bytes", "max_bytes"}, "native custody manifest")
    require(manifest["schema"] == SCHEMA and manifest["status"] == "passed",
            "native custody manifest has another schema or disposition")
    attempt_index.check_head(manifest["head"])
    attempt_index.original_custody_path(manifest["original_root"])
    transport.cap(manifest["max_bytes"])
    files, directories = manifest["files"], manifest["directories"]
    require(type(manifest["root_mode"]) is int and 0o700 <= manifest["root_mode"] <= 0o777
            and isinstance(files, dict) and isinstance(directories, dict)
            and len(files) <= MAX_FILES and len(directories) <= MAX_DIRECTORIES
            and not set(files) & set(directories), "native custody roster is malformed")

    def placed(relative):
        acceptance.relative_path(relative)
        parts = PurePosixPath(relative).parts
        require(len(relative.encode()) <= transport.MAX_PATH_BYTES and len(parts) <= 64
                and all(parent.as_posix() in directories
                        for parent in PurePosixPath(relative).parents if parent.as_posix() != "."),
                "native custody path exceeds a bound or lacks its parent: " + relative)

    for relative, permissions in directories.items():
        placed(relative)
        require(type(permissions) is int and permissions & ~0o777 == 0 and permissions & 0o700 == 0o700,
                "native custody directory mode is malformed")
    total = 0
    for relative, item in files.items():
        placed(relative)
        acceptance.exact(item, {"sha256", "bytes", "mode"}, "native custody file")
        require(type(item["mode"]) is int and item["mode"] & ~0o777 == 0 and item["mode"] & 0o400,
                "native custody file mode is malformed")
        acceptance.checksum(item["sha256"])
        total += acceptance.uint(item["bytes"], "native custody file length")
    attempts = manifest["attempts"]
    require(isinstance(attempts, list) and attempts, "native custody manifest names no attempt")
    names = []
    for fact in attempts:
        acceptance.exact(fact, {"id", "kind", "status", "output", "selectable", "refusal"},
                         "transported attempt")
        names.append(attempt_index.name(fact["id"]))
        require(fact["kind"] in attempt_index.KINDS and fact["status"] in attempt_index.STATUSES
                and type(fact["selectable"]) is bool
                and (fact["refusal"] is None if fact["selectable"] else
                     isinstance(fact["refusal"], str) and bool(fact["refusal"]))
                and (not fact["selectable"] or fact["status"] == "passed")
                and attempt_index.relative(fact["output"]) in directories,
                "transported attempt facts are malformed")
    # The journal namespace travels whole: the index and one receipt per admission.
    require(names == sorted(set(names))
            and {name for name in files if name.startswith("attempts/")}
            == {"attempts/index.jsonl", *("attempts/" + name + "/attempt.json" for name in names)}
            and {name for name in directories if name == "attempts" or name.startswith("attempts/")}
            == {"attempts", *("attempts/" + name for name in names)},
            "native custody manifest omits or invents journal custody")
    census, omitted, trees = manifest["census"], manifest["omitted"], manifest["work_trees"]
    acceptance.exact(census, {"files", "bytes"}, "original custody census")
    require(isinstance(omitted, list) and isinstance(trees, list) and trees == sorted(set(map(str, trees)))
            and all(attempt_index.relative(tree) not in files for tree in trees),
            "omitted custody summary is malformed")
    left = [0, 0]
    for item in omitted:
        acceptance.exact(item, {"path", "scope", "files", "bytes"}, "omitted custody")
        require(isinstance(item["path"], str), "omitted custody summary is malformed")
        inside = item["path"] == "." or item["path"] in directories
        require(item["path"] not in files
                and (item["scope"] == "children" and inside
                     or item["scope"] == "tree" and not inside), "omitted custody summary is malformed")
        left[0] += acceptance.uint(item["files"], "omitted file count")
        left[1] += acceptance.uint(item["bytes"], "omitted bytes")
    require(acceptance.uint(census["files"], "original file count") == len(files) + left[0]
            and acceptance.uint(census["bytes"], "original bytes") == total + left[1]
            and manifest["file_count"] == len(files) and manifest["directory_count"] == len(directories)
            and manifest["total_bytes"] == total and total + len(data) <= manifest["max_bytes"],
            "native custody manifest does not account for the original root")
    require(attempt_index.canonical(manifest) == data, "native custody manifest is not canonical")
    return manifest


def directory_members(manifest):
    return [(PREFIX, manifest["root_mode"]),
            *((PREFIX + relative + "/", mode) for relative, mode in manifest["directories"].items())]


def archive_write(root, manifest_data, archive, max_bytes):
    """Write one deterministic raw PAX tar; no archive name exists until it is whole."""
    manifest = decode(manifest_data)
    descriptor, temporary = tempfile.mkstemp(prefix=".custody-transport-", suffix=".pending",
                                            dir=archive.parent)
    try:
        with os.fdopen(descriptor, "wb") as raw:
            os.fchmod(raw.fileno(), 0o600)
            writer = functional_transport.LimitedWriter(raw, max_bytes)
            with tarfile.open(fileobj=writer, mode="w|", format=tarfile.PAX_FORMAT) as output:
                info = tarfile.TarInfo("manifest.json")
                info.size, info.mode = len(manifest_data), 0o600
                info.uid = info.gid = info.mtime = 0
                output.addfile(info, io.BytesIO(manifest_data))
                for name, mode in directory_members(manifest):
                    member = tarfile.TarInfo(name)
                    member.type, member.mode = tarfile.DIRTYPE, mode
                    member.uid = member.gid = member.mtime = 0
                    output.addfile(member)
                for relative, identity in manifest["files"].items():
                    path = package.owned_file(root, relative)
                    with path.open("rb") as source:
                        output.addfile(functional_transport.archive_member(
                            PREFIX + relative, path, identity["mode"]), source)
            raw.flush()
            os.fsync(raw.fileno())
        digest = sha256(temporary)
        os.link(temporary, archive)
        functional_transport.sync_directory(archive.parent)
        return digest
    finally:
        Path(temporary).unlink(missing_ok=True)


def read_archive(archive, archive_sha256, manifest_sha256, max_bytes, output=None):
    """Strictly read one archive; ``output`` restores it into the caller's empty directory."""
    transport.cap(max_bytes)
    archive = transport.rooted(archive, file=True)
    require(output is None or (output.is_dir() and not output.is_symlink()
                               and next(output.iterdir(), None) is None),
            "the restore target is not an empty directory")
    size = archive.stat().st_size
    require(size <= max_bytes and sha256(archive) == acceptance.checksum(archive_sha256),
            "native custody archive exceeds its cap or differs from the producer digest")
    with tarfile.open(archive, "r:") as source:
        entries = iter(source)
        first = next(entries, None)
        require(first is not None and first.name == "manifest.json" and first.size <= MAX_MANIFEST_BYTES,
                "native custody archive lacks a bounded first manifest")
        functional_transport.check_transport_member(first, "manifest.json", first.size, 0o600)
        with source.extractfile(first) as stream:
            data = stream.read(MAX_MANIFEST_BYTES + 1)
        manifest = validate_manifest(data, manifest_sha256)
        require(manifest["max_bytes"] >= size, "native custody archive exceeds its native cap")
        if output is not None:
            output.chmod(0o700)
            for relative in sorted(manifest["directories"], key=lambda name: (name.count("/"), name)):
                (output / relative).mkdir(mode=0o700)
                (output / relative).chmod(0o700)
        last = first
        for name, mode in directory_members(manifest):
            member = next(entries, None)
            require(member is not None, "native custody archive omitted a directory")
            transport.check_directory_member(member, name, mode)
            last = member
        expected = iter(manifest["files"].items())
        count = 0
        for member in entries:
            relative, identity = next(expected, (None, None))
            require(relative is not None, "native custody archive has an extra member")
            functional_transport.check_transport_member(member, PREFIX + relative, identity["bytes"],
                                                        identity["mode"])
            digest = hashlib.sha256()
            with source.extractfile(member) as original:
                if output is None:
                    while block := original.read(transport.CHUNK):
                        digest.update(block)
                else:
                    with (output / relative).open("xb") as copied:
                        while block := original.read(transport.CHUNK):
                            digest.update(block)
                            copied.write(block)
                        os.fchmod(copied.fileno(), identity["mode"])
                        copied.flush()
                        os.fsync(copied.fileno())
            require(digest.hexdigest() == identity["sha256"],
                    "native custody file bytes differ from the manifest: " + relative)
            count += 1
            last = member
        require(count == len(manifest["files"]), "native custody archive omitted a file")
        end = last.offset_data + ((last.size + 511) // 512) * 512
    require(size == ((end + 1024 + 10239) // 10240) * 10240, "native custody tar trailer is noncanonical")
    with archive.open("rb") as stream:
        stream.seek(end)
        while block := stream.read(transport.CHUNK):
            require(not any(block), "native custody tar trailer contains data")
    if output is not None:
        for relative, mode in sorted(manifest["directories"].items(),
                                     key=lambda item: (-item[0].count("/"), item[0])):
            (output / relative).chmod(mode)
            functional_transport.sync_directory(output / relative)
        output.chmod(manifest["root_mode"])
        functional_transport.sync_directory(output)
        require(restored_roster(output) == manifest_roster(manifest),
                "restored native custody differs from the manifest")
    return manifest, data


def manifest_roster(manifest):
    return (manifest["root_mode"], manifest["directories"],
            {name: (item["bytes"], item["mode"]) for name, item in manifest["files"].items()})


def restored_roster(root):
    """Names, lengths and modes of a restored root; its bytes were hashed as they were written."""
    files, directories = {}, {}
    stack = [root]
    while stack:
        with os.scandir(stack.pop()) as entries:
            for entry in entries:
                path = Path(entry.path)
                relative = path.relative_to(root).as_posix()
                if entry.is_dir(follow_symlinks=False):
                    directories[relative] = transport.checked_mode(path, True)[0]
                    stack.append(path)
                else:
                    mode, length = transport.checked_mode(path, False)
                    files[relative] = (length, mode)
    return transport.checked_mode(root, True)[0], dict(sorted(directories.items())), dict(sorted(files.items()))


def produce(root, archive, producer, max_bytes, omit=()):
    """Native side: publish a producer record only after the archive replays as a relocated copy."""
    root = transport.rooted(root)
    transport.cap(max_bytes)
    archive = transport.fresh(archive, (root,))
    producer = transport.fresh(producer, (root, archive))
    head = attempt_index.head(root)
    with Reads(root) as seen:
        facts, needed, records = judge(root, head)
    trees = work_trees(root, facts, records, omit)
    files, directories = roster(root, facts, needed, seen, trees)
    census, omitted = account(root, files, directories)
    total = sum(item["bytes"] for item in files.values())
    manifest = {"schema": SCHEMA, "status": "passed", "head": head, "original_root": str(root),
                "attempts": facts, "work_trees": trees, "census": census, "omitted": omitted,
                "root_mode": transport.checked_mode(root, True)[0], "directories": directories,
                "files": files, "file_count": len(files), "directory_count": len(directories),
                "total_bytes": total, "max_bytes": max_bytes}
    data = attempt_index.canonical(manifest)
    manifest_sha = hashlib.sha256(data).hexdigest()
    validate_manifest(data, manifest_sha)
    archive_sha = archive_write(root, data, archive, max_bytes)
    try:
        with tempfile.TemporaryDirectory(prefix=".custody-readback-", dir=archive.parent) as scratch:
            relocated = Path(scratch).resolve(strict=True) / "custody"
            relocated.mkdir(mode=0o700)
            read_archive(archive, archive_sha, manifest_sha, max_bytes, relocated)
            require_same(facts, judge(relocated, head, str(root))[0])
        require(attempt_index.head(root) == head, "the original journal advanced during transport")
        record = {"schema": PRODUCER_SCHEMA, "status": "passed", "head": head, "original_root": str(root),
                  "attempts": facts, "script_sha256": sha256(__file__),
                  "transport": {"archive_name": archive.name, "archive_sha256": archive_sha,
                                "archive_bytes": archive.stat().st_size, "manifest_sha256": manifest_sha,
                                "max_bytes": max_bytes, "file_count": len(files),
                                "directory_count": len(directories), "total_bytes": total}}
        return {**record, "census": census, "producer_sha256": transport.publish(producer, record)}
    except BaseException:
        # No producer record names this archive, so it is not a transfer.
        archive.unlink(missing_ok=True)
        raise


def read_producer(path, expected_sha256):
    path = transport.rooted(path, file=True)
    with path.open("rb") as stream:
        data = stream.read(acceptance.MAX_JSON_BYTES + 1)
    require(len(data) <= acceptance.MAX_JSON_BYTES
            and hashlib.sha256(data).hexdigest() == acceptance.checksum(expected_sha256),
            "native custody producer differs from its external digest")
    record = acceptance.decode(data)
    acceptance.exact(record, {"schema", "status", "head", "original_root", "attempts", "script_sha256",
                              "transport"}, "native custody producer")
    require(record["schema"] == PRODUCER_SCHEMA and record["status"] == "passed"
            and acceptance.checksum(record["script_sha256"]) == sha256(__file__),
            "native custody producer is not this frozen implementation")
    attempt_index.check_head(record["head"])
    attempt_index.original_custody_path(record["original_root"])
    facts = record["transport"]
    acceptance.exact(facts, {"archive_name", "archive_sha256", "archive_bytes", "manifest_sha256",
                             "max_bytes", "file_count", "directory_count", "total_bytes"},
                     "native custody producer transport")
    require(isinstance(facts["archive_name"], str) and "/" not in facts["archive_name"]
            and acceptance.relative_path(facts["archive_name"]) == facts["archive_name"],
            "native custody producer archive name differs")
    acceptance.checksum(facts["archive_sha256"])
    acceptance.checksum(facts["manifest_sha256"])
    for key in ("archive_bytes", "max_bytes", "file_count", "directory_count", "total_bytes"):
        acceptance.uint(facts[key], "native custody producer " + key, 1)
    require(facts["archive_bytes"] <= facts["max_bytes"] and transport.canonical(record) == data,
            "native custody producer is not canonical or exceeds its cap")
    return path, data, record


class Unconfirmed(Exception):
    """The verified root is in place, but its admission did not conclude."""


@contextmanager
def placing(namespace):
    """Serialize placements into one journal namespace without leaving a file in it."""
    descriptor = os.open(namespace, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def admit(archive, producer, producer_sha256, journal_heads, max_bytes, output, record):
    """Bundle side: a custody root appears only after the relocated journal replays.

    The rename into the journal namespace is the commit. Every refusal, and
    every file the record keeps, comes before it. A failure after it is never
    reported as a rejection: the verified root stays, the outcome is
    ``unconfirmed`` and admitting the same transfer again confirms it in place.
    """
    transport.cap(max_bytes)
    record = transport.fresh(record)
    output = Path(output)
    require(output.is_absolute() and not record.is_relative_to(output.parent)
            and not output.is_relative_to(record),
            "the admission record must lie outside the native journal namespace")
    record.mkdir(mode=0o700)
    known = {"schema": ADMISSION_SCHEMA, "output": str(output), "archive": str(archive),
             "producer_sha256": producer_sha256, "journal_heads": str(journal_heads),
             "collector_sha256": sha256(__file__)}
    try:
        admit_checked(archive, producer, producer_sha256, journal_heads, max_bytes, output, record, known)
        transport.publish(record / "receipt.json", {**known, "status": "admitted", "error": None})
    except REJECTIONS as error:
        # ``placement`` is recorded at the commit, so its absence means nothing was placed.
        if "placement" not in known:
            # The refusal is retained; this transfer put nothing in the journal namespace.
            transport.publish(record / "receipt.json", {**known, "status": "rejected", "error": str(error)})
            raise
        message = ("the verified root is in place at " + str(output) + ", but its admission did not conclude: "
                   + str(error) + "; admit the same transfer again with a new record directory to confirm it")
        try:
            transport.publish(record / "receipt.json", {**known, "status": "unconfirmed", "error": message})
        except REJECTIONS:
            pass  # The record itself may be what failed; the raised outcome still says what is on disk.
        raise Unconfirmed(message) from error
    return {**known, "status": "admitted"}


def admit_checked(archive, producer, producer_sha256, journal_heads, max_bytes, output, record, known):
    producer_path, producer_data, produced = read_producer(producer, producer_sha256)
    facts = produced["transport"]
    archive = transport.rooted(archive, file=True)
    require(archive != producer_path and archive.name == facts["archive_name"]
            and archive.stat().st_size == facts["archive_bytes"],
            "the delivered archive differs from its producer record")
    anchors_path = transport.rooted(journal_heads, file=True)
    anchors = acceptance.read_json(anchors_path)
    require(isinstance(anchors, list), "operator journal heads must be an array")
    for item in anchors:
        acceptance.exact(item, {"head", "original_root"}, "native journal anchor")
    named = [item for item in anchors
             if attempt_index.check_head(item["head"])["journal_id"] == produced["head"]["journal_id"]]
    require(len(named) == 1, "operator journal heads do not name this journal exactly once")
    head = named[0]["head"]
    original_root = str(attempt_index.original_custody_path(named[0]["original_root"]))
    require(produced["head"] == head and produced["original_root"] == original_root,
            "the producer names another head or original root than the operator")
    namespace = output.parent
    require(output.name == head["journal_id"] and namespace.name == "native-attempts"
            and namespace.is_dir() and namespace.resolve(strict=True) == namespace
            and all(not path.is_relative_to(namespace.parent)
                    for path in (archive, producer_path, anchors_path)),
            "admit to <bundle>/native-attempts/<journal id>, with the transfer and the operator heads "
            "outside the bundle")
    cap = min(max_bytes, facts["max_bytes"])

    def checked(manifest, root):
        """Everything that can still refuse this transfer, for a root that is not yet committed."""
        require(manifest["head"] == head and manifest["original_root"] == original_root
                and manifest["attempts"] == produced["attempts"]
                and all(manifest[key] == facts[key] for key in ("file_count", "directory_count", "total_bytes")),
                "the producer record differs from its archive manifest")
        judged = judge(root, head, original_root)[0]
        require_same(manifest["attempts"], judged)
        require(sha256(archive) == facts["archive_sha256"] and sha256(producer_path) == producer_sha256
                and acceptance.read_json(anchors_path) == anchors,
                "transfer inputs changed during admission")
        known.update({"head": head, "original_root": original_root, "archive_sha256": facts["archive_sha256"],
                      "manifest_sha256": facts["manifest_sha256"],
                      "journal_heads_sha256": sha256(anchors_path), "attempts": judged,
                      "file_count": facts["file_count"], "directory_count": facts["directory_count"],
                      "total_bytes": facts["total_bytes"]})

    def retain(manifest_data):
        for name, data in (("producer.json", producer_data), ("manifest.json", manifest_data)):
            with (record / name).open("xb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())

    if os.path.lexists(output):
        # An earlier admission placed a root and may not have concluded. Confirm it where it is.
        manifest, manifest_data = read_archive(archive, facts["archive_sha256"], facts["manifest_sha256"], cap)
        require(output.is_dir() and not output.is_symlink()
                and restored_roster(output) == manifest_roster(manifest)
                and all(sha256(output / name) == item["sha256"] for name, item in manifest["files"].items()),
                "an existing root at " + str(output) + " is not this transfer; nothing was replaced")
        checked(manifest, output)
        retain(manifest_data)
        known["placement"] = "confirmed"
    else:
        pending = output.with_name("." + output.name + ".pending")
        require(not os.path.lexists(pending),
                "an interrupted transfer left " + str(pending) + "; inspect and remove it before retrying")
        # Creating it is the claim: a concurrent admission fails here and removes nothing.
        pending.mkdir(mode=0o700)
        try:
            manifest, manifest_data = read_archive(archive, facts["archive_sha256"],
                                                   facts["manifest_sha256"], cap, pending)
            checked(manifest, pending)
            retain(manifest_data)
            with placing(namespace):
                # A rename would silently replace an empty directory.
                require(not os.path.lexists(output),
                        "another admission placed " + str(output) + " first; nothing was replaced")
                os.rename(pending, output)
                known["placement"] = "placed"
        except BaseException:
            if "placement" not in known:
                shutil.rmtree(pending, ignore_errors=True)
            raise
    functional_transport.sync_directory(namespace)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    commands = parser.add_subparsers(dest="command", required=True)
    native = commands.add_parser("produce", help="archive one complete original custody root")
    native.add_argument("--root", required=True, type=Path)
    native.add_argument("--archive", required=True, type=Path)
    native.add_argument("--producer", required=True, type=Path)
    native.add_argument("--max-bytes", required=True, type=int)
    native.add_argument("--omit", action="append", default=[], metavar="DIRECTORY",
                        help="a further work tree inside an admitted output, relative to the root")
    bundle = commands.add_parser("admit", help="restore, replay and place one transported custody root")
    bundle.add_argument("--archive", required=True, type=Path)
    bundle.add_argument("--producer-manifest", required=True, type=Path)
    bundle.add_argument("--producer-sha256", required=True)
    bundle.add_argument("--journal-heads", required=True, type=Path,
                        help="operator-held native journal heads and original roots")
    bundle.add_argument("--max-bytes", required=True, type=int)
    bundle.add_argument("--output", required=True, type=Path)
    bundle.add_argument("--record", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "produce":
            result = produce(args.root, args.archive, args.producer, args.max_bytes, args.omit)
        else:
            result = admit(args.archive, args.producer_manifest, args.producer_sha256, args.journal_heads,
                           args.max_bytes, args.output, args.record)
        print(json.dumps(result, sort_keys=True))
    except Unconfirmed as error:
        print("native custody admission unconfirmed: " + str(error), file=sys.stderr)
        return 2
    except REJECTIONS as error:
        print("native custody transport failed: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
