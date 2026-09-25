"""Durable, append-only admission journal for native release attempts.

The journal is written before dispatch and retained outside each disposable
runner output. An interrupted write or an unfinished admission rejects replay.
It is local custody evidence; an independent operator must still retain and
anchor the complete journal outside the candidate bundle.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

SCHEMA = "kasumi-native-attempt-index-v1"
ACCEPTANCE_SCHEMA = "kasumi-release-acceptance-v1"
KIND_OUTCOMES = {"repeatable-assembly": "kasumi-owned-repeatable-assembly-v1"}
DOMAIN_SCHEMA = "kasumi-owned-repeatable-assembly-domain-observation-v1"
TARGETS = {"x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
           "aarch64-apple-darwin"}
INDEX = "index.jsonl"
MAX_ROW_BYTES = 1 << 16
ZERO = "0" * 64
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


def require(value, message):
    if not value:
        raise ValueError(message)


def exact(value, keys, label):
    require(isinstance(value, dict) and set(value) == set(keys), label + " fields differ")


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate attempt index JSON key")
        result[key] = value
    return result


def decode(data):
    require(len(data) <= MAX_ROW_BYTES and data.endswith(b"\n"),
            "attempt index row is oversized or truncated")
    value = json.loads(data, object_pairs_hook=unique_pairs,
                       parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    require(canonical(value) == data, "attempt index row is not canonical")
    return value


def relative(value):
    require(isinstance(value, str) and value and "\\" not in value,
            "invalid attempt index path")
    path = PurePosixPath(value)
    require(not path.is_absolute() and ".." not in path.parts
            and path.as_posix() == value and value != ".", "unsafe attempt index path")
    return value


def disjoint_output(output, existing):
    """Keep native attempts out of each other's retained output trees."""
    candidate = PurePosixPath(output)
    return all(not candidate.is_relative_to(PurePosixPath(other))
               and not PurePosixPath(other).is_relative_to(candidate)
               for other in existing)


def name(value):
    require(isinstance(value, str) and ID.fullmatch(value), "invalid native attempt id")
    return value


def owned_file(root, relative_path):
    root = Path(root).resolve(strict=True)
    path = root / relative(relative_path)
    require(path.is_relative_to(root), "attempt index file escapes custody")
    ancestor = path
    while ancestor != root:
        require(not ancestor.is_symlink(), "attempt index file is aliased")
        ancestor = ancestor.parent
    require(stat.S_ISREG(path.stat(follow_symlinks=False).st_mode),
            "attempt index file is absent or aliased")
    require(path.resolve(strict=True).is_relative_to(root), "attempt index file escapes custody")
    return path


def file_ref(root, path):
    relative_path = Path(path).relative_to(root).as_posix()
    root = Path(root).resolve(strict=True)
    path = owned_file(root, relative_path)
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"path": path.relative_to(root).as_posix(), "sha256": digest,
            "bytes": path.stat().st_size}


def check_ref(root, value):
    root = Path(root).resolve(strict=True)
    exact(value, {"path", "sha256", "bytes"}, "attempt index reference")
    require(isinstance(value["sha256"], str)
            and re.fullmatch(r"[0-9a-f]{64}", value["sha256"])
            and type(value["bytes"]) is int and value["bytes"] >= 0,
            "invalid attempt index reference identity")
    path = owned_file(root, value["path"])
    require(file_ref(root, path) == value, "attempt index reference bytes differ")
    return path


def fsync_directory(path):
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def census(attempts, entries):
    names = set()
    with os.scandir(attempts) as children:
        for child in children:
            if child.name == INDEX:
                require(child.is_file(follow_symlinks=False), "attempt index is not a regular file")
                continue
            name(child.name)
            require(child.is_dir(follow_symlinks=False), "attempt namespace contains an aliased entry")
            names.add(child.name)
    require(names == set(entries), "attempt namespace omits or invents an indexed admission")
    for attempt_id, entry in entries.items():
        expected = {"attempt.json"} if entry["terminal"] is not None else set()
        with os.scandir(attempts / attempt_id) as children:
            actual = set()
            for child in children:
                require(child.is_file(follow_symlinks=False),
                        "attempt directory contains an aliased or non-file entry")
                actual.add(child.name)
        require(actual == expected, "attempt directory omits or invents terminal custody")


def check_outcome(root, begin, receipt, outcome):
    require(isinstance(outcome, dict)
            and outcome.get("schema") == KIND_OUTCOMES[begin["kind"]]
            and outcome.get("custody_root") == str(root / begin["output"])
            and outcome.get("attempt_id") == begin["id"]
            and outcome.get("status") == receipt["status"]
            and outcome.get("started_at") == receipt["started_at"]
            and outcome.get("finished_at") == receipt["finished_at"],
            "native attempt receipt differs from original outcome")


def check_domain_observation(root, begin, receipt):
    """Bind an unqualified domain observation to its original native attempt."""
    observed_ref = receipt["domain_observation"]
    if receipt["status"] != "passed":
        require(observed_ref is None,
                "failed native attempt cannot select a domain observation")
        return
    exact(observed_ref, {"path", "sha256", "bytes"}, "domain observation reference")
    require(observed_ref["path"] == begin["output"] + "/domain-observation.json",
            "domain observation is outside its admitted output")
    observation = json.loads(check_ref(root, observed_ref).read_bytes(),
                             object_pairs_hook=unique_pairs)
    exact(observation, {"schema", "status", "attempt_id", "custody_root", "target",
                        "started_at", "finished_at", "launcher", "report", "outputs"},
          "native domain observation")
    require(observation["schema"] == DOMAIN_SCHEMA
            and observation["status"] == "unqualified"
            and observation["attempt_id"] == begin["id"]
            and observation["custody_root"] == str(root / begin["output"])
            and observation["started_at"] == receipt["started_at"]
            and observation["finished_at"] == receipt["finished_at"]
            and observation["target"] in TARGETS,
            "native domain observation differs from original attempt")
    output = root / begin["output"]
    require(observation["launcher"] == {
                "path": "launcher.json", "sha256": receipt["evidence"]["sha256"],
                "bytes": receipt["evidence"]["bytes"]},
            "domain observation selected another launcher")
    check_ref(output, observation["launcher"])
    require(observation["report"]["path"] == "assembly/attempt.json",
            "domain observation selected another assembly report")
    check_ref(output, observation["report"])
    outputs = observation["outputs"]
    require(isinstance(outputs, list) and len(outputs) == 2,
            "domain observation output roster differs")
    by_id = {}
    for item in outputs:
        exact(item, {"id", "name", "first", "second"}, "domain output")
        kind, name = item["id"], item["name"]
        require(kind in {"package", "source"} and kind not in by_id
                and isinstance(name, str) and "/" not in name and "\\" not in name
                and name.startswith("kasumi-")
                and (name.endswith("-source.tar.gz") if kind == "source" else
                     name.endswith("-" + observation["target"] + ".tar.gz")),
                "domain observation output identity differs")
        for side, directory in (("first", "assembly-a-output"),
                                ("second", "assembly-b-output")):
            require(item[side]["path"] == "assembly/" + directory + "/" + name,
                    "domain observation output path differs")
            check_ref(output, item[side])
        require(item["first"]["sha256"] == item["second"]["sha256"]
                and item["first"]["bytes"] == item["second"]["bytes"],
                "domain observation outputs differ")
        by_id[kind] = item
    require(set(by_id) == {"source", "package"}
            and outputs == sorted(outputs, key=lambda item: item["id"]),
            "domain observation output roster differs")


def replay_rows(root, attempts, stream, *, complete):
    entries = {}
    outputs = set()
    previous = ZERO
    sequence = 0
    while line := stream.readline(MAX_ROW_BYTES + 1):
        row = decode(line)
        require(row.get("schema") == SCHEMA and type(row.get("sequence")) is int
                and row["sequence"] == sequence + 1 and row.get("previous_sha256") == previous,
                "attempt index sequence or hash chain differs")
        sequence += 1
        previous = hashlib.sha256(line).hexdigest()
        event = row.get("event")
        attempt_id = name(row.get("id"))
        if event == "begin":
            exact(row, {"schema", "sequence", "previous_sha256", "event", "id", "kind",
                        "output", "started_at"}, "attempt admission")
            output = relative(row["output"])
            require(isinstance(row["kind"], str) and row["kind"] in KIND_OUTCOMES
                    and not PurePosixPath(output).parts[0] == "attempts"
                    and disjoint_output(output, outputs) and attempt_id not in entries
                    and isinstance(row["started_at"], str) and row["started_at"],
                    "duplicate or invalid native attempt admission")
            entries[attempt_id] = {"begin": row, "terminal": None}
            outputs.add(output)
        elif event == "terminal":
            exact(row, {"schema", "sequence", "previous_sha256", "event", "id", "receipt"},
                  "attempt terminal event")
            require(attempt_id in entries and entries[attempt_id]["terminal"] is None,
                    "attempt terminal event has no unique admission")
            require(row["receipt"]["path"] == "attempts/" + attempt_id + "/attempt.json",
                    "attempt terminal receipt is outside its admission")
            receipt = json.loads(check_ref(root, row["receipt"]).read_bytes(),
                                 object_pairs_hook=unique_pairs)
            exact(receipt, {"schema", "id", "status", "evidence", "domain_observation", "started_at",
                            "finished_at", "processes"}, "native attempt receipt")
            begin = entries[attempt_id]["begin"]
            require(receipt["schema"] == ACCEPTANCE_SCHEMA and receipt["id"] == attempt_id
                    and receipt["status"] in {"passed", "failed", "interrupted"}
                    and receipt["started_at"] == begin["started_at"]
                    and isinstance(receipt["finished_at"], str)
                    and isinstance(receipt["processes"], list),
                    "native attempt terminal state differs")
            evidence = receipt["evidence"]
            require(isinstance(evidence, dict)
                    and PurePosixPath(relative(evidence.get("path"))).is_relative_to(begin["output"]),
                    "native attempt result escapes admitted output")
            outcome = json.loads(check_ref(root, evidence).read_bytes(), object_pairs_hook=unique_pairs)
            check_outcome(root, begin, receipt, outcome)
            check_domain_observation(root, begin, receipt)
            entries[attempt_id]["terminal"] = row
        else:
            raise ValueError("unknown native attempt index event")
    census(attempts, entries)
    if complete:
        require(entries and all(value["terminal"] is not None for value in entries.values()),
                "native attempt index has an unfinished admission")
    return entries, sequence, previous


@contextmanager
def locked_index(root, *, create=False, shared=False):
    root = Path(root)
    require(not root.is_symlink(), "attempt custody root is aliased")
    root = root.resolve(strict=True)
    require(root.is_dir(), "attempt custody root is absent")
    attempts = root / "attempts"
    if create and not attempts.exists():
        attempts.mkdir()
        fsync_directory(root)
    require(not attempts.is_symlink() and attempts.is_dir(), "attempt namespace is absent or aliased")
    flags = (os.O_RDONLY if shared else os.O_RDWR | os.O_APPEND) | getattr(os, "O_NOFOLLOW", 0)
    if create:
        flags |= os.O_CREAT
    descriptor = os.open(attempts / INDEX, flags, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_SH if shared else fcntl.LOCK_EX)
        if create:
            fsync_directory(attempts)
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            stream.seek(0)
            entries, sequence, previous = replay_rows(root, attempts, stream, complete=False)
        yield root, attempts, descriptor, entries, sequence, previous
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def append(descriptor, row):
    data = canonical(row)
    require(len(data) <= MAX_ROW_BYTES, "attempt index row exceeds bound")
    while data:
        count = os.write(descriptor, data)
        require(count > 0, "attempt index append did not progress")
        data = data[count:]
    os.fsync(descriptor)


def replay(root, *, complete=True):
    with locked_index(root, shared=True) as (_, _, _, entries, _, _):
        if complete:
            require(entries and all(value["terminal"] is not None for value in entries.values()),
                    "native attempt index has an unfinished admission")
        return entries


def begin(root, attempt_id, kind, output, started_at):
    name(attempt_id)
    require(isinstance(kind, str) and kind in KIND_OUTCOMES,
            "unknown native attempt kind")
    with locked_index(root, create=True) as (root, attempts, descriptor, entries, sequence, previous):
        output = Path(output)
        require(output.is_absolute() and not output.exists(),
                "native attempt output is not a fresh absolute path")
        output = output.resolve()
        require(output.is_relative_to(root), "native attempt output escapes permanent custody")
        relative_output = output.relative_to(root).as_posix()
        relative(relative_output)
        require(not output.is_relative_to(attempts)
                and attempt_id not in entries
                and disjoint_output(relative_output,
                                    (item["begin"]["output"] for item in entries.values())),
                "native attempt admission reuses an id or output")
        (attempts / attempt_id).mkdir(exist_ok=False)
        fsync_directory(attempts)
        row = {"schema": SCHEMA, "sequence": sequence + 1, "previous_sha256": previous,
               "event": "begin", "id": attempt_id, "kind": kind,
               "output": relative_output, "started_at": started_at}
        append(descriptor, row)
        return row


def finish(root, attempt_id, receipt):
    name(attempt_id)
    with locked_index(root) as (root, attempts, descriptor, entries, sequence, previous):
        require(attempt_id in entries and entries[attempt_id]["terminal"] is None,
                "native attempt has no open admission")
        begin_row = entries[attempt_id]["begin"]
        exact(receipt, {"schema", "id", "status", "evidence", "domain_observation", "started_at",
                        "finished_at", "processes"}, "native attempt receipt")
        require(receipt["schema"] == ACCEPTANCE_SCHEMA and receipt["id"] == attempt_id
                and receipt["started_at"] == begin_row["started_at"]
                and receipt["status"] in {"passed", "failed", "interrupted"},
                "native attempt receipt differs from admission")
        require(PurePosixPath(relative(receipt["evidence"]["path"])).is_relative_to(begin_row["output"]),
                "native attempt evidence escapes admitted output")
        outcome = json.loads(check_ref(root, receipt["evidence"]).read_bytes(),
                             object_pairs_hook=unique_pairs)
        check_outcome(root, begin_row, receipt, outcome)
        check_domain_observation(root, begin_row, receipt)
        path = attempts / attempt_id / "attempt.json"
        data = canonical(receipt)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        file = os.open(path, flags, 0o600)
        try:
            while data:
                count = os.write(file, data)
                require(count > 0, "attempt receipt write did not progress")
                data = data[count:]
            os.fsync(file)
        finally:
            os.close(file)
        fsync_directory(path.parent)
        row = {"schema": SCHEMA, "sequence": sequence + 1, "previous_sha256": previous,
               "event": "terminal", "id": attempt_id, "receipt": file_ref(root, path)}
        append(descriptor, row)
        return row
