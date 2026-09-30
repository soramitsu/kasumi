"""Durable, append-only admission journal for native release attempts.

Each native host keeps one journal under its own custody root. The first row
names the journal, its host and its target; every later row admits or
terminates one attempt of a registered kind. The journal is written before
dispatch and retained outside each disposable runner output. An interrupted
write or an unfinished admission rejects replay, and a torn or rewritten
journal is never repaired.

Every dispatcher writes its outcome record, the file its terminal receipt
names as ``evidence``, inside the admitted output. The record carries the
kind's schema from ``KIND_OUTCOMES`` together with ``attempt_id``,
``custody_root``, ``status``, ``started_at`` and ``finished_at``. Every kind
except repeatable-assembly also names the journal ``target`` and a sorted
``products`` roster of ``{"id", "file"}`` references relative to the custody
root. A passed outcome retains the kind's complete roster; a failed or
interrupted one retains any subset of it. The repeatable-assembly launcher
keeps its original record and retains its products through its domain
observation.

``head`` is the value an independent operator anchors outside the candidate
bundle. A bundle is replayed against those anchors with ``replay_journals``,
which rejects a repeated journal or attempt id. The journal is local custody
evidence; it cannot certify an anchor it did not receive.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

SCHEMA = "kasumi-native-attempt-index-v2"
ACCEPTANCE_SCHEMA = "kasumi-release-acceptance-v1"
DOMAIN_SCHEMA = "kasumi-owned-repeatable-assembly-domain-observation-v1"
TARGETS = frozenset({"x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
                     "aarch64-apple-darwin"})
LINUX = frozenset(target for target in TARGETS if "-linux-" in target)
BINARIES = frozenset({"kasumid", "kasumictl", "kasumi-authority"})
# The acceptance verifier's domain gate kinds; a unit test pins this roster to
# its SCENARIOS table.
DOMAIN_KINDS = frozenset({
    "audit-retention", "backup-cleanup", "benchmark-matrix", "capacity-ha",
    "capacity-standalone", "concurrency", "correctness", "dependency-review", "ha-faults",
    "ha-soak", "installed", "key-retention", "observability", "oci-smoke", "package-smoke",
    "providers", "recovery", "repeatable-assembly", "systemd-smoke"})


def outcome_schema(kind):
    return "kasumi-native-" + kind + "-outcome-v1"


# kind -> (outcome schema, product roster of a passed outcome, admissible targets)
KINDS = {
    "functional": (outcome_schema("functional"),
                   BINARIES | {"source-archive", "source-inventory"}, TARGETS),
    "independent-build": (outcome_schema("independent-build"), BINARIES, TARGETS),
    "oci-image": (outcome_schema("oci-image"), frozenset({"image", "image-sbom"}), LINUX),
    **{kind: (outcome_schema(kind), frozenset({"report"}),
              LINUX if kind in {"oci-smoke", "systemd-smoke"} else TARGETS)
       for kind in sorted(DOMAIN_KINDS - {"repeatable-assembly"})},
    "repeatable-assembly": ("kasumi-owned-repeatable-assembly-v1", None, TARGETS),
}
KIND_OUTCOMES = {kind: spec[0] for kind, spec in KINDS.items()}
STATUSES = {"passed", "failed", "interrupted"}
INDEX = "index.jsonl"
MAX_ROW_BYTES = 1 << 16
MAX_JSON_BYTES = 16 << 20
ZERO = "0" * 64
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
IDENTITY_FIELDS = {"schema", "sequence", "previous_sha256", "event", "journal_id", "host", "target"}
BEGIN_FIELDS = {"schema", "sequence", "previous_sha256", "event", "id", "kind", "output",
                "started_at"}
TERMINAL_FIELDS = {"schema", "sequence", "previous_sha256", "event", "id", "receipt"}
RECEIPT_FIELDS = {"schema", "id", "status", "evidence", "domain_observation", "started_at",
                  "finished_at", "processes"}
HEAD_FIELDS = {"journal_id", "host", "target", "sequence", "sha256"}


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


def reject_constant(value):
    raise ValueError("nonfinite attempt index JSON: " + value)


def decode(data):
    require(len(data) <= MAX_ROW_BYTES and data.endswith(b"\n"),
            "attempt index row is oversized or truncated")
    value = json.loads(data, object_pairs_hook=unique_pairs, parse_constant=reject_constant)
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


def timestamp(value, label):
    require(isinstance(value, str), label + " is not a UTC timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError:
        raise ValueError(label + " is not a UTC timestamp") from None
    require(parsed.tzinfo is not None and parsed.utcoffset() == dt.timedelta(),
            label + " is not a UTC timestamp")
    return parsed


def check_identity(value):
    """The journal's own identity: one host building one native target."""
    require(isinstance(value.get("journal_id"), str) and ID.fullmatch(value["journal_id"])
            and isinstance(value.get("host"), str) and ID.fullmatch(value["host"])
            and value.get("target") in TARGETS,
            "invalid attempt journal identity")
    return {"journal_id": value["journal_id"], "host": value["host"], "target": value["target"]}


def check_head(value):
    exact(value, HEAD_FIELDS, "attempt journal head")
    check_identity(value)
    require(type(value["sequence"]) is int and value["sequence"] >= 1
            and isinstance(value["sha256"], str) and DIGEST.fullmatch(value["sha256"]),
            "invalid attempt journal head")
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
    require(isinstance(value["sha256"], str) and DIGEST.fullmatch(value["sha256"])
            and type(value["bytes"]) is int and value["bytes"] >= 0,
            "invalid attempt index reference identity")
    path = owned_file(root, value["path"])
    require(file_ref(root, path) == value, "attempt index reference bytes differ")
    return path


def json_ref(root, value):
    """Parse exactly the referenced bytes, never a later replacement."""
    path = check_ref(root, value)
    with path.open("rb") as stream:
        data = stream.read(MAX_JSON_BYTES + 1)
    require(len(data) <= MAX_JSON_BYTES and len(data) == value["bytes"]
            and hashlib.sha256(data).hexdigest() == value["sha256"],
            "attempt index reference bytes differ")
    return json.loads(data, object_pairs_hook=unique_pairs, parse_constant=reject_constant)


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


def check_products(output, kind, products, passed):
    """Retain each kind's products by exact bytes inside its admitted output."""
    roster = KINDS[kind][1]
    require(isinstance(products, list), "native attempt product roster differs")
    ids = []
    paths = set()
    for item in products:
        exact(item, {"id", "file"}, "native attempt product")
        require(item["id"] in roster and isinstance(item["file"], dict)
                and item["file"].get("path") not in paths,
                "native attempt product roster differs")
        check_ref(output, item["file"])
        ids.append(item["id"])
        paths.add(item["file"]["path"])
    require(ids == sorted(set(ids)) and (not passed or set(ids) == roster),
            "native attempt product roster differs")


def check_outcome(root, identity, begin, receipt, outcome):
    kind = begin["kind"]
    require(isinstance(outcome, dict)
            and outcome.get("schema") == KIND_OUTCOMES[kind]
            and outcome.get("custody_root") == str(root / begin["output"])
            and outcome.get("attempt_id") == begin["id"]
            and outcome.get("status") == receipt["status"]
            and outcome.get("started_at") == receipt["started_at"]
            and outcome.get("finished_at") == receipt["finished_at"],
            "native attempt receipt differs from original outcome")
    if KINDS[kind][1] is None:
        check_domain_observation(root, identity, begin, receipt)
        return
    require(receipt["domain_observation"] is None,
            "native attempt kind has no domain observation")
    require(outcome.get("target") == identity["target"],
            "native attempt outcome names another target")
    check_products(root / begin["output"], kind, outcome.get("products"),
                   receipt["status"] == "passed")


def check_domain_observation(root, identity, begin, receipt):
    """Bind an unqualified domain observation to its original native attempt."""
    observed_ref = receipt["domain_observation"]
    if receipt["status"] != "passed":
        require(observed_ref is None,
                "failed native attempt cannot select a domain observation")
        return
    exact(observed_ref, {"path", "sha256", "bytes"}, "domain observation reference")
    require(observed_ref["path"] == begin["output"] + "/domain-observation.json",
            "domain observation is outside its admitted output")
    observation = json_ref(root, observed_ref)
    exact(observation, {"schema", "status", "attempt_id", "custody_root", "target",
                        "started_at", "finished_at", "launcher", "report", "outputs"},
          "native domain observation")
    require(observation["schema"] == DOMAIN_SCHEMA
            and observation["status"] == "unqualified"
            and observation["attempt_id"] == begin["id"]
            and observation["custody_root"] == str(root / begin["output"])
            and observation["started_at"] == receipt["started_at"]
            and observation["finished_at"] == receipt["finished_at"]
            and observation["target"] == identity["target"],
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


def check_admission(row, identity, entries):
    """The same admission contract binds a new row and a replayed one."""
    exact(row, BEGIN_FIELDS, "attempt admission")
    output = relative(row["output"])
    require(isinstance(row["kind"], str) and row["kind"] in KINDS, "unknown native attempt kind")
    require(identity["target"] in KINDS[row["kind"]][2],
            "native attempt kind is not admissible on the journal target")
    require(PurePosixPath(output).parts[0] != "attempts"
            and disjoint_output(output, (item["begin"]["output"] for item in entries.values()))
            and row["id"] not in entries,
            "duplicate or invalid native attempt admission")
    timestamp(row["started_at"], "native attempt start")


def check_receipt(root, identity, begin, receipt):
    """The same terminal contract binds a new receipt and a replayed one."""
    exact(receipt, RECEIPT_FIELDS, "native attempt receipt")
    require(receipt["schema"] == ACCEPTANCE_SCHEMA and receipt["id"] == begin["id"]
            and receipt["status"] in STATUSES
            and receipt["started_at"] == begin["started_at"]
            and isinstance(receipt["processes"], list),
            "native attempt receipt differs from admission")
    require(timestamp(receipt["finished_at"], "native attempt finish")
            >= timestamp(begin["started_at"], "native attempt start"),
            "native attempt finished before its admission")
    evidence = receipt["evidence"]
    require(isinstance(evidence, dict)
            and PurePosixPath(relative(evidence.get("path"))).is_relative_to(begin["output"]),
            "native attempt evidence escapes admitted output")
    check_outcome(root, identity, begin, receipt, json_ref(root, evidence))


def replay_rows(root, attempts, stream):
    identity = None
    entries = {}
    previous = ZERO
    sequence = 0
    while line := stream.readline(MAX_ROW_BYTES + 1):
        row = decode(line)
        require(row.get("schema") == SCHEMA, "attempt index row has a foreign schema")
        require(type(row.get("sequence")) is int and row["sequence"] == sequence + 1
                and row.get("previous_sha256") == previous,
                "attempt index sequence or hash chain differs")
        sequence += 1
        previous = hashlib.sha256(line).hexdigest()
        event = row.get("event")
        if sequence == 1:
            require(event == "journal", "attempt journal does not begin with its identity")
            exact(row, IDENTITY_FIELDS, "attempt journal identity")
            identity = check_identity(row)
            continue
        require(event != "journal", "attempt journal repeats its identity")
        attempt_id = name(row.get("id"))
        if event == "begin":
            check_admission(row, identity, entries)
            entries[attempt_id] = {"begin": row, "terminal": None}
        elif event == "terminal":
            exact(row, TERMINAL_FIELDS, "attempt terminal event")
            require(attempt_id in entries and entries[attempt_id]["terminal"] is None,
                    "attempt terminal event has no unique admission")
            require(isinstance(row["receipt"], dict)
                    and row["receipt"].get("path") == "attempts/" + attempt_id + "/attempt.json",
                    "attempt terminal receipt is outside its admission")
            check_receipt(root, identity, entries[attempt_id]["begin"], json_ref(root, row["receipt"]))
            entries[attempt_id]["terminal"] = row
        else:
            raise ValueError("unknown native attempt index event")
    require(identity is not None, "attempt journal has no identity row")
    census(attempts, entries)
    return {"identity": identity, "entries": entries, "sequence": sequence, "sha256": previous}


def journal_head(journal):
    return {**journal["identity"], "sequence": journal["sequence"], "sha256": journal["sha256"]}


def custody(root):
    root = Path(root)
    require(not root.is_symlink(), "attempt custody root is aliased")
    root = root.resolve(strict=True)
    require(root.is_dir(), "attempt custody root is absent")
    return root


@contextmanager
def locked_index(root, *, shared=False):
    root = custody(root)
    attempts = root / "attempts"
    require(not attempts.is_symlink() and attempts.is_dir(), "attempt namespace is absent or aliased")
    flags = (os.O_RDONLY if shared else os.O_RDWR | os.O_APPEND) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(attempts / INDEX, flags)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_SH if shared else fcntl.LOCK_EX)
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            stream.seek(0)
            journal = replay_rows(root, attempts, stream)
        yield root, attempts, descriptor, journal
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


def create(root, journal_id, host, target):
    """Create this host's journal, or confirm an existing one has this exact identity.

    A torn or empty journal is never rewritten: it fails closed like any other
    unreadable journal.
    """
    identity = check_identity({"journal_id": journal_id, "host": host, "target": target})
    row = {"schema": SCHEMA, "sequence": 1, "previous_sha256": ZERO, "event": "journal", **identity}
    root = custody(root)
    attempts = root / "attempts"
    if not attempts.exists() and not attempts.is_symlink():
        attempts.mkdir(mode=0o700)
        fsync_directory(root)
    require(not attempts.is_symlink() and attempts.is_dir(), "attempt namespace is absent or aliased")
    index = attempts / INDEX
    if not index.exists() and not index.is_symlink():
        with os.scandir(attempts) as children:
            require(next(children, None) is None,
                    "attempt namespace holds custody without a journal")
        flags = os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(index, flags, 0o600)
        except FileExistsError:
            pass
        else:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                append(descriptor, row)
                fsync_directory(attempts)
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
            return row
    with locked_index(root, shared=True) as (_, _, _, journal):
        require(journal["identity"] == identity, "attempt journal identity differs")
    return row


def head(root):
    """The chain tip an independent operator anchors outside the bundle."""
    with locked_index(root, shared=True) as (_, _, _, journal):
        return journal_head(journal)


def replay(root, *, complete=True, head=None):
    with locked_index(root, shared=True) as (_, _, _, journal):
        if head is not None:
            require(journal_head(journal) == check_head(head),
                    "attempt journal head differs from its anchor")
        entries = journal["entries"]
        if complete:
            require(entries, "native attempt journal has no admission")
            require(all(value["terminal"] is not None for value in entries.values()),
                    "native attempt index has an unfinished admission")
        return entries


def replay_journals(journals, *, complete=True):
    """Replay every host's journal against its anchor as one attempt history.

    ``journals`` holds ``(root, anchored head)`` pairs. The result maps each
    attempt id to its entry and owning journal id.
    """
    roots = []
    journal_ids = set()
    attempts = {}
    for root, anchor in journals:
        anchor = check_head(anchor)
        resolved = custody(root)
        require(all(not resolved.is_relative_to(other) and not other.is_relative_to(resolved)
                    for other in roots),
                "native attempt journals share custody")
        require(anchor["journal_id"] not in journal_ids, "duplicate native attempt journal id")
        entries = replay(resolved, complete=complete, head=anchor)
        for attempt_id, entry in entries.items():
            require(attempt_id not in attempts, "duplicate native attempt id across journals")
            attempts[attempt_id] = {"journal": anchor["journal_id"], **entry}
        roots.append(resolved)
        journal_ids.add(anchor["journal_id"])
    require(journal_ids, "no native attempt journal was supplied")
    return attempts


def begin(root, attempt_id, kind, output, started_at):
    name(attempt_id)
    require(isinstance(kind, str) and kind in KINDS,
            "unknown native attempt kind")
    with locked_index(root) as (root, attempts, descriptor, journal):
        entries = journal["entries"]
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
        row = {"schema": SCHEMA, "sequence": journal["sequence"] + 1,
               "previous_sha256": journal["sha256"], "event": "begin", "id": attempt_id,
               "kind": kind, "output": relative_output, "started_at": started_at}
        check_admission(row, journal["identity"], entries)
        (attempts / attempt_id).mkdir(mode=0o700, exist_ok=False)
        fsync_directory(attempts)
        append(descriptor, row)
        return row


def finish(root, attempt_id, receipt):
    name(attempt_id)
    with locked_index(root) as (root, attempts, descriptor, journal):
        entries = journal["entries"]
        require(attempt_id in entries and entries[attempt_id]["terminal"] is None,
                "native attempt has no open admission")
        check_receipt(root, journal["identity"], entries[attempt_id]["begin"], receipt)
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
        row = {"schema": SCHEMA, "sequence": journal["sequence"] + 1,
               "previous_sha256": journal["sha256"], "event": "terminal", "id": attempt_id,
               "receipt": file_ref(root, path)}
        append(descriptor, row)
        return row


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    commands = parser.add_subparsers(dest="command", required=True)
    created = commands.add_parser("create", help="create this host's journal and print its head")
    created.add_argument("--root", type=Path, required=True)
    created.add_argument("--journal-id", required=True)
    created.add_argument("--host", required=True)
    created.add_argument("--target", required=True, choices=sorted(TARGETS))
    shown = commands.add_parser("head", help="print the journal head to anchor")
    shown.add_argument("--root", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "create":
            create(args.root, args.journal_id, args.host, args.target)
        sys.stdout.buffer.write(canonical(head(args.root)))
    except (OSError, ValueError) as error:
        print("Attempt journal rejected: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
