"""Replay the native permanent-session witness from its retained files.

The sorted Control ledgers can be much larger than RAM on the reference host.
The temporary SQLite index joins original operation outcomes to claim ordinals
and page boundaries. Verification never opens the installation for writing.
"""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import uuid

from package_release import owned_directory, owned_file
from verify_release_acceptance import (BACKUP_SESSION_FLOOR, checksum, decode, number, read_json,
                                       require, sha256, uint)

SCHEMA = "kasumi-backup-session-floor-v1"
LABELS = ("pre-restart", "post-restart", "post-replay")


def document(root, name):
    return read_json(owned_file(root, name))


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode()


def identity(value):
    require(isinstance(value, str) and str(uuid.UUID(value)) == value and uuid.UUID(value).int > 0,
            "noncanonical or nil session identity")
    return value


def session_id(nonce, ordinal):
    raw = hashlib.sha256(f"{SCHEMA}/{nonce}/{ordinal}".encode()).digest()
    return str(uuid.UUID(bytes=raw[:16], version=4))


def checked_lines(root, name, expected_digest, consume):
    digest = hashlib.sha256()
    count = size = 0
    with owned_file(root, name).open("rb") as stream:
        while line := stream.readline((1 << 20) + 1):
            require(len(line) <= 1 << 20 and line.endswith(b"\n"), "truncated or oversized ledger row")
            digest.update(line)
            consume(decode(line))
            count += 1
            size += len(line)
    require(digest.hexdigest() == checksum(expected_digest), name + " original digest differs")
    return count, size


def index_originals(db, root, plan, summary, minimum_failed=257):
    db.executescript("""
        CREATE TABLE original(id TEXT PRIMARY KEY, ord INTEGER UNIQUE, kind TEXT, result BLOB);
        CREATE TABLE position(ord INTEGER PRIMARY KEY, claim INTEGER, id TEXT, digest TEXT);
        CREATE INDEX session_position ON position(id);
    """)
    resolutions = {}
    total = plan["sessions"]
    nonce = identity(plan["nonce"])

    def insert(row):
        ordinal = uint(row["ordinal"], "session ordinal")
        identifier = session_id(nonce, ordinal)
        require(ordinal < total and identifier == row["session_id"] and
                row["request_id"] == f"floor-{ordinal:06d}", "original request identity differs")
        number(row["seconds"], "original operation duration")
        kind = row["kind"]
        require(kind in ("complete", "aborted") and row["stage"] in ("populate", "resolve"),
                "original result is not terminal")
        if (profile := plan.get("profile")) and (interval := profile["complete_interval"]) is not None:
            reserve = total - plan["kill_reserve"]
            complete = ordinal % interval == 0 if ordinal < reserve else ordinal < reserve + plan["kill_reserve"] // 2
            require(kind == ("complete" if complete else "aborted"), "original differs from the prospective workload")
        result = row["checkpoint"] if kind == "complete" else row["outcome"]
        require(isinstance(result, dict) and
                (row["outcome"] is None if kind == "complete" else row["checkpoint"] is None),
                "original result is ambiguous")
        if row["resolution"] is not None:
            require(row["stage"] == "resolve" and ordinal >= total - plan["kill_reserve"],
                    "resolution belongs to the wrong stage or target")
            resolutions[ordinal] = row["resolution"]
        db.execute("INSERT INTO original VALUES(?,?,?,?)",
                   (identifier, ordinal, kind, hashlib.sha256(canonical(result)).digest()))

    count, _ = checked_lines(root, "original.jsonl", summary["original_journal_sha256"], insert)
    require(count == total == summary["originals"], "original cohort is incomplete")
    failed, = db.execute("SELECT count(*) FROM original WHERE kind='aborted'").fetchone()
    require(failed == uint(summary["original_failed"], "failed sessions", minimum_failed),
            "original failed cohort differs")
    return failed, resolutions


# Both terminal formats reserve the whole envelope before the session starts.
SLOT_CAPACITY = (64 << 10) + (2 << 20) + 84
SLOT_HEADER = 72


def terminal_digests(path, identifier, kind):
    """Authenticate the physical record and its exact logical ciphertext."""
    with path.open("rb") as stream:
        extent = os.fstat(stream.fileno()).st_size
        header = stream.read(SLOT_HEADER)
        tag = {"intent": 1, "outcome": 2}[kind]
        require(len(header) == SLOT_HEADER and header[:8] in (b"KSMSES01", b"KSMSES02") and header[8] == tag
                and header[9:16] == bytes(7) and header[16:32] == uuid.UUID(identity(identifier)).bytes,
                "terminal belongs to a different session or slot")
        length = int.from_bytes(header[32:40], "little")
        require(0 < length <= SLOT_CAPACITY, "invalid terminal ciphertext length")
        require(extent == SLOT_HEADER + SLOT_CAPACITY
                or (header[:8] == b"KSMSES02" and extent == SLOT_HEADER + length),
                "invalid terminal extent")
        physical = hashlib.sha256(header)
        payload = hashlib.sha256()
        remaining = length
        while remaining:
            data = stream.read(min(65536, remaining))
            require(data, "truncated terminal ciphertext")
            physical.update(data)
            payload.update(data)
            remaining -= len(data)
        require(payload.digest() == header[40:72], "terminal ciphertext digest mismatch")
        while data := stream.read(65536):
            require(data.count(0) == len(data), "nonzero terminal padding")
            physical.update(data)
    return physical.hexdigest(), length, payload.hexdigest()


def index_destination(db, root):
    """Reconstruct the native destination census with a disk-backed sort."""
    base = owned_directory(root, "persistent/destination")
    db.execute("CREATE TABLE destination(name TEXT PRIMARY KEY, size INTEGER, digest TEXT, payload_size INTEGER, payload_digest TEXT) WITHOUT ROWID")

    def visit(directory, depth):
        require(depth <= 8, "unexpected destination directory depth")
        with os.scandir(directory) as entries:
            for entry in entries:
                if entry.is_dir(follow_symlinks=False):
                    visit(entry.path, depth + 1)
                else:
                    require(entry.is_file(follow_symlinks=False), "unowned destination entry")
                    path = Path(entry.path)
                    name = path.relative_to(base).as_posix()
                    size = entry.stat(follow_symlinks=False).st_size
                    terminal = (None, None, None)
                    if path.name in ("intent.kasumi", "outcome.kasumi"):
                        require(path.parent.parent == base / "sessions", "unexpected terminal path")
                        terminal = terminal_digests(path, path.parent.name, path.stem)
                    db.execute("INSERT INTO destination VALUES(?,?,?,?,?)", (name, size, *terminal))

    visit(base, 0)
    aggregate = hashlib.sha256()
    stats = dict(files=0, bytes=0, intents=0, outcomes=0, session_objects=0)
    for name, size, digest in db.execute("SELECT name,size,digest FROM destination ORDER BY name"):
        stats["files"] += 1
        stats["bytes"] += size
        if name.endswith("intent.kasumi"):
            stats["intents"] += 1
        elif name.endswith("outcome.kasumi"):
            stats["outcomes"] += 1
        elif "/objects/" in name:
            stats["session_objects"] += 1
        aggregate.update(f"{name}\t{size}\t{digest or '-'}\n".encode())
    return {**stats, "sha256": aggregate.hexdigest()}


def check_ciphertext(db, identifier, kind, size, digest):
    row = db.execute("SELECT payload_size,payload_digest FROM destination WHERE name=?",
                     (f"sessions/{identifier}/{kind}.kasumi",)).fetchone()
    require(row == (uint(size, "selected ciphertext length", 1), checksum(digest)),
            "published " + kind + " differs from its selected Control row")


def index_selected(db, root, obs, total, identities, destination):
    incarnation = identity(identities["source_incarnation"])
    # StoragePurpose serializes this internally tagged Rust struct in declaration order.
    purpose = {"kind": "Standalone", "installation_id": identity(identities["installation"]),
               "tenant": "floor-source", "incarnation": incarnation}
    purpose_digest = hashlib.sha256(json.dumps(purpose, separators=(",", ":")).encode()).hexdigest()
    previous = ""
    source_and_destination = None

    def insert(row):
        nonlocal previous, source_and_destination
        ident = identity(row["session_id"])
        require(ident > previous, "duplicate or unordered selected session")
        previous = ident
        original = db.execute("SELECT ord,kind,result FROM original WHERE id=?", (ident,)).fetchone()
        require(original is not None, "unrecognized selected session")
        ordinal, kind, expected = original
        binding, decision = row["binding"], row["decision"]
        require(isinstance(decision, dict) and binding["tenant"] == "floor-source" and
                binding["source_incarnation"] == incarnation and binding["principal"] == "owner" and
                binding["destination_alias"] == "floor" and binding["request_id"] == f"floor-{ordinal:06d}",
                "selected claim differs from its original request")
        for key in ("record_sha256", "source_purpose_sha256", "intent_ciphertext_sha256"):
            checksum(binding[key])
        for key in ("command_id", "binding_nonce"):
            identity(binding[key])
        physical = binding["namespace_binding"]
        require(physical["kind"] == "filesystem" and binding["source_purpose_sha256"] == purpose_digest and
                all(physical[key] == destination[key] for key in ("device", "inode")),
                "missing original source purpose or physical destination binding")
        for key in ("installation_id", "namespace_id"):
            identity(physical[key])
        for key in ("origin_node_id", "inode"):
            uint(physical[key], key, 1)
        uint(physical["device"], "filesystem device", 1)
        scope = (binding["source_purpose_sha256"], physical)
        if source_and_destination is None:
            source_and_destination = scope
        require(scope == source_and_destination, "original source or physical destination changed across cohort")
        position = binding["position"]
        uint(position["term"], "Control term", 1)
        uint(position["index"], "Control index", 1)
        checksum(position["command_sha256"])
        claim = uint(binding["ordinal"], "claim ordinal", 1)
        terminal = uint(decision["ordinal"], "terminal ordinal", claim + 1)
        require(terminal <= 2 * total, "terminal row beyond cohort")
        outcome = decision["outcome"]
        require(outcome["outcome"] == kind and
                outcome["intent_ciphertext_sha256"] == binding["intent_ciphertext_sha256"],
                "terminal outcome belongs to a different original intent")
        if kind == "complete":
            result = outcome["checkpoint"]
            require(result["backup_id"] == ident and result["tenant"] == binding["tenant"] and
                    result["source_incarnation"] == incarnation and
                    uint(result["revision"], "checkpoint revision") == uint(binding["revision"], "claim revision"),
                    "completed checkpoint differs from its claim")
        else:
            result = outcome
            require(result["session_id"] == ident and result["principal"] == "owner" and result["reason"],
                    "abort identity or failure reason is missing")
        require(hashlib.sha256(canonical(result)).digest() == expected, "original terminal outcome changed")
        checksum(decision["decision_sha256"])
        checksum(decision["ciphertext_sha256"])
        check_ciphertext(db, ident, "outcome", decision["ciphertext_bytes"], decision["ciphertext_sha256"])
        check_ciphertext(db, ident, "intent", binding["intent_ciphertext_bytes"], binding["intent_ciphertext_sha256"])
        db.executemany("INSERT INTO position VALUES(?,?,?,?)", (
            (claim, 1, ident, checksum(binding["row_sha256"])),
            (terminal, 0, ident, checksum(decision["row_sha256"]))))

    count, size = checked_lines(root, "streams/pre-restart.jsonl", obs["stream_sha256"], insert)
    require(count == total and size == uint(obs["stream_bytes"], "ledger length"), "selected cohort differs")


def check_pages(db, obs, total, failed):
    pages = obs["pages"]
    require(isinstance(pages, list) and pages, "missing bounded session observations")
    head = obs["head"]
    require(uint(head["count"], "selected rows") == 2 * total and
            uint(obs["sessions"], "selected sessions") == total and
            uint(obs["completed"], "complete sessions") == total - failed and
            uint(obs["aborted"], "aborted sessions") == failed and uint(obs["pending"], "pending") == 0,
            "selected Control counts differ from original decisions")
    aggregate = obs["aggregate"]
    require(aggregate["last_binding_revision"] == head["last_applied_revision"] and
            aggregate["completed"] == total - failed and aggregate["aborted"] == failed and
            aggregate["claimed_without_terminal"] == 0, "Control aggregate differs from selected entries")
    end = largest = 0
    for index, page in enumerate(pages):
        start = uint(page["scanned_from"], "first page row", 1)
        require(uint(page["index"], "page number") == index and start == end + 1,
                "page gap, overlap or ordering error")
        end = uint(page["scanned_through"], "last page row", start)
        require(end <= head["count"] and end - start < 512, "page scanned more than its budget")
        rows = db.execute("SELECT claim,id,digest FROM position WHERE ord BETWEEN ? AND ? ORDER BY ord",
                          (start, end)).fetchall()
        claims = [identifier for claim, identifier, _ in rows if claim]
        require(len(rows) == end - start + 1 and len(claims) == uint(page["entries"], "page entries")
                and len(claims) <= 256, "page cardinality differs from the selected ledger")
        interval = (claims[0], claims[-1]) if claims else (None, None)
        require(interval == (page["first_session"], page["last_session"]), "wrong session page endpoints")
        cursor = {"after_ordinal": end, "after_row_sha256": rows[-1][2]} if index + 1 < len(pages) else None
        require(page["next"] == cursor, "continuation differs from its committed row")
        largest = max(largest, len(claims))
    require(end == 2 * total and largest == obs["max_page_entries"], "page chain incomplete")


def check_boundaries(db, witness, failed):
    boundary, cleanup, verified = witness["boundary"], witness["cleanup"], witness["verify"]
    limits = witness["limits"]
    require(limits["session_record_bytes"] == boundary["record_limit"] == 65_536 and
            limits["cleanup_page_objects"] == limits["observation_page_sessions"] == 256,
            "historical record and cleanup limits differ")
    accepted = identity(boundary["accepted_session"])
    for kind in ("intent", "outcome"):
        require(uint(boundary[f"accepted_{kind}_plaintext_bytes"], "accepted plaintext") == 65_536 and
                0 < uint(boundary[f"accepted_{kind}_ciphertext_bytes"], "ciphertext") <=
                uint(limits["encrypted_session_record_read_bytes"], "encrypted read bound"),
                "record did not exercise the exact boundary")
        check_ciphertext(db, accepted, kind, boundary[f"accepted_{kind}_ciphertext_bytes"],
                         boundary[f"accepted_{kind}_ciphertext_sha256"])
        require("backup session record exceeds limit" in boundary[f"rejected_{kind}_write"] and
                boundary[f"forged_{kind}_read"] and
                verified["boundary_after_restart"][f"forged_{kind}_read"] == boundary[f"forged_{kind}_read"],
                "missing original record refusal or changed cold-reopen result")
    require(boundary["encrypted_read_limit"] == limits["encrypted_session_record_read_bytes"] and
            boundary["accepted_status_outcome"]["session_id"] == accepted and
            len({accepted, identity(boundary["forged_intent_session"]),
                 identity(boundary["forged_outcome_session"])}) == 3 and
            boundary["forged_intent_plaintext_bytes"] == 65_537 and
            verified["boundary_after_restart"]["accepted_unchanged"] is True,
            "independent boundary record identities differ")
    passes = cleanup["passes"]
    require(isinstance(passes, list) and len(passes) >= 2 and cleanup["bound"] == 256 and
            all(isinstance(cleanup[key], str) and cleanup[key].startswith("InvalidArgument:")
                for key in ("over_bound_request", "zero_request")), "missing cleanup boundary")
    staged = uint(cleanup["staged_objects"], "staged cleanup objects", 257)
    ident = identity(cleanup["session_id"])
    deleted = 0
    for index, page in enumerate(passes):
        n = uint(page["deleted_objects"], "deleted objects")
        require(n <= 256 and page["session_id"] == ident and
                page["more_objects_observed"] is (index + 1 < len(passes)), "cleanup page or cursor differs")
        deleted += n
    empty = {"session_id": ident, "deleted_objects": 0, "more_objects_observed": False}
    require(deleted == staged and cleanup["repeat"] == verified["cleanup_after_restart"] == empty,
            "cleanup did not exhaust the original objects")
    replayed = verified["replayed"]
    require(uint(replayed["aborted"], "replayed aborts") == failed and
            uint(replayed["complete"], "replayed completions") + failed == witness["observed_distinct_sessions"] and
            sum(uint(v, "retained refusal count") for v in verified["aborted_backup_refusals"].values()) == failed
            and all(k.startswith("Conflict:") for k in verified["aborted_backup_refusals"]),
            "replay did not return every original terminal result")


def original_kill(root, receipt, process, stage, target, marker):
    require(receipt["stage"] == process["stage"] == stage and receipt["target"] == target and
            receipt["marker"] == marker and receipt["signal"] == process["signal"] == 9 and
            receipt["exit_code"] is process["exit_code"] is None and receipt["operation_returned"] is False and
            receipt["process_id"] == process["process_id"] and
            all(receipt[key] == process[key] for key in ("stdout", "stderr")),
            "missing original SIGKILL at the named native operation")
    number(receipt["seconds_from_marker_to_reap"], "time from barrier to process death")
    markers = []
    dispatched = []
    with owned_file(root, process["stdout"]).open("rb") as stream:
        while line := stream.readline((1 << 20) + 1):
            require(len(line) <= 1 << 20, "oversized child output line")
            if line.startswith((marker + " ").encode()):
                require(dispatched == ([] if target is None else [target]), "kill barrier precedes its dispatch")
                markers.append(decode(line[len(marker) + 1:]))
            else:
                # Rust libtest prefixes the first stdout line with the exact test name.
                line = line.removeprefix(f"test {process['argv'][2]} ... ".encode())
            if line.startswith(b"KASUMI_FLOOR_DISPATCH "):
                dispatched.append(decode(line[len(b"KASUMI_FLOOR_DISPATCH "):]))
            require(not line.startswith(b"KASUMI_FLOOR_WRITTEN "), "interrupted operation returned")
    require(markers == [receipt["marker_payload"]] and dispatched == ([] if target is None else [target]),
            "native child did not report the original barrier and dispatch")
    return markers[0]


def check_kills(root, witness, resolved, db):
    processes = witness["processes"]
    reserve = uint(witness["plan"]["kill_reserve"], "kill targets", 2)
    total = witness["observed_distinct_sessions"]
    require(processes == document(root, "processes.json") and
            [p["stage"] for p in processes] == ["populate", *(["kill"] * reserve), "resolve", "verify"],
            "incorrect original child process order")
    logs = set()
    for process in processes:
        for key in ("stdout", "stderr"):
            path = process[key]
            require(path not in logs and path.startswith("logs/") and
                    sha256(owned_file(root, path)) == checksum(process[key + "_sha256"]), "child log changed")
            logs.add(path)
    population, before, after = processes[0], processes[-2], processes[-1]
    for process in (population, after):
        require(process["exit_code"] == 0 and process["signal"] is None and
                process["process_id"] == witness[process["stage"]]["process_id"], "native session stage failed")
    require(before["process_id"] == witness["resolve"]["process_id"] != after["process_id"],
            "verification did not use a fresh process")
    cold = document(root, "cold-kill.json")
    require(cold == witness["cold_kill"], "cold kill differs from original receipt")
    marker = original_kill(root, cold, before, "resolve", None, "KASUMI_FLOOR_PRE_RESTART_DURABLE")
    pre = document(root, "streams/pre-restart.observation.json")
    require(marker == {"process_id": before["process_id"], "stream": pre["stream"],
                       "stream_sha256": pre["stream_sha256"], "sessions": total, "head": pre["head"],
                       "resolve_sha256": sha256(owned_file(root, "resolve.json"))},
            "cold kill did not preserve the completed pre-restart observation")
    kills = witness["kills"]
    require(len(kills) == len(resolved) == reserve and
            witness["resolve"]["resolutions"] == [resolved[i] for i in sorted(resolved)],
            "an interrupted process lacks its original resolution")
    kinds = set()
    for ordinal, record, process in zip(range(total - reserve, total), kills, processes[1:-2], strict=True):
        payload = original_kill(root, record, process, "kill", ordinal, "KASUMI_FLOOR_WRITE_OUTSTANDING")
        original = document(root, f"inflight-{ordinal:06d}.json")
        resolution = resolved[ordinal]
        ident = session_id(witness["plan"]["nonce"], ordinal)
        kind = original["kind"]
        write, method = {"complete": ("claim", "backup_checkpoint_named"),
                         "aborted": ("terminal", "abort_backup_session")}[kind]
        request = f"floor-{ordinal:06d}"
        expected_input = {"destination": "floor", "session_id": ident}
        if kind == "complete":
            expected_input["request_id"] = request
        else:
            expected_input["reason"] = f"floor failure {ordinal:06d}: source capture abandoned"
        require(original["ordinal"] == ordinal and original["session_id"] == ident and
                original["request_id"] == request and original["input"] == expected_input and
                resolution["operation"] == original["operation"] == method and
                payload == {"ordinal": ordinal, "session_id": ident, "write": write,
                            "point": "control-apply-row-durable-before-publication", "process_id": process["process_id"]},
                "recovery used a different request or interrupted write")
        old, new = resolution["observed_after_kill"], resolution["observed_after_resolution"]
        positions = dict(db.execute("SELECT claim,ord FROM position WHERE id=?", (ident,)))
        added = 0
        for key, is_claim in (("claim_ordinal", 1), ("terminal_ordinal", 0)):
            require(uint(new[key], key, 1) == positions[is_claim], "resolved position differs from selected ledger")
            if old[key] is None:
                added += 1
            else:
                require(old[key] == new[key], "resolution replaced a committed row")
        previous, current = old["destination_sha256"], new["destination_sha256"]
        require(set(previous) == set(current) == {"intent", "outcome", "root"} and
                all(value is None or checksum(value) == current[key] for key, value in previous.items()),
                "resolution changed an existing destination object")
        require(new["claim_ordinal"] < new["terminal_ordinal"] and
                uint(resolution["rows_added"], "resolved rows") == added ==
                resolution["head_after"]["count"] - resolution["head_before"]["count"],
                "recovery changed a decided effect")
        kinds.add(kind)
    require(kinds == {"aborted", "complete"}, "missing interrupted backup or terminal write")


def verify(installation, witness):
    """Accept only the full native release cohort."""
    return replay_installation(installation, witness, "full")


def replay_installation(installation, witness, cohort):
    root = Path(installation)
    require(cohort in ("full", "regression", "page"), "unknown native session cohort")
    require(witness == document(root, "witness.json") and witness["schema"] == SCHEMA and
            witness["case"] == "backup-sessions" and witness["cohort"] == cohort and
            "former_limit" not in witness and uint(witness["floor"], "session floor") == BACKUP_SESSION_FLOOR and
            witness["crosses_floor"] is (cohort == "full"), "wrong backup-session evidence contract")
    plan = document(root, "plan.json")
    require(plan == witness["plan"] and plan["schema"] == SCHEMA and plan["cohort"] == cohort,
            "session plan differs")
    total = uint(plan["sessions"], "planned sessions", BACKUP_SESSION_FLOOR if cohort == "full" else 2)
    if profile := plan.get("profile"):
        probe = document(root, "filesystem-probe.json")
        disk = document(root, "disk-policy.json")
        require(cohort == "full" and probe["status"] == "passed" and
                sha256(owned_file(root, "filesystem-probe.json")) == checksum(profile["probe_sha256"]) and
                probe["device"] == profile["device"] and uint(probe["namespace_entries"], "probed sessions") >= total and
                disk["profile"] == profile and disk["max_bytes"] == 200 << 30 and
                disk["max_persistent_files"] == profile["max_persistent_files"] and
                disk["max_persistent_subdirectories"] == profile["max_persistent_subdirectories"] and
                profile["directory_policy"] == probe["fixture_directory_policy"] and
                profile["file_allocation_policy"] == probe["fixture_file_policy"] and
                (profile["complete_interval"] is None or 2 <= uint(profile["complete_interval"], "completion interval") <= 256),
                "session workload or disk policy differs from its original measured filesystem")
    require(total == uint(witness["observed_distinct_sessions"], "reported sessions") and
            witness["minimum_failed_terminal_outcomes"] == 257, "session counts differ from plan")
    for key in ("boundary", "resolve", "verify", "populate", "kills", "cleanup"):
        require(witness[key] == document(root, key + ".json"), "original " + key + " report differs")
    identities = document(root, "ids.json")
    independent, verified = witness["independent"], witness["verify"]
    physical = verified["data_identities"]
    if profile:
        require(physical["persistent/destination"]["device"] == profile["device"],
                "session destination used a different filesystem from the measured profile")
    require(physical == witness["resolve"]["data_identities"] and
            set(physical) == {".", "persistent", "persistent/node.kv", "persistent/destination", "scratch"} and
            all(uint(row["device"], "selected device", 1) and uint(row["inode"], "selected inode", 1)
                and isinstance(row["directory"], bool) for row in physical.values()),
            "cold replay used different installation storage")
    refusals = witness["resolve"]["page_refusals"]
    require(set(refusals) == {"over_bound", "forged_cursor"} and
            all(text.startswith("InvalidArgument:") for text in refusals.values()),
            "missing native page-boundary or cursor refusal")
    reference_digest = None
    with tempfile.TemporaryDirectory(prefix="kasumi-session-verification-") as work:
        with closing(sqlite3.connect(Path(work) / "originals.sqlite")) as db:
            try:
                census = index_destination(db, root)
                minimum_failed = 1 if cohort == "regression" else 257
                failed, resolutions = index_originals(db, root, plan, independent, minimum_failed)
                require(failed == uint(witness["failed_terminal_outcomes"], "retained failures", minimum_failed),
                        "reported retained failures differ")
                for label in LABELS:
                    obs = document(root, f"streams/{label}.observation.json")
                    name = f"streams/{label}.jsonl"
                    digest = checksum(obs["stream_sha256"])
                    require(obs["label"] == label and obs["stream"] == name and
                            independent["streams"][label]["sha256"] == digest,
                            "stream identity differs")
                    if reference_digest is None:
                        index_selected(db, root, obs, total, identities, physical["persistent/destination"])
                        reference_digest = digest
                    else:
                        path = owned_file(root, name)
                        require(digest == reference_digest == sha256(path) and
                                path.stat().st_size == uint(obs["stream_bytes"], "ledger size"),
                                "cold-reopen or replay stream changed")
                    summary = independent["streams"][label]
                    require(summary == {"stream": name, "sha256": digest, "bytes": obs["stream_bytes"],
                                        "pages": len(obs["pages"]), "max_page_entries": obs["max_page_entries"],
                                        "process_id": obs["process_id"], "head": obs["head"],
                                        "aborted": obs["aborted"], "completed": obs["completed"]},
                            "independent stream receipt differs from original page traversal")
                    pid = witness["resolve" if label == "pre-restart" else "verify"]["process_id"]
                    require(obs["process_id"] == pid and obs["head"] == verified["head_before"] ==
                            verified["head_after"] and obs["aggregate"] == verified["aggregate_before"] ==
                            verified["aggregate_after"], "replay changed the original selected state")
                    require(uint(obs["max_page_entries"], "observed page size") <=
                            uint(plan.get("page_limit", 256), "configured page size", 1) <= 256,
                            "page exceeded its original request")
                    check_pages(db, obs, total, failed)
                limits, head = witness["limits"], verified["head_before"]
                require(identity(identities["control_incarnation"]) == head["origin_incarnation"] and
                        uint(head["encoded_bytes"], "selected Control bytes", 1) == limits["selected_binding_bytes"]
                        <= uint(plan["control_binding_budget"], "configured Control bytes", 1) ==
                        limits["control_binding_budget_bytes"] and checksum(head["sha256"]),
                        "selected Control ledger exceeds its original quota or belongs to another incarnation")
                check_boundaries(db, witness, failed)
                check_kills(root, witness, resolutions, db)
            except sqlite3.IntegrityError as error:
                raise ValueError("repeated original session, request or committed row ordinal") from error
    require(census == verified["destination_before"] == witness["resolve"]["destination"] == verified["destination_after"] and
            uint(census["intents"], "republished intents") >= total and
            uint(census["outcomes"], "republished outcomes") >= total and checksum(census["sha256"]),
            "original destination changed across cold reopen or replay")
    return total
