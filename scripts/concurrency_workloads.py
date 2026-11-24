"""Fixed two-worker HA workloads and replay of original installed client replies."""
import hashlib
import json
import re

from domain_run import require
import repeatable_assembly as owned

# Two data workers issue the first and third workloads. During backup and
# membership maintenance the second worker executes one real control operation.
# The snapshot workload also crosses OpenRaft's 5,000-entry production policy.
COUNTS = {"reads-writes": (500, 500), "backup-writes": (1000, 1),
          "snapshot-writes": (5500, 500), "membership-writes": (1000, 1)}
HASH = re.compile(r"[0-9a-f]{64}\Z")


def payload(attempt, scenario, index):
    value = f"{attempt}/{scenario}/{index}"
    return {"step": index, "sha256": hashlib.sha256(value.encode()).hexdigest()}


def documents(attempt, scenario):
    prefix = hashlib.sha256(f"{attempt}/{scenario}".encode()).hexdigest()[:24]
    return [f"conc-{prefix}-{index}" for index in (0, 1)]


def batch(attempt, scenario, index, collection):
    keys = documents(attempt, scenario)
    # Rust serializes MutationBatch and the tagged Put fields in declaration
    # order, and canonicalizes fields of each untyped document body.
    body = dict(sorted(payload(attempt, scenario, index).items()))
    return {"idempotency_key": f"conc/{keys[0]}/{index}", "operations": [
        {"op": "put", "collection": collection, "id": key, "body": body,
         **({"expected": "absent"} if index == 0 else {})} for key in keys]}


def request(attempt, scenario, worker, index, collection):
    keys = documents(attempt, scenario)
    if worker in ("seed", "write"):
        value = batch(attempt, scenario, index, collection)
        args = ["mutate", json.dumps(value, sort_keys=True, separators=(",", ":"))]
    elif worker == "read":
        args = ["get", collection, keys[index % 2]]
    else:
        require(worker == "snapshot", "unexpected data worker")
        read = {"documents": [{"collection": collection, "id": key} for key in keys],
                "queries": [], "time_bounds": None}
        args = ["read-snapshot", json.dumps(read, sort_keys=True, separators=(",", ":"))]
    return {"id": index, "argv": args, "timeout_ms": 30000}


def reply_result(line, identifier):
    reply = json.loads(line)
    require(type(reply.get("id")) is int and reply["id"] == identifier
            and type(reply.get("status")) is int and reply["status"] == 0
            and reply.get("document", {}).get("ok") is True, "native client rejected the request")
    return reply["document"]["result"]


def replay_data(attempt, name, collection, incarnation, counts, rows, replies):
    keys = documents(attempt, name)
    writes = {}
    observed = []
    for worker, count in {"seed": 1, "write": counts[0],
                          **({"read": counts[1]} if name == "reads-writes" else {}),
                          **({"snapshot": counts[1]} if name == "snapshot-writes" else {})}.items():
        intervals = rows[worker]
        require(len(intervals) == len(replies[worker]) == count,
                "shortened, extra or missing native client operations")
        end = -1
        last_revision = -1
        for position, (row, line) in enumerate(zip(intervals, replies[worker])):
            i = 0 if worker == "seed" else position + 1
            owned.exact(row, {"id", "sent_ns", "finished_ns"}, "original client timing")
            require(type(row["id"]) is int and i == row["id"] and type(row["sent_ns"]) is int
                    and type(row["finished_ns"]) is int and max(end, 0) <= row["sent_ns"]
                    < row["finished_ns"], "unordered native client requests")
            end = row["finished_ns"]
            result = reply_result(line, i)
            if worker in {"seed", "write"}:
                receipt = result["receipt"]
                revision = receipt["revision"]
                encoded = json.dumps(batch(attempt, name, i, collection), ensure_ascii=False, separators=(",", ":")).encode()
                require(result["idempotency_key"] == f"conc/{keys[0]}/{i}"
                        and result["request_digest"] == hashlib.sha256(encoded).hexdigest()
                        and type(revision) is int and revision > last_revision and revision > 0
                        and receipt["versions"] == {f"/{collection}/{key}": revision for key in keys},
                        "write reply does not commit this atomic pair")
                require(not writes or revision > next(reversed(writes)), "committed write revisions repeated or regressed")
                writes[revision] = (i, row)
                last_revision = revision
            elif worker == "read":
                observed.append((result["document"], keys[i % 2], row))
            else:
                snapshot = result["snapshot"]
                require(snapshot["incarnation"] == incarnation and type(snapshot["revision"]) is int
                        and snapshot["revision"] > 0 and snapshot["queries"] == []
                        and [entry["key"] for entry in snapshot["documents"]]
                        == [{"collection": collection, "id": key} for key in keys],
                        "snapshot belongs to another generation or omits part of the atomic pair")
                pair = [entry["document"] for entry in snapshot["documents"]]
                require(pair[0]["version"] == pair[1]["version"] <= snapshot["revision"]
                        and pair[0]["body"] == pair[1]["body"], "coherent snapshot returned a torn pair")
                observed.extend(zip(pair, keys, [row, row]))
    ordered = iter(writes.items())
    next_commit = next(ordered)
    latest = 0
    for doc, key, row in observed:
        while next_commit is not None and next_commit[1][1]["finished_ns"] <= row["sent_ns"]:
            latest = next_commit[0]
            next_commit = next(ordered, None)
        version = doc["version"]
        require(doc["id"] == key and type(version) is int and version in writes and version >= latest,
                "read did not return an original committed document")
        step, write = writes[version]
        require(doc["body"] == payload(attempt, name, step) and write["sent_ns"] < row["finished_ns"],
                "read has the wrong body or saw a future write")
    return writes


def raft_observation(status, incarnation, voters):
    require(status["mode"] == "replicated" and status["incarnation"] == incarnation
            and status["observation"] == "local_committed_state"
            and status["node_id"] == status["leader"] and status["node_id"] in voters
            and status["raft_voters"] == voters
            and type(status["raft_applied_index"]) is int and status["raft_applied_index"] > 0,
            "management status is not from the original tenant leader and voters")
    for name in ("raft_snapshot_index", "raft_membership_index"):
        index = status[name]
        require(index is None or type(index) is int and 0 <= index <= status["raft_applied_index"],
                "Raft evidence is ahead of committed application")
    return status


def overlap(a, b):
    return max(a["sent_ns"], b["sent_ns"]) < min(a["finished_ns"], b["finished_ns"])


def samples(name, rows):
    writes = rows["write"]
    role = {"reads-writes": "read", "snapshot-writes": "snapshot"}.get(name, "maintenance")
    others = rows[role]
    require(writes and others and any(overlap(write, item) for write in writes for item in others),
            "the two original workers never had operations in flight together")
    ordered = sorted([*writes, *others], key=lambda row: (row["sent_ns"], row["finished_ns"], row["id"]))
    return [{"sequence": n, "elapsed_ns": row["finished_ns"] - row["sent_ns"], "status": "passed"}
            for n, row in enumerate(ordered)]
