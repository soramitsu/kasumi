#!/usr/bin/env python3
"""Shared capacity qualification for the standalone and HA capacity domains.

One operation procedure serves both halves of a domain. A runner executes it
live against installed native processes: every product invocation is an owned
child with an original receipt, every daemon is an owned service, and the
exact corpus driver from the frozen functional evidence measures, loads and
exhaustively verifies the corpus after every operation. The adapter executes
the same procedure again over the retained run with ``Replay``: each step must
be the next original receipt with the exact command, executable and exit, and
every output is re-validated by the same checks that steered the live run. A
report's own status, counts, limits or labels are never accepted.

Admitted limits come from the retained installed configuration, never from the
runner: RSS from the explicit memory admission high-water mark, allocated disk
from the persistent and scratch disk maxima, maintenance workspace from the
scratch disk maximum and the retained-read budget from the explicit admission
reservation cap. Resource rows are projections of raw in-process kernel and
filesystem samples bound to original process receipts.
"""
from __future__ import annotations

import sys


def _renew(arguments):
    """Owned renewal service: renew one profile until standard input closes.

    Standard library only. Each renewal is a child of this process group, which
    the enclosing controller drains, and each outcome is one stdout row.
    """
    import json
    import os
    import select
    import subprocess
    import time

    kasumid, profile, period = arguments[0], arguments[1], float(arguments[2])
    sequence, due = 0, time.monotonic()
    while True:
        readable, _, _ = select.select([sys.stdin.buffer], [], [], max(0.0, due - time.monotonic()))
        if readable:
            if not os.read(sys.stdin.fileno(), 4096):
                return 0
            continue
        started = time.monotonic_ns()
        try:
            child = subprocess.run([kasumid, "credential", "renew", profile], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
            code, output, error = child.returncode, child.stdout, child.stderr
        except subprocess.TimeoutExpired:
            code, output, error = None, b"", b"renewal timed out"
        row = {"sequence": sequence, "started_ns": started, "finished_ns": time.monotonic_ns(),
               "exit_code": code, "output": output.decode("utf-8", "replace")[:4096],
               "error": error.decode("utf-8", "replace")[-2048:]}
        sys.stdout.buffer.write(json.dumps(row, sort_keys=True, separators=(",", ":")).encode() + b"\n")
        sys.stdout.buffer.flush()
        sequence += 1
        due = time.monotonic() + (period if code == 0 else 30)


if __name__ == "__main__" and sys.argv[1:2] == ["renew"]:
    raise SystemExit(_renew(sys.argv[2:]))

import ctypes  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import math  # noqa: E402
import os  # noqa: E402
from pathlib import Path  # noqa: E402
import re  # noqa: E402
import stat  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
import uuid  # noqa: E402

import domain_run  # noqa: E402
from domain_run import require  # noqa: E402
import gate_process  # noqa: E402
import repeatable_assembly as owned  # noqa: E402
from release_gate import sha256  # noqa: E402

LIBRARY = "scripts/capacity_domain.py"
PLAN_SCHEMA = "kasumi-capacity-plan-v1"
REFERENCE = "aarch64-unknown-linux-gnu"
MIN_CORPUS = 3 << 30
OPERATIONS = ("snapshot", "compaction", "restart", "filesystem-backup", "s3-backup",
              "retained-read-pressure", "filesystem-restore", "s3-restore")
HA_OPERATIONS = OPERATIONS[:6] + ("follower-replacement",) + OPERATIONS[6:]
TIMING = {"measured_seconds": 86400, "startup_seconds": 3600, "drain_seconds": 3600}
DRIVER_TIMEOUT = 86400
COMMAND_TIMEOUT = 3600
MAINTENANCE_TIMEOUT = 21600
POLL_TIMEOUT = 60
READY_POLLS = 900
SETTLE_POLLS = 1800
SAMPLE_SECONDS = 5
RENEW_SECONDS = 600
REPLY_SECONDS = 120
CHURN_REQUESTS = 250
CHURN = "capacity_churn"
# The only refusal a retained-read pressure reader may receive.
PRESSURE_REFUSAL = "resource_exhausted"
PARAMETERS = {"timing": TIMING, "driver_timeout": DRIVER_TIMEOUT, "command_timeout": COMMAND_TIMEOUT,
              "maintenance_timeout": MAINTENANCE_TIMEOUT, "sample_seconds": SAMPLE_SECONDS,
              "renew_seconds": RENEW_SECONDS, "churn_requests": CHURN_REQUESTS}
NAME = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")
ALPHABET = bytes(c for c in range(0x21, 0x7F) if c not in (0x22, 0x5C))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def exact(value, fields, label):
    require(isinstance(value, dict) and set(value) == set(fields), label + " fields differ from contract")


def integer(value, label, low, high=(1 << 64) - 1):
    require(type(value) is int and low <= value <= high, label + " is outside its bound")
    return value


def absolute(value, label):
    require(isinstance(value, str) and Path(value).is_absolute() and ".." not in Path(value).parts,
            label + " is not an absolute path")
    return value


def operation_uuid(attempt, label):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "kasumi-capacity/" + attempt + "/" + label))


# ---- Corpus: the driver's exact public generator, reproduced for read checks. ----

def corpus_plan(value):
    exact(value, {"run_id", "seed_sha256", "collection", "documents", "document_bytes", "batch_documents"},
          "capacity corpus plan")
    parsed = uuid.UUID(value["run_id"]) if isinstance(value["run_id"], str) else None
    require(parsed is not None and str(parsed) == value["run_id"] and parsed.int != 0,
            "corpus run identity must be a canonical non-nil UUID")
    require(isinstance(value["seed_sha256"], str) and HEX.fullmatch(value["seed_sha256"]),
            "corpus seed is not a SHA-256 value")
    require(isinstance(value["collection"], str) and NAME.fullmatch(value["collection"])
            and value["collection"] != CHURN, "corpus collection name is invalid or reserved")
    integer(value["documents"], "corpus documents", 1)
    size = integer(value["document_bytes"], "document bytes", 128, 1 << 20)
    batch = integer(value["batch_documents"], "batch documents", 1, 256)
    require((size + 2048) * batch <= 4 << 20, "corpus batch exceeds the driver work bound")
    return value


def corpus_bytes(corpus):
    return corpus["documents"] * corpus["document_bytes"]


def check_corpus_limits(limits, corpus):
    minimum = corpus_bytes(corpus)
    for name in ("max_logical_bytes", "max_snapshot_bytes"):
        require(isinstance(limits, dict) and type(limits.get(name)) is int and limits[name] >= minimum,
                f"tenant {name} cannot admit the document bodies of the corpus")


def document_id(corpus, ordinal):
    return "capacity-" + uuid.UUID(corpus["run_id"]).hex + "-" + str(ordinal)


def document(corpus, ordinal):
    require(type(ordinal) is int and 0 <= ordinal < corpus["documents"], "corpus ordinal out of range")
    length = corpus["document_bytes"] - len(canonical({"ordinal": ordinal, "payload": "", "version": 0}))
    require(length >= 0, "document framing exceeds configured size")
    seed = bytes.fromhex(corpus["seed_sha256"])
    payload = bytearray()
    counter = 0
    while len(payload) < length:
        block = hashlib.sha256(b"kasumi-capacity-corpus-v1\0" + seed + ordinal.to_bytes(8, "big")
                               + counter.to_bytes(8, "big")).digest()
        counter += 1
        for byte in block:
            if byte < 184:
                payload.append(ALPHABET[byte % 92])
                if len(payload) == length:
                    break
    return {"ordinal": ordinal, "payload": payload.decode("ascii"), "version": 0}


def corpus_collection(name):
    return {"name": name, "retention_class": "operational", "write_mode": "mutable",
            "schema": {"type": "object", "required": ["ordinal", "payload", "version"],
                       "additionalProperties": False,
                       "properties": {"ordinal": {"type": "integer"}, "payload": {"type": "string"},
                                      "version": {"type": "integer"}}},
            "indexes": [], "strict_read_audit": False}


def churn_collection():
    return {"name": CHURN, "retention_class": "operational", "write_mode": "mutable",
            "schema": {"type": "object", "required": ["index", "pad"], "additionalProperties": False,
                       "properties": {"index": {"type": "integer"}, "pad": {"type": "string"}}},
            "indexes": [], "strict_read_audit": False}


def driver_config(profile, corpus):
    return {"endpoint": profile["native_endpoint"], "ca_pem": profile["server_ca"],
            "client_certificate_pem": profile["identity"]["certificate"],
            "client_private_key_pem": profile["identity"]["private_key"],
            "server_certificate_sha256": profile["native_certificate_pin"],
            "token_file": profile["bearer_file"], "timeout_ms": 30000, "corpus": corpus}


def driver_executable(evidence, functional):
    """The frozen functional network-driver gate's exact capacity driver."""
    import package_release as package

    gate, = (gate for gate in functional["gates"] if gate["name"] == "network-driver")
    matches = [(path, record["sha256"]) for path, record in gate["executables"].items()
               if record["target"] == "kasumi-bench-capacity" and record["test"] is False]
    require(len(matches) == 1, "frozen capacity driver missing or ambiguous")
    path, digest = matches[0]
    return package.verify_file(Path(evidence) / "target", path, digest), digest


# ---- Plans and installed limits. ----

def common_plan(plan, kind):
    exact(plan.get("churn"), {"pad_bytes", "rounds"}, "churn plan")
    integer(plan["churn"]["pad_bytes"], "churn pad bytes", 1, 1 << 20)
    integer(plan["churn"]["rounds"], "churn rounds", 1, 64)
    exact(plan.get("pressure"), {"readers", "requests", "documents"}, "retained-read pressure plan")
    pressure = plan["pressure"]
    integer(pressure["readers"], "pressure readers", 2, 16)
    integer(pressure["requests"], "pressure requests", 1, 1000)
    integer(pressure["documents"], "pressure documents per read", 1, 64)
    corpus = corpus_plan(plan["corpus"])
    require(pressure["documents"] * corpus["document_bytes"] <= 4 << 20,
            "pressure read exceeds the response work bound")
    require(plan.get("schema") == PLAN_SCHEMA and plan.get("kind") == kind, "unsupported capacity plan")
    integer(plan.get("compaction_growth_percent"), "compaction growth percent", 101, 200)
    for alias in ("filesystem_destination", "s3_destination"):
        require(isinstance(plan.get(alias), str) and NAME.fullmatch(plan[alias]), alias + " is invalid")
    require(plan["filesystem_destination"] != plan["s3_destination"], "backup destinations must differ")
    return corpus


def qualification(plan, target):
    """Only the full-size corpus on the reference platform can qualify."""
    corpus = corpus_plan(plan["corpus"])
    return (domain_run.QUALIFYING if corpus_bytes(corpus) > MIN_CORPUS and target == REFERENCE
            else domain_run.REHEARSAL)


def destinations(config, plan):
    configured = config.get("backup_destinations", {})
    require(configured.get(plan["filesystem_destination"], {}).get("kind") == "filesystem"
            and configured.get(plan["s3_destination"], {}).get("kind") == "s3",
            "installation lacks the planned filesystem and S3 backup destinations")


def admitted_limits(configs, total):
    """Limits a node admits, identical across every measured node."""
    seen = set()
    for config in configs:
        admission, disk, scratch = config["admission"], config["persistent_disk"], config["scratch_disk"]
        values = (integer(admission.get("high_water_bytes"), "explicit memory high-water mark", 1),
                  integer(admission.get("max_inflight_bytes"), "explicit admission reservation cap", 1),
                  integer(disk["max_bytes"], "persistent disk maximum", 1),
                  integer(scratch["max_bytes"], "scratch disk maximum", 1))
        seen.add(values)
    require(len(seen) == 1, "measured nodes admit different resource limits")
    rss, retention, persistent, scratch = seen.pop()
    limits = {"rss_bytes": rss, "allocated_disk_bytes": persistent + scratch,
              "maintenance_workspace_bytes": scratch}
    require(scratch <= total // 4 and retention <= total // 4,
            "maintenance workspace or retained-read budget is not bounded below a quarter of the corpus")
    return {"limits": limits, "read_retention_budget_bytes": retention}


def storage_roots(config):
    return {"persistent": sorted(str(Path(p)) for p in config["persistent_disk"]["roots"].values()),
            "scratch": str(Path(config["scratch_disk"]["directory"]))}


# ---- Product outputs. ----

def parse_json(raw, label):
    try:
        value = json.loads(raw)
    except ValueError as error:
        raise ValueError(label + " is not JSON") from error
    require(isinstance(value, dict), label + " is not a JSON object")
    return value


def ready_output(code, raw):
    if code != 0:
        return False
    try:
        value = json.loads(raw)
    except ValueError:
        return False
    return isinstance(value, dict) and value.get("ready") is True and value.get("lifecycle") == "serving"


def gauges(text):
    values = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        name, _, raw = line.rpartition(" ")
        require(name and name not in values, "duplicate or malformed protected metric")
        values[name] = float(raw)
    return values


def storage(metrics, tenant):
    """The tenant database's storage families: dedicated group or shared node."""
    dedicated = metrics.get('kasumi_local_group_storage_dedicated{tenant="' + tenant + '"}')
    prefix, label = (("kasumi_local_group_storage_", 'tenant="' + tenant + '"') if dedicated == 1
                     else ("kasumi_storage_", ""))

    def value(suffix, extra=""):
        labels = ",".join(item for item in (label, extra) if item)
        return metrics.get(prefix + suffix + ("{" + labels + "}" if labels else ""))

    result = {"dedicated": dedicated == 1, "cycle": value("compaction_cycle"),
              "idle": value("compaction_phase", 'phase="idle"'),
              "reclaimed_files": value("reclaimed_files_total"),
              "reclaimed_bytes": value("reclaimed_bytes_total"),
              "relocated_bytes": value("relocated_bytes_total"),
              "snapshot_retained_bytes": value("snapshot_retained_bytes"),
              "segment_bytes": value("segment_bytes")}
    return {key: (None if isinstance(item, float) and not math.isfinite(item) else item)
            for key, item in result.items()}


def compacted(before, after):
    keys = ("cycle", "idle", "reclaimed_files")
    return (all(isinstance(before[k], float) and isinstance(after[k], float) for k in keys)
            and after["cycle"] > before["cycle"] and after["idle"] == 1
            and after["reclaimed_files"] > before["reclaimed_files"])


def checkpoint_facts(created, checkpoint, status, verified, path, tenant, incarnation, revision):
    exact(created, {"checkpoint", "session_id"}, "backup create response")
    exact(checkpoint, {"tenant", "source_incarnation", "revision", "resident_sha256", "backup_id",
                       "manifest_ciphertext_sha256", "key_lineage_digest"}, "backup checkpoint")
    require(uuid.UUID(created["session_id"]).int > 0 and created["checkpoint"] == path
            and checkpoint == verified and checkpoint["backup_id"] == created["session_id"]
            and checkpoint["tenant"] == tenant and checkpoint["source_incarnation"] == incarnation,
            "verified backup differs from the original checkpoint")
    integer(checkpoint["revision"], "checkpoint revision", revision)
    for key in ("resident_sha256", "manifest_ciphertext_sha256", "key_lineage_digest"):
        require(isinstance(checkpoint[key], str) and HEX.fullmatch(checkpoint[key]), "invalid checkpoint digest")
    require(status["intent"]["session_id"] == created["session_id"]
            and status["intent"]["revision"] == checkpoint["revision"]
            and status["outcome"]["outcome"] == "complete" and status["outcome"]["checkpoint"] == checkpoint,
            "durable backup session differs from the verified checkpoint")
    return checkpoint


def journal(path):
    rows = [json.loads(line) for line in Path(path).read_bytes().splitlines()]
    require(rows and all(isinstance(row, dict) for row in rows), "driver journal is empty or malformed")
    return rows


def check_measurement(directory, corpus, digest):
    rows = journal(Path(directory) / "events.jsonl")
    require(len(rows) == 2, "corpus measurement did not complete")
    start, end = rows
    require(start.get("event") == "started" and start.get("mode") == "measure"
            and start.get("corpus") == corpus and start.get("executable_sha256") == digest
            and start.get("expected_canonical_bytes") == corpus_bytes(corpus)
            and end.get("event") == "measured" and end.get("algorithm") == "gzip-9"
            and end.get("documents") == corpus["documents"] and end.get("input_bytes") == corpus_bytes(corpus)
            and type(end.get("output_bytes")) is int and end["output_bytes"] * 4 >= corpus_bytes(corpus) * 3,
            "corpus measurement differs from the plan or is compressible")
    return {"input_bytes": end["input_bytes"], "output_bytes": end["output_bytes"],
            "expected_sha256": end["expected_sha256"]}


def check_driver(directory, mode, corpus, digest, profile, incarnation, expected):
    """A completed driver run against this profile's endpoint and credential resource."""
    directory = Path(directory)
    rows = journal(directory / "events.jsonl")
    start, end = rows[0], rows[-1]
    claims = start.get("credential_binding_claims") or {}
    require(start.get("event") == "started" and start.get("mode") == mode
            and start.get("corpus") == corpus and start.get("executable_sha256") == digest
            and start.get("endpoint") == profile["native_endpoint"]
            and claims.get("kasumi_resource") == {"kind": "database", "incarnation": incarnation},
            "driver ran another corpus, executable, endpoint or credential resource")
    require(end.get("event") == "passed" and end.get("documents") == corpus["documents"]
            and end.get("canonical_bytes") == corpus_bytes(corpus)
            and end.get("expected_sha256") == end.get("observed_sha256") == expected
            and end.get("integrity_sha256") == sha256(directory / "integrity.jsonl")
            and not any(row.get("event") == "failed" for row in rows),
            "driver did not exhaustively verify the measured corpus")
    if mode == "load":
        require(any(row.get("event") == "load_completed" for row in rows), "corpus load did not complete")


def churn_requests(attempt, label, start, count, pad_bytes):
    rows = []
    for index in range(start, start + count):
        seed = hashlib.sha256((attempt + "/" + label + "/" + str(index)).encode()).hexdigest()
        pad = (seed * (pad_bytes // 64 + 1))[:pad_bytes]
        batch = {"idempotency_key": "capacity/" + attempt + "/" + label + "/" + str(index),
                 "operations": [{"op": "put", "collection": CHURN, "id": "churn-" + str(index % 64),
                                 "body": {"index": index, "pad": pad}}]}
        rows.append({"id": index, "argv": ["mutate", json.dumps(batch, sort_keys=True, separators=(",", ":"))],
                     "timeout_ms": 30000})
    return rows


def churn_reply(reply, request):
    require(reply.get("id") == request["id"] and reply.get("status") == 0
            and reply.get("document", {}).get("ok") is True, "churn write was not committed")
    receipt = reply["document"]["result"]["receipt"]
    integer(receipt["revision"], "churn revision", 1)
    return receipt["revision"]


def committed_batches(rows, corpus):
    revisions = []
    remaining = corpus["documents"]
    for row in rows:
        if row.get("event") != "committed":
            continue
        first = corpus["documents"] - remaining
        count = min(remaining, corpus["batch_documents"])
        revision = integer(row["revision"], "original mutation revision", 1)
        expected = {"/" + corpus["collection"] + "/" + document_id(corpus, i): revision
                    for i in range(first, first + count)}
        require(count > 0 and row["first"] == first and row["count"] == count
                and row["idempotency_key"] == document_id(corpus, first)
                and row["versions"] == expected and (not revisions or revision > revisions[-1]),
                "original mutation receipts do not cover the exact corpus in commit order")
        revisions.append(revision)
        remaining -= count
    require(remaining == 0, "missing original corpus mutation receipts")
    return revisions


def pressure_requests(corpus, pressure, reader):
    rows = []
    span = pressure["documents"]
    for index in range(pressure["requests"]):
        first = ((reader * pressure["requests"] + index) * span) % corpus["documents"]
        ordinals = [(first + n) % corpus["documents"] for n in range(span)]
        read = {"documents": [{"collection": corpus["collection"], "id": document_id(corpus, n)} for n in ordinals],
                "queries": [], "time_bounds": None}
        rows.append({"id": index, "argv": ["read-snapshot", json.dumps(read, sort_keys=True, separators=(",", ":"))],
                     "timeout_ms": 30000, "ordinals": ordinals})
    return rows


def pressure_reply(reply, request, corpus, incarnation, revisions):
    """Exact original corpus bodies, or the typed capacity refusal."""
    require(reply.get("id") == request["id"] and type(reply.get("status")) is int, "pressure reply misnumbered")
    result = reply.get("document", {})
    if reply["status"] != 0:
        require(result.get("ok") is False and result.get("error", {}).get("class") == PRESSURE_REFUSAL,
                "retained reader failed for a reason other than admitted capacity")
        return False
    require(result.get("ok") is True, "retained reader reply is inconsistent")
    snapshot = result["result"]["snapshot"]
    require(snapshot["incarnation"] == incarnation and type(snapshot["revision"]) is int
            and snapshot["revision"] > 0 and snapshot["queries"] == []
            and [entry["key"] for entry in snapshot["documents"]]
            == [{"collection": corpus["collection"], "id": document_id(corpus, n)} for n in request["ordinals"]],
            "retained snapshot belongs to another generation or omits a requested document")
    for entry, ordinal in zip(snapshot["documents"], request["ordinals"]):
        body = entry["document"]
        require(body is not None and type(body["version"]) is int and body["version"] == revisions[ordinal // corpus["batch_documents"]] <= snapshot["revision"]
                and body["body"] == document(corpus, ordinal), "retained snapshot returned a different corpus body")
    return True


def renewal_rows(raw, origin_ns):
    rows = []
    for index, line in enumerate(raw.splitlines()):
        row = json.loads(line)
        exact(row, {"sequence", "started_ns", "finished_ns", "exit_code", "output", "error"}, "renewal row")
        require(row["sequence"] == index and type(row["started_ns"]) is int
                and type(row["finished_ns"]) is int and origin_ns <= row["started_ns"] <= row["finished_ns"]
                and (row["exit_code"] is None or type(row["exit_code"]) is int), "renewal row is malformed")
        if row["exit_code"] == 0:
            renewed = parse_json(row["output"], "renewal output")
            require(set(renewed) == {"family_id", "expires_at_ms"}, "renewal output differs")
        rows.append(row)
    return rows


# ---- Kernel and filesystem resource samples. ----

class _RusageInfo(ctypes.Structure):
    _fields_ = [("uuid", ctypes.c_uint8 * 16)] + [(name, ctypes.c_uint64) for name in (
        "user_time", "system_time", "pkg_idle_wkups", "interrupt_wkups", "pageins", "wired_size",
        "resident_size", "phys_footprint", "proc_start_abstime", "proc_exit_abstime")]


def resident_bytes(pid):
    """Kernel resident set of one live process, or None once it is unavailable."""
    if sys.platform.startswith("linux"):
        try:
            for line in (Path("/proc") / str(pid) / "status").read_text().splitlines():
                if line.startswith("VmRSS:"):
                    number, unit = line.split()[1:3]
                    require(unit == "kB", "unexpected VmRSS unit")
                    return int(number) * 1024
        except (FileNotFoundError, ProcessLookupError):
            return None
        return None
    if sys.platform == "darwin":
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        info = _RusageInfo()
        if library.proc_pid_rusage(ctypes.c_int(pid), 0, ctypes.byref(info)) != 0:
            return None
        return int(info.resident_size)
    raise RuntimeError("unsupported capacity sampling platform")


def allocated_bytes(root):
    """Allocated blocks beneath one owned directory, without following links."""
    total = 0
    pending = [Path(root)]
    device = os.lstat(root).st_dev
    while pending:
        directory = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except FileNotFoundError:
            continue
        for entry in entries:
            try:
                info = entry.stat(follow_symlinks=False)
            except FileNotFoundError:
                continue
            if info.st_dev != device:
                continue
            total += info.st_blocks * 512
            if stat.S_ISDIR(info.st_mode):
                pending.append(Path(entry.path))
    return total


class Sampler:
    """Raw samples on the controller clock; projections are recomputed later."""

    def __init__(self, path, clock, nodes):
        self.path, self.clock, self.nodes = Path(path), clock, nodes
        self.tracked = {}
        self.lock = threading.Lock()
        self.stopped = threading.Event()
        self.thread = None
        self.last = -1.0
        self.error = None

    def track(self, name, node, pid, birth):
        with self.lock:
            self.tracked[name] = (node, pid, birth)

    def untrack(self, name):
        with self.lock:
            self.tracked.pop(name, None)

    def sample(self):
        with self.lock:
            processes = []
            for name, (node, pid, birth) in sorted(self.tracked.items()):
                if gate_process.leader_identity(pid) != {"group": pid, "birth": birth}:
                    continue
                rss = resident_bytes(pid)
                if rss is None or gate_process.leader_identity(pid) != {"group": pid, "birth": birth}:
                    continue
                processes.append({"name": name, "node": node, "pid": pid, "birth": birth, "rss_bytes": rss})
            disk = {}
            for node, roots in sorted(self.nodes.items()):
                disk[node] = {"persistent_bytes": sum(allocated_bytes(p) for p in roots["persistent"]),
                              "scratch_bytes": allocated_bytes(roots["scratch"])}
            elapsed = self.clock()
            require(elapsed > self.last, "resource sample clock did not advance")
            self.last = elapsed
            row = {"elapsed_seconds": elapsed, "processes": processes, "disk": disk}
            with self.path.open("ab") as stream:
                stream.write(canonical(row) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            return elapsed

    def start(self):
        def loop():
            while not self.stopped.wait(SAMPLE_SECONDS):
                try:
                    self.sample()
                except BaseException as error:  # retained; the main thread fails closed
                    self.error = repr(error)
                    return
        self.thread = threading.Thread(target=loop, name="capacity-sampler", daemon=True)
        self.thread.start()

    def stop(self):
        self.stopped.set()
        if self.thread is not None:
            self.thread.join()
        require(self.error is None, "resource sampling failed: " + str(self.error))


def raw_samples(path):
    rows = []
    previous = -1.0
    for line in Path(path).read_bytes().splitlines():
        row = json.loads(line)
        exact(row, {"elapsed_seconds", "processes", "disk"}, "raw resource sample")
        elapsed = row["elapsed_seconds"]
        require(type(elapsed) is float and math.isfinite(elapsed) and elapsed > previous,
                "raw resource samples are unordered")
        previous = elapsed
        for process in row["processes"]:
            exact(process, {"name", "node", "pid", "birth", "rss_bytes"}, "sampled process")
            integer(process["rss_bytes"], "sampled RSS", 0)
        for usage in row["disk"].values():
            exact(usage, {"persistent_bytes", "scratch_bytes"}, "sampled disk")
            integer(usage["persistent_bytes"], "sampled persistent bytes", 0)
            integer(usage["scratch_bytes"], "sampled scratch bytes", 0)
        rows.append(row)
    return rows


def project(rows, started, finished, nodes):
    """Per-operation resource rows in the acceptance contract's exact shape."""
    result = []
    for row in rows:
        if not started <= row["elapsed_seconds"] <= finished:
            continue
        require(set(row["disk"]) == set(nodes), "resource sample omits a measured node")
        result.append({
            "elapsed_seconds": row["elapsed_seconds"],
            "rss_bytes": max([p["rss_bytes"] for p in row["processes"] if p["node"] in nodes] or [0]),
            "allocated_disk_bytes": max(u["persistent_bytes"] + u["scratch_bytes"] for u in row["disk"].values()),
            "maintenance_workspace_bytes": max(u["scratch_bytes"] for u in row["disk"].values())})
    require(len(result) >= 2, "operation has fewer than two actual resource samples")
    return result


def within_limits(rows, limits):
    """A measured peak above its admitted limit fails the operation."""
    for row in rows:
        for key, ceiling in limits.items():
            require(row[key] <= ceiling, "measured " + key + " exceeds its admitted limit")
    return rows


def projection_bytes(rows):
    return b"".join(canonical(row) + b"\n" for row in rows)


# ---- Backends: one procedure, executed live or replayed over original receipts. ----

class Live:
    """Executes the procedure; every child and daemon is owned by the run."""

    replay = False

    def __init__(self, run, paths, digests, details):
        self.run, self.paths, self.digests = run, paths, digests
        self.output = run.output
        self.source = str(run.source)
        self.lock = threading.RLock()
        self.details = details
        self.sampler = None
        run.report["details"] = details
        run.save()

    def save(self):
        with self.lock:
            self.run.save()

    def record(self, keys, value):
        target = self.details
        for key in keys[:-1]:
            target = target.setdefault(key, {})
        target[keys[-1]] = value
        self.save()

    def config(self, identifier, path):
        with self.lock:
            return self.run.configuration(identifier, path)

    def path(self, name):
        path = self.output / name
        directory = self.output
        for part in Path(name).parts[:-1]:
            directory = directory / part
            directory.mkdir(mode=0o700, exist_ok=True)
        return str(path)

    def input(self, name, value):
        domain_run.durable_json(Path(self.path(name)), value)
        return str(self.output / name)

    def read(self, name):
        return owned.read(self.output / name)

    def retain(self, label, path):
        ref = owned.retain(self.output, Path(path))
        self.record(("retained", label), ref)
        return owned.read(owned.check_ref(self.output, ref))

    def digest(self, executable):
        names = [name for name, path in self.paths.items() if path == executable]
        require(len(names) == 1, "command selects an unadmitted executable")
        return self.digests[names[0]]

    def command(self, step, argv, timeout=COMMAND_TIMEOUT, *, node=None, scenario=None):
        self.run.dispatch()
        if self.run.services is not None:
            self.run.services.assert_alive()

        def observe(record):
            if (node and self.sampler is not None and record.get("process_group")
                    and record.get("leader_birth")):
                self.sampler.track(step, node, record["process_group"], record["leader_birth"])
        try:
            item = owned.run_owned(self.output, step, argv, self.source, self.run.environment, timeout,
                                   observe_process=observe)
        finally:
            if self.sampler is not None:
                self.sampler.untrack(step)
        receipt = owned.read(owned.check_ref(self.output, item["receipt"]))
        with self.lock:
            self.run.report["processes"].append({"id": step, "receipt": item["receipt"],
                                                 "log": item["stdout"], "executable": item["executable"]})
            self.run.save()
        require(receipt["executable"]["sha256"] == self.digest(argv[0]), "command executed other bytes: " + step)
        if scenario is not None:
            self.run.observe(scenario, step, item["receipt"], 0, receipt["exit_code"])
        require(receipt["exit_code"] == 0 and receipt["status"] == "passed", "capacity command failed: " + step)
        return owned.check_ref(self.output, item["stdout"]).read_bytes()

    def poll(self, label, argv, accept, limit, interval=1.0):
        receipts = self.details.setdefault("polls", {}).setdefault(label, [])
        (self.output / "polls" / label).mkdir(parents=True, exist_ok=False)
        for index in range(limit):
            if self.run.services is not None:
                self.run.services.assert_alive()
            item = owned.run_owned(self.output, "polls/" + label + "/" + f"{index:04d}", argv, self.source,
                                   self.run.environment, POLL_TIMEOUT)
            with self.lock:
                receipts.append(item["receipt"])
                self.run.save()
            record = owned.read(owned.check_ref(self.output, item["receipt"]))
            require(record["executable"]["sha256"] == self.digest(argv[0]), "poll executed other bytes")
            output = owned.check_ref(self.output, item["stdout"]).read_bytes()
            if accept(record["exit_code"], output):
                return output
            time.sleep(interval)
        raise ValueError("installed state did not settle: " + label)

    def start(self, nodes):
        services = self.run.start_services(TIMING["measured_seconds"], TIMING["startup_seconds"],
                                           TIMING["drain_seconds"])
        self.record(("clock_origin_ns",), time.monotonic_ns() - round(services.elapsed() * 1e9))
        (self.output / "resources").mkdir()
        self.sampler = Sampler(self.output / "resources" / "samples.jsonl", services.elapsed, nodes)
        self.sampler.sample()
        self.sampler.start()

    def enter(self, phase):
        self.record(("phases", phase), self.run.services.enter(phase))

    def serve(self, name, argv, *, node=None, interactive=False):
        with self.lock:
            identifier = self.run.service(name, argv, {"path": argv[0], "sha256": self.digest(argv[0])},
                                          interactive=interactive)
        record = self.run.services.active[name]["record"]
        if node is not None:
            self.sampler.track(identifier, node, record["process_group"], record["leader_birth"])
        return identifier

    def observed(self, name, produce):
        """Retain a local observation the procedure then checks in both modes."""
        value = produce()
        domain_run.durable_json(Path(self.path(name)), value)
        return value

    def member(self, entry):
        with self.lock:
            self.run.report["topology"].append(entry)
            self.run.save()

    def _ended(self, name, record, disposition):
        self.sampler.untrack(record["id"])
        self.details.setdefault("stops", []).append({"id": record["id"], "disposition": disposition})
        self.save()
        require(domain_run.service_disposition(record) == disposition,
                "owned service did not end by its requested " + disposition + ": " + name)

    def stop(self, name):
        self._ended(name, self.run.services.stop(name, 600), "clean-stop")

    def end(self, name):
        self._ended(name, self.run.services.end_input(name, 180), "input-closed")

    def spawn_session(self, name, argv):
        with self.lock:
            identifier = self.run.service(name, argv, {"path": argv[0], "sha256": self.digest(argv[0])},
                                          interactive=True)
        return identifier

    def converse(self, sessions, during=None):
        """Run every session's requests concurrently; ``during`` samples meanwhile.

        Sessions are spawned and ended on this thread; only replies move on
        worker threads. Returns the parsed replies and the number of samples.
        """
        identifiers = {name: self.spawn_session(name, argv) for name, (argv, _) in sessions.items()}
        results, errors = {}, []

        def talk(name):
            identifier = identifiers[name]
            requests = sessions[name][1]
            replies = []
            try:
                with (self.output / "services" / (identifier + ".log")).open("rb") as stream:
                    for request in requests:
                        wire = {key: request[key] for key in ("id", "argv", "timeout_ms")}
                        self.run.services.send(name, canonical(wire) + b"\n")
                        line, deadline = b"", time.monotonic() + REPLY_SECONDS
                        while time.monotonic() < deadline:
                            line += stream.readline()
                            if line.endswith(b"\n"):
                                break
                            time.sleep(.005)
                        require(line.endswith(b"\n"), "native session did not answer before its deadline")
                        replies.append(json.loads(line))
                results[name] = replies
            except BaseException as error:
                errors.append(repr(error))

        threads = [threading.Thread(target=talk, args=(name,), daemon=True) for name in sessions]
        for thread in threads:
            thread.start()
        count = 0
        if during is not None:
            during(count)
            count += 1
        while any(thread.is_alive() for thread in threads):
            if during is not None:
                time.sleep(SAMPLE_SECONDS)
                during(count)
                count += 1
            else:
                time.sleep(.05)
        for thread in threads:
            thread.join()
        if during is not None:
            during(count)
            count += 1
        for name in sessions:
            self.end(name)
        require(not errors, "native session failed: " + repr(errors))
        return results, count

    def mark(self, operation, edge):
        elapsed = self.sampler.sample()
        self.record(("operations", operation, edge), elapsed)
        return elapsed

    def sleep(self, seconds):
        time.sleep(seconds)

    def finish(self, operations, nodes):
        """Stop sampling, then publish each operation's projection of raw samples."""
        self.sampler.stop()
        rows = raw_samples(self.output / "resources" / "samples.jsonl")
        self.record(("samples",), owned.ref(self.output, self.output / "resources" / "samples.jsonl"))
        for operation in operations:
            entry = self.details["operations"][operation]
            path = self.output / "ops" / operation / "resources.jsonl"
            projected = within_limits(project(rows, entry["started"], entry["finished"], nodes),
                                      self.details["limits"]["limits"])
            with path.open("xb") as stream:
                stream.write(projection_bytes(projected))
                stream.flush()
                os.fsync(stream.fileno())
            entry["resources"] = owned.ref(self.output, path)
        self.save()


class Replay:
    """Re-executes the procedure over a retained run; writes nothing."""

    replay = True

    def __init__(self, facts, paths, digests):
        self.report, self.custody, self.receipts = facts["report"], facts["custody"], facts["receipts"]
        self.original = Path(self.report["custody_root"])
        self.source = str(Path(self.report["evidence_root"]) / "source")
        self.details = self.report["details"]
        self.paths, self.digests = paths, digests
        self.items = list(self.report["processes"])
        self.position = 0
        self.configurations = iter(self.report["configurations"])
        self.stops = iter(self.details.get("stops", []))
        self.nodes = {}
        self.services = {}
        self.members = 0

    def save(self):
        pass

    def record(self, keys, value):
        target = self.details
        for key in keys:
            require(isinstance(target, dict) and key in target, "run omitted a recorded fact: " + "/".join(keys))
            target = target[key]
        require(target == value, "recorded fact differs from its replay: " + "/".join(keys))

    def config(self, identifier, _):
        item = next(self.configurations, None)
        require(item is not None and item["id"] == identifier, "capacity input was substituted: " + identifier)
        return owned.check_ref(self.custody, item["file"])

    def path(self, name):
        return str(self.original / name)

    def input(self, name, value):
        require(owned.read(self.custody / name) == value, "retained run input differs: " + name)
        return str(self.original / name)

    def read(self, name):
        return owned.read(self.custody / name)

    def retain(self, label, _):
        return owned.read(owned.check_ref(self.custody, self.details["retained"][label]))

    def digest(self, executable):
        names = [name for name, path in self.paths.items() if path == executable]
        require(len(names) == 1, "replayed command selects an unadmitted executable")
        return self.digests[names[0]]

    def _next(self, step):
        require(self.position < len(self.items), "run ended before step " + step)
        item = self.items[self.position]
        self.position += 1
        require(item["id"] == step, "original step differs: expected " + step + ", found " + item["id"])
        return item, self.receipts[step]

    def command(self, step, argv, timeout=COMMAND_TIMEOUT, *, node=None, scenario=None):
        item, original = self._next(step)
        record = original["record"]
        require(not original["service"] and record["command"] == argv and record["exit_code"] == 0
                and record["timeout_seconds"] == timeout and record["working_directory"] == self.source
                and record["executable"]["sha256"] == self.digest(argv[0])
                and item["receipt"]["path"] == step + "/process.json"
                and item["log"]["path"] == step + "/stdout.log",
                "original command differs: " + step)
        if node is not None:
            self.nodes[step] = node
        return owned.check_ref(self.custody, record["stdout"]).read_bytes()

    def poll(self, label, argv, accept, limit, interval=1.0):
        receipts = self.details["polls"][label]
        require(1 <= len(receipts) <= limit, "poll count exceeds its bound: " + label)
        output = None
        for index, ref in enumerate(receipts):
            path = owned.check_ref(self.custody, ref)
            require(path == self.custody / "polls" / label / f"{index:04d}" / "process.json",
                    "poll receipt was substituted: " + label)
            record = owned.read(path)
            require(record["command"] == argv and record["executable"]["sha256"] == self.digest(argv[0])
                    and record["working_directory"] == self.source and type(record["exit_code"]) is int
                    and record["timeout_seconds"] == POLL_TIMEOUT,
                    "poll command differs: " + label)
            output = owned.check_ref(self.custody, record["stdout"]).read_bytes()
            require(accept(record["exit_code"], output) == (index == len(receipts) - 1),
                    "poll selection skipped or invented an observation: " + label)
        return output

    def start(self, _):
        pass

    def observed(self, name, _):
        return owned.read(self.custody / name)

    def member(self, entry):
        topology = self.report["topology"]
        require(self.members < len(topology) and topology[self.members] == entry,
                "original HA member differs from its replay")
        self.members += 1

    def enter(self, phase):
        require(phase in self.details["phases"], "run omitted a controller phase")

    def serve(self, name, argv, *, node=None, interactive=False):
        item, original = self._next_service(name)
        record = original["record"]
        require(original["service"] and record["name"] == name and record["command"] == argv
                and record["executable"]["sha256"] == self.digest(argv[0])
                and record["working_directory"] == self.source
                and item["log"]["path"] == "services/" + item["id"] + ".log",
                "original service differs: " + name)
        if node is not None:
            self.nodes[item["id"]] = node
        self.services[name] = item["id"]
        return item["id"]

    def _next_service(self, name):
        require(self.position < len(self.items), "run ended before service " + name)
        item = self.items[self.position]
        self.position += 1
        require(re.fullmatch(re.escape(name) + r"-[0-9]{4}", item["id"]) is not None,
                "original service order differs at " + name)
        return item, self.receipts[item["id"]]

    def _ended(self, name, disposition):
        identifier = self.services.pop(name, None)
        stop = next(self.stops, None)
        require(identifier is not None and stop == {"id": identifier, "disposition": disposition}
                and self.receipts[identifier]["disposition"] == disposition,
                "service did not end by its requested " + disposition + ": " + name)

    def stop(self, name):
        self._ended(name, "clean-stop")

    def end(self, name):
        self._ended(name, "input-closed")

    def converse(self, sessions, during=None):
        results = {}
        for name, (argv, requests) in sessions.items():
            identifier = self.serve(name, argv)
            replies = (self.custody / "services" / (identifier + ".log")).read_bytes().splitlines()
            require(len(replies) == len(requests), "session replies differ from its requests: " + name)
            results[name] = [json.loads(line) for line in replies]
        count = 0
        if during is not None:
            count = self.details["operations"]["retained-read-pressure"]["samples"]
            require(type(count) is int and count >= 2, "pressure has fewer than two observations")
            for index in range(count):
                during(index)
        for name in sessions:
            self.end(name)
        return results, count

    def mark(self, operation, edge):
        value = self.details["operations"][operation][edge]
        require(type(value) is float and math.isfinite(value), "operation boundary is missing")
        return value

    def sleep(self, _):
        pass

    def finish(self, operations, nodes):
        rows = raw_samples(owned.check_ref(self.custody, self.details["samples"]))
        require(self.details["samples"]["path"] == "resources/samples.jsonl", "raw samples substituted")
        previous = -1.0
        for operation in operations:
            entry = self.details["operations"][operation]
            require(previous < entry["started"] < entry["finished"], "operations overlap or are unordered")
            previous = entry["finished"]
            path = owned.check_ref(self.custody, entry["resources"])
            projected = within_limits(project(rows, entry["started"], entry["finished"], nodes),
                                      self.details["limits"]["limits"])
            require(path == self.custody / "ops" / operation / "resources.jsonl"
                    and path.read_bytes() == projection_bytes(projected),
                    "operation resources differ from the raw samples")
        return rows

    def done(self):
        require(self.position == len(self.items) and next(self.configurations, None) is None
                and next(self.stops, None) is None and self.members == len(self.report["topology"])
                and not self.services, "run retained an unreplayed process, input, member or stop")


# ---- Steps shared by both procedures. ----

class Corpus:
    """Measurement, load and exhaustive verification through the exact driver."""

    def __init__(self, io, corpus):
        self.io, self.corpus = io, corpus
        self.driver = io.paths["driver"]
        self.digest = io.digests["driver"]
        self.measured = None
        self.revisions = None

    def measure(self, profile):
        connection = self.io.input("connection/measure.json", driver_config(profile, self.corpus))
        self.io.command("measure-corpus", [self.driver, connection, "measure", self.io.path("measure")], DRIVER_TIMEOUT)
        root = self.io.custody if self.io.replay else self.io.output
        self.measured = check_measurement(root / "measure", self.corpus, self.digest)
        self.io.record(("measurement",), self.measured)

    def run(self, step, mode, directory, profile, incarnation, *, scenario=None, node=None):
        connection = self.io.input(directory + "/connection.json", driver_config(profile, self.corpus))
        argv = [self.driver, connection, mode, self.io.path(directory + "/driver")]
        if mode == "load":
            argv.append("--allow-writes")
        try:
            self.io.command(step, argv, DRIVER_TIMEOUT, scenario=scenario, node=node)
        except ValueError:
            pending = Path(self.io.path(directory + "/driver")) / "last-original-batch.json"
            if mode == "load" and not self.io.replay and pending.is_file():
                # Read-only inspection of the original uncertain batch; never a retry.
                self.io.command(step + "-resolve", [self.driver, connection, "resolve",
                                                    self.io.path(directory + "/resolution"),
                                                    self.io.path(directory + "/driver")], DRIVER_TIMEOUT)
            raise
        root = self.io.custody if self.io.replay else self.io.output
        check_driver(root / directory / "driver", mode, self.corpus, self.digest, profile, incarnation,
                     self.measured["expected_sha256"])
        if mode == "load":
            self.revisions = committed_batches(journal(root / directory / "driver" / "events.jsonl"), self.corpus)
        self.io.record(("driver", step), {
            "events": owned.ref(root, root / directory / "driver" / "events.jsonl"),
            "integrity": owned.ref(root, root / directory / "driver" / "integrity.jsonl")})


def churn(io, attempt, label, round_index, plan, data_profile_path, ctl):
    requests = churn_requests(attempt, label, round_index * CHURN_REQUESTS, CHURN_REQUESTS,
                              plan["churn"]["pad_bytes"])
    name = label + "-churn-" + str(round_index)
    replies, _ = io.converse({name: ([ctl, "--profile", data_profile_path, "session"], requests)})
    return [churn_reply(reply, request) for reply, request in zip(replies[name], requests)]


def backup(io, operation, alias, kasumid, operator, tenant, incarnation, revision):
    path = io.path("ops/" + operation + "/checkpoint.json")
    created = parse_json(io.command(operation + "-create", [kasumid, "backup", "create", operator, alias, path],
                                    MAINTENANCE_TIMEOUT), "backup create response")
    checkpoint = io.read("ops/" + operation + "/checkpoint.json")
    status = parse_json(io.command(operation + "-status", [kasumid, "backup", "status", operator, alias,
                                                           created["session_id"]]), "backup status")
    verified = parse_json(io.command(operation + "-verify-backup", [kasumid, "backup", "verify", operator, alias,
                                                                    created["session_id"]], MAINTENANCE_TIMEOUT),
                          "backup verification")
    checkpoint_facts(created, checkpoint, status, verified, path, tenant, incarnation, revision)
    io.record(("operations", operation, "checkpoint"), checkpoint)
    return checkpoint


def renewal_argv(io, profile):
    return [io.paths["python"], "-I", "-B", "-S", io.source + "/" + LIBRARY, "renew", io.paths["kasumid"],
            profile, str(RENEW_SECONDS)]


def verify_renewals(facts, details):
    """Every renewal service's rows are well formed and it renewed at least once.

    The replay already bound each renewal service's exact command and profile.
    """
    origin = details["clock_origin_ns"]
    require(type(origin) is int, "controller clock origin is missing")
    for identifier, original in facts["receipts"].items():
        if original["service"] and original["record"]["name"].startswith("renewal"):
            raw = (facts["custody"] / "services" / (identifier + ".log")).read_bytes()
            require(any(row["exit_code"] == 0 for row in renewal_rows(raw, origin)),
                    "renewal service never renewed its credential")


def verify_samples(rows, replay, receipts):
    """Every sampled process is the original owned process at that moment."""
    for row in rows:
        for process in row["processes"]:
            original = receipts.get(process["name"])
            require(original is not None and replay.nodes.get(process["name"]) == process["node"],
                    "resource sample names an unowned or unmeasured process")
            record = original["record"]
            require(record.get("process_group") == process["pid"] and record.get("leader_birth") == process["birth"],
                    "resource sample identity differs from the original process receipt")
            if original["service"]:
                require(record["started_elapsed_seconds"] <= row["elapsed_seconds"]
                        <= record["finished_elapsed_seconds"], "resource sample lies outside the process lifetime")


def gate_details(root, report_path, operations):
    """The acceptance gate's capacity details, lifted from the original report."""
    root = Path(root).resolve(strict=True)
    report_path = Path(report_path).resolve(strict=True)
    custody = report_path.parent
    details = owned.read(report_path)["details"]
    corpus = details["corpus"]

    def lifted(ref):
        return owned.ref(root, owned.check_ref(custody, ref))

    measure = custody / "measure" / "events.jsonl"
    return {"corpus": {"documents": corpus["documents"], "canonical_bytes": corpus_bytes(corpus),
                       "seed_sha256": corpus["seed_sha256"],
                       "compression": {"algorithm": "gzip-9",
                                       "input_bytes": details["measurement"]["input_bytes"],
                                       "output_bytes": details["measurement"]["output_bytes"],
                                       "log": owned.ref(root, measure)}},
            "operations": [{"id": operation,
                            "integrity": lifted(details["driver"][operation + "-verify"]["integrity"]),
                            "verification": lifted(details["driver"][operation + "-verify"]["events"]),
                            "resources": lifted(details["operations"][operation]["resources"]),
                            "limits": details["limits"]["limits"],
                            "read_retention_budget_bytes": details["limits"]["read_retention_budget_bytes"]}
                           for operation in operations]}


def locate_report(root, domain):
    """The report beside the gate's measured compression journal."""
    import verify_release_acceptance as acceptance

    details = domain["details"]
    acceptance.exact(details, {"corpus", "operations"}, "capacity details")
    log = details["corpus"]["compression"]["log"]
    path = acceptance.reference(Path(root).resolve(strict=True), log)
    require(path.name == "events.jsonl" and path.parent.name == "measure",
            "capacity compression log is not the runner's original measurement")
    report = path.parent.parent / "report.json"
    require(report.is_file() and not report.is_symlink(), "capacity run report is absent")
    return report


def admitted_digests(root, domain, candidates):
    """Candidate binaries plus the frozen functional driver and interpreter."""
    import verify_release_acceptance as acceptance

    target = domain["id"].split(":", 1)[1]
    primary = candidates[target]["primary"]["functional"]
    functional_path = acceptance.reference(Path(root).resolve(strict=True), primary)
    functional = owned.read(functional_path)
    return {**domain["binaries"], "driver": driver_executable(functional_path.parent, functional)[1],
            "python": functional["python_executable"]["sha256"]}


def verify_scenarios(facts, operations):
    """Each operation's scenario is exactly its exhaustive post-operation verification."""
    require(set(facts["scenarios"]) == set(operations), "capacity scenario roster differs")
    for operation in operations:
        rows = facts["scenarios"][operation]
        require([row["step"] for row in rows] == [operation + "-verify"]
                and rows[0]["exit_code"] == rows[0]["expected_exit"] == 0,
                "capacity scenario does not select its own exhaustive verification")
