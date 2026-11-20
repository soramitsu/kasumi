"""Capacity domain procedure, replay and adversarial verification tests.

A simulated product records one complete standalone run with real retained
receipt files and hashes. The adapter's replay must accept it exactly and
reject every substituted output, command, process, resource row and reply.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))

import capacity_domain as cap  # noqa: E402
import repeatable_assembly as owned  # noqa: E402
import run_capacity_ha as ha  # noqa: E402
import run_capacity_standalone as standalone  # noqa: E402

RUN_ID = "00000000-0000-0000-0000-000000000001"
INCARNATION = "11111111-1111-1111-1111-111111111111"
TENANT = "capacity-tenant"


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    return str(path)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Product:
    """Deterministic stand-in for the installed product's command outputs."""

    def __init__(self, root, corpus, profiles):
        self.root, self.corpus, self.profiles = Path(root), corpus, profiles
        self.applied, self.snapshot, self.revision = 10, None, 10
        self.cycle, self.reclaimed, self.reserved = 1.0, 3.0, 128.0
        self.incarnation = INCARNATION
        self.sessions = 0
        self.ready_calls = 0
        self.recoveries = {}

    def expected(self):
        digest = hashlib.sha256()
        for ordinal in range(self.corpus["documents"]):
            body = cap.canonical(cap.document(self.corpus, ordinal))
            digest.update(ordinal.to_bytes(8, "big") + len(body).to_bytes(8, "big") + body)
        return digest.hexdigest()

    def driver(self, argv, digest):
        connection = json.loads(Path(argv[1]).read_text())
        mode, directory = argv[2], Path(argv[3])
        directory.mkdir(mode=0o700)
        total = cap.corpus_bytes(self.corpus)
        if mode == "measure":
            rows = [{"event": "started", "mode": "measure", "corpus": self.corpus, "executable_sha256": digest,
                     "expected_canonical_bytes": total, "algorithm": "gzip-9"},
                    {"event": "measured", "algorithm": "gzip-9", "documents": self.corpus["documents"],
                     "input_bytes": total, "output_bytes": total, "expected_sha256": self.expected()}]
        else:
            profile = next(p for p in self.profiles.values() if p["bearer_file"] == connection["token_file"])
            integrity = b"".join(cap.canonical({"first": n, "documents": 1}) + b"\n"
                                 for n in range(self.corpus["documents"]))
            (directory / "integrity.jsonl").write_bytes(integrity)
            rows = [{"event": "started", "mode": mode, "corpus": self.corpus, "executable_sha256": digest,
                     "endpoint": connection["endpoint"],
                     "credential_binding_claims": {"kasumi_resource": profile["resource"]}}]
            if mode == "load":
                batch = self.corpus["batch_documents"]
                for first in range(0, self.corpus["documents"], batch):
                    count = min(batch, self.corpus["documents"] - first)
                    revision = 1 + first // batch
                    versions = {"/" + self.corpus["collection"] + "/" + cap.document_id(self.corpus, i): revision
                                for i in range(first, first + count)}
                    rows.append(dict(event="committed", first=first, count=count, versions=versions,
                                     revision=revision, idempotency_key=cap.document_id(self.corpus, first)))
                rows.append({"event": "load_completed", "documents": self.corpus["documents"]})
            rows.append({"event": "passed", "documents": self.corpus["documents"], "canonical_bytes": total,
                         "expected_sha256": self.expected(), "observed_sha256": self.expected(),
                         "integrity_sha256": sha(integrity)})
        (directory / "events.jsonl").write_bytes(b"".join(cap.canonical(r) + b"\n" for r in rows))
        return b""

    def status(self):
        return {"mode": "standalone", "observation": "local_committed_state", "incarnation": self.incarnation,
                "revision": self.revision, "raft_applied_index": self.applied, "raft_snapshot_index": self.snapshot,
                "node_id": 1, "leader": 1, "raft_voters": [1]}

    def metrics(self):
        lines = ['kasumi_local_group_storage_dedicated{tenant="%s"} 0' % TENANT,
                 "kasumi_storage_compaction_cycle %s" % self.cycle,
                 'kasumi_storage_compaction_phase{phase="idle"} 1',
                 "kasumi_storage_reclaimed_files_total %s" % self.reclaimed,
                 "kasumi_storage_reclaimed_bytes_total 100", "kasumi_storage_relocated_bytes_total 50",
                 "kasumi_storage_snapshot_retained_bytes 0", "kasumi_storage_segment_bytes 1000",
                 "kasumi_admission_reserved_bytes %s" % self.reserved]
        return ("\n".join(lines) + "\n").encode()

    def run(self, argv, paths, digests):
        """Return (exit, stdout) for one command."""
        name = next(key for key, value in paths.items() if value == argv[0])
        if name == "driver":
            return 0, self.driver(argv, digests["driver"])
        if name == "kasumictl":
            command = argv[3]
            if command == "ready":
                self.ready_calls += 1
                if self.ready_calls % 2:
                    return 9, b'{"ok":false}\n'
                return 0, b'{"ready":true,"lifecycle":"serving"}\n'
            if command == "manage":
                return 0, cap.canonical(self.status()) + b"\n"
            if command == "metrics":
                return 0, self.metrics()
            if command in ("set-limits", "create-collection"):
                return 0, b'{"ok":true}\n'
        if name == "kasumid":
            if argv[1:3] == ["backup", "create"]:
                session = str(uuid.uuid5(uuid.NAMESPACE_URL, argv[4]))
                checkpoint = {"tenant": TENANT, "source_incarnation": self.incarnation, "revision": self.revision,
                              "resident_sha256": "a" * 64, "backup_id": session,
                              "manifest_ciphertext_sha256": "b" * 64, "key_lineage_digest": "c" * 64}
                write_json(argv[5], checkpoint)
                self.recoveries[session] = checkpoint
                return 0, cap.canonical({"checkpoint": argv[5], "session_id": session})
            if argv[1:3] == ["backup", "status"]:
                checkpoint = self.recoveries[argv[5]]
                return 0, cap.canonical({"intent": {"session_id": argv[5], "revision": checkpoint["revision"]},
                                         "outcome": {"outcome": "complete", "checkpoint": checkpoint}})
            if argv[1:3] == ["backup", "verify"]:
                return 0, cap.canonical(self.recoveries[argv[5]])
            if argv[1:3] == ["local-recovery", "start"]:
                request = json.loads(Path(argv[4]).read_text())
                self.recoveries[request["operation_id"]] = request
                return 0, b"{}"
            if argv[1:3] == ["local-recovery", "status"]:
                request = self.recoveries[argv[4]]
                profile = dict(self.profiles["data"], resource={"kind": "database",
                                                                "incarnation": request["target_incarnation"]},
                               bearer_file=str(self.root / ("token-" + argv[4])))
                path = write_json(self.root / "profiles" / ("recovery-" + argv[4] + ".json"), profile)
                self.profiles["restored-" + argv[4]] = profile
                self.incarnation = request["target_incarnation"]
                return 0, cap.canonical({"phase": "finished", "last_failure": None, "request": request,
                                         "client_profile": path})
        raise AssertionError("unexpected simulated command " + repr(argv))

    def reply(self, request):
        command = request["argv"][0]
        if command == "mutate":
            self.revision += 1
            self.applied += 1
            if self.applied >= 12:
                self.snapshot = self.applied
            self.cycle += 0.5
            self.reclaimed += 1
            return {"id": request["id"], "status": 0, "document": {"ok": True, "result": {"receipt": {
                "revision": self.revision}}}}
        documents = [{"key": {"collection": self.corpus["collection"], "id": cap.document_id(self.corpus, n)},
                      "document": {"version": 1 + n // self.corpus["batch_documents"], "body": cap.document(self.corpus, n)}}
                     for n in request["ordinals"]]
        return {"id": request["id"], "status": 0, "document": {"ok": True, "result": {"snapshot": {
            "incarnation": self.incarnation, "revision": self.revision, "queries": [], "documents": documents}}}}


class Recorder:
    """A Live-shaped backend that writes the same custody layout without processes."""

    replay = False

    def __init__(self, custody, evidence, paths, digests, product):
        self.custody = self.output = Path(custody)
        self.source = str(Path(evidence) / "source")
        self.paths, self.digests, self.product = paths, digests, product
        self.details = {"target": cap.REFERENCE, "paths": paths, "digests": digests, "functional_sha256": "f" * 64}
        self.report = {"processes": [], "configurations": [], "details": self.details, "topology": [],
                       "custody_root": str(custody), "evidence_root": str(evidence), "attempt_id": "attempt-1"}
        self.receipts, self.services, self.tracked = {}, {}, {}
        self.clock, self.pid, self.spawned = 1.0, 1000, 0
        self.scenarios = {}

    def tick(self):
        self.clock += 1.0
        return self.clock

    def save(self):
        pass

    def record(self, keys, value):
        target = self.details
        for key in keys[:-1]:
            target = target.setdefault(key, {})
        target[keys[-1]] = copy.deepcopy(value)

    def config(self, identifier, path):
        ref = owned.retain(self.custody, Path(path))
        self.report["configurations"].append({"id": identifier, "file": ref})
        return owned.check_ref(self.custody, ref)

    def path(self, name):
        (self.custody / name).parent.mkdir(parents=True, exist_ok=True)
        return str(self.custody / name)

    def input(self, name, value):
        return write_json(self.path(name), value)

    def read(self, name):
        return owned.read(self.custody / name)

    def retain(self, label, path):
        ref = owned.retain(self.custody, Path(path))
        self.record(("retained", label), ref)
        return owned.read(owned.check_ref(self.custody, ref))

    def digest(self, executable):
        return self.digests[next(k for k, v in self.paths.items() if v == executable)]

    def _receipt(self, directory, argv, timeout, code, stdout):
        directory.mkdir(parents=True)
        (directory / "stdout.log").write_bytes(stdout)
        (directory / "stderr.log").write_bytes(b"")
        self.pid += 1
        record = {"command": argv, "exit_code": code, "timeout_seconds": timeout, "working_directory": self.source,
                  "executable": {"path": argv[0], "sha256": self.digest(argv[0])}, "process_group": self.pid,
                  "leader_birth": "linux:" + str(self.pid),
                  "stdout": owned.ref(self.custody, directory / "stdout.log"),
                  "stderr": owned.ref(self.custody, directory / "stderr.log")}
        write_json(directory / "process.json", record)
        return record

    def command(self, step, argv, timeout=cap.COMMAND_TIMEOUT, *, node=None, scenario=None):
        code, stdout = self.product.run(argv, self.paths, self.digests)
        record = self._receipt(self.custody / step, argv, timeout, code, stdout)
        if node is not None:
            self.tracked[step] = (node, record)
            self.sample()
            del self.tracked[step]
        receipt = owned.ref(self.custody, self.custody / step / "process.json")
        self.report["processes"].append({"id": step, "receipt": receipt, "log": record["stdout"],
                                         "executable": {"path": "blobs/x", "sha256": record["executable"]["sha256"]}})
        self.receipts[step] = {"ref": receipt, "record": record, "service": False, "exit_code": code,
                               "disposition": "command"}
        if scenario is not None:
            self.scenarios.setdefault(scenario, []).append({"step": step, "exit_code": code, "expected_exit": 0})
        assert code == 0, step
        return stdout

    def poll(self, label, argv, accept, limit, interval=1.0):
        receipts = self.details.setdefault("polls", {}).setdefault(label, [])
        for index in range(limit):
            code, stdout = self.product.run(argv, self.paths, self.digests)
            directory = self.custody / "polls" / label / f"{index:04d}"
            self._receipt(directory, argv, cap.POLL_TIMEOUT, code, stdout)
            receipts.append(owned.ref(self.custody, directory / "process.json"))
            if accept(code, stdout):
                return stdout
        raise AssertionError("simulated poll did not settle")

    def start(self, nodes):
        self.nodes = nodes
        (self.custody / "resources").mkdir()
        self.details["clock_origin_ns"] = 0
        self.sample()

    def sample(self):
        processes = [{"name": name, "node": node, "pid": record["process_group"], "birth": record["leader_birth"],
                      "rss_bytes": 1 << 20}
                     for name, (node, record) in sorted(self.tracked.items())]
        row = {"elapsed_seconds": self.tick(), "processes": processes,
               "disk": {node: {"persistent_bytes": 1 << 20, "scratch_bytes": 128} for node in self.nodes}}
        with (self.custody / "resources" / "samples.jsonl").open("ab") as stream:
            stream.write(cap.canonical(row) + b"\n")
        return row["elapsed_seconds"]

    def observed(self, name, produce):
        value = produce()
        write_json(self.custody / name, value)
        return value

    def member(self, entry):
        self.report["topology"].append(entry)

    def enter(self, phase):
        self.record(("phases", phase), self.tick())

    def serve(self, name, argv, *, node=None, interactive=False):
        self.spawned += 1
        identifier = f"{name}-{self.spawned:04d}"
        self.pid += 1
        record = {"name": name, "command": argv, "working_directory": self.source, "process_group": self.pid,
                  "executable": {"path": argv[0], "sha256": self.digest(argv[0])},
                  "leader_birth": "linux:" + str(self.pid), "started_elapsed_seconds": self.tick(),
                  "finished_elapsed_seconds": None}
        (self.custody / "services").mkdir(exist_ok=True)
        log = self.custody / "services" / (identifier + ".log")
        if name.startswith("renewal"):
            log.write_bytes(cap.canonical({"sequence": 0, "started_ns": 5, "finished_ns": 6, "exit_code": 0,
                                           "output": '{"expires_at_ms":1,"family_id":"x"}', "error": ""}) + b"\n")
        else:
            log.write_bytes(b"")
        self.report["processes"].append({"id": identifier, "receipt": {"path": "services/" + identifier + ".json"},
                                         "log": {"path": "services/" + identifier + ".log"}, "executable": {}})
        self.receipts[identifier] = {"ref": None, "record": record, "service": True, "exit_code": 0,
                                     "disposition": None}
        self.services[name] = identifier
        if node is not None:
            self.tracked[identifier] = (node, record)
        return identifier

    def _ended(self, name, disposition):
        identifier = self.services.pop(name)
        self.tracked.pop(identifier, None)
        self.receipts[identifier]["record"]["finished_elapsed_seconds"] = self.tick()
        self.receipts[identifier]["disposition"] = disposition
        self.details.setdefault("stops", []).append({"id": identifier, "disposition": disposition})

    def stop(self, name):
        self._ended(name, "clean-stop")

    def end(self, name):
        self._ended(name, "input-closed")

    def converse(self, sessions, during=None):
        results = {}
        for name, (argv, requests) in sessions.items():
            identifier = self.serve(name, argv)
            replies = [self.product.reply(request) for request in requests]
            (self.custody / "services" / (identifier + ".log")).write_bytes(
                b"".join(cap.canonical(reply) + b"\n" for reply in replies))
            results[name] = json.loads(json.dumps(replies))
        count = 0
        if during is not None:
            for count in range(2):
                during(count)
            count = 2
        for name in sessions:
            self.end(name)
        return results, count

    def mark(self, operation, edge):
        elapsed = self.sample()
        self.record(("operations", operation, edge), elapsed)
        return elapsed

    def sleep(self, _):
        pass

    def finish(self, operations, nodes):
        rows = cap.raw_samples(self.custody / "resources" / "samples.jsonl")
        self.details["samples"] = owned.ref(self.custody, self.custody / "resources" / "samples.jsonl")
        for operation in operations:
            entry = self.details["operations"][operation]
            path = self.custody / "ops" / operation / "resources.jsonl"
            path.write_bytes(cap.projection_bytes(cap.project(rows, entry["started"], entry["finished"], nodes)))
            entry["resources"] = owned.ref(self.custody, path)

    def facts(self):
        scenarios = {name: [{"step": row["step"], "exit_code": row["exit_code"],
                             "expected_exit": row["expected_exit"]} for row in rows]
                     for name, rows in self.scenarios.items()}
        return {"report": json.loads(json.dumps(self.report)), "custody": self.custody,
                "receipts": json.loads(json.dumps(self.receipts)), "scenarios": scenarios}


class Fixture:
    def __init__(self, directory, *, scratch=256):
        self.directory = Path(directory).resolve()
        root = self.directory
        self.corpus = {"run_id": RUN_ID, "seed_sha256": "12" * 32, "collection": "capacity", "documents": 4,
                       "document_bytes": 256, "batch_documents": 2}
        install = root / "installation"
        for name in ("persistent", "scratch", "fs-backup"):
            (install / name).mkdir(parents=True)
        config = {"mode": "standalone", "replication": None,
                  "tenants": [{"tenant": TENANT, "incarnation": INCARNATION,
                               "serving": {"installation_id": "22222222-2222-2222-2222-222222222222"},
                               "keys": {"kind": "file", "path": str(install / "keys.json")}}],
                  "native": {"listen": "127.0.0.1:9444"}, "admin": {"listen": "127.0.0.1:9445"},
                  "backup_destinations": {"files": {"kind": "filesystem"}, "objects": {"kind": "s3"}},
                  "admission": {"high_water_bytes": 8 << 30, "max_inflight_bytes": 256},
                  "persistent_disk": {"roots": {"main": str(install / "persistent")}, "max_bytes": 64 << 30},
                  "scratch_disk": {"directory": str(install / "scratch"), "max_bytes": scratch}}
        identity = {"certificate": str(install / "client.pem"), "private_key": str(install / "client.key")}
        self.profiles = {
            "data": {"tenant": TENANT, "resource": {"kind": "database", "incarnation": INCARNATION},
                     "native_endpoint": "https://localhost:9444", "server_ca": str(install / "ca.pem"),
                     "identity": identity, "native_certificate_pin": "d" * 64,
                     "bearer_file": str(install / "default.token")},
            "operator": {"tenant": TENANT, "resource": {"kind": "database", "incarnation": INCARNATION},
                         "principal": "operator", "bearer_file": str(install / "operator.token"),
                         "administrative_members": {"1": {"endpoint": "https://localhost:9445"}}},
            "control": {"resource": {"kind": "control"}, "bearer_file": str(install / "control.token")}}
        self.plan = {"schema": cap.PLAN_SCHEMA, "kind": standalone.KIND,
                     "configuration": write_json(install / "kasumi.json", config),
                     "tenant_limits": write_json(root / "limits.json", {"max_logical_bytes": 1 << 40, "max_snapshot_bytes": 1 << 40}),
                     "corpus": self.corpus, "churn": {"pad_bytes": 64, "rounds": 3},
                     "pressure": {"readers": 2, "requests": 2, "documents": 2},
                     "compaction_growth_percent": 110, "filesystem_destination": "files",
                     "s3_destination": "objects"}
        for role, profile in self.profiles.items():
            self.plan[role + "_profile"] = write_json(install / "profiles" / (role + ".json"), profile)
        self.plan_path = write_json(root / "plan.json", self.plan)
        evidence = root / "evidence"
        (evidence / "source").mkdir(parents=True)
        self.paths = {name: "/opt/kasumi/" + name for name in ("kasumid", "kasumictl", "kasumi-authority",
                                                                "driver", "python")}
        self.digests = {name: sha(name.encode()) for name in self.paths}
        custody = root / "custody"
        custody.mkdir()
        self.product = Product(root, self.corpus, self.profiles)
        self.recorder = Recorder(custody, evidence, self.paths, self.digests, self.product)

    def record(self):
        operations, nodes = standalone.procedure(self.recorder, self.plan_path, "attempt-1")
        self.recorder.finish(operations, nodes)
        return self.recorder.facts()


def replay(facts):
    backend = cap.Replay(facts, facts["report"]["details"]["paths"], facts["report"]["details"]["digests"])
    operations, nodes = standalone.procedure(backend, None, facts["report"]["attempt_id"])
    rows = backend.finish(operations, nodes)
    backend.done()
    cap.verify_samples(rows, backend, facts["receipts"])
    cap.verify_renewals(facts, facts["report"]["details"])
    cap.verify_scenarios(facts, operations)
    return operations


class GeneratorTests(unittest.TestCase):
    def test_snapshot_limit_rejects_impossible_capacity_corpus(self):
        corpus = {"documents": 98400, "document_bytes": 32768}
        with self.assertRaisesRegex(ValueError, "max_snapshot_bytes"):
            cap.check_corpus_limits({"max_logical_bytes": 4 << 30, "max_snapshot_bytes": 1536 << 20}, corpus)
        cap.check_corpus_limits({"max_logical_bytes": 4 << 30, "max_snapshot_bytes": 6 << 30}, corpus)

    def test_python_generator_matches_the_rust_driver_vectors(self):
        corpus = {"run_id": RUN_ID, "seed_sha256": "12" * 32, "collection": "capacity",
                  "documents": 3 << 20, "document_bytes": 1024, "batch_documents": 128}
        cap.corpus_plan(corpus)
        first = cap.canonical(cap.document(corpus, 0))
        self.assertEqual(len(first), 1024)
        self.assertEqual(sha(first), "394fe15da12aa133d39dce92047bd3286962ba6d6136a0615b19d3f8565ac67a")
        self.assertEqual(sha(cap.canonical(cap.document(corpus, 999))),
                         "0f2ce61facf68acfb2587f4d7ce740598149abeea7491f1ee373f5e092ad2a7b")
        self.assertEqual(cap.document_id(corpus, 7), "capacity-00000000000000000000000000000001-7")

    def test_corpus_plan_rejects_unbounded_or_reserved_inputs(self):
        good = {"run_id": RUN_ID, "seed_sha256": "12" * 32, "collection": "capacity", "documents": 1,
                "document_bytes": 128, "batch_documents": 1}
        for key, value in (("run_id", str(uuid.UUID(int=0))), ("collection", cap.CHURN),
                           ("document_bytes", 127), ("batch_documents", 257), ("documents", 0),
                           ("seed_sha256", "XY" * 32)):
            with self.subTest(key=key), self.assertRaises((ValueError, AttributeError)):
                cap.corpus_plan({**good, key: value})
        with self.assertRaises(ValueError):
            cap.corpus_plan({**good, "document_bytes": 1 << 20, "batch_documents": 8})

    def test_only_a_full_corpus_on_the_reference_platform_qualifies(self):
        plan = {"corpus": {"run_id": RUN_ID, "seed_sha256": "12" * 32, "collection": "capacity",
                           "documents": 98400, "document_bytes": 32768, "batch_documents": 96}}
        self.assertEqual(cap.qualification(plan, cap.REFERENCE), "qualifying")
        self.assertEqual(cap.qualification(plan, "aarch64-apple-darwin"), cap.domain_run.REHEARSAL)
        plan["corpus"]["documents"] = 98304
        self.assertEqual(cap.qualification(plan, cap.REFERENCE), cap.domain_run.REHEARSAL)


class LimitAndOutputTests(unittest.TestCase):
    def config(self, scratch=256 << 20, retention=64 << 20, high=None):
        return {"admission": {"high_water_bytes": 8 << 30 if high is None else high, "max_inflight_bytes": retention},
                "persistent_disk": {"max_bytes": 32 << 30}, "scratch_disk": {"max_bytes": scratch}}

    def test_limits_come_from_explicit_identical_installed_configuration(self):
        total = 3 << 30
        limits = cap.admitted_limits([self.config(), self.config()], total)
        self.assertEqual(limits, {"limits": {"rss_bytes": 8 << 30, "allocated_disk_bytes": (32 << 30) + (256 << 20),
                                             "maintenance_workspace_bytes": 256 << 20},
                                  "read_retention_budget_bytes": 64 << 20})
        for configs in ([self.config(scratch=total // 4 + 1)], [self.config(retention=total // 4 + 1)],
                        [self.config(), self.config(scratch=1 << 20)]):
            with self.assertRaises(ValueError):
                cap.admitted_limits(configs, total)
        implicit = self.config()
        implicit["admission"]["high_water_bytes"] = None
        with self.assertRaises(ValueError):
            cap.admitted_limits([implicit], total)

    def test_metrics_select_the_dedicated_or_shared_database_and_reject_unknowns(self):
        shared = cap.gauges('kasumi_local_group_storage_dedicated{tenant="t"} 0\n'
                            "kasumi_storage_compaction_cycle 2\nkasumi_storage_compaction_phase{phase=\"idle\"} 1\n"
                            "kasumi_storage_reclaimed_files_total 5\n")
        self.assertEqual(cap.storage(shared, "t")["cycle"], 2.0)
        dedicated = cap.gauges('kasumi_local_group_storage_dedicated{tenant="t"} 1\n'
                               'kasumi_local_group_storage_compaction_cycle{tenant="t"} NaN\n'
                               "kasumi_storage_compaction_cycle 9\n")
        self.assertIsNone(cap.storage(dedicated, "t")["cycle"])
        before = {"cycle": 1.0, "idle": 1.0, "reclaimed_files": 1.0}
        self.assertTrue(cap.compacted(before, {"cycle": 2.0, "idle": 1.0, "reclaimed_files": 2.0}))
        self.assertFalse(cap.compacted(before, {"cycle": 2.0, "idle": 0.0, "reclaimed_files": 2.0}))
        self.assertFalse(cap.compacted(before, {"cycle": None, "idle": 1.0, "reclaimed_files": 2.0}))
        with self.assertRaises(ValueError):
            cap.gauges("kasumi_storage_compaction_cycle 1\nkasumi_storage_compaction_cycle 2\n")

    def test_projection_needs_two_samples_and_takes_per_sample_maxima(self):
        rows = [{"elapsed_seconds": t, "processes": [{"name": "a", "node": "n", "pid": 1, "birth": "b",
                                                      "rss_bytes": 10 * t}],
                 "disk": {"n": {"persistent_bytes": 100, "scratch_bytes": int(t)}}} for t in (1.0, 2.0, 3.0)]
        projected = cap.project(rows, 1.5, 3.0, ["n"])
        self.assertEqual(projected, [{"elapsed_seconds": 2.0, "rss_bytes": 20.0, "allocated_disk_bytes": 102,
                                      "maintenance_workspace_bytes": 2},
                                     {"elapsed_seconds": 3.0, "rss_bytes": 30.0, "allocated_disk_bytes": 103,
                                      "maintenance_workspace_bytes": 3}])
        with self.assertRaises(ValueError):
            cap.project(rows, 2.5, 3.0, ["n"])
        with self.assertRaises(ValueError):
            cap.project(rows, 1.0, 3.0, ["n", "other"])

    def test_pressure_replies_accept_exact_bodies_or_the_capacity_refusal_only(self):
        corpus = {"run_id": RUN_ID, "seed_sha256": "12" * 32, "collection": "capacity", "documents": 5,
                  "document_bytes": 256, "batch_documents": 1}
        request, = cap.pressure_requests(corpus, {"readers": 2, "requests": 1, "documents": 2}, 1)
        self.assertEqual(request["ordinals"], [2, 3])
        documents = [{"key": {"collection": "capacity", "id": cap.document_id(corpus, n)},
                      "document": {"version": 3, "body": cap.document(corpus, n)}} for n in (2, 3)]
        reply = {"id": 0, "status": 0, "document": {"ok": True, "result": {"snapshot": {
            "incarnation": INCARNATION, "revision": 4, "queries": [], "documents": documents}}}}
        self.assertTrue(cap.pressure_reply(reply, request, corpus, INCARNATION, [3] * 5))
        refused = {"id": 0, "status": 8, "document": {"ok": False, "error": {"class": "resource_exhausted"}}}
        self.assertFalse(cap.pressure_reply(refused, request, corpus, INCARNATION, [3] * 5))
        for change in ("body", "class", "generation", "future"):
            bad = copy.deepcopy(refused if change == "class" else reply)
            if change == "body":
                bad["document"]["result"]["snapshot"]["documents"][1]["document"]["body"]["payload"] += "x"
            elif change == "class":
                bad["document"]["error"]["class"] = "unavailable"
            elif change == "generation":
                bad["document"]["result"]["snapshot"]["incarnation"] = str(uuid.UUID(int=5))
            else:
                bad["document"]["result"]["snapshot"]["documents"][0]["document"]["version"] = 5
            with self.subTest(change=change), self.assertRaises(ValueError):
                cap.pressure_reply(bad, request, corpus, INCARNATION, [3] * 5)

    def test_checkpoint_must_be_verified_complete_and_cover_the_corpus(self):
        session = str(uuid.UUID(int=9))
        checkpoint = {"tenant": TENANT, "source_incarnation": INCARNATION, "revision": 20, "resident_sha256": "a" * 64,
                      "backup_id": session, "manifest_ciphertext_sha256": "b" * 64, "key_lineage_digest": "c" * 64}
        created = {"checkpoint": "/c.json", "session_id": session}
        status = {"intent": {"session_id": session, "revision": 20},
                  "outcome": {"outcome": "complete", "checkpoint": checkpoint}}
        cap.checkpoint_facts(created, checkpoint, status, checkpoint, "/c.json", TENANT, INCARNATION, 20)
        with self.assertRaises(ValueError):
            cap.checkpoint_facts(created, checkpoint, status, checkpoint, "/c.json", TENANT, INCARNATION, 21)
        with self.assertRaises(ValueError):
            cap.checkpoint_facts(created, checkpoint, status, dict(checkpoint, revision=19), "/c.json",
                                 TENANT, INCARNATION, 19)
        with self.assertRaises(ValueError):
            cap.checkpoint_facts(created, checkpoint, {**status, "outcome": {"outcome": "aborted",
                                                                             "checkpoint": checkpoint}},
                                 checkpoint, "/c.json", TENANT, INCARNATION, 20)

    def test_renewal_rows_are_contiguous_and_bound_to_the_controller_clock(self):
        row = {"sequence": 0, "started_ns": 10, "finished_ns": 11, "exit_code": 0,
               "output": '{"expires_at_ms":1,"family_id":"f"}', "error": ""}
        self.assertEqual(len(cap.renewal_rows(cap.canonical(row), 10)), 1)
        for change in ({"sequence": 1}, {"started_ns": 9}, {"output": "{}"}, {"extra": 1}):
            with self.subTest(change=change), self.assertRaises((ValueError, KeyError)):
                cap.renewal_rows(cap.canonical({**row, **change}), 10)

    def test_ha_plan_requires_replacement_and_recovery_inputs(self):
        self.assertEqual(ha.port("https://localhost:9444/"), 9444)
        accept = ha.settled_leader([1, 2, 3], INCARNATION)
        status = {"mode": "replicated", "observation": "local_committed_state", "incarnation": INCARNATION,
                  "node_id": 2, "leader": 2, "raft_voters": [1, 2, 3], "raft_applied_index": 5, "revision": 5}
        self.assertTrue(accept(0, cap.canonical(status)))
        self.assertFalse(accept(0, cap.canonical({**status, "leader": 1})))
        self.assertFalse(accept(0, cap.canonical({**status, "raft_voters": [1, 2, 4]})))
        self.assertFalse(accept(1, cap.canonical(status)))
        self.assertFalse(accept(0, b"not json"))


class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.mkdtemp()
        self.fixture = Fixture(self.directory)
        self.facts = self.fixture.record()

    def tearDown(self):
        shutil.rmtree(self.directory)

    def rejected(self, facts=None):
        with self.assertRaises((ValueError, KeyError, StopIteration, TypeError)):
            replay(facts or self.facts)

    def rewrite(self, relative, transform):
        path = self.facts["custody"] / relative
        path.write_bytes(transform(path.read_bytes()))
        return path

    def rebind_stdout(self, step, transform):
        """Change one command's output and rebind its receipt hash honestly."""
        self.rewrite(step + "/stdout.log", transform)
        record = self.facts["receipts"][step]["record"]
        record["stdout"] = owned.ref(self.facts["custody"], self.facts["custody"] / step / "stdout.log")

    def test_untampered_run_replays_every_operation(self):
        self.assertEqual(replay(self.facts), cap.OPERATIONS)
        details = self.facts["report"]["details"]
        self.assertEqual(details["operations"]["snapshot"]["snapshot_index"], 260)
        self.assertEqual(details["operations"]["retained-read-pressure"]["readers"],
                         {"pressure-reader-0": {"served": 2, "refused": 0},
                          "pressure-reader-1": {"served": 2, "refused": 0}})
        self.assertEqual([p["id"] for p in self.facts["report"]["processes"]][:3],
                         ["measure-corpus", "node-0001", "renewal-0002"])
        self.assertEqual(sorted(details["polls"]), ["filesystem-restore-ready", "restart-ready", "s3-restore-ready",
                                                    "startup-ready"])

    def test_gate_details_lift_the_original_measurement_and_operations(self):
        report = self.facts["custody"] / "report.json"
        write_json(report, self.facts["report"])
        details = cap.gate_details(self.facts["custody"], report, cap.OPERATIONS)
        self.assertEqual(details["corpus"]["compression"]["log"]["path"], "measure/events.jsonl")
        self.assertEqual([op["id"] for op in details["operations"]], list(cap.OPERATIONS))
        self.assertEqual(details["operations"][0]["verification"]["path"], "ops/snapshot/driver/events.jsonl")
        self.assertEqual(details["operations"][0]["limits"]["maintenance_workspace_bytes"], 256)

    def test_changed_snapshot_observation_is_rejected(self):
        step = "snapshot-status-1"
        self.rebind_stdout(step, lambda raw: raw.replace(b'"raft_snapshot_index":260', b'"raft_snapshot_index":9'))
        self.rejected()

    def test_substituted_command_is_rejected(self):
        self.facts["receipts"]["restart-status"]["record"]["command"][2] = "/other/operator.json"
        self.rejected()

    def test_omitted_or_reordered_process_is_rejected(self):
        processes = self.facts["report"]["processes"]
        omitted = copy.deepcopy(self.facts)
        omitted["report"]["processes"] = [p for p in processes if p["id"] != "s3-backup-status"]
        self.rejected(omitted)
        swapped = copy.deepcopy(self.facts)
        items = swapped["report"]["processes"]
        a = next(i for i, p in enumerate(items) if p["id"] == "filesystem-backup-create")
        items[a], items[a + 1] = items[a + 1], items[a]
        self.rejected(swapped)

    def test_extra_retained_process_is_rejected(self):
        extra = copy.deepcopy(self.facts)
        extra["report"]["processes"].append(copy.deepcopy(extra["report"]["processes"][0]))
        self.rejected(extra)

    def test_other_executable_bytes_are_rejected(self):
        self.facts["receipts"]["load"]["record"]["executable"]["sha256"] = "0" * 64
        self.rejected()

    def test_skipped_poll_observation_is_rejected(self):
        polls = self.facts["report"]["details"]["polls"]["startup-ready"]
        self.assertEqual(len(polls), 2)
        self.facts["report"]["details"]["polls"]["startup-ready"] = polls[1:]
        self.rejected()

    def test_changed_resource_projection_is_rejected(self):
        self.rewrite("ops/compaction/resources.jsonl", lambda raw: raw.replace(b'"rss_bytes":1048576',
                                                                              b'"rss_bytes":1048575', 1))
        entry = self.facts["report"]["details"]["operations"]["compaction"]
        entry["resources"] = owned.ref(self.facts["custody"], self.facts["custody"] / entry["resources"]["path"])
        self.rejected()

    def test_sample_naming_another_process_is_rejected(self):
        path = self.facts["custody"] / "resources" / "samples.jsonl"
        rows = [json.loads(line) for line in path.read_bytes().splitlines()]
        target = next(row for row in rows if row["processes"])
        target["processes"][0]["pid"] += 1
        path.write_bytes(b"".join(cap.canonical(row) + b"\n" for row in rows))
        self.facts["report"]["details"]["samples"] = owned.ref(self.facts["custody"], path)
        backend = cap.Replay(self.facts, self.fixture.paths, self.fixture.digests)
        standalone.procedure(backend, None, "attempt-1")
        with self.assertRaises(ValueError):
            cap.verify_samples(cap.raw_samples(path), backend, self.facts["receipts"])

    def test_changed_pressure_reply_is_rejected(self):
        identifier = next(i for i in self.facts["receipts"] if i.startswith("pressure-reader-0-"))
        self.rewrite("services/" + identifier + ".log", lambda raw: raw.replace(b'"version":1', b'"version":2', 1))
        self.rejected()

    def test_changed_backup_verification_is_rejected(self):
        self.rebind_stdout("s3-backup-verify-backup", lambda raw: raw.replace(b'"revision":', b'"revision":1'))
        self.rejected()

    def test_restore_of_another_checkpoint_is_rejected(self):
        path = self.facts["custody"] / "ops" / "s3-restore" / "request.json"
        request = json.loads(path.read_text())
        request["checkpoint"]["revision"] += 1
        path.write_text(json.dumps(request))
        self.rejected()

    def test_unrequested_service_end_is_rejected(self):
        identifier = next(i for i in self.facts["receipts"] if i.startswith("node-"))
        self.facts["receipts"][identifier]["disposition"] = "input-closed"
        self.rejected()

    def test_renewal_service_without_a_renewal_is_rejected(self):
        identifier = next(i for i in self.facts["receipts"] if i.startswith("renewal-"))
        self.rewrite("services/" + identifier + ".log", lambda raw: raw.replace(b'"exit_code":0', b'"exit_code":1'))
        self.rejected()

    def test_scenario_selecting_another_step_is_rejected(self):
        self.facts["scenarios"]["restart"] = [{"step": "restart-status", "exit_code": 0, "expected_exit": 0}]
        self.rejected()

    def test_changed_driver_journal_is_rejected(self):
        path = self.facts["custody"] / "ops" / "restart" / "driver" / "events.jsonl"
        path.write_bytes(path.read_bytes().replace(b'"mode":"verify"', b'"mode":"load"'))
        self.rejected()

    def test_resource_row_above_its_admitted_limit_fails_the_run(self):
        rows = [{"elapsed_seconds": 1.0, "rss_bytes": 5, "allocated_disk_bytes": 1, "maintenance_workspace_bytes": 1}]
        limits = {"rss_bytes": 4, "allocated_disk_bytes": 9, "maintenance_workspace_bytes": 9}
        with self.assertRaises(ValueError):
            cap.within_limits(rows, limits)
        cap.within_limits(rows, dict(limits, rss_bytes=5))

    def test_oversized_maintenance_workspace_is_refused_before_dispatch(self):
        fixture = Fixture(Path(self.directory) / "oversized", scratch=1 << 30)
        with self.assertRaises(ValueError):
            fixture.record()
        self.assertEqual(fixture.recorder.report["processes"], [])


if __name__ == "__main__":
    unittest.main()
