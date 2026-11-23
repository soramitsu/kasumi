"""HA-fault and recovery runners against a stand-in product; never release evidence.

The stand-ins are one small script that speaks the product's command surface:
daemons heartbeat into a shared state directory, ``manage status`` elects a
leader among live voters, data commands refuse once every authority has been
silent for longer than the installed lease, and SIGHUP reloads one certificate.
They prove the runners' custody, fault timing and replaying adapters. They
prove nothing about Kasumi.
"""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import attempt_index
import domain_run
import ha_fault_driver as driver
import process_ha_topology as topology
from test_process_ha import fixture_control_placement
import release_gate
import repeatable_assembly as owned
import run_ha_faults as faults
import run_recovery as recovery
import test_domain_runs
import verify_release_acceptance as acceptance

INCARNATION = "0b5c0d63-3d56-4f0e-9d0b-4b3ad7a0c001"
CONTROL_INCARNATION = "0b5c0d63-3d56-4f0e-9d0b-4b3ad7a0c002"
LEASE_MS = 1000

PRODUCT = r'''
import base64, fcntl, hashlib, json, os, signal, subprocess, sys, time
from pathlib import Path
HERE = Path(__file__).resolve().parent
STATE = HERE / "state"
STALE = 0.6
args = sys.argv[1:]
knobs = HERE / "behavior.json"
behavior = json.loads(knobs.read_text()) if knobs.exists() else {}
registry = json.loads((STATE / "registry.json").read_text())


def load(name, default):
    path = STATE / name
    return json.loads(path.read_text()) if path.exists() else default


def save(name, value):
    pending = STATE / (name + ".pending-" + str(os.getpid()))
    pending.write_text(json.dumps(value))
    os.replace(pending, STATE / name)


class Lock:
    def __enter__(self):
        self.fd = os.open(STATE / "lock", os.O_CREAT | os.O_RDWR)
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, *_):
        fcntl.flock(self.fd, fcntl.LOCK_UN)
        os.close(self.fd)


def leaf(path):
    try:
        data = Path(path).read_bytes()
        block = data.split(b"-----BEGIN CERTIFICATE-----")[1].split(b"-----END CERTIFICATE-----")[0]
        der = base64.b64decode(b"".join(block.split()), validate=True)
        return hashlib.sha256(der).hexdigest() if der else None
    except Exception:
        return None


def alive(node):
    path = STATE / ("hb-" + str(node))
    try:
        pid = int(path.read_text())
        os.kill(pid, 0)
        if time.time() - path.stat().st_mtime < STALE:
            return True
        # A busy native builder can delay all Python heartbeats. Distinguish
        # a live but unscheduled stand-in from the SIGKILL fault the
        # controller actually sent. Both BSD and Linux ps expose these states.
        result = subprocess.run(["/bin/ps", "-o", "stat=", "-p", str(pid)],
                                capture_output=True, text=True, check=False)
        state = result.stdout.strip()
        return result.returncode == 0 and bool(state) and state[0] not in "TXZ"
    except (OSError, ValueError):
        return False


def beat(node):
    pending = STATE / (".hb-" + str(node) + "-" + str(os.getpid()))
    pending.write_text(str(os.getpid()))
    os.replace(pending, STATE / ("hb-" + str(node)))


def elect(cluster, key, members):
    if key == "leader":
        isolated = load("partition.json", {}).get("node")
        members = [n for n in members if n != isolated]
    current = cluster.get(key)
    if current in members and alive(current):
        return current
    live = [member for member in members if alive(member)]
    cluster[key] = min(live) if len(live) * 2 > len(members) else None
    return cluster[key]


def cluster_state():
    cluster = load("cluster.json", {"voters": registry["voters"], "learners": [], "leader": None,
                                    "control_leader": None, "applied": 0})
    elect(cluster, "leader", cluster["voters"])
    elect(cluster, "control_leader", registry["controls"])
    save("cluster.json", cluster)
    return cluster


def fail(message, code=1):
    print(json.dumps({"ok": False, "error": message}))
    sys.exit(code)


if args[:1] == ["serve"]:
    config = json.loads(Path(args[1]).read_text())
    node = config["replication"]["node_id"]
    reloads = []

    def reload_tls():
        if "admin" in config:
            current = leaf(config["admin"]["tls"]["certificate"])
            if current is None:
                print(json.dumps({"level": "WARN", "fields": {"event": "tls_reload_failed"}}),
                      flush=True)
            else:
                save("tls-" + str(node), current)

    reload_tls()
    signal.signal(signal.SIGHUP, lambda *_: reloads.append(1))
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(behavior.get("stop_exit", 0)))
    print(json.dumps({"event": "daemon_starting", "node": node}), flush=True)
    while True:
        beat(node)
        if reloads:
            reloads.clear()
            reload_tls()
        time.sleep(.05)


def data(words):
    with Lock():
        cluster = cluster_state()
        if cluster["leader"] is None:
            return 1, {"ok": False, "error": "unavailable"}
        heard = [(STATE / ("hb-" + str(a))).stat().st_mtime for a in registry["authorities"]
                 if (STATE / ("hb-" + str(a))).exists()]
        expired = not heard or time.time() - max(heard) > registry["lease_ms"] / 1000
        if expired and not any(alive(a) for a in registry["authorities"]) and not behavior.get("ignore_lease"):
            return 1, {"ok": False, "error": "authority lease expired"}
        documents = load("documents.json", {})
        if words[0] == "put":
            documents[words[2]] = json.loads(words[3])
            save("documents.json", documents)
            cluster["applied"] += 1
            save("cluster.json", cluster)
            return 0, {"ok": True, "result": {"receipt": {"revision": cluster["applied"] + 1}}}
        return 0, {"ok": True, "result": {"document": {"id": words[2],
                                                       "body": documents.get(words[2]),
                                                       "version": 1}}}


if args[:1] == ["--profile"]:
    profile = json.loads(Path(args[1]).read_text())
    rest = args[2:]
    if rest[0] == "session":
        for line in sys.stdin:
            request = json.loads(line)
            status, document = data(request["argv"])
            print(json.dumps({"id": request["id"], "status": status, "document": document}),
                  flush=True)
        sys.exit(0)
    if rest[0] in ("put", "get"):
        status, document = data(rest)
        print(json.dumps(document))
        sys.exit(status)
    if rest[0] == "manage":
        (member, bound), = profile["administrative_members"].items()
        node = int(member)
        if not alive(node):
            fail("member unreachable")
        serving = load("tls-" + str(node), None)
        if serving is not None and serving not in bound["certificate_pins"]:
            fail("server certificate is not pinned")
        request = json.loads(Path(rest[1]).read_text())
        operation = request["operation"]
        role = registry["roles"][str(node)]
        with Lock():
            cluster = cluster_state()
            if operation == "status":
                if role == "data" and cluster["leader"] is None:
                    fail("no data leader")
                output = {"mode": "replicated", "observation": "local_committed_state",
                          "incarnation": profile["resource"]["incarnation"], "node_id": node,
                          "leader": cluster["leader"], "raft_voters": sorted(cluster["voters"]),
                          "raft_applied_index": cluster["applied"] + 1,
                          "raft_membership_index": 1, "raft_snapshot_index": None,
                          "control_leader": cluster["control_leader"]}
                cut = load("partition.json", {})
                if cut.get("node") == node:
                    output["leader"] = node
                    output["raft_applied_index"] = cut["position"]
            elif operation == "add_learner":
                if not alive(request["node_id"]) or node != cluster["leader"]:
                    fail("learner unreachable")
                cluster["learners"].append(request["node_id"])
                output = {"caught_up": request["node_id"]}
            elif operation == "change_membership":
                if (node != cluster["leader"]
                        or not set(request["voters"]) <= {*cluster["voters"], *cluster["learners"]}):
                    fail("voters were not added as learners")
                cluster["voters"] = sorted(request["voters"])
                output = {"changed": True, "publish_control_route_required": True}
            elif operation == "publish_data_membership":
                if (node != cluster["control_leader"] or request["tenant"] != "unit"
                        or request["incarnation"] != registry["data_incarnation"]
                        or request["previous_voters"] != registry["voters"]
                        or sorted(request["voters"]) != cluster["voters"]):
                    fail("dedicated Control did not observe the expected Data membership")
                output = {"published": True}
            else:
                fail("unknown operation")
            save("cluster.json", cluster)
        print(json.dumps(output))
        sys.exit(0)

PHASES = ["prepare", "materialize", "initialize", "complete", "fence_source", "activate",
          "confirm", "publish", "finished"]
STOPS = {"stop_activation": ["permanent-stop"],
         "stop_target": ["issuer-drain", "gate-closure", "worker-drain", "storage-drain"],
         "cleanup": ["exact-deletion", "parent-sync", "durable-evidence"]}
TARGET_WORK = {"materialize", "initialize", "stop_target", "cleanup"}


def phase_id(state, kind):
    state["sequence"] = state.get("sequence", 0) + 1
    seed = state["request"]["operation_id"] + kind + str(state["sequence"])
    digest = hashlib.sha256(seed.encode()).hexdigest()
    return "-".join((digest[:8], digest[8:12], digest[12:16], digest[16:20], digest[20:32]))


def generation(target, request):
    digest = hashlib.sha256(json.dumps(request["tenant"]).encode()).hexdigest()
    return (Path(registry["target_roots"][str(target)]) / "generations"
            / (digest + "." + request["target_incarnation"] + ".kv"))


def complete(state):
    """Side effects of finishing the current point, then move to the next one."""
    request, phase = state["request"], state["phase"]
    if phase == "prepare":
        identifier = phase_id(state, "prepare")
        state["issuer_preparation"] = identifier
        state["phases"][identifier] = {
            "operation_id": request["operation_id"], "phase_id": identifier, "phase": "prepare",
            "input": {"kind": "authority", "input": {"source_incarnation": request["source_incarnation"]}},
            "outcome": {"kind": "authority", "outcome": {"signed": True}}}
    if phase == "materialize":
        for target in request["target_nodes"]:
            directory = generation(target, request)
            directory.mkdir(parents=True)
            (directory / "store.kv").write_bytes(b"stand-in generation\n")
            identifier = phase_id(state, "materialize")
            state["voters"][target]["materialization"] = identifier
            state["phases"][identifier] = {
                "operation_id": request["operation_id"], "phase_id": identifier,
                "phase": "materialize",
                "input": {"kind": "target", "input": {"node_id": int(target), "request": {
                    "target_incarnation": request["target_incarnation"]}}},
                "outcome": {"kind": "target", "outcome": {"materialized": True}}}
    if phase == "activate" and state["activation"] is None:
        state["activation"] = phase_id(state, "activate")
    if phase == "publish":
        state["route_publication"] = phase_id(state, "publish")
    if phase in STOPS:
        stages = STOPS[phase]
        if state["stage"] == "exact-deletion":
            for target in request["target_nodes"]:
                directory = generation(target, request)
                if directory.exists():
                    inode = directory.stat().st_ino
                    (directory / "store.kv").unlink()
                    directory.rmdir()
                    phase = phase_id(state, "cleanup-" + target)
                    state["voters"][target]["cleanup"] = phase
                    journal = directory.parents[1] / "stopped-journal.json"
                    journal.write_text(json.dumps({
                        "query": {"operation_id": request["operation_id"], "phase_id": phase,
                                  "target_incarnation": request["target_incarnation"],
                                  "node_id": int(target)},
                        "intent_id": request["operation_id"], "attempt_id": phase,
                        "stop_receipt_sha256": hashlib.sha256(phase.encode()).hexdigest(),
                        "binding_sha256": hashlib.sha256(str(inode).encode()).hexdigest(),
                        "progress": "deleted"}))
        index = stages.index(state["stage"])
        if index + 1 < len(stages):
            state["stage"] = stages[index + 1]
            return
        order = list(STOPS)
        following = order.index(phase) + 1
        if following < len(order):
            state["phase"], state["stage"] = order[following], STOPS[order[following]][0]
        else:
            state["phase"], state["stage"] = "stopped", None
        return
    state["phase"] = PHASES[PHASES.index(phase) + 1]


def recovery_state(operation):
    path = STATE / ("recovery-" + operation + ".json")
    if not path.exists():
        fail("unknown recovery operation")
    return json.loads(path.read_text())


def show(state):
    return {key: value for key, value in state.items() if key not in ("phases", "sequence", "sub")}


if args[:1] == ["control-recovery"]:
    begun = time.time()
    action = args[1]
    with Lock():
        cluster = cluster_state()
    if cluster["control_leader"] is None:
        fail("Control is unavailable")
    if action == "start":
        request = json.loads(Path(args[3]).read_text())
        Path(args[4]).write_text(json.dumps({"format": 1}))
        with Lock():
            path = STATE / ("recovery-" + request["operation_id"] + ".json")
            state = json.loads(path.read_text()) if path.exists() else {
                "request": request, "phase": "prepare", "stage": None, "created_revision": 1,
                "updated_revision": 1, "pending_phase": None, "sub": 0, "activation": None,
                "issuer_preparation": None, "route_publication": None,
                "voters": {target: {"materialization": None} for target in request["target_nodes"]},
                "phases": {}}
            save(path.name, state)
        print(json.dumps(show(state)))
        sys.exit(0)
    operation = args[3]
    if action == "status":
        print(json.dumps(show(recovery_state(operation))))
        sys.exit(0)
    if action == "phase":
        print(json.dumps(recovery_state(operation)["phases"][args[4]]))
        sys.exit(0)
    if action == "target-deletion-via-control":
        target = args[6]
        if not alive(int(target)):
            fail("target is unavailable")
        journal = Path(registry["target_roots"][target]) / "stopped-journal.json"
        print(journal.read_text())
        sys.exit(0)
    if action == "stop":
        with Lock():
            state = recovery_state(operation)
            if state["activation"] is not None or state["phase"] in PHASES[PHASES.index("activate"):]:
                fail("activation is committed; recovery continues forward")
            if state["phase"] not in STOPS and state["phase"] != "stopped":
                state.update(phase="stop_activation", stage="permanent-stop", sub=0,
                             pending_phase=None, updated_revision=state["updated_revision"] + 1)
                save("recovery-" + operation + ".json", state)
        print(json.dumps(show(state)))
        sys.exit(0)
    if action == "resume":
        deadline = begun + int(args[5]) / 1000
        state = recovery_state(operation)
        if state["phase"] in ("finished", "stopped"):
            print(json.dumps(show(state)))
            sys.exit(0)
        worker = (registry["targets"][0] if state["phase"] in TARGET_WORK
                  else cluster["control_leader"])
        time.sleep(.05)
        if time.time() > deadline:
            fail("deadline exceeded before the step began")
        if not alive(worker):
            fail("working daemon is unavailable")
        heartbeat = STATE / ("hb-" + str(worker))
        worker_pid = heartbeat.read_bytes()
        with Lock():
            state = recovery_state(operation)
            state["updated_revision"] += 1
            started_revision = state["updated_revision"]
            state["pending_phase"] = "pending"
            save("recovery-" + operation + ".json", state)
        # In the controlled process fixture, hold the scheduled crash case
        # after its durable start. The driver still kills the original daemon.
        armed = load("armed-recovery-fault.json", {})
        hold_for_fault = armed.get("operation") == operation
        if hold_for_fault:
            save("begun-recovery-fault.json", {"step": armed["step"], "worker_pid": int(worker_pid),
                                              "client_pid": os.getpid(), "revision": started_revision})
        until = time.time() + .7
        while True:
            if time.time() > deadline:
                fail("deadline exceeded after the step began")
            if not alive(worker) or heartbeat.read_bytes() != worker_pid:
                fail("working daemon was lost in flight")
            if not hold_for_fault and time.time() >= until:
                break
            time.sleep(.02)
        with Lock():
            state = recovery_state(operation)
            if state["updated_revision"] != started_revision:
                fail("another request changed the pending step")
            state["sub"] += 1
            state["updated_revision"] += 1
            # One surviving activation wins under this lock. Both racing
            # clients must be able to read the original winner on return.
            if state["phase"] == "activate" or state["sub"] == 4:
                state["sub"] = 0
                state["pending_phase"] = None
                complete(state)
            save("recovery-" + operation + ".json", state)
        print(json.dumps(show(state)))
        sys.exit(0)
    fail("unknown control-recovery action")
print(json.dumps({"ok": True, "argv": args}))
sys.exit(0)
'''


def pem(der):
    return (b"-----BEGIN CERTIFICATE-----\n" + base64.b64encode(der)
            + b"\n-----END CERTIFICATE-----\n")


def private(path, data):
    path.write_bytes(data)
    path.chmod(0o600)


class FaultFixture(test_domain_runs.DomainFixture):
    """Nine stand-in daemons, a spare learner and an operator's fault plan."""

    PARAMETERS = {"measured_seconds": 900, "startup_seconds": 120, "drain_seconds": 120,
                  "settle_polls": 600, "poll_pause_seconds": 0.05, "outage_margin_seconds": 0.2,
                  "load_seconds": 0.4, "reload_seconds": 0.3}

    def install(self):
        release = self.evidence / "target/release"
        for name in sorted(acceptance.package.BINARIES):
            path = release / name
            path.write_text("#!" + sys.executable + "\n# stand-in " + name + "\n" + PRODUCT)
            path.chmod(0o755)
            self.binaries[name] = (path, release_gate.sha256(path))
        (release / "state").mkdir()
        manifest = {"max_lease_ms": LEASE_MS, "clock_rate_error_ppm": 0, "partitions": {}}
        installed = self.root / "installed"
        plan = {"schema": topology.SCHEMA, "nodes": [],
                "binaries": {name: str(self.binaries[name][0])
                             for name in ("kasumid", "kasumi-authority")}}
        roles, self.leaves, self.homes = {}, {}, {}
        for role_index, role in enumerate(("data", "control", "authority")):
            peers, configs = [], []
            for index in range(3):
                node_id = role_index * 3 + index + 1
                name = f"{role}-{index + 1}"
                configs.append(self.node(installed, name, role, node_id, manifest, peers))
                plan["nodes"].append({"id": name, "role": role, "group": role,
                                      "config": str(installed / name / "config.json")})
                roles[str(node_id)] = role
            voters = [peer["node_id"] for peer in peers]
            if role == "data":
                spare_home, spare = self.node(installed, "data-spare", "data", 10, manifest, peers)
                spare["replication"].update(peers=peers, initial_voters=voters)
                (spare_home / "config.json").write_text(json.dumps(spare))
                spare_route = {key: peers[-1][key] for key in ("endpoint", "certificate_pins", "failure_domain")}
            for home, config in configs:
                config.update(fixture_control_placement(role))
                if role == "control":
                    config["control"]["remote_data"]["nodes"]["10"] = spare_route
                config["replication"].update(peers=peers, initial_voters=voters)
                (home / "config.json").write_text(json.dumps(config))
        roles["10"] = "data"
        self.topology = installed / "topology.json"
        self.topology.write_text(json.dumps(plan))
        (release / "state/registry.json").write_text(json.dumps({
            "voters": [1, 2, 3], "controls": [4, 5, 6], "authorities": [7, 8, 9],
            "lease_ms": LEASE_MS, "roles": roles, "data_incarnation": INCARNATION}))
        resource = {"kind": "database", "incarnation": INCARNATION}
        profiles = installed / "profiles"
        profiles.mkdir()

        def profile(name, value):
            path = profiles / (name + ".json")
            path.write_text(json.dumps(value))
            return str(path)

        def member(node_id, leaf, tenant="unit", kind=resource):
            return {"tenant": tenant, "resource": kind, "administrative_members": {
                str(node_id): {"endpoint": f"https://127.0.0.1:{21000 + node_id}",
                               "certificate_pins": [leaf]}}}

        rotated = installed / "data-2"
        new_der = b"rotated admin leaf data-2"
        (rotated / "admin-next.pem").write_bytes(pem(new_der))
        (rotated / "admin-restore.pem").write_bytes(pem(new_der))
        (rotated / "admin-invalid.pem").write_bytes(b"not a certificate\n")
        private(rotated / "admin-next-key.pem", b"stand-in private key next\n")
        new_leaf = hashlib.sha256(new_der).hexdigest()
        control = {"kind": "control", "incarnation": CONTROL_INCARNATION}
        self.plan_path = installed / "ha-faults-plan.json"
        self.plan = {
            "schema": faults.PLAN_SCHEMA, "collection": "faults",
            "data_profile": profile("data", {"tenant": "unit", "resource": resource}),
            "members": {str(n): profile(f"member-{n}", member(n, self.leaves[n]))
                        for n in (1, 2, 3, 10)},
            "control_members": {str(n): profile(f"control-{n}", member(n, self.leaves[n],
                                                                       "_control", control))
                                for n in (4, 5, 6)},
            "spare": {"id": "data-spare", "config": str(installed / "data-spare/config.json")},
            "trust_rotation": {
                "member": "data-2", "listener": "admin",
                "certificate": str(rotated / "admin-next.pem"),
                "private_key": str(rotated / "admin-next-key.pem"),
                "invalid_certificate": str(rotated / "admin-invalid.pem"),
                "restore_certificate": str(rotated / "admin-restore.pem"),
                "new_trust_profile": profile("new-trust", member(2, new_leaf))}}
        self.plan_path.write_text(json.dumps(self.plan))

    def node(self, installed, name, role, node_id, manifest, peers):
        home = installed / name
        for child in ("persistent", "scratch"):
            (home / child).mkdir(parents=True, mode=0o700)
        der = ("synthetic replication leaf " + name).encode()
        (home / "leaf.pem").write_bytes(pem(der))
        admin_der = ("synthetic admin leaf " + name).encode()
        (home / "admin.pem").write_bytes(pem(admin_der))
        private(home / "admin-key.pem", b"stand-in private key\n")
        self.leaves[node_id] = hashlib.sha256(admin_der).hexdigest()
        peers.append({"node_id": node_id, "endpoint": f"https://127.0.0.1:{20000 + node_id}",
                      "failure_domain": name,
                      "certificate_pins": [hashlib.sha256(der).hexdigest()]})
        config = {"mode": "replicated", "tenants": [], "target_recovery": None,
                  "database_path": str(home / "persistent/node.kv"),
                  "persistent_disk": {"roots": {"node": str(home / "persistent")}},
                  "scratch_disk": {"directory": str(home / "scratch")},
                  "signer_verifier": {"identity": {"node_id": node_id},
                                      "database_path": str(home / "persistent/verifier.kv")},
                  "replication": {"node_id": node_id,
                                  "listener": {"listen": f"127.0.0.1:{22000 + node_id}",
                                               "tls": {"certificate": str(home / "leaf.pem")}}},
                  "admin": {"tls": {"certificate": str(home / "admin.pem"),
                                    "private_key": str(home / "admin-key.pem")}},
                  "native": {"tls": {"certificate": str(home / "admin.pem"),
                                     "private_key": str(home / "admin-key.pem")}}}
        if role == "data":
            config["tenants"] = [{"tenant": "unit",
                                  "serving": {"kind": "independent", "authority": "issuer"}}]
            config["serving_authorities"] = {"issuer": {"manifest": manifest}}
        if role == "authority":
            config["installation"] = {"manifest": manifest}
        self.homes[name] = home
        return home, config

    def contract(self, module):
        patcher = patch.object(module, "PARAMETERS", dict(self.PARAMETERS))
        patcher.start()
        self.addCleanup(patcher.stop)

    def adapters(self, kind, module):
        patcher = patch.dict(acceptance.DOMAIN_ADAPTERS, {kind: module.verify_domain})
        patcher.start()
        self.addCleanup(patcher.stop)


class HaFaultTests(FaultFixture):

    def setUp(self):
        super().setUp()
        state = self.evidence / "target/release/state"

        class FixtureLinks:
            def __init__(self, routes):
                self.nodes = set(routes)

            def __enter__(self):
                return self

            def __exit__(self, *_):
                (state / "partition.json").unlink(missing_ok=True)

            def call(self, value):
                return value

            def cut(self, isolated, pids):
                self.isolated = isolated
                position = owned.read(state / "cluster.json")["applied"] + 1
                (state / "partition.json").write_text(json.dumps({"node": isolated, "position": position}))
                return 3

            def heal(self):
                (state / "partition.json").unlink()
                edges = [(a, b) for a in self.nodes for b in self.nodes if a != b and self.isolated in (a, b)]
                return {"unidentified": 0, "rejected": [{"source": a, "target": b, "count": 1}
                                                        for a, b in edges]}

        self.enterContext(patch.object(faults.ha_peer_links, "Links", FixtureLinks))

    def run_faults(self, attempt="faults-1"):
        output = self.root / "runs" / attempt
        output.parent.mkdir(exist_ok=True)
        with domain_run.Run(faults.KIND, faults.RUNNER, faults.MODULES, self.evidence, output,
                            self.root, attempt, dict(faults.PARAMETERS),
                            domain_run.QUALIFYING) as run:
            faults.execute(run, dict(faults.PARAMETERS), self.topology, self.plan_path)
        return output

    def test_every_fault_is_replayed_and_accepted_and_forgeries_are_rejected(self):
        self.contract(faults)
        self.adapters(faults.KIND, faults)
        custody = self.run_faults()
        report = owned.read(custody / "report.json")
        self.assertEqual(report["status"], "passed")
        self.assertEqual({item["id"] for item in report["scenarios"]},
                         acceptance.SCENARIOS["ha-faults"])
        # Each majority write and read must address its observed surviving leader.
        actions = [json.loads(line) for line in (custody / driver.LEDGER).read_bytes().splitlines()]
        for observation, probe in (("leader-loss-elected", "leader-loss-write"),
                                   ("partition-majority", "partition-write")):
            sample, = (item for item in report["processes"] if item["id"].endswith("-" + observation))
            leader = owned.read(owned.check_ref(custody, sample["log"]))["leader"]
            for verb in ("put", "get"):
                call, = (row for row in actions if row["kind"] == "call"
                         and row["step"].endswith("-" + probe + "-" + verb))
                self.assertEqual(call["argv"][2], self.plan["members"][str(leader)])
        # The nine originals are the topology; restarts are separate executions.
        self.assertEqual(len(report["topology"]), 9)
        dispositions = {}
        for item in report["processes"]:
            record = owned.read(owned.check_ref(custody, item["receipt"]))
            if record.get("schema") == domain_run.SERVICE_SCHEMA:
                dispositions.setdefault(domain_run.service_disposition(record), []).append(
                    record["name"])
        # Data leader, Control leader and three authorities were SIGKILLed.
        self.assertEqual(len(dispositions["fault"]), 5)
        self.assertEqual(dispositions["input-closed"], ["load"])
        details = report["details"]
        self.assertEqual(details["lease_seconds"], LEASE_MS / 1000)
        outage = details["facts"]["outage"]
        self.assertGreater(outage["ended"] - outage["started"], LEASE_MS / 1000)
        # Every refusal the scenarios demanded is retained outside the roster.
        refused = [item for item in details["attempts"]
                   if owned.read(owned.check_ref(custody, item["receipt"]))["exit_code"] != 0]
        self.assertTrue(any("expired-write" in item["id"] for item in refused))
        self.assertTrue(any("trust-old-refused" in item["id"] for item in refused))
        self.assertEqual(owned.read(custody / "outcome.json")["qualification"], "qualifying")

        record, identity, configs = self.gate(custody, faults.gate_details(
            self.root, custody / "report.json"))
        kind, attempt = self.accept(record, identity, configs)
        self.assertEqual((kind, attempt), ("ha-faults", "runs/faults-1/outcome.json"))

        def rejected(message, change):
            altered = copy.deepcopy(record)
            change(altered)
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                self.accept(altered, identity, configs)

        rejected("HA fault gate details differ", lambda r: r["details"].update(
            outage_seconds=r["details"]["outage_seconds"] + 1))
        # The adapter recomputes the outage before the shared contract checks it.
        rejected("HA fault gate details differ", lambda r: r["details"].update(
            outage_seconds=r["details"]["lease_seconds"] - 0.5))
        rejected("omitted or substituted an original owned process",
                 lambda r: r["processes"].pop())
        rejected("HA members must be separate owned processes|topology differs",
                 lambda r: r["topology"][0].update(process_id=r["topology"][1]["process_id"]))

        def forged(change, message):
            snapshot = custody.with_name(custody.name + "-snapshot")
            shutil.copytree(custody, snapshot)
            try:
                self.rewrite(custody, change)
                record, identity, configs = self.gate(custody, faults.gate_details(
                    self.root, custody / "report.json"))
                with self.subTest(forgery=message), self.assertRaisesRegex(ValueError, message):
                    self.accept(record, identity, configs)
            finally:
                shutil.rmtree(custody)
                shutil.copytree(snapshot, custody)
                shutil.rmtree(snapshot)

        def ledger(transform):
            def change(report):
                path = custody / driver.LEDGER
                rows = [json.loads(line) for line in path.read_bytes().splitlines()]
                path.write_bytes(b"".join(driver.canonical(row) for row in transform(rows)))
                report["details"]["ledger"] = owned.ref(custody, path)
            return change

        forged(ledger(lambda rows: rows[:-1]), "ledger has rows|ledger ended|differs")
        forged(ledger(lambda rows: [dict(row, argv=row["argv"][:-1]) if row["kind"] == "call"
                                    and "partition-write-get" in row["step"] else row
                                    for row in rows]), "action ledger differs")

        def outage_facts(report):
            report["details"]["facts"]["outage"]["ended"] += 100

        forged(outage_facts, "facts differ from the replayed script")

        forged(ledger(lambda rows: [row for row in rows if row["kind"] != "heal-peers"]),
               "action ledger differs")
        forged(ledger(lambda rows: [dict(row, observations={"unidentified": 3, "rejected": []})
                                    if row["kind"] == "heal-peers" else row for row in rows]),
               "did not observe both")

        def load_error(report):
            path = custody / "load.jsonl"
            rows = [json.loads(line) for line in path.read_bytes().splitlines()]
            rows[-1]["verdict"] = "error"
            path.write_bytes(b"".join(json.dumps(row).encode() + b"\n" for row in rows))
            report["details"]["load"] = owned.ref(custody, path)

        forged(load_error, "load row differs from its original session reply")

        def relabelled(report):
            report["invocation"]["parameters"] = dict(report["invocation"]["parameters"],
                                                      settle_polls=1)

        forged(relabelled, "differ from the qualifying contract")
        self.accept(record, identity, configs)

    def test_serving_after_lease_expiry_fails_and_stays_journaled(self):
        self.contract(faults)
        self.behave(ignore_lease=True)
        with self.assertRaisesRegex(ValueError, "continued after its authority lease expired"):
            self.run_faults("faults-lease")
        custody = self.root / "runs/faults-lease"
        report = owned.read(custody / "report.json")
        self.assertEqual(report["status"], "failed")
        receipts = [owned.read(owned.check_ref(custody, item["receipt"]))
                    for item in report["processes"] if "sha256" in item["receipt"]]
        services = [r for r in receipts if r.get("schema") == domain_run.SERVICE_SCHEMA]
        self.assertTrue(all(r["cleanup"]["drained"] for r in services))
        entries = attempt_index.replay(self.root)
        attempts = [{"id": "faults-lease", "receipt": entries["faults-lease"]["terminal"]["receipt"]}]
        acceptance.verify_attempts(self.root, attempts, {})
        with self.assertRaisesRegex(ValueError, "selected attempt failed"):
            acceptance.verify_attempts(self.root, attempts,
                                       {"runs/faults-lease/outcome.json": "ha-faults"})

    def test_rehearsal_is_labelled_and_rejected(self):
        self.contract(faults)
        self.adapters(faults.KIND, faults)
        output = self.root / "runs/rehearsal"
        output.parent.mkdir(exist_ok=True)
        parameters = dict(faults.PARAMETERS, settle_polls=599)
        with domain_run.Run(faults.KIND, faults.RUNNER, faults.MODULES, self.evidence, output,
                            self.root, "rehearsal", parameters, domain_run.REHEARSAL) as run:
            faults.execute(run, parameters, self.topology, self.plan_path)
        record, identity, configs = self.gate(output, faults.gate_details(
            self.root, output / "report.json"))
        with self.assertRaisesRegex(ValueError, "non-qualifying rehearsal"):
            self.accept(record, identity, configs)

    def test_plan_and_staged_inputs_are_checked_before_dispatch(self):
        plan = json.loads(self.plan_path.read_text())
        faults.check_plan(copy.deepcopy(plan))
        for change, message in (
                (lambda p: p.update(schema="other"), "unsupported HA fault plan"),
                (lambda p: p["trust_rotation"].update(listener="replication"),
                 "not a client endpoint"),
                (lambda p: p["members"].update({"01": p["members"]["1"]}), "map node ids"),
                (lambda p: p.pop("spare"), "fields differ")):
            changed = copy.deepcopy(plan)
            change(changed)
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                faults.check_plan(changed)
        # A staged certificate elsewhere cannot be renamed over the installed one.
        moved = copy.deepcopy(plan)
        moved["trust_rotation"]["certificate"] = str(self.root / "elsewhere.pem")
        self.plan_path.write_text(json.dumps(moved))
        with self.assertRaisesRegex(ValueError, "not beside its target"):
            self.run_faults("faults-staged")
        outcome = owned.read(self.root / "runs/faults-staged/outcome.json")
        self.assertEqual((outcome["status"], outcome["dispatch_started"]), ("failed", False))


    def test_learner_requires_pinned_transport_and_control_approval_before_dispatch(self):
        configs = {row["id"]: Path(row["config"]) for row in owned.read(self.topology)["nodes"]}
        for label, message in (("transport", "installed pinned transport pool"),
                               ("approval", "approved Control topology")):
            originals = {name: path.read_bytes() for name, path in configs.items()}
            with self.subTest(label=label):
                for name, path in configs.items():
                    config = json.loads(originals[name])
                    if label == "transport" and name.startswith("data-"):
                        config["replication"]["peers"].pop()
                    if label == "approval" and name == "control-2":
                        config["control"]["remote_data"]["nodes"]["10"]["endpoint"] += "/other"
                    path.write_text(json.dumps(config))
                with self.assertRaisesRegex(ValueError, message):
                    self.run_faults("learner-" + label)
                outcome = owned.read(self.root / "runs" / ("learner-" + label) / "outcome.json")
                self.assertFalse(outcome["dispatch_started"])
            for name, path in configs.items():
                path.write_bytes(originals[name])


class RecoveryFixture(FaultFixture):
    """The nine stand-ins plus three separately installed recovery targets."""

    PARAMETERS = {"measured_seconds": 1800, "startup_seconds": 120, "drain_seconds": 120,
                  "settle_polls": 600, "poll_pause_seconds": 0.05, "step_limit": 1500,
                  "request_timeout_ms": 60000, "deadlines_ms": [5, 20, 250, 400],
                  "fault_delays": [0.35, 0.5, 0.65]}

    def install(self):
        super().install()
        installed = self.root / "installed"
        release = self.evidence / "target/release"
        registry = json.loads((release / "state/registry.json").read_text())
        manifest = {"max_lease_ms": LEASE_MS, "clock_rate_error_ppm": 0, "partitions": {}}
        peers, configs, targets = [], [], []
        for index in range(3):
            node_id = 11 + index
            name = f"target-{index + 1}"
            home, config = self.node(installed, name, "data", node_id, manifest, peers)
            generation_root = home / "persistent/generations"
            generation_root.mkdir()
            config["target_recovery"] = {"generation_root": str(generation_root)}
            configs.append((home, config))
            targets.append({"id": name, "config": str(home / "config.json")})
            registry["roles"][str(node_id)] = "data"
            registry.setdefault("target_roots", {})[str(node_id)] = str(home / "persistent")
        for home, config in configs:
            config["replication"].update(peers=peers, initial_voters=[11, 12, 13])
            (home / "config.json").write_text(json.dumps(config))
        registry["targets"] = [11, 12, 13]
        (release / "state/registry.json").write_text(json.dumps(registry))
        plan = json.loads(self.plan_path.read_text())
        profiles = installed / "profiles"

        def request(name, operation, target):
            path = installed / (name + ".json")
            path.write_text(json.dumps({
                "operation_id": operation, "tenant": "unit", "source_incarnation": INCARNATION,
                "target_incarnation": target, "source_mode": {"mode": "source_unavailable"},
                "target_nodes": {str(n): {"failure_domain": f"zone-{n}"} for n in (11, 12, 13)},
                "phase_timeout_ms": 60000}))
            return str(path)

        control = {"tenant": "_control",
                   "resource": {"kind": "control", "incarnation": CONTROL_INCARNATION},
                   "administrative_members": {str(n): {"endpoint": f"https://127.0.0.1:{21000 + n}",
                                                       "certificate_pins": [self.leaves[n]]}
                                              for n in (4, 5, 6)}}
        (profiles / "control-admin.json").write_text(json.dumps(control))
        self.recovery_plan_path = installed / "recovery-plan.json"
        self.recovery_plan = {
            "schema": recovery.PLAN_SCHEMA, "collection": "faults",
            "control_profile": str(profiles / "control-admin.json"),
            "control_members": plan["control_members"],
            "source_members": {key: plan["members"][key] for key in ("1", "2", "3")},
            "data_profile": plan["data_profile"],
            "stopped_request": request("stopped-request", "5f0e7c1a-0d7e-4c4e-8a51-3f1d2c9b0a01",
                                       "5f0e7c1a-0d7e-4c4e-8a51-3f1d2c9b0a11"),
            "request": request("recovery-request", "5f0e7c1a-0d7e-4c4e-8a51-3f1d2c9b0a02",
                               "5f0e7c1a-0d7e-4c4e-8a51-3f1d2c9b0a12"),
            "targets": targets}
        self.recovery_plan_path.write_text(json.dumps(self.recovery_plan))


class RecoveryTests(RecoveryFixture):
    def fault_after_pending_write(self, original, driver_instance, label, argv, name, observation, delay, scenarios=()):
        record = json.loads(observation)
        if argv[1:3] != ["control-recovery", "resume"] or "updated_revision" not in record:
            return original(driver_instance, label, argv, name, observation, delay, scenarios)
        state = self.binaries["kasumid"][0].parent / "state"
        armed, begun = state / "armed-recovery-fault.json", state / "begun-recovery-fault.json"
        services = driver_instance.run.services
        send = services.crash
        revision = record["updated_revision"]
        armed.write_text(json.dumps({"step": label, "operation": argv[4]}))

        def crash(service, path, *, client=None):
            end = time.monotonic() + 30
            while time.monotonic() < end:
                if begun.exists():
                    pending = json.loads(begun.read_text())
                    if (client and pending["step"] == label and pending["revision"] > revision
                            and pending["client_pid"] == client["group"]
                            and pending["worker_pid"] == services.active[service]["process"].pid):
                        return send(service, path, client=client)
                time.sleep(.01)
            raise AssertionError("scheduled original never published its pending step: " + label)

        try:
            with patch.object(services, "crash", crash):
                return original(driver_instance, label, argv, name, observation, delay, scenarios)
        finally:
            armed.unlink(missing_ok=True)
            begun.unlink(missing_ok=True)


    def run_recovery(self, attempt="recovery-1"):
        output = self.root / "runs" / attempt
        output.parent.mkdir(exist_ok=True)
        with domain_run.Run(recovery.KIND, recovery.RUNNER, recovery.MODULES, self.evidence,
                            output, self.root, attempt, dict(recovery.PARAMETERS),
                            domain_run.QUALIFYING) as run:
            original = driver.Live.faulted
            def scheduled(instance, *args, **kwargs):
                return self.fault_after_pending_write(original, instance, *args, **kwargs)
            with patch.object(driver.Live, "faulted", scheduled):
                recovery.execute(run, dict(recovery.PARAMETERS), self.topology,
                                 self.recovery_plan_path)
        return output

    def witnessed(self):
        """A product that reports its target-local deletion stage in Control status."""
        patcher = patch.object(recovery, "deletion_stage", lambda record: record.get("stage"))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_without_a_deletion_stage_witness_the_run_fails_with_open_cells(self):
        self.contract(recovery)
        with self.assertRaisesRegex(ValueError, "open recovery cells") as raised:
            self.run_recovery("recovery-open")
        message = str(raised.exception)
        for label in recovery.DELETION_LABELS:
            self.assertIn(label + "-crash", message)
            self.assertIn(label + "-cancellation", message)
        custody = self.root / "runs/recovery-open"
        report = owned.read(custody / "report.json")
        self.assertEqual(report["status"], "failed")
        facts = report["details"]["facts"]
        # Everything that has a product witness still ran and landed.
        landed = {cell for cell, outcome in facts["cells"].items() if outcome.get("landed")}
        required = {f"{label}-{fault}" for label in recovery.RECOVERY_LABELS.values()
                    for fault in ("crash", "cancellation")}
        self.assertEqual(required - landed, set(), facts["open"])
        # The Control-visible stop phases were faulted as diagnostics, not counted.
        self.assertTrue({"boundary-stop-target-crash", "boundary-cleanup-cancellation"} <= set(facts["cells"]))
        self.assertEqual([item["cell"] for item in facts["open"]],
                         [f"{label}-{fault}" for label in recovery.DELETION_LABELS
                          for fault in ("crash", "cancellation")])
        entries = attempt_index.replay(self.root)
        attempts = [{"id": "recovery-open",
                     "receipt": entries["recovery-open"]["terminal"]["receipt"]}]
        acceptance.verify_attempts(self.root, attempts, {})

    def test_witnessed_matrix_is_replayed_and_accepted_and_forgeries_are_rejected(self):
        self.contract(recovery)
        self.witnessed()
        self.adapters(recovery.KIND, recovery)
        custody = self.run_recovery()
        report = owned.read(custody / "report.json")
        self.assertEqual(report["status"], "passed")
        self.assertEqual({item["id"] for item in report["scenarios"]},
                         acceptance.SCENARIOS["recovery"])
        facts = report["details"]["facts"]
        self.assertEqual(facts["available_source_voters"], 1)
        self.assertEqual(facts["activation_winners"], 1)
        self.assertEqual(facts["forward"]["stop_exit"], 1)
        self.assertEqual(facts["stopped"]["remaining"], [])
        self.assertTrue(facts["stopped"]["unrelated_kept"])
        self.assertTrue(facts["stopped"]["persisted"])
        self.assertEqual(set(facts["stopped"]["journals"]), {"target-1", "target-2", "target-3"})
        self.assertEqual(facts["stopped"]["journals"], facts["stopped"]["reopened_journals"])
        record, identity, configs = self.gate(custody, recovery.gate_details(
            self.root, custody / "report.json"))
        self.assertEqual(record["details"]["source_voters"], 3)
        kind, attempt = self.accept(record, identity, configs)
        self.assertEqual((kind, attempt), ("recovery", "runs/recovery-1/outcome.json"))

        def rejected(message, change):
            altered = copy.deepcopy(record)
            change(altered)
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                self.accept(altered, identity, configs)

        rejected("recovery gate details differ",
                 lambda r: r["details"].update(available_source_voters=0))
        rejected("recovery gate details differ|unique activation winner",
                 lambda r: r["details"].update(activation_winners=2))
        rejected("omitted or substituted", lambda r: r["processes"].pop(0))

        def forged(change, message):
            snapshot = custody.with_name(custody.name + "-snapshot")
            shutil.copytree(custody, snapshot)
            try:
                self.rewrite(custody, change)
                record, identity, configs = self.gate(custody, recovery.gate_details(
                    self.root, custody / "report.json"))
                with self.subTest(forgery=message), self.assertRaisesRegex(ValueError, message):
                    self.accept(record, identity, configs)
            finally:
                shutil.rmtree(custody)
                shutil.copytree(snapshot, custody)
                shutil.rmtree(snapshot)

        def unplanted(report):
            path = custody / driver.LEDGER
            rows = [json.loads(line) for line in path.read_bytes().splitlines()]
            for row in rows:
                if row["kind"] == "inspect" and row["result"] is not None:
                    row["result"]["inode"] += 1
                    break
            path.write_bytes(b"".join(driver.canonical(row) for row in rows))
            report["details"]["ledger"] = owned.ref(custody, path)

        # A touched unrelated file changes the script's own path: the replay
        # then expects a different next action than the ledger holds.
        forged(unplanted, "action ledger differs|recovery facts differ")

        def second_winner(report):
            path = custody / driver.LEDGER
            rows = [json.loads(line) for line in path.read_bytes().splitlines()]
            for row in rows:
                if row["kind"] == "race":
                    row["results"][0]["exit_code"] = 3
            path.write_bytes(b"".join(driver.canonical(row) for row in rows))
            report["details"]["ledger"] = owned.ref(custody, path)

        forged(second_winner, "racing client differs from its original receipt")

        def claimed_landing(report):
            report["details"]["facts"]["cells"]["activation-crash"]["delay_seconds"] = 99

        forged(claimed_landing, "recovery facts differ")
        self.accept(record, identity, configs)

    def test_requests_and_targets_are_checked_before_dispatch(self):
        plan = json.loads(self.recovery_plan_path.read_text())
        recovery.check_plan(copy.deepcopy(plan))
        for change, message in (
                (lambda p: p.update(schema="other"), "unsupported recovery plan"),
                (lambda p: p["targets"].pop(), "three separately installed target"),
                (lambda p: p["targets"][1].update(id=p["targets"][0]["id"]), "targets repeat")):
            changed = copy.deepcopy(plan)
            change(changed)
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                recovery.check_plan(changed)
        request = json.loads(Path(plan["request"]).read_text())
        recovery.check_request(copy.deepcopy(request), "unit")
        planned = dict(request, source_mode={"mode": "planned", "retirement_id": "r",
                                             "source_backup_destination": "d"})
        with self.assertRaisesRegex(ValueError, "source-unavailable"):
            recovery.check_request(planned, "unit")
        # The same request twice is not two recovery attempts.
        Path(plan["stopped_request"]).write_text(Path(plan["request"]).read_text())
        with self.assertRaisesRegex(ValueError, "not distinct attempts"):
            self.run_recovery("recovery-same")
        outcome = owned.read(self.root / "runs/recovery-same/outcome.json")
        self.assertEqual((outcome["status"], outcome["dispatch_started"]), ("failed", False))


class DeletionObservationTests(unittest.TestCase):
    def test_stopped_cleanup_follows_each_installed_generation(self):
        request = {"tenant": "unit", "target_incarnation": INCARNATION}
        name = hashlib.sha256(b'"unit"').hexdigest() + "." + INCARNATION + ".kv"
        targets = [{"id": str(n), "generation_root": "/installed/" + str(n)} for n in range(3)]
        snapshots = {}
        for n, target in enumerate(targets):
            directory = {"type": "dir", "device": 1, "inode": 10 * n + 1}
            snapshots[target["id"]] = {target["generation_root"]: {
                name: directory, name + "/root.kvroot": {**directory, "type": "file",
                                                         "inode": 10 * n + 2},
                "tenant-audit-archives": {**directory, "inode": 10 * n + 3}}}
        def entries(materialized=False):
            return recovery.generation_entries(snapshots, targets, request,
                                               materialized=materialized)
        self.assertEqual(len(entries(True)), 6)
        last = snapshots["2"]["/installed/2"]
        last[name]["inode"] = snapshots["1"]["/installed/1"][name]["inode"]
        with self.assertRaisesRegex(ValueError, "share a physical generation"):
            entries(True)
        last.pop(name + "/root.kvroot")
        with self.assertRaisesRegex(ValueError, "missing materialized generation on 2"):
            entries(True)
        for n in (0, 1):
            root = "/installed/" + str(n)
            snapshots[str(n)][root].pop(name)
            snapshots[str(n)][root].pop(name + "/root.kvroot")
        self.assertEqual(list(entries()), ["/installed/2/" + name])
        last[name] = {"type": "other", "device": 1, "inode": 900}
        self.assertTrue(entries())
        last.pop(name)
        self.assertEqual(entries(), {})

    def test_crash_interruption_requires_a_live_original_client_at_the_signal(self):
        receipt = {"process_group": 17, "leader_birth": "linux:123"}
        witness = {"step": "original", "group": 17, "birth": "linux:123", "live": True}
        def interrupted(proof):
            live = driver.fault_client_live(proof, "original", receipt)
            return driver.interrupted({"client_live": live, "exit_code": 1, "started": 1,
                                       "fault_elapsed": 2, "finished": 3})
        self.assertTrue(interrupted({"client_at_signal": witness}))
        self.assertFalse(interrupted({}))
        self.assertFalse(interrupted({"client_at_signal": {**witness, "live": False}}))
        for field, value in (("birth", "linux:321"), ("group", 4), ("step", "unrelated")):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "original process"):
                interrupted({"client_at_signal": {**witness, field: value}})

    operation = "aa000000-0000-0000-0000-000000000001"
    phase = "bb000000-0000-0000-0000-000000000002"
    incarnation = "cc000000-0000-0000-0000-000000000003"
    intent = "dd000000-0000-0000-0000-000000000004"
    attempt = "ee000000-0000-0000-0000-000000000005"

    def observed(self, node, progress="deleting"):
        return {"query": {"operation_id": self.operation, "phase_id": self.phase,
                          "target_incarnation": self.incarnation, "node_id": node},
                "intent_id": self.intent, "attempt_id": self.attempt,
                "stop_receipt_sha256": "a" * 64, "binding_sha256": "b" * 64,
                "progress": progress}

    def run_fault(self, node, stages, interrupted=True, begun=False):
        targets = [{"id": f"target-{i}", "node_id": i, "observer_profile": "observer"}
                   for i in [11, 12, 13]]
        router = lambda *fields: list(fields)
        ctx = SimpleNamespace(targets=targets, live={11, 12, 13}, stopped={"target_incarnation": self.incarnation},
                              polls=2, pause=0, timeout=9000, recovery=router, kasumid=router,
                              resume=router, parameters={"fault_delays": [0.2]},
                              by_node={t["node_id"]: {**t, "executable": {}, "config": "installed"} for t in targets})
        phase = {"operation_id": self.operation, "phase_id": self.phase, "phase": "cleanup",
                 "outcome": None, "effect_attempts": {"target_command": {}} if begun else {},
                 "input": {"kind": "target", "input": {"node_id": node,
                          "request": {"command_id": self.intent, "step": {"Stop": {}}}}}}
        d = Mock()
        d.call.return_value = json.dumps(phase).encode()
        d.attempt.side_effect = [(0, json.dumps(v).encode()) for v in stages]
        d.crash.return_value = {"id": "caller"}
        d.faulted.return_value = {"process": "target", "exit_code": 1 if interrupted else 0,
                                  "started": 1, "fault_elapsed": 2, "finished": 3, "client_live": True}
        facts = {"cells": {}}
        recovery.target_deletion_fault(d, ctx, self.operation, self.phase, 0, facts)
        return d, facts

    def test_distinct_target_certificate_observes_original_cleanup_via_control(self):
        expected = self.observed(11)
        query = expected["query"]
        observer = Mock()
        observer.attempt.return_value = (0, json.dumps(expected).encode())
        ctx = SimpleNamespace(timeout=9000, recovery=Mock(return_value=["routed"]))
        target = {"node_id": 11, "control_observer": True}
        self.assertTrue(recovery.can_observe_deletion(target))
        actual, _ = recovery.deletion_view(observer, ctx, query, target, "cleanup")
        self.assertEqual(expected, actual)
        ctx.recovery.assert_called_once_with("target-deletion-via-control", self.operation,
                                             self.phase, self.incarnation, "11", "9000")
        observer.attempt.assert_called_once_with("cleanup", ["routed"])

    def test_materialized_terminal_requires_its_original_physical_binding(self):
        ctx = SimpleNamespace(timeout=1000, polls=2, pause=0, recovery=Mock(return_value=["routed"]),
                              stopped={"operation_id": self.operation,
                                       "target_incarnation": self.incarnation})
        target = {"id": "target-11", "node_id": 11}
        final = {"voters": {"11": {"cleanup": self.phase}}}
        original = self.observed(11, "deleted")
        for reported, expected in ((original, original), ({**original, "binding_sha256": None}, None),
                                   ({**original, "progress": "parent_synced"}, None)):
            observer = Mock()
            observer.attempt.side_effect = [(1, b"starting"), (0, json.dumps(reported).encode())]
            self.assertEqual(recovery.stopped_deletion(observer, ctx, final, target, "cold"),
                             expected)
            self.assertEqual(observer.attempt.call_count, 2)

    def test_caller_disconnection_requires_unchanged_original_pending_journal(self):
        original = self.observed(11)
        driver, facts = self.run_fault(11, [original, original])
        self.assertTrue(facts["cells"]["exact-deletion-cancellation"]["landed"])
        driver.mark.assert_called_once_with("exact-deletion-cancellation", "caller", -9)
        for after in (self.observed(11, "unlinked"), {**original, "attempt_id": self.intent}):
            driver, facts = self.run_fault(11, [original, after])
            self.assertFalse(facts["cells"])
            driver.mark.assert_not_called()

    def test_only_cold_unfinished_target_after_original_inflight_crash_counts(self):
        driver, facts = self.run_fault(12, [self.observed(12, "unlinked")])
        self.assertEqual(facts["cells"]["parent-sync-crash"]["victim"], 12)
        driver.mark.assert_called_once_with("parent-sync-crash", "target", -9)
        for stages, interrupted, begun in (([], False, False), ([], True, True),
                                            ([self.observed(12, "deleted")], True, False)):
            driver, facts = self.run_fault(12, stages, interrupted, begun)
            self.assertFalse(facts["cells"])
            driver.mark.assert_not_called()

    def test_only_begun_owner_drain_marks_can_attribute_a_fault(self):
        for stage, label in [("closing_gates", "gate-closure"), ("draining_workers", "worker-drain"),
                             ("draining_storage", "storage-drain")]:
            observed = {**self.observed(12, stage), "binding_sha256": None}
            d, facts = self.run_fault(12, [observed])
            self.assertTrue(facts["cells"][label + "-crash"]["landed"])
            d.mark.assert_called_once_with(label + "-crash", "target", -9)
        for stage in ("stop_recorded", "gates_closed", "workers_drained", "storage_drained", "deleted"):
            d, facts = self.run_fault(12, [self.observed(12, stage)])
            self.assertFalse(facts["cells"])
            d.mark.assert_not_called()

    def test_substituted_target_and_missing_physical_binding_are_refused(self):
        for observation in (self.observed(11), {**self.observed(12), "binding_sha256": None}):
            with self.assertRaises(ValueError):
                self.run_fault(12, [observation])


class IssuerObservationTests(unittest.TestCase):
    op = DeletionObservationTests.operation
    phase_id = DeletionObservationTests.phase
    target = DeletionObservationTests.incarnation
    command = DeletionObservationTests.intent
    attempt = DeletionObservationTests.attempt
    authority = "11000000-0000-0000-0000-000000000001"
    boot = "22000000-0000-0000-0000-000000000002"
    grace = "33000000-0000-0000-0000-000000000003"

    def observation(self, stage, begun=True):
        query = {"tenant": "city", "command_id": self.command, "target_incarnation": self.target}
        observed = None if stage is None else {"query": query, "node_id": 22, "authority_id": self.authority,
                "partition": 0, "boot_id": self.boot, "term": 4, "stage": stage, "command_sha256": "c" * 64,
                "first_stop_sha256": None if stage == "submitting" else "d" * 64,
                "interval_id": self.grace if stage in ("draining", "drained") else None}
        return {"phase": {"phase_id": self.phase_id, "operation_id": self.op}, "query": query,
                "attempt_id": self.attempt if begun else None, "observed": observed}

    def trial(self, phase_input, views):
        route = lambda *fields: list(fields)
        node = {"id": "issuer-22", "role": "authority", "executable": {}, "config": "installed"}
        ctx = SimpleNamespace(stopped={"tenant": "city", "target_incarnation": self.target}, issuer_domains={22: (self.authority, 0)},
                              by_node={22: node}, name=lambda _: node["id"], live={22},
                              polls=1, pause=0, timeout=10000, recovery=route, resume=route, parameters={"fault_delays": [0.2]})
        control = {"phase_id": self.phase_id, "operation_id": self.op, "outcome": None,
                   "effect_attempts": {}, "input": phase_input}
        d = Mock()
        d.call.return_value = json.dumps(control).encode()
        d.attempt.side_effect = [(0, json.dumps(v).encode()) for v in views]
        d.crash.return_value = {"id": "caller"}
        d.faulted.return_value = {"process": "original-issuer", "exit_code": 1,
                                  "started": 1, "fault_elapsed": 2, "finished": 3, "client_live": True}
        facts = {"cells": {}}
        recovery.issuer_stop_fault(d, ctx, self.op, self.phase_id, 0, facts)
        return d, facts["cells"]

    def test_original_submission_and_issuer_interval_are_independently_attributed(self):
        command = {"tenant": "city", "command_id": self.command}
        permanent = {"kind": "authority", "input": {**command, "action": {"kind": "stop_target"}}}
        issuer = {"kind": "target", "input": {"request": {"step": {"Stop": command}}}}
        for packet, initial, stage, label in ((permanent, None, "submitting", "permanent-stop"),
                                               (issuer, "committed", "draining", "issuer-drain")):
            pending = self.observation(stage)
            d, facts = self.trial(packet, [self.observation(initial, False), pending, pending, pending])
            self.assertEqual(set(facts), {label + "-crash", label + "-cancellation"})
            self.assertEqual(facts[label + "-crash"]["victim"], 22)
            self.assertEqual(d.mark.call_args_list[-1].args, (label + "-crash", "original-issuer", -9))

    def test_restarted_grace_or_other_process_cannot_prove_the_original_crash(self):
        packet = {"kind": "target", "input": {"request": {"step": {"Stop": {"tenant": "city", "command_id": self.command}}}}}
        waiting = self.observation("draining")
        for override in ({"boot_id": self.grace}, {"interval_id": self.boot}, {"term": 5}, {"stage": "drained"}):
            cold = {**waiting, "observed": {**waiting["observed"], **override}}
            _, facts = self.trial(packet, [self.observation("committed", False), waiting, waiting, cold])
            self.assertEqual(set(facts), {"issuer-drain-cancellation"})
        _, facts = self.trial(packet, [self.observation("draining", False)])
        self.assertFalse(facts)

    def test_different_authority_or_phase_rejected(self):
        packet = {"kind": "authority", "input": {"tenant": "city", "command_id": self.command, "action": {"kind": "stop_target"}}}
        pending = self.observation("submitting")
        for other in ({**pending, "phase": {"phase_id": self.op, "operation_id": self.phase_id}},
                      {**pending, "observed": {**pending["observed"], "authority_id": self.boot}}):
            with self.assertRaises(ValueError):
                self.trial(packet, [self.observation(None, False), other])


if __name__ == "__main__":
    unittest.main()
