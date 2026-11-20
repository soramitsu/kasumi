#!/usr/bin/env python3
"""Inject HA faults into the installed nine-process topology and replay them.

Every fault is an owned action on an owned candidate daemon: a controller
SIGKILL (leader loss, authority outage), a whole-group SIGSTOP/SIGCONT freeze
(an isolated minority: no peer or client reaches it and it reaches no one), a
clean stop and respawn, a SIGHUP reload after an operator-staged certificate
rename, and Raft membership commands. Every observation is an owned candidate
``kasumictl`` process. The adapter replays the same scenario script against the
retained receipts, so each verdict is recomputed by the code that produced it.

A network partition between separate hosts, and failure domains reserved by an
operator, are outside what a single installation's process owner can create;
this runner never changes host networking.
"""
from __future__ import annotations

import sys
if __name__ == "__main__" and not (sys.flags.isolated and sys.flags.no_site
                                  and sys.flags.dont_write_bytecode):
    raise SystemExit("HA fault runner requires native Python -I -S -B")

import argparse
import json
import os
from pathlib import Path
import re
import threading
import time

if __name__ == "__main__":
    _scripts = Path(__file__).resolve(strict=True).parent
    if sys.pycache_prefix is not None or "PYTHONPYCACHEPREFIX" in os.environ:
        raise SystemExit("HA fault runner forbids a redirected Python bytecode cache")
    if ((_scripts / "__pycache__").exists() or (_scripts / "__pycache__").is_symlink()
            or any(path.suffix in {".pyc", ".pyo"} or (path.suffix == ".py" and path.is_symlink())
                   for path in _scripts.rglob("*"))):
        raise SystemExit("HA fault runner requires source-only Python imports")
    sys.path.insert(0, str(_scripts))

import domain_run
from domain_run import require
import ha_fault_driver as driver
import process_ha_topology as topology
import repeatable_assembly as owned

KIND = "ha-faults"
RUNNER = "scripts/run_ha_faults.py"
MODULES = ("scripts/ha_fault_driver.py",)
PLAN_SCHEMA = "kasumi-ha-faults-plan-v1"
REFERENCE = "aarch64-unknown-linux-gnu"
# The qualifying contract; any other value is a labelled rehearsal.
PARAMETERS = {"measured_seconds": 21600, "startup_seconds": 1800, "drain_seconds": 1800,
              "settle_polls": 900, "poll_pause_seconds": 1.0, "outage_margin_seconds": 5,
              "load_seconds": 5, "reload_seconds": 2}
SCENARIOS = ("leader-loss", "partition", "lease-length-outage", "fresh-admission",
             "endpoint-trust-rotation", "learner-catchup", "voter-replacement-under-load")
LISTENERS = ("native", "admin")
REPLY_SECONDS = 60


# ---- Inputs: identical in the producer and the adapter. ----

def absolute(value, label):
    require(isinstance(value, str) and Path(value).is_absolute()
            and os.path.normpath(value) == value, label + " is not a canonical absolute path")
    return value


def check_plan(plan):
    owned.exact(plan, {"schema", "collection", "data_profile", "members", "control_members",
                       "spare", "trust_rotation"}, "HA fault plan")
    require(plan["schema"] == PLAN_SCHEMA, "unsupported HA fault plan")
    require(isinstance(plan["collection"], str) and plan["collection"]
            and "/" not in plan["collection"], "HA fault collection is invalid")
    absolute(plan["data_profile"], "data client profile")
    for key in ("members", "control_members"):
        require(isinstance(plan[key], dict) and plan[key]
                and all(value.isdigit() and int(value) > 0 and str(int(value)) == value
                        for value in plan[key]), key + " must map node ids to profiles")
        for node, path in plan[key].items():
            absolute(path, key + " profile " + node)
    owned.exact(plan["spare"], {"id", "config"}, "spare data member")
    absolute(plan["spare"]["config"], "spare configuration")
    rotation = plan["trust_rotation"]
    owned.exact(rotation, {"member", "listener", "certificate", "private_key",
                           "invalid_certificate", "restore_certificate", "new_trust_profile"},
                "endpoint trust rotation")
    require(rotation["listener"] in LISTENERS, "trust rotation listener is not a client endpoint")
    for key in ("certificate", "private_key", "invalid_certificate", "restore_certificate",
                "new_trust_profile"):
        absolute(rotation[key], "trust rotation " + key)
    return plan


def spare_member(spare, config, nodes, data_voters, leaf):
    """The learner: a separately installed data process outside the nine."""
    require(spare["id"] not in {node["id"] for node in nodes}
            and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", spare["id"]),
            "spare reuses an HA process name or is not a process name")
    replication = config.get("replication")
    require(config.get("mode") == "replicated" and isinstance(config.get("tenants"), list)
            and config["tenants"] and isinstance(replication, dict), "spare is not a data member")
    node_id = replication.get("node_id")
    require(type(node_id) is int and node_id > 0
            and node_id not in {node["node_id"] for node in nodes}
            and sorted(replication.get("initial_voters", [])) == data_voters
            and node_id not in data_voters, "spare must join the original data voters as a learner")
    own = [peer for peer in replication.get("peers", []) if peer.get("node_id") == node_id]
    require(len(own) == 1 and own[0].get("certificate_pins") == [leaf]
            and leaf not in {node["certificate"]["leaf_sha256"] for node in nodes},
            "spare TLS identity is not its own distinct pinned leaf")
    roots = [*config["persistent_disk"]["roots"].values(), config["scratch_disk"]["directory"]]
    require(all(isinstance(root, str) and Path(root).is_absolute() for root in roots),
            "spare storage roots are not absolute")
    for node in nodes:
        for other in [*node["persistent_roots"], node["scratch_root"]]:
            require(all(root != other and not Path(root).is_relative_to(other)
                        and not Path(other).is_relative_to(root) for root in roots),
                    "spare storage overlaps an HA process")
    return {"id": spare["id"], "config": spare["config"], "node_id": node_id,
            "leaf_sha256": leaf, "roots": roots}


def lease(configs, nodes, tenant):
    """The actual installed serving lease of the data tenant, in seconds."""
    manifests = []
    for node in nodes:
        config = configs[node["id"]]
        if node["role"] == "data":
            serving = [t["serving"] for t in config["tenants"] if t.get("tenant") == tenant]
            require(len(serving) == 1 and serving[0].get("kind") == "independent",
                    "data tenant has no independent installed authority")
            manifests.append(config["serving_authorities"][serving[0]["authority"]]["manifest"])
        elif node["role"] == "authority":
            manifests.append(config["installation"]["manifest"])
    require(len(manifests) == 6 and all(item == manifests[0] for item in manifests),
            "data members and authorities install different serving leases")
    manifest = manifests[0]
    milliseconds, ppm = manifest.get("max_lease_ms"), manifest.get("clock_rate_error_ppm")
    require(type(milliseconds) is int and 100 <= milliseconds <= 60000
            and type(ppm) is int and 0 <= ppm <= 10000, "installed lease is out of bounds")
    return milliseconds / 1000, ppm


def installed_tls(rotation, configs, nodes):
    member = next((node for node in nodes if node["id"] == rotation["member"]), None)
    require(member is not None and member["role"] == "data", "trust rotation member is not data")
    tls = configs[member["id"]][rotation["listener"]]["tls"]
    certificate = absolute(tls["certificate"], "rotated certificate")
    key = absolute(tls["private_key"], "rotated key")
    for staged, installed in (("certificate", certificate), ("invalid_certificate", certificate),
                              ("restore_certificate", certificate), ("private_key", key)):
        require(Path(rotation[staged]).parent == Path(installed).parent
                and rotation[staged] != installed, "staged " + staged + " is not beside its target")
    return member, certificate, key


def profile_endpoint(profile, listener, node_id, leaf):
    if listener == "admin":
        bound = profile.get("administrative_members")
        require(isinstance(bound, dict) and list(bound) == [str(node_id)]
                and bound[str(node_id)].get("certificate_pins") == [leaf],
                "trust profile does not pin exactly the rotated administrative leaf")
    else:
        require(profile.get("native_certificate_pin") == leaf,
                "trust profile does not pin exactly the rotated native leaf")


def retained_inputs(read, leaf, keep, plan_path, admitted):
    """Every installed input the script uses, through the producer's or adapter's reader.

    ``read`` returns retained JSON, ``leaf`` a retained PEM chain's first-leaf
    digest and ``keep`` retains exact bytes. Private keys are never retained.
    """
    nodes = admitted["nodes"]
    plan = check_plan(read("ha-faults-plan", plan_path))
    configs = {node["id"]: read("node-" + node["id"], node["config"]) for node in nodes}
    spare_config = read("spare-config", plan["spare"]["config"])
    profiles = {"data": read("data-profile", plan["data_profile"]),
                "members": {node: read("member-" + node, path)
                            for node, path in sorted(plan["members"].items())},
                "control_members": {node: read("control-" + node, path)
                                    for node, path in sorted(plan["control_members"].items())},
                "new_trust": read("new-trust-profile", plan["trust_rotation"]["new_trust_profile"])}
    rotation = plan["trust_rotation"]
    member, certificate, key = installed_tls(rotation, configs, nodes)
    leaves = {"spare": leaf("spare-certificate",
                            spare_config["replication"]["listener"]["tls"]["certificate"]),
              "old": leaf("trust-installed-certificate", certificate),
              "new": leaf("trust-certificate", rotation["certificate"])}
    keep("trust-invalid-certificate", rotation["invalid_certificate"])
    # The restore copy must be byte-identical to the new chain; the producer
    # checks that before dispatch and the adapter checks its replacement row.
    require(leaves["new"] != leaves["old"], "rotation does not install a new leaf")
    return {"plan": plan, "configs": configs, "spare_config": spare_config, "profiles": profiles,
            "leaves": leaves, "rotation": {"member": member, "certificate": certificate,
                                           "private_key": key, "new_leaf": leaves["new"],
                                           "old_leaf": leaves["old"]}}


class Context:
    """Everything a scenario script reads, built only from retained inputs."""

    def __init__(self, inputs, admitted, paths, attempt_id, parameters):
        plan, configs, profiles = inputs["plan"], inputs["configs"], inputs["profiles"]
        self.plan, self.paths, self.attempt_id = plan, paths, attempt_id
        self.polls = parameters["settle_polls"]
        self.margin = parameters["outage_margin_seconds"]
        self.load_seconds = parameters["load_seconds"]
        self.pause = parameters["poll_pause_seconds"]
        self.reload_seconds = parameters["reload_seconds"]
        self.status = None
        # After an administrative-endpoint rotation the rotated member is
        # reached only through the profile that pins its new leaf.
        self.rotated_admin = None
        self.nodes = admitted["nodes"]
        self.by_id = {node["id"]: node for node in self.nodes}
        self.by_node = {node["node_id"]: node for node in self.nodes}
        self.voters = sorted(node["node_id"] for node in self.nodes if node["role"] == "data")
        self.controls = sorted(node["node_id"] for node in self.nodes if node["role"] == "control")
        self.authorities = [node for node in self.nodes if node["role"] == "authority"]
        data = profiles["data"]
        self.tenant = data["tenant"]
        self.incarnation = data["resource"]["incarnation"]
        self.spare = spare_member(plan["spare"], inputs["spare_config"], self.nodes, self.voters,
                                  inputs["leaves"]["spare"])
        self.spare_executable = admitted["binaries"]["kasumid"]
        require(set(map(int, plan["members"])) == {*self.voters, self.spare["node_id"]}
                and set(map(int, plan["control_members"])) == set(self.controls),
                "member profiles do not cover exactly the data voters, spare and Control")
        for node, profile in profiles["members"].items():
            bound = profile.get("administrative_members")
            require(isinstance(bound, dict) and list(bound) == [node]
                    and profile.get("tenant") == self.tenant
                    and profile.get("resource") == data["resource"],
                    "member profile does not select exactly its own data member")
        for node, profile in profiles["control_members"].items():
            bound = profile.get("administrative_members")
            require(isinstance(bound, dict) and list(bound) == [node]
                    and (profile.get("resource") or {}).get("kind") == "control",
                    "Control member profile does not select exactly its own Control member")
        self.lease_seconds, self.clock_ppm = lease(configs, self.nodes, self.tenant)
        self.rotation = inputs["rotation"]
        rotated = self.rotation["member"]["node_id"]
        listener = plan["trust_rotation"]["listener"]
        # The installed client that trusts the old leaf: the rotated member's
        # own management profile, or the data client of its native endpoint.
        if listener == "admin":
            self.old_trust = plan["members"][str(rotated)]
            old = profiles["members"][str(rotated)]
            require(profiles["new_trust"].get("tenant") == self.tenant
                    and profiles["new_trust"].get("resource") == data["resource"],
                    "administrative trust profile does not manage the data tenant")
        else:
            self.old_trust, old = plan["data_profile"], data
        profile_endpoint(profiles["new_trust"], listener, rotated, self.rotation["new_leaf"])
        profile_endpoint(old, listener, rotated, self.rotation["old_leaf"])

    def name(self, node_id):
        if node_id == self.spare["node_id"]:
            return self.spare["id"]
        return self.by_node[node_id]["id"]

    def node(self, node_id):
        return self.by_node[node_id]

    def ctl(self, profile, *words):
        return [self.paths["kasumictl"], "--profile", profile, *words]

    def member(self, node_id):
        if node_id == self.rotated_admin:
            return self.plan["trust_rotation"]["new_trust_profile"]
        return self.plan["members"][str(node_id)]

    def control_member(self, node_id):
        return self.plan["control_members"][str(node_id)]


# ---- The scenario script: one code path for the run and its replay. ----

def body(attempt_id, step):
    return {"attempt": attempt_id, "step": step}


def settled(value, ctx, voters, leaders=None):
    return (value["mode"] == "replicated" and value["incarnation"] == ctx.incarnation
            and value["leader"] in (leaders if leaders is not None else voters)
            and value["raft_voters"] == voters and type(value["raft_applied_index"]) is int)


def view(d, ctx, label, node, voters, leaders=None, *, scenarios=()):
    """Poll one member until it reports a leader among ``leaders``; return the call."""
    status = ctx.ctl(ctx.member(node), "manage", ctx.status)
    d.poll(label + "-poll", status, lambda value: settled(value, ctx, voters, leaders),
           limit=ctx.polls, pause=ctx.pause)
    value = d.json(label, status, scenarios)
    require(settled(value, ctx, voters, leaders), "member view changed between two samples")
    return value


def probe(d, ctx, label, step, scenarios):
    """One authenticated durable write and its exact read-back."""
    document = "fault-" + str(step)
    expected = body(ctx.attempt_id, step)
    put = d.json(label + "-put", ctx.ctl(ctx.plan["data_profile"], "put", ctx.plan["collection"],
                                          document, json.dumps(expected, sort_keys=True), "--if",
                                          "any"), scenarios)
    require(put.get("ok") is True, "authenticated write was not acknowledged")
    got = d.json(label + "-get", ctx.ctl(ctx.plan["data_profile"], "get", ctx.plan["collection"],
                                          document), scenarios)
    require(got.get("ok") is True and got["result"]["document"]["body"] == expected,
            "read-back differs from the acknowledged write")


def raw_view(d, ctx, label, node):
    """The exact bytes of one leader observation, retained before a fault."""
    status = ctx.ctl(ctx.member(node), "manage", ctx.status)
    d.poll(label + "-poll", status, lambda value: settled(value, ctx, ctx.voters), limit=ctx.polls, pause=ctx.pause)
    raw = d.call(label, status)
    value = driver.decode(raw)
    require(value is not None and settled(value, ctx, ctx.voters), "leader view changed")
    return value, raw


def leader_loss(d, ctx):
    scenario = ["leader-loss"]
    before, raw = raw_view(d, ctx, "leader-loss-before", ctx.voters[0])
    lost = before["leader"]
    d.crash(ctx.name(lost), raw, scenario)
    survivors = [node for node in ctx.voters if node != lost]
    after = view(d, ctx, "leader-loss-elected", survivors[0], ctx.voters, survivors,
                 scenarios=scenario)
    probe(d, ctx, "leader-loss-write", 1, scenario)
    d.spawn(ctx.name(lost), ctx.node(lost)["executable"], ctx.node(lost)["config"])
    rejoined = view(d, ctx, "leader-loss-rejoined", lost, ctx.voters, [after["leader"]],
                    scenarios=scenario)
    require(rejoined["node_id"] == lost, "restarted member answered for another node")
    # The separate Control group loses its leader while data keeps serving.
    control = rejoined["control_leader"]
    require(control in ctx.controls, "data members report no Control leader")
    d.crash(ctx.name(control), raw, scenario)
    others = [node for node in ctx.controls if node != control]
    status = ctx.ctl(ctx.member(ctx.voters[0]), "manage", ctx.status)
    d.poll("control-loss-elected-poll", status,
           lambda value: settled(value, ctx, ctx.voters) and value["control_leader"] in others,
           limit=ctx.polls, pause=ctx.pause)
    probe(d, ctx, "control-loss-write", 2, scenario)
    node = ctx.node(control)
    d.spawn(node["id"], node["executable"], node["config"])
    observed = ctx.ctl(ctx.control_member(control), "manage", ctx.status)
    d.poll("control-loss-rejoined-poll", observed,
           lambda value: value["node_id"] == control and value["control_leader"] in ctx.controls,
           limit=ctx.polls, pause=ctx.pause)
    d.json("control-loss-rejoined", observed, scenario)


def partition(d, ctx):
    """Isolate the data leader: its whole process group is frozen, then thawed."""
    scenario = ["partition"]
    before = view(d, ctx, "partition-before", ctx.voters[0], ctx.voters)
    isolated = before["leader"]
    d.signal(ctx.name(isolated), "SIGSTOP")
    survivors = [node for node in ctx.voters if node != isolated]
    majority = view(d, ctx, "partition-majority", survivors[0], ctx.voters, survivors,
                    scenarios=scenario)
    probe(d, ctx, "partition-write", 3, scenario)
    committed = view(d, ctx, "partition-committed", majority["leader"], ctx.voters,
                     [majority["leader"]], scenarios=scenario)
    d.signal(ctx.name(isolated), "SIGCONT")
    status = ctx.ctl(ctx.member(isolated), "manage", ctx.status)
    d.poll("partition-healed-poll", status,
           lambda value: (settled(value, ctx, ctx.voters, [majority["leader"]])
                          and value["raft_applied_index"] >= committed["raft_applied_index"]),
           limit=ctx.polls, pause=ctx.pause)
    healed = d.json("partition-healed", status, scenario)
    require(healed["node_id"] == isolated and healed["leader"] == majority["leader"]
            and healed["raft_applied_index"] >= committed["raft_applied_index"],
            "former leader did not rejoin the majority's committed history")


def outage(d, ctx):
    """Every authority is down for longer than the installed serving lease."""
    scenario = ["lease-length-outage"]
    probe(d, ctx, "outage-before", 4, scenario)
    _, raw = raw_view(d, ctx, "outage-view", ctx.voters[0])
    started = None
    for node in ctx.authorities:
        started = d.crash(node["id"], raw, scenario)["fault"]["elapsed_seconds"]
    expires = started + ctx.lease_seconds * (1 + ctx.clock_ppm / 1_000_000) + ctx.margin
    while d.clock() < expires:
        d.pause(min(.5, ctx.pause))
    document = ctx.ctl(ctx.plan["data_profile"], "put", ctx.plan["collection"], "fault-expired",
                       json.dumps(body(ctx.attempt_id, "expired"), sort_keys=True), "--if", "any")
    code, _ = d.attempt("outage-expired-write", document)
    require(code != 0, "data serving continued after its authority lease expired")
    ended = d.clock()
    for node in ctx.authorities:
        d.spawn(node["id"], node["executable"], node["config"])
    return started, ended


def fresh_admission(d, ctx):
    scenario = ["fresh-admission"]
    document = ctx.ctl(ctx.plan["data_profile"], "put", ctx.plan["collection"], "fault-readmitted",
                       json.dumps(body(ctx.attempt_id, "readmitted"), sort_keys=True), "--if", "any")
    d.poll("fresh-admission-poll", document, lambda value: value.get("ok") is True,
           limit=ctx.polls, pause=ctx.pause)
    probe(d, ctx, "fresh-admission-write", 5, scenario)
    view(d, ctx, "fresh-admission-view", ctx.voters[0], ctx.voters, scenarios=scenario)


def trust_rotation(d, ctx):
    scenario = ["endpoint-trust-rotation"]
    rotation, plan = ctx.rotation, ctx.plan["trust_rotation"]
    member = rotation["member"]
    if plan["listener"] == "admin":
        def through(profile):
            return ctx.ctl(profile, "manage", ctx.status)
    else:
        def through(profile):
            return ctx.ctl(profile, "get", ctx.plan["collection"], "fault-1")
    d.json("trust-before", through(ctx.old_trust), scenario)
    d.replace(plan["private_key"], rotation["private_key"], "private")
    d.replace(plan["certificate"], rotation["certificate"], "public")
    d.signal(member["id"], "SIGHUP")
    d.poll("trust-rotated-poll", through(plan["new_trust_profile"]), lambda value: True,
           limit=ctx.polls, pause=ctx.pause)
    d.json("trust-rotated", through(plan["new_trust_profile"]), scenario)
    code, _ = d.attempt("trust-old-refused", through(ctx.old_trust))
    require(code != 0, "the replaced endpoint certificate is still trusted")
    if plan["listener"] == "admin":
        ctx.rotated_admin = member["node_id"]
    # An invalid replacement is rejected and the last valid identity keeps serving.
    d.replace(plan["invalid_certificate"], rotation["certificate"], "public")
    d.signal(member["id"], "SIGHUP")
    d.pause(ctx.reload_seconds)
    d.json("trust-invalid-retained", through(plan["new_trust_profile"]), scenario)
    d.replace(plan["restore_certificate"], rotation["certificate"], "public")
    d.signal(member["id"], "SIGHUP")
    d.json("trust-restored", through(plan["new_trust_profile"]), scenario)
    probe(d, ctx, "trust-write", 6, scenario)
    return member["id"]


def learner(d, ctx):
    scenario = ["learner-catchup"]
    spare = ctx.spare
    d.spawn(spare["id"], ctx.spare_executable, spare["config"])
    leader = view(d, ctx, "learner-leader", ctx.voters[0], ctx.voters)
    request = d.request("add-learner", {"operation": "add_learner", "node_id": spare["node_id"]})
    added = d.json("learner-add", ctx.ctl(ctx.member(leader["leader"]), "manage", request), scenario)
    require(added == {"caught_up": spare["node_id"]}, "learner was not caught up")
    status = ctx.ctl(ctx.member(spare["node_id"]), "manage", ctx.status)
    d.poll("learner-applied-poll", status,
           lambda value: (settled(value, ctx, ctx.voters, [leader["leader"]])
                          and value["node_id"] == spare["node_id"]
                          and value["raft_applied_index"] >= leader["raft_applied_index"]),
           limit=ctx.polls, pause=ctx.pause)
    d.json("learner-applied", status, scenario)


def replacement(d, ctx, load):
    """Replace one original follower with the caught-up learner under load."""
    scenario = ["voter-replacement-under-load"]
    leader = view(d, ctx, "replace-leader", ctx.voters[0], ctx.voters)["leader"]
    removed = next(node for node in ctx.voters if node != leader)
    voters = sorted([*[node for node in ctx.voters if node != removed], ctx.spare["node_id"]])
    change = d.request("replace-voter", {"operation": "change_membership", "voters": voters})
    publish = d.request("publish-voters", {"operation": "publish_membership", "voters": voters})
    client = d.spawn_client("load", ctx.ctl(ctx.plan["data_profile"], "session"))
    load.start(client)
    d.pause(ctx.load_seconds)
    window = [d.clock()]
    changed = d.json("replace-change", ctx.ctl(ctx.member(leader), "manage", change), scenario)
    require(changed == {"changed": True, "publish_control_route_required": True},
            "membership change was not committed")
    published = d.json("replace-publish", ctx.ctl(ctx.member(leader), "manage", publish), scenario)
    require(isinstance(published, dict), "membership publication returned no document")
    window.append(d.clock())
    d.pause(ctx.load_seconds)
    load.stop()
    d.end_client("load")
    d.stop(ctx.name(removed), scenario)
    status = ctx.ctl(ctx.member(leader), "manage", ctx.status)
    d.poll("replace-committed-poll", status, lambda value: settled(value, ctx, voters),
           limit=ctx.polls, pause=ctx.pause)
    d.json("replace-committed", status, scenario)
    return {"client": client, "window": window, "removed": removed, "voters": voters}


def script(d, ctx, load):
    """The whole domain. Returns the facts its gate details are computed from."""
    ctx.status = d.request("status", {"operation": "status"})
    members = {}
    for node in ctx.nodes:
        members[node["id"]] = d.spawn(node["id"], node["executable"], node["config"])
    d.poll("startup", ctx.ctl(ctx.member(ctx.voters[0]), "manage", ctx.status),
           lambda value: settled(value, ctx, ctx.voters), limit=ctx.polls, pause=ctx.pause)
    measured = d.phase("measured")
    leader_loss(d, ctx)
    partition(d, ctx)
    started, ended = outage(d, ctx)
    fresh_admission(d, ctx)
    rotated = trust_rotation(d, ctx)
    learner(d, ctx)
    replaced = replacement(d, ctx, load)
    drain = d.phase("drain")
    for node_id in replaced["voters"]:
        d.stop(ctx.name(node_id))
    for node in ctx.nodes:
        if node["role"] != "data":
            d.stop(node["id"])
    return {"members": members, "measured": measured, "drain": drain,
            "outage": {"started": started, "ended": ended}, "rotated": rotated, **replaced}


def cycle_requests(attempt_id, collection, cycle):
    document = "load-" + str(cycle % 256)
    payload = json.dumps(body(attempt_id, "load-" + str(cycle)), sort_keys=True, separators=(",", ":"))
    return [{"id": cycle * 2, "argv": ["put", collection, document, payload, "--if", "any"],
             "timeout_ms": REPLY_SECONDS * 500},
            {"id": cycle * 2 + 1, "argv": ["get", collection, document],
             "timeout_ms": REPLY_SECONDS * 500}]


def judge(attempt_id, request, reply):
    value = driver.decode(reply)
    document = value.get("document") if value is not None else None
    if (value is None or value.get("id") != request["id"] or value.get("status") != 0
            or not isinstance(document, dict) or document.get("ok") is not True):
        return "error"
    if request["argv"][0] == "get":
        observed = (document.get("result") or {}).get("document") or {}
        if observed.get("body") != body(attempt_id, "load-" + str(request["id"] // 2)):
            return "mismatch"
    return "ok"


def check_load(rows, replies, attempt_id, collection, window):
    """Every reply succeeded and some were answered across the membership change."""
    previous = 0.0
    for index, row in enumerate(rows):
        owned.exact(row, {"sequence", "line", "sent_elapsed_seconds", "received_elapsed_seconds",
                          "verdict"}, "load row")
        request = cycle_requests(attempt_id, collection, index // 2)[index % 2]
        require(row["sequence"] == index and row["line"] == index and index < len(replies)
                and 0 <= row["sent_elapsed_seconds"] <= row["received_elapsed_seconds"]
                and row["received_elapsed_seconds"] >= previous
                and row["verdict"] == judge(attempt_id, request, replies[index]),
                "load row differs from its original session reply")
        previous = row["received_elapsed_seconds"]
    started, finished = window
    require(rows and len(replies) == len(rows) and all(row["verdict"] == "ok" for row in rows)
            and any(row["sent_elapsed_seconds"] < started for row in rows)
            and any(started <= row["received_elapsed_seconds"] <= finished for row in rows)
            and any(row["received_elapsed_seconds"] > finished for row in rows),
            "the replacement was not under continuous successful load")


class Load:
    """One writer thread on the interactive session; the main thread owns all else."""

    def __init__(self, run, d, ctx):
        self.run, self.d, self.ctx = run, d, ctx
        self.path = run.output / "load.jsonl"
        self.rows = self.path.open("xb")
        self.stopping = threading.Event()
        self.error = None
        self.thread = None

    def start(self, identifier):
        self.log = self.run.output / "services" / (identifier + ".log")
        self.thread = threading.Thread(target=self.loop, name="ha-fault-load", daemon=True)
        self.thread.start()

    def reply(self, offset):
        until = time.monotonic() + REPLY_SECONDS
        while time.monotonic() < until:
            with self.log.open("rb") as stream:
                stream.seek(offset)
                line = stream.readline()
            if line.endswith(b"\n"):
                return line
            time.sleep(.005)
        raise ValueError("load session did not reply in time")

    def loop(self):
        offset = line = cycle = 0
        try:
            while not self.stopping.is_set():
                for request in cycle_requests(self.run.attempt_id, self.ctx.plan["collection"], cycle):
                    sent = self.run.services.elapsed()
                    self.d.send("load", (json.dumps(request, sort_keys=True,
                                                    separators=(",", ":")) + "\n").encode())
                    reply = self.reply(offset)
                    offset += len(reply)
                    row = {"sequence": request["id"], "line": line, "sent_elapsed_seconds": sent,
                           "received_elapsed_seconds": self.run.services.elapsed(),
                           "verdict": judge(self.run.attempt_id, request, reply)}
                    line += 1
                    self.rows.write((json.dumps(row, sort_keys=True, separators=(",", ":"))
                                     + "\n").encode())
                    self.rows.flush()
                cycle += 1
        except BaseException as error:
            self.error = error

    def stop(self):
        self.stopping.set()
        if self.thread is not None:
            self.thread.join(REPLY_SECONDS * 3)
            require(not self.thread.is_alive(), "load thread did not stop")
        os.fsync(self.rows.fileno())
        self.rows.close()
        require(self.error is None, "load session failed: " + repr(self.error))


def tls_failures(log):
    """Structured reload-failure events in one daemon's own original log."""
    count = 0
    for line in log.read_bytes().splitlines():
        value = driver.decode(line)
        if value is not None and "tls_reload_failed" in (
                value.get("event"), (value.get("fields") or {}).get("event")):
            count += 1
    return count


# ---- Producer ----

def execute(run, parameters, topology_path, plan_path):
    target = run.bind()
    require(target == REFERENCE or run.report["qualification"] == domain_run.REHEARSAL,
            "qualifying HA faults run on the native Linux ARM64 reference")
    run.configuration("ha-topology", topology_path)
    admitted = topology.inspect(Path(topology_path).resolve(strict=True), run.environment)
    for name in ("kasumid", "kasumi-authority"):
        require(admitted["binaries"][name]["path"] == run.binary_paths[name]
                and admitted["binaries"][name]["sha256"] == run.report["binaries"][name],
                "HA topology does not install the qualified candidate: " + name)

    def read(identifier, path):
        return owned.read(run.configuration(identifier, path))

    def leaf(identifier, path):
        return topology.certificate(run.configuration(identifier, path))["leaf_sha256"]

    def keep(identifier, path):
        run.configuration(identifier, path)

    inputs = retained_inputs(read, leaf, keep, plan_path, admitted)
    rotation = inputs["plan"]["trust_rotation"]
    require(owned.sha256(Path(rotation["restore_certificate"]))
            == owned.sha256(Path(rotation["certificate"])),
            "staged restore certificate is not the new certificate chain")
    # Storage roots are host facts: check the spare's live directories here.
    spare_config = inputs["spare_config"]
    for root in [*spare_config["persistent_disk"]["roots"].values(),
                 spare_config["scratch_disk"]["directory"]]:
        topology.directory(root)
    domain_run.durable_json(run.output / "topology-admission.json", admitted)
    ctx = Context(inputs, admitted, run.binary_paths, run.attempt_id, parameters)
    # The acceptance contract measures outages and leases in whole seconds.
    require(ctx.lease_seconds >= 1, "the installed serving lease is shorter than one second")
    details = {"admission": owned.ref(run.output, run.output / "topology-admission.json"),
               "binary_paths": dict(run.binary_paths), "lease_seconds": ctx.lease_seconds,
               "clock_rate_error_ppm": ctx.clock_ppm, "facts": None, "load": None}
    run.report["details"] = details
    run.save()
    run.start_services(parameters["measured_seconds"], parameters["startup_seconds"],
                       parameters["drain_seconds"])
    d = driver.Live(run, details)
    load = Load(run, d, ctx)
    try:
        facts = script(d, ctx, load)
    finally:
        if not load.rows.closed:
            if load.thread is not None:
                load.stop()
            else:
                load.rows.close()
        d.close()
    run.report["topology"] = members(ctx, facts)
    details.update(facts=facts, load=owned.ref(run.output, load.path))
    run.save()
    verdict(run.output, run.report, ctx, facts)
    run.passed(details)


def members(ctx, facts):
    """The nine original executions: the gate's topology."""
    return [{"id": node["id"], "role": node["role"], "group": node["group"],
             "certificate_sha256": node["certificate"]["leaf_sha256"],
             "process_id": facts["members"][node["id"]]} for node in ctx.nodes]


def verdict(custody, report, ctx, facts):
    """Checks over the whole retained run, shared by producer and adapter."""
    logs = {item["id"]: item["log"] for item in report["processes"]}
    rows = [json.loads(line) for line in (custody / "load.jsonl").read_bytes().splitlines()]
    replies = owned.check_ref(custody, logs[facts["client"]]).read_bytes() \
        .splitlines(keepends=True)
    check_load(rows, replies, report["attempt_id"], ctx.plan["collection"], facts["window"])
    rotated = [identifier for identifier in logs
               if identifier.rsplit("-", 1)[0] == facts["rotated"]]
    require(sum(tls_failures(owned.check_ref(custody, logs[identifier])) for identifier in rotated)
            == 1, "the invalid TLS replacement was not exposed exactly once by the rotated member")
    outage_seconds = facts["outage"]["ended"] - facts["outage"]["started"]
    require(outage_seconds > ctx.lease_seconds * (1 + ctx.clock_ppm / 1_000_000),
            "authority outage did not exceed the installed lease")
    return round(outage_seconds, 6)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    for name in ("evidence", "journal", "output", "topology", "plan"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--rehearsal", action="store_true",
                        help="non-qualifying: shorter budgets on any native target")
    args = parser.parse_args(argv)
    parameters = dict(PARAMETERS)
    if args.rehearsal:
        parameters.update(measured_seconds=3600, startup_seconds=600, drain_seconds=600,
                          settle_polls=300)
    qualification = domain_run.QUALIFYING if parameters == PARAMETERS else domain_run.REHEARSAL
    with domain_run.Run(KIND, RUNNER, MODULES, args.evidence, args.output, args.journal,
                        args.attempt_id, parameters, qualification) as run:
        execute(run, parameters, args.topology, args.plan)
    print("HA faults " + ("qualifying" if qualification == domain_run.QUALIFYING
                          else "NON-QUALIFYING REHEARSAL") + " retained: " + str(args.output))
    return 0


def gate_details(root, report_path):
    """The gate's details, lifted from a passed run's original report."""
    root = Path(root).resolve(strict=True)
    report = owned.read(Path(report_path))
    outage = report["details"]["facts"]["outage"]
    return {"lease_seconds": report["details"]["lease_seconds"],
            "outage_seconds": round(outage["ended"] - outage["started"], 6),
            "report": owned.ref(root, Path(report_path).resolve(strict=True))}


# ---- Acceptance adapter: replay the script against the original evidence. ----

class _NoLoad:
    """The adapter's stand-in for the producer's load thread; it sends nothing."""

    def start(self, identifier):
        return None

    def stop(self):
        return None


def verify_domain(root, domain, files, configs, artifacts, candidates):
    import verify_release_acceptance as acceptance

    facts = domain_run.verify_run(root, domain, files, configs, KIND, RUNNER, MODULES)
    report, custody = facts["report"], facts["custody"]
    require(report["target"] == acceptance.REFERENCE and not domain["artifacts"],
            "HA faults ran on another native target or consumed an artifact")
    require(report["invocation"]["parameters"] == PARAMETERS,
            "HA fault parameters differ from the qualifying contract")
    details = report["details"]
    owned.exact(details, {"admission", "binary_paths", "lease_seconds", "clock_rate_error_ppm",
                          "facts", "load", "attempts", "ledger"}, "HA fault details")
    retained = {item["id"]: owned.check_ref(custody, item["file"])
                for item in report["configurations"]}
    admitted = owned.read(owned.check_ref(custody, details["admission"]))
    nodes = admitted["nodes"]
    topology.verify_retained_control(nodes, retained)
    topology_plan = owned.read(retained["ha-topology"])
    require(len(nodes) == 9 and admitted["plan_sha256"] == owned.sha256(retained["ha-topology"])
            and topology_plan["nodes"] == [{key: node[key] for key in ("id", "role", "group", "config")}
                                           for node in nodes]
            and all(owned.sha256(retained["node-" + node["id"]]) == node["config_sha256"]
                    and node["executable"]["sha256"] == domain["binaries"][
                        "kasumi-authority" if node["role"] == "authority" else "kasumid"]
                    for node in nodes)
            and {name: item["sha256"] for name, item in admitted["binaries"].items()}
            == {name: domain["binaries"][name] for name in ("kasumid", "kasumi-authority")},
            "HA faults retained another topology or candidate")
    paths = details["binary_paths"]
    evidence = Path(report["evidence_root"])
    require(set(paths) == set(domain["binaries"])
            and all(Path(path).name == name and Path(path).is_relative_to(evidence)
                    for name, path in paths.items())
            and all(item["path"] == paths[name] for name, item in admitted["binaries"].items()),
            "HA faults selected executables outside the frozen candidate")
    used = set()

    def read(identifier, path):
        used.add(identifier)
        return owned.read(retained[identifier])

    def leaf(identifier, path):
        used.add(identifier)
        return topology.certificate(retained[identifier])["leaf_sha256"]

    def keep(identifier, path):
        used.add(identifier)

    inputs = retained_inputs(read, leaf, keep, None, admitted)
    require(used | {"ha-topology"} == set(retained), "HA faults retained an unused input")
    ctx = Context(inputs, admitted, paths, report["attempt_id"], PARAMETERS)
    d = driver.Replay(facts, paths)
    original = script(d, ctx, _NoLoad())
    d.finish()
    require(details["facts"] == original, "HA fault facts differ from the replayed script")
    require(driver.scenario_rows(facts) == d.expected and set(d.expected) == set(SCENARIOS)
            == acceptance.SCENARIOS[KIND], "HA fault scenario rows differ from the replayed script")
    topology_members = members(ctx, original)
    require(report["topology"] == topology_members == domain["topology"],
            "HA fault topology differs from the nine original spawns")
    acceptance.check_topology(topology_members, domain["processes"], domain["binaries"], "required")
    thawed = {}
    for row in d.signals:
        if row["signal"] == "SIGSTOP":
            require(row["process"] not in thawed, "a daemon was frozen twice")
            thawed[row["process"]] = False
        elif row["signal"] == "SIGCONT":
            require(thawed.get(row["process"]) is False, "a daemon was thawed without a freeze")
            thawed[row["process"]] = True
    require(thawed and all(thawed.values()), "an isolated daemon was never thawed")
    staged = {ctx.plan["trust_rotation"][key]: name for key, name in (
        ("certificate", "trust-certificate"), ("invalid_certificate", "trust-invalid-certificate"),
        ("restore_certificate", "trust-certificate"))}
    for row in d.replacements:
        require(row["replacement"] == "private"
                or row["sha256"] == owned.sha256(retained[staged[row["source"]]]),
                "an installed certificate replacement differs from its retained bytes")
    require(details["load"] == owned.ref(custody, custody / "load.jsonl"),
            "load rows are not the run's original rows")
    outage_seconds = verdict(custody, report, ctx, original)
    require(details["lease_seconds"] == ctx.lease_seconds
            and details["clock_rate_error_ppm"] == ctx.clock_ppm,
            "reported lease differs from the installed configuration")
    require(domain["details"] == {"lease_seconds": ctx.lease_seconds,
                                  "outage_seconds": outage_seconds,
                                  "report": domain["details"]["report"]},
            "HA fault gate details differ from the replayed run")
    return facts["evidence"]


if __name__ == "__main__":
    raise SystemExit(main())
