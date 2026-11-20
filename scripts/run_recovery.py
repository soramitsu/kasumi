#!/usr/bin/env python3
"""Drive distributed recovery through crashes and cancellations, then replay it.

With two of the three source data voters SIGKILLed (an absent source quorum),
the runner starts two Control recoveries of the same tenant onto three
separately installed target processes. The first is stopped after
materialization and must delete exactly its own target storage. The second
must finish: each product step is one owned ``kasumid control-recovery
resume``. At every observable point the runner first cancels a step with the
product's own request deadline, then SIGKILLs the daemon doing that work
while a step is in flight, restarts it and continues. A fault counts for a
point only when the product's own durable record afterwards shows that point
begun and not completed. Activation is raced by two clients, and a stop
after committed activation must not turn the recovery back.

The eight target-local deletion sub-phases are not reported by any Kasumi
interface today: Control status names only stop_activation, stop_target,
cleanup and stopped. ``deletion_stage`` therefore returns None, those sixteen
cells stay open and the run fails after retaining everything it could do.
The adapter replays the same script, so it accepts exactly what this runner
could honestly establish.
"""
from __future__ import annotations

import sys
if __name__ == "__main__" and not (sys.flags.isolated and sys.flags.no_site
                                  and sys.flags.dont_write_bytecode):
    raise SystemExit("recovery runner requires native Python -I -S -B")

import argparse
import hashlib
import json
import os
from pathlib import Path
import re

if __name__ == "__main__":
    _scripts = Path(__file__).resolve(strict=True).parent
    if sys.pycache_prefix is not None or "PYTHONPYCACHEPREFIX" in os.environ:
        raise SystemExit("recovery runner forbids a redirected Python bytecode cache")
    if ((_scripts / "__pycache__").exists() or (_scripts / "__pycache__").is_symlink()
            or any(path.suffix in {".pyc", ".pyo"} or (path.suffix == ".py" and path.is_symlink())
                   for path in _scripts.rglob("*"))):
        raise SystemExit("recovery runner requires source-only Python imports")
    sys.path.insert(0, str(_scripts))

import domain_run
from domain_run import require
import ha_fault_driver as driver
import process_ha_topology as topology
import repeatable_assembly as owned

KIND = "recovery"
RUNNER = "scripts/run_recovery.py"
MODULES = ("scripts/ha_fault_driver.py",)
PLAN_SCHEMA = "kasumi-recovery-plan-v1"
REFERENCE = "aarch64-unknown-linux-gnu"
PARAMETERS = {"measured_seconds": 43200, "startup_seconds": 1800, "drain_seconds": 1800,
              "settle_polls": 900, "poll_pause_seconds": 1.0, "step_limit": 2048,
              "request_timeout_ms": 600000,
              "deadlines_ms": [5, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000],
              # A fault before the client connects lets it finish on a newly
              # elected leader and spends one of the point's steps: start late.
              "fault_delays": [0.2, 0.5, 1, 2, 5, 10]}
# Product phase -> acceptance phase label.
RECOVERY_LABELS = {"prepare": "preparation", "materialize": "materialization",
                   "initialize": "initialization", "fence_source": "source-fencing",
                   "activate": "activation", "confirm": "confirmation",
                   "publish": "route-publication"}
DELETION_LABELS = ("permanent-stop", "issuer-drain", "gate-closure", "worker-drain",
                   "storage-drain", "exact-deletion", "parent-sync", "durable-evidence")
STOP_PHASES = ("stop_activation", "stop_target", "cleanup")
FAULTS = ("cancellation", "crash")
# Product phases whose work a target process performs; the rest run on Control.
TARGET_WORK = {"materialize", "initialize", "stop_target", "cleanup"}
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
SOURCE_UNAVAILABLE = {"mode": "source_unavailable"}
SCENARIOS = ({f"{label}-{fault}" for label in (*RECOVERY_LABELS.values(), *DELETION_LABELS)
              for fault in ("crash", "cancellation")}
             | {"absent-source-quorum", "independent-source-target-authorization",
                "single-activation-winner", "forward-after-activation", "physical-bindings",
                "unrelated-file-isolation"})


def deletion_stage(record):
    """The target-local deletion sub-phase a Control status reports, if any.

    No Kasumi interface reports one: the Control record names the pending stop
    phase only, and the signed target cleanup fact carries no sub-phase. An
    injection cannot be placed inside issuer drain, gate closure, worker or
    storage drain, exact deletion, parent sync or durable evidence, so none
    is claimed. Supply a product witness here before those cells can pass.
    """
    return None


# ---- Inputs ----

def absolute(value, label):
    require(isinstance(value, str) and Path(value).is_absolute()
            and os.path.normpath(value) == value, label + " is not a canonical absolute path")
    return value


def node_map(value, label):
    require(isinstance(value, dict) and value
            and all(key.isdigit() and str(int(key)) == key and int(key) > 0 for key in value),
            label + " must map node ids to profiles")
    for key, path in value.items():
        absolute(path, label + " " + key)
    return value


def check_plan(plan):
    owned.exact(plan, {"schema", "collection", "control_profile", "control_members",
                       "source_members", "data_profile", "stopped_request", "request",
                       "targets"}, "recovery plan")
    require(plan["schema"] == PLAN_SCHEMA, "unsupported recovery plan")
    require(isinstance(plan["collection"], str) and plan["collection"]
            and "/" not in plan["collection"], "recovery probe collection is invalid")
    for key in ("control_profile", "data_profile", "stopped_request", "request"):
        absolute(plan[key], key)
    node_map(plan["control_members"], "Control members")
    node_map(plan["source_members"], "source members")
    require(isinstance(plan["targets"], list) and len(plan["targets"]) == 3,
            "recovery needs three separately installed target processes")
    for target in plan["targets"]:
        owned.exact(target, {"id", "config"}, "recovery target")
        require(isinstance(target["id"], str) and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", target["id"]),
                "recovery target name is invalid")
        absolute(target["config"], "recovery target configuration")
    require(len({target["id"] for target in plan["targets"]}) == 3, "recovery targets repeat")
    return plan


def check_request(request, label):
    require(isinstance(request, dict), label + " is not an object")
    for key in ("operation_id", "source_incarnation", "target_incarnation"):
        require(isinstance(request.get(key), str) and UUID.fullmatch(request[key])
                and request[key] != "00000000-0000-0000-0000-000000000000",
                label + " " + key + " is not a canonical UUID")
    require(isinstance(request.get("tenant"), str) and request["tenant"]
            and request.get("source_mode") == SOURCE_UNAVAILABLE
            and isinstance(request.get("target_nodes"), dict) and len(request["target_nodes"]) == 3
            and type(request.get("phase_timeout_ms")) is int,
            label + " is not a three-target source-unavailable recovery")
    return request


def target_member(target, config, nodes, request, leaf):
    replication = config.get("replication")
    require(config.get("mode") == "replicated" and config.get("target_recovery") is not None
            and isinstance(replication, dict), "recovery target does not host recovery targets")
    node_id = replication.get("node_id")
    voters = sorted(int(key) for key in request["target_nodes"])
    require(type(node_id) is int and node_id in voters
            and node_id not in {node["node_id"] for node in nodes}
            and sorted(replication.get("initial_voters", [])) == voters
            and target["id"] not in {node["id"] for node in nodes},
            "recovery target is not one of the request's three separate target voters")
    own = [peer for peer in replication.get("peers", []) if peer.get("node_id") == node_id]
    require(len(own) == 1 and own[0].get("certificate_pins") == [leaf]
            and leaf not in {node["certificate"]["leaf_sha256"] for node in nodes},
            "recovery target TLS identity is not its own distinct pinned leaf")
    roots = list(config["persistent_disk"]["roots"].values())
    scratch = config["scratch_disk"]["directory"]
    for root in [*roots, scratch]:
        absolute(root, "recovery target storage root")
        for node in nodes:
            for other in [*node["persistent_roots"], node["scratch_root"]]:
                require(root != other and not Path(root).is_relative_to(other)
                        and not Path(other).is_relative_to(root),
                        "recovery target storage overlaps an HA process")
    return {"id": target["id"], "config": target["config"], "node_id": node_id,
            "leaf_sha256": leaf, "roots": sorted(roots), "scratch": scratch}


def retained_inputs(read, leaf, plan_path, admitted):
    nodes = admitted["nodes"]
    plan = check_plan(read("recovery-plan", plan_path))
    requests = {"stopped": check_request(read("stopped-request", plan["stopped_request"]),
                                         "stopped recovery"),
                "finished": check_request(read("recovery-request", plan["request"]),
                                          "finished recovery")}
    configs = {node["id"]: read("node-" + node["id"], node["config"]) for node in nodes}
    targets = []
    for index, target in enumerate(plan["targets"]):
        config = read("target-" + target["id"], target["config"])
        targets.append(target_member(target, config, nodes, requests["finished"],
                                     leaf("target-certificate-" + target["id"],
                                          config["replication"]["listener"]["tls"]["certificate"])))
    profiles = {"control": read("control-profile", plan["control_profile"]),
                "data": read("data-profile", plan["data_profile"]),
                "control_members": {key: read("control-" + key, path)
                                    for key, path in sorted(plan["control_members"].items())},
                "source_members": {key: read("source-" + key, path)
                                   for key, path in sorted(plan["source_members"].items())}}
    return {"plan": plan, "requests": requests, "configs": configs, "targets": targets,
            "profiles": profiles}


class Context:
    def __init__(self, inputs, admitted, paths, attempt_id, parameters):
        self.plan, self.paths, self.attempt_id = inputs["plan"], paths, attempt_id
        self.parameters = parameters
        self.polls = parameters["settle_polls"]
        self.pause = parameters["poll_pause_seconds"]
        self.timeout = parameters["request_timeout_ms"]
        self.nodes = admitted["nodes"]
        self.by_node = {node["node_id"]: node for node in self.nodes}
        self.voters = sorted(n["node_id"] for n in self.nodes if n["role"] == "data")
        self.controls = sorted(n["node_id"] for n in self.nodes if n["role"] == "control")
        self.targets = inputs["targets"]
        for target in self.targets:
            self.by_node[target["node_id"]] = {**target, "executable": admitted["binaries"]["kasumid"]}
        self.stopped, self.finished = inputs["requests"]["stopped"], inputs["requests"]["finished"]
        tenant, source = self.finished["tenant"], self.finished["source_incarnation"]
        require(self.stopped["tenant"] == tenant and self.stopped["source_incarnation"] == source
                and self.stopped["target_nodes"] == self.finished["target_nodes"]
                and self.stopped["operation_id"] != self.finished["operation_id"]
                and len({self.stopped["target_incarnation"], self.finished["target_incarnation"],
                         source}) == 3,
                "the two recoveries are not distinct attempts for the same tenant and targets")
        profiles = inputs["profiles"]
        require(profiles["data"].get("tenant") == tenant
                and profiles["data"].get("resource") == {"kind": "database", "incarnation": source},
                "data client does not address the source incarnation")
        control = profiles["control"]
        require((control.get("resource") or {}).get("kind") == "control"
                and sorted(map(int, control.get("administrative_members", {}))) == self.controls,
                "Control administrator profile does not bind every Control member")
        require(sorted(map(int, self.plan["control_members"])) == self.controls
                and sorted(map(int, self.plan["source_members"])) == self.voters,
                "member profiles do not cover exactly Control and the source voters")
        for key, profile in profiles["control_members"].items():
            require(list(profile.get("administrative_members", {})) == [key]
                    and (profile.get("resource") or {}).get("kind") == "control",
                    "Control member profile does not select its own member")
        for key, profile in profiles["source_members"].items():
            require(list(profile.get("administrative_members", {})) == [key]
                    and profile.get("tenant") == tenant
                    and profile.get("resource") == {"kind": "database", "incarnation": source},
                    "source member profile does not select its own source voter")
        self.live = set()
        self.status_request = None

    def name(self, node_id):
        return self.by_node[node_id]["id"]

    def kasumid(self, *words):
        return [self.paths["kasumid"], *words]

    def recovery(self, action, *words):
        return self.kasumid("control-recovery", action, self.plan["control_profile"], *words)

    def status(self, operation, timeout=None):
        return self.recovery("status", operation, str(timeout or 60000))

    def resume(self, operation, timeout):
        return self.recovery("resume", operation, "1", str(timeout))

    def manage(self, profile):
        return [self.paths["kasumictl"], "--profile", profile, "manage", self.status_request]


# ---- The scenario script ----

def spawn(d, ctx, node_id):
    node = ctx.by_node[node_id]
    identifier = d.spawn(node["id"], node["executable"], node["config"])
    ctx.live.add(node_id)
    return identifier


def record(d, ctx, operation, label):
    """One decoded Control record of ``operation``, and its exact bytes."""
    for index in range(ctx.polls):
        code, raw = d.attempt(f"{label}-{index:04d}", ctx.status(operation))
        value = driver.decode(raw) if code == 0 else None
        if (value is not None and isinstance(value.get("request"), dict)
                and value["request"].get("operation_id") == operation
                and isinstance(value.get("phase"), str)
                and type(value.get("updated_revision")) is int):
            return value, raw
        d.pause(ctx.pause)
    raise ValueError("Control recovery status did not answer: " + label)


def point(value):
    return value["phase"], deletion_stage(value)


def control_leader(d, ctx, label):
    """The Control leader as a live Control member reports it."""
    for index in range(ctx.polls):
        for node in ctx.controls:
            if node not in ctx.live:
                continue
            code, raw = d.attempt(f"{label}-{index:04d}-{node}",
                                  ctx.manage(ctx.plan["control_members"][str(node)]))
            value = driver.decode(raw) if code == 0 else None
            if value is not None and value.get("control_leader") in ctx.controls \
                    and value["control_leader"] in ctx.live:
                return value["control_leader"]
        d.pause(ctx.pause)
    raise ValueError("Control has no live leader: " + label)


def victim(d, ctx, phase, label):
    if phase in TARGET_WORK:
        return ctx.targets[0]["node_id"]
    return control_leader(d, ctx, label + "-leader")


def cell_label(value):
    phase, stage = point(value)
    if stage is not None:
        require(stage in DELETION_LABELS, "product reported an unknown deletion stage")
        return stage, True
    if phase in RECOVERY_LABELS:
        return RECOVERY_LABELS[phase], True
    if phase in STOP_PHASES:
        return "boundary-" + phase.replace("_", "-"), False
    return None, False


def cancel(d, ctx, operation, before, cell, counted):
    """Cancel one step with the product's own deadline until it lands inside the point."""
    start = point(before)
    for deadline in ctx.parameters["deadlines_ms"]:
        code, _ = d.attempt(f"{cell}-deadline-{deadline}", ctx.resume(operation, deadline))
        after, _ = record(d, ctx, operation, f"{cell}-after-{deadline}")
        if point(after) != start:
            return {"landed": False, "reason": "the point completed", "deadline_ms": deadline}
        if code != 0 and after["updated_revision"] > before["updated_revision"]:
            if counted:
                d.count_observation(cell)
            return {"landed": True, "deadline_ms": deadline,
                    "revisions": [before["updated_revision"], after["updated_revision"]]}
        before = after
    return {"landed": False, "reason": "no deadline interrupted a begun step"}


def crash(d, ctx, operation, cell, counted, start):
    """SIGKILL the working daemon while a step is in flight, then restart it."""
    for index, delay in enumerate(ctx.parameters["fault_delays"]):
        before, raw = record(d, ctx, operation, f"{cell}-before-{index}")
        if point(before) != start:
            return {"landed": False, "reason": "the point completed"}
        target = victim(d, ctx, start[0], f"{cell}-{index}")
        result = d.faulted(f"{cell}-fault-{index}", ctx.resume(operation, ctx.timeout),
                           ctx.name(target), raw, delay)
        ctx.live.discard(target)
        killed = result["process"]
        spawn(d, ctx, target)
        if target in ctx.controls:
            control_leader(d, ctx, f"{cell}-restarted-{index}")
        after, _ = record(d, ctx, operation, f"{cell}-after-{index}")
        if (driver.interrupted(result) and point(after) == start
                and after["updated_revision"] > before["updated_revision"]):
            if counted:
                d.mark(cell, killed, -9)
                d.count_observation(cell)
            return {"landed": True, "delay_seconds": delay, "victim": target,
                    "revisions": [before["updated_revision"], after["updated_revision"]]}
        if point(after) != start:
            return {"landed": False, "reason": "the point completed", "delay_seconds": delay}
    return {"landed": False, "reason": "no fault interrupted a begun step"}


def drive(d, ctx, operation, label, terminal, facts, hooks=()):
    """Advance one product step at a time; fault each observable point once."""
    seen, phases = set(), []
    for step in range(ctx.parameters["step_limit"]):
        value, _ = record(d, ctx, operation, f"{label}-status-{step:04d}")
        if not phases or phases[-1] != value["phase"]:
            phases.append(value["phase"])
        if value["phase"] == terminal:
            return value, phases
        here = point(value)
        cell, counted = cell_label(value)
        if cell is not None and here not in seen:
            seen.add(here)
            facts["cells"][cell + "-cancellation"] = cancel(d, ctx, operation, value,
                                                            cell + "-cancellation", counted)
            value, _ = record(d, ctx, operation, f"{label}-between-{step:04d}")
            if point(value) == here:
                facts["cells"][cell + "-crash"] = crash(d, ctx, operation, cell + "-crash",
                                                        counted, here)
            else:
                facts["cells"][cell + "-crash"] = {"landed": False, "reason": "the point completed"}
            continue
        if any(hook(d, ctx, operation, value, facts) for hook in hooks):
            continue
        d.attempt(f"{label}-resume-{step:04d}", ctx.resume(operation, ctx.timeout))
    raise ValueError("recovery did not reach " + terminal + ": " + label)


def race(d, ctx, operation, value, facts):
    """Two clients resume the pending activation at once; one activation may exist."""
    if value["phase"] != "activate" or facts.get("race") is not None:
        return False
    outputs = d.race("activation-race", [ctx.resume(operation, ctx.timeout)] * 2)
    after, _ = record(d, ctx, operation, "activation-race-after")
    seen = {driver.decode(raw).get("activation") for code, raw in outputs
            if code == 0 and driver.decode(raw) is not None}
    seen.add(after.get("activation"))
    winners = sorted(item for item in seen if item is not None)
    facts["race"] = {"exit_codes": [code for code, _ in outputs], "activations": winners}
    return True


def forward(d, ctx, operation, value, facts):
    """After committed activation a stop request cannot turn recovery back."""
    if facts.get("forward") is not None or value.get("activation") is None \
            or value["phase"] in ("prepare", "materialize", "initialize", "complete",
                                  "retire_source", "fence_source", "activate"):
        return False
    code, raw = d.attempt("forward-stop", ctx.recovery(
        "stop", operation, d.custody("home/recovery-forward-stop.json"), str(ctx.timeout)))
    reply = driver.decode(raw) if code == 0 else None
    facts["forward"] = {"stop_exit": code,
                        "stop_phase": reply.get("phase") if reply is not None else None}
    return True


def storage(d, ctx):
    return {target["id"]: {root: d.listing(root) for root in target["roots"]}
            for target in ctx.targets}


def created(before, after):
    """Entries present now that the earlier listing did not have, by physical identity."""
    result = {}
    for target, roots in after.items():
        for root, entries in roots.items():
            for name, identity in entries.items():
                if before[target][root].get(name) != identity:
                    result[root + "/" + name] = identity
    return result


def surviving(before, after):
    """Every earlier entry keeps its exact physical identity."""
    return all(after[target][root].get(name) == identity
               for target, roots in before.items() for root, entries in roots.items()
               for name, identity in entries.items())


def script(d, ctx):
    ctx.status_request = d.request("status", {"operation": "status"})
    facts = {"members": {}, "cells": {}, "lost": [], "open": []}
    for node in ctx.nodes:
        facts["members"][node["id"]] = spawn(d, ctx, node["node_id"])
    for target in ctx.targets:
        spawn(d, ctx, target["node_id"])
    source = ctx.manage(ctx.plan["source_members"][str(ctx.voters[0])])
    d.poll("startup-source", source, lambda value: (value["leader"] in ctx.voters
                                                     and value["raft_voters"] == ctx.voters),
           limit=ctx.polls, pause=ctx.pause)
    control_leader(d, ctx, "startup-control")
    facts["measured"] = d.phase("measured")

    # An absent source quorum: two of three source voters are gone for good.
    raw = d.call("source-before", source)
    view = driver.decode(raw)
    require(view is not None and view["leader"] in ctx.voters, "source has no leader")
    lost = [view["leader"], next(node for node in ctx.voters if node != view["leader"])]
    for node in lost:
        killed = d.crash(ctx.name(node), raw, ["absent-source-quorum"])
        ctx.live.discard(node)
        facts["lost"].append(killed["id"])
    probe = [ctx.paths["kasumictl"], "--profile", ctx.plan["data_profile"], "put",
             ctx.plan["collection"], "absent-quorum",
             json.dumps({"attempt": ctx.attempt_id}, sort_keys=True), "--if", "any"]
    code, _ = d.attempt("absent-source-write", probe)
    require(code != 0, "the source accepted a write without its quorum")
    facts["available_source_voters"] = len(ctx.voters) - len(lost)

    # Unrelated files beside every target's storage, then the first recovery,
    # stopped after materialization, must delete exactly its own storage.
    planted = {}
    for target in ctx.targets:
        for root in target["roots"]:
            path = root + "/unrelated-" + ctx.attempt_id
            planted[path] = d.plant(path, ("unrelated " + path + "\n").encode())
    before = storage(d, ctx)
    stopped = ctx.stopped["operation_id"]
    reply = d.json("stopped-start", ctx.recovery("start", ctx.plan["stopped_request"],
                                                  d.custody("home/recovery-stopped.json"),
                                                  str(ctx.timeout)))
    require(reply.get("phase") == "prepare" and reply.get("request") == ctx.stopped,
            "the first recovery did not start at preparation")
    for step in range(ctx.parameters["step_limit"]):
        value, _ = record(d, ctx, stopped, f"stopped-advance-{step:04d}")
        if value["phase"] not in ("prepare", "materialize"):
            break
        d.attempt(f"stopped-resume-{step:04d}", ctx.resume(stopped, ctx.timeout))
    else:
        raise ValueError("the first recovery never materialized")
    materialized = storage(d, ctx)
    own = created(before, materialized)
    require(any(identity["type"] == "file" for identity in own.values()),
            "materialization created no target storage")
    d.json("stopped-stop", ctx.recovery("stop", stopped, d.custody("home/recovery-stopped-stop.json"),
                                        str(ctx.timeout)))
    final, phases = drive(d, ctx, stopped, "stopped", "stopped", facts)
    after = storage(d, ctx)
    kept = all(d.inspect(path) == {**identity, "sha256": hashlib.sha256(
        ("unrelated " + path + "\n").encode()).hexdigest()} for path, identity in planted.items())
    deleted = [name for name, identity in own.items() if identity["type"] == "file"
               and identity == created(before, after).get(name)]
    facts["stopped"] = {"phases": phases, "created": own, "remaining": deleted,
                        "unrelated_kept": kept, "survived": surviving(before, after)}
    if kept and not deleted and facts["stopped"]["survived"]:
        d.json("stopped-final", ctx.status(stopped), ["unrelated-file-isolation"])

    # The second recovery finishes through every fault.
    operation = ctx.finished["operation_id"]
    before = storage(d, ctx)
    reply = d.json("finished-start", ctx.recovery("start", ctx.plan["request"],
                                                   d.custody("home/recovery-finished.json"),
                                                   str(ctx.timeout)))
    require(reply.get("phase") == "prepare" and reply.get("request") == ctx.finished,
            "the second recovery did not start at preparation")
    final, phases = drive(d, ctx, operation, "finished", "finished", facts, (race, forward))
    facts["finished"] = {"phases": phases, "activation": final.get("activation"),
                         "route_publication": final.get("route_publication")}
    winners = (facts.get("race") or {}).get("activations", [])
    facts["activation_winners"] = len(winners)
    if len(winners) == 1 and final.get("activation") == winners[0]:
        d.json("finished-winner", ctx.status(operation), ["single-activation-winner"])
    forwarded = facts.get("forward")
    if (forwarded is not None and not any(phase in ("stop_activation", "stop_target", "cleanup",
                                                    "stopped") for phase in phases)
            and (forwarded["stop_phase"] is None or forwarded["stop_phase"] not in STOP_PHASES)):
        d.json("finished-forward", ctx.status(operation), ["forward-after-activation"])
    if final.get("route_publication") is not None and len(lost) * 2 > len(ctx.voters):
        d.json("finished-absent-quorum", ctx.status(operation), ["absent-source-quorum"])

    # Physical bindings survive a clean restart of a target.
    bound = storage(d, ctx)
    generation = created(before, bound)
    first = ctx.targets[0]
    d.stop(first["id"])
    ctx.live.discard(first["node_id"])
    spawn(d, ctx, first["node_id"])
    restarted, _ = record(d, ctx, operation, "bindings-restarted")
    rebound = storage(d, ctx)
    facts["bindings"] = {"created": generation,
                         "preserved": bool(generation) and surviving(bound, rebound)}
    if facts["bindings"]["preserved"] and restarted["phase"] == "finished":
        d.json("bindings-after-restart", ctx.status(operation), ["physical-bindings"])

    # Source and target authorization are separate signed phases.
    issuer = final.get("issuer_preparation")
    voters = final.get("voters") or {}
    target_phase = (voters.get(str(first["node_id"])) or {}).get("materialization")
    if isinstance(issuer, str) and isinstance(target_phase, str) and issuer != target_phase:
        source_record = d.json("authorization-source", ctx.recovery(
            "phase", operation, issuer, str(ctx.timeout)), ["independent-source-target-authorization"])
        target_record = d.json("authorization-target", ctx.recovery(
            "phase", operation, target_phase, str(ctx.timeout)),
            ["independent-source-target-authorization"])
        facts["authorization"] = authorization(ctx, operation, source_record, target_record,
                                               first["node_id"])
    else:
        facts["authorization"] = False

    facts["drain"] = d.phase("drain")
    for node_id in sorted(ctx.live):
        d.stop(ctx.name(node_id))
    ctx.live.clear()
    facts["open"] = open_cells(facts)
    return facts


def contains(value, needle):
    return needle in json.dumps(value, sort_keys=True)


def authorization(ctx, operation, source, target, node_id):
    """The issuer authorized the source and the target its own incarnation, separately."""
    request = ctx.finished
    try:
        return (source["operation_id"] == target["operation_id"] == operation
                and source["phase_id"] != target["phase_id"]
                and source["phase"] == "prepare" and source["input"]["kind"] == "authority"
                and source["outcome"] is not None
                and contains(source["input"], request["source_incarnation"])
                and target["input"]["kind"] == "target"
                and target["input"]["input"]["node_id"] == node_id
                and target["outcome"] is not None and target["outcome"]["kind"] == "target"
                and contains(target["input"], request["target_incarnation"]))
    except (KeyError, TypeError):
        return False


def open_cells(facts):
    """Every acceptance cell this run could not honestly establish, with its reason."""
    cells = facts["cells"]
    result = []
    for label in (*RECOVERY_LABELS.values(), *DELETION_LABELS):
        for fault in ("crash", "cancellation"):
            name = f"{label}-{fault}"
            outcome = cells.get(name)
            if not outcome or not outcome.get("landed"):
                result.append({"cell": name, "reason": (outcome or {}).get(
                    "reason", "the product reports no observable point for this phase"
                    if label in DELETION_LABELS else "the phase was never observed pending")})
    checks = {"absent-source-quorum": facts.get("available_source_voters") == 1
              and (facts.get("finished") or {}).get("route_publication") is not None,
              "single-activation-winner": facts.get("activation_winners") == 1,
              "forward-after-activation": facts.get("forward") is not None,
              "physical-bindings": (facts.get("bindings") or {}).get("preserved") is True,
              "unrelated-file-isolation": (facts.get("stopped") or {}).get("unrelated_kept") is True
              and not facts["stopped"]["remaining"] and facts["stopped"]["survived"],
              "independent-source-target-authorization": facts.get("authorization") is True}
    result.extend({"cell": name, "reason": "the product witness did not hold"}
                  for name, held in checks.items() if not held)
    return result


# ---- Producer ----

def execute(run, parameters, topology_path, plan_path):
    target = run.bind()
    require(target == REFERENCE or run.report["qualification"] == domain_run.REHEARSAL,
            "qualifying recovery runs on the native Linux ARM64 reference")
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

    inputs = retained_inputs(read, leaf, plan_path, admitted)
    for target_member_ in inputs["targets"]:
        for root in [*target_member_["roots"], target_member_["scratch"]]:
            topology.directory(root)
    domain_run.durable_json(run.output / "topology-admission.json", admitted)
    ctx = Context(inputs, admitted, run.binary_paths, run.attempt_id, parameters)
    details = {"admission": owned.ref(run.output, run.output / "topology-admission.json"),
               "binary_paths": dict(run.binary_paths), "facts": None}
    run.report["details"] = details
    run.save()
    run.start_services(parameters["measured_seconds"], parameters["startup_seconds"],
                       parameters["drain_seconds"])
    d = driver.Live(run, details)
    try:
        facts = script(d, ctx)
    finally:
        d.close()
    run.report["topology"] = members(ctx, facts)
    details["facts"] = facts
    run.save()
    require(not facts["open"], "open recovery cells: " + ", ".join(
        item["cell"] + " (" + item["reason"] + ")" for item in facts["open"]))
    run.passed(details)


def members(ctx, facts):
    return [{"id": node["id"], "role": node["role"], "group": node["group"],
             "certificate_sha256": node["certificate"]["leaf_sha256"],
             "process_id": facts["members"][node["id"]]} for node in ctx.nodes]


def gate_details(root, report_path):
    root = Path(root).resolve(strict=True)
    report = owned.read(Path(report_path))
    facts = report["details"]["facts"]
    return {"source_voters": len([n for n in owned.read(
                Path(report_path).parent / "topology-admission.json")["nodes"] if n["role"] == "data"]),
            "available_source_voters": facts["available_source_voters"],
            "activation_winners": facts["activation_winners"],
            "report": owned.ref(root, Path(report_path).resolve(strict=True))}


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
        parameters.update(measured_seconds=7200, startup_seconds=600, drain_seconds=600,
                          settle_polls=300)
    qualification = domain_run.QUALIFYING if parameters == PARAMETERS else domain_run.REHEARSAL
    with domain_run.Run(KIND, RUNNER, MODULES, args.evidence, args.output, args.journal,
                        args.attempt_id, parameters, qualification) as run:
        execute(run, parameters, args.topology, args.plan)
    print("recovery " + ("qualifying" if qualification == domain_run.QUALIFYING
                         else "NON-QUALIFYING REHEARSAL") + " retained: " + str(args.output))
    return 0


# ---- Acceptance adapter ----

def verify_domain(root, domain, files, configs, artifacts, candidates):
    import verify_release_acceptance as acceptance

    facts = domain_run.verify_run(root, domain, files, configs, KIND, RUNNER, MODULES)
    report, custody = facts["report"], facts["custody"]
    require(report["target"] == acceptance.REFERENCE and not domain["artifacts"],
            "recovery ran on another native target or consumed an artifact")
    require(report["invocation"]["parameters"] == PARAMETERS,
            "recovery parameters differ from the qualifying contract")
    details = report["details"]
    owned.exact(details, {"admission", "binary_paths", "facts", "attempts", "ledger", "races"},
                "recovery details")
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
                    for node in nodes)
            and {name: item["sha256"] for name, item in admitted["binaries"].items()}
            == {name: domain["binaries"][name] for name in ("kasumid", "kasumi-authority")},
            "recovery retained another topology or candidate")
    paths = details["binary_paths"]
    evidence = Path(report["evidence_root"])
    require(set(paths) == set(domain["binaries"])
            and all(Path(path).name == name and Path(path).is_relative_to(evidence)
                    for name, path in paths.items())
            and all(item["path"] == paths[name] for name, item in admitted["binaries"].items()),
            "recovery selected executables outside the frozen candidate")
    used = set()

    def read(identifier, path):
        used.add(identifier)
        return owned.read(retained[identifier])

    def leaf(identifier, path):
        used.add(identifier)
        return topology.certificate(retained[identifier])["leaf_sha256"]

    inputs = retained_inputs(read, leaf, None, admitted)
    require(used | {"ha-topology"} == set(retained), "recovery retained an unused input")
    ctx = Context(inputs, admitted, paths, report["attempt_id"], PARAMETERS)
    d = driver.Replay(facts, paths)
    original = script(d, ctx)
    d.finish()
    require(details["facts"] == original and not original["open"],
            "recovery facts differ from the replayed script or leave cells open")
    require(driver.scenario_rows(facts) == d.expected and set(d.expected) == SCENARIOS
            == acceptance.SCENARIOS[KIND], "recovery scenario rows differ from the replayed script")
    topology_members = members(ctx, original)
    require(report["topology"] == topology_members == domain["topology"],
            "recovery topology differs from the nine original spawns")
    acceptance.check_topology(topology_members, domain["processes"], domain["binaries"], "required")
    require(domain["details"] == {"source_voters": len(ctx.voters),
                                  "available_source_voters": original["available_source_voters"],
                                  "activation_winners": original["activation_winners"],
                                  "report": domain["details"]["report"]},
            "recovery gate details differ from the replayed run")
    return facts["evidence"]


if __name__ == "__main__":
    raise SystemExit(main())
