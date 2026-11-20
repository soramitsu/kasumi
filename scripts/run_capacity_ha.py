#!/usr/bin/env python3
"""Qualify HA capacity on the nine installed native processes with an incompressible corpus.

Three data, three Control and three authority processes run from the admitted
HA topology. The corpus is measured with the frozen driver and loaded through
the tenant's data voters. Every capacity operation then runs in order: a Raft
snapshot covering the corpus, a completed compaction cycle on every data
voter, a restart of the data group, filesystem and S3 backups, retained read
pressure, replacement of a data follower by a separately installed node that
catches up the whole corpus, and Control recoveries from each backup. The
exact driver verifies every document after each operation, through the
replacement node after replacement and through the recovered generation after
each recovery. ``verify_domain`` replays the same procedure over the run.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

if __name__ == "__main__":
    scripts = Path(__file__).resolve(strict=True).parent
    if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode
            and sys.pycache_prefix is None and "PYTHONPYCACHEPREFIX" not in os.environ):
        raise SystemExit("HA capacity requires Python -I -B -S")
    if any(p.name == "__pycache__" or p.suffix in {".pyc", ".pyo"}
           or (p.suffix == ".py" and p.is_symlink()) for p in scripts.rglob("*")):
        raise SystemExit("HA capacity requires source-only Python imports")
    sys.path.insert(0, str(scripts))

import capacity_domain as cap
import domain_run
from domain_run import require
import process_ha_topology as topology
import repeatable_assembly as owned
from release_gate import sha256

KIND = "capacity-ha"
RUNNER = "scripts/run_capacity_ha.py"
MODULES = (cap.LIBRARY,)
PARAMETERS = cap.PARAMETERS
REPLACEMENT = "replacement"
RESTORES = (("filesystem-restore", "filesystem-backup"), ("s3-restore", "s3-backup"))
RECOVERY_STEPS = "16"
RECOVERY_TIMEOUT_MS = "600000"
PLAN_FIELDS = {"schema", "kind", "topology", "data_profile", "operator_profile", "control_profile",
               "observer_profiles", "tenant_limits", "corpus", "churn", "pressure",
               "compaction_growth_percent", "filesystem_destination", "s3_destination", "replacement",
               "restores"}


def check_plan(plan):
    cap.exact(plan, PLAN_FIELDS, "HA capacity plan")
    corpus = cap.common_plan(plan, KIND)
    for key in ("topology", "data_profile", "operator_profile", "control_profile", "tenant_limits"):
        cap.absolute(plan[key], key)
    require(isinstance(plan["observer_profiles"], dict) and len(plan["observer_profiles"]) == 3,
            "one observer profile per data voter is required")
    for path in plan["observer_profiles"].values():
        cap.absolute(path, "observer profile")
    cap.exact(plan["replacement"], {"replaced", "configuration", "certificate", "operator_profile",
                                    "observer_profile", "data_profile"}, "follower replacement plan")
    require(isinstance(plan["replacement"]["replaced"], str), "replaced data member is not named")
    for key in ("configuration", "certificate", "operator_profile", "observer_profile", "data_profile"):
        cap.absolute(plan["replacement"][key], "replacement " + key)
    cap.exact(plan["restores"], {name for name, _ in RESTORES}, "recovery plans")
    for spec in plan["restores"].values():
        cap.exact(spec, {"template", "data_profile", "targets"}, "recovery plan")
        cap.absolute(spec["template"], "recovery template")
        cap.absolute(spec["data_profile"], "recovered data profile")
        require(isinstance(spec["targets"], list) and len(spec["targets"]) <= 3, "recovery target roster")
        for path in spec["targets"]:
            cap.absolute(path, "recovery target configuration")
    return corpus


def port(endpoint):
    return int(endpoint.rstrip("/").rsplit(":", 1)[1])


def admitted_topology(io, plan, paths, digests):
    """The admitted nine-process installation, bound to retained configuration bytes."""
    retained = io.config("ha-topology", plan["topology"])
    admitted = io.observed("topology-admission.json",
                           lambda: topology.inspect(Path(plan["topology"]).resolve(strict=True),
                                                    {"PATH": "/usr/bin:/bin"}))
    declared = owned.read(retained)
    nodes = admitted["nodes"]
    require(admitted["plan_sha256"] == sha256(retained) and len(nodes) == 9
            and declared["nodes"] == [{k: n[k] for k in ("id", "role", "group", "config")} for n in nodes]
            and all(admitted["binaries"][name] == {"path": paths[name], "sha256": digests[name]}
                    for name in ("kasumid", "kasumi-authority")),
            "HA admission differs from the retained topology or candidate binaries")
    configs = {}
    for node in nodes:
        path = io.config("node-" + node["id"], node["config"])
        require(sha256(path) == node["config_sha256"], "HA node configuration changed after admission")
        configs[node["id"]] = owned.read(path)
        require(configs[node["id"]]["replication"]["node_id"] == node["node_id"], "HA node identity differs")
    topology.verify_control_placement(nodes, configs)
    return nodes, configs


def check_data(plan, nodes, configs, profiles, observers):
    data = [n for n in nodes if n["role"] == "data"]
    voters = sorted(n["node_id"] for n in data)
    tenant = profiles["data"]["tenant"]
    incarnation = profiles["data"]["resource"]["incarnation"]
    for node in data:
        config = configs[node["id"]]
        require(any(t["tenant"] == tenant and t["incarnation"] == incarnation for t in config["tenants"]),
                "data voter does not host the measured tenant generation")
        cap.destinations(config, plan)
    natives = {port(c["native"]["listen"]) for n, c in configs.items() if n in {d["id"] for d in data}}
    admins = {configs[n["id"]]["replication"]["node_id"]: port(configs[n["id"]]["admin"]["listen"]) for n in data}
    for role in ("data", "operator"):
        require(profiles[role]["tenant"] == tenant
                and profiles[role]["resource"] == {"kind": "database", "incarnation": incarnation},
                role + " profile addresses another tenant generation")
    require(port(profiles["data"]["native_endpoint"]) in natives, "data profile is outside the data voters")
    members = profiles["operator"]["administrative_members"]
    require(len(members) == 1 and all(int(m) in admins and port(v["endpoint"]) == admins[int(m)]
                                      for m, v in members.items()),
            "operator profile must select exactly one enrolled data voter")
    require(profiles["control"]["resource"]["kind"] == "control", "control profile is not a Control credential")
    require(sorted(map(int, observers)) == voters, "observer profiles do not cover the data voters")
    for member, profile in observers.items():
        selected = list(profile["administrative_members"].items())
        require(profile["resource"]["kind"] == "control" and len(selected) == 1 and int(selected[0][0]) == int(member)
                and port(selected[0][1]["endpoint"]) == admins[int(member)],
                "observer profile does not address its own data voter")
    return data, voters, tenant, incarnation


def leader_status(raw, voters, incarnation):
    value = cap.parse_json(raw, "status")
    require(value["mode"] == "replicated" and value["observation"] == "local_committed_state"
            and value["incarnation"] == incarnation and value["node_id"] == value["leader"]
            and value["raft_voters"] == voters and type(value["raft_applied_index"]) is int
            and type(value["revision"]) is int, "status is not the tenant leader's committed state")
    return value


def settled_leader(voters, incarnation):
    def accept(code, raw):
        if code != 0:
            return False
        try:
            leader_status(raw, voters, incarnation)
        except (ValueError, KeyError, TypeError):
            return False
        return True
    return accept


def procedure(io, plan_path, attempt):
    plan = owned.read(io.config("capacity-plan", plan_path))
    corpus = check_plan(plan)
    paths, digests = io.paths, io.digests
    kasumid, ctl = paths["kasumid"], paths["kasumictl"]
    nodes, configs = admitted_topology(io, plan, paths, digests)
    profiles = {role: owned.read(io.config(role + "-profile", plan[role + "_profile"]))
                for role in ("data", "operator", "control")}
    observers = {member: owned.read(io.config("observer-" + member, path))
                 for member, path in sorted(plan["observer_profiles"].items())}
    tenant_limits = owned.read(io.config("tenant-limits", plan["tenant_limits"]))
    cap.check_corpus_limits(tenant_limits, corpus)
    data, voters, tenant, incarnation = check_data(plan, nodes, configs, profiles, observers)
    spec = plan["replacement"]
    replacement = owned.read(io.config("replacement-node", spec["configuration"]))
    certificate = topology.certificate(io.config("replacement-certificate", spec["certificate"]))
    replaced = next((n for n in data if n["id"] == spec["replaced"]), None)
    new_id = replacement["replication"]["node_id"]
    require(replaced is not None and type(new_id) is int and new_id not in {n["node_id"] for n in nodes}
            and replacement.get("mode") == "replicated"
            and certificate["leaf_sha256"] not in {n["certificate"]["leaf_sha256"] for n in nodes}
            and any(t["tenant"] == tenant and t["incarnation"] == incarnation for t in replacement["tenants"]),
            "replacement is not a distinct installed data node for the measured tenant")
    replacement_profiles = {role: owned.read(io.config("replacement-" + role + "-profile", spec[role + "_profile"]))
                            for role in ("operator", "observer", "data")}
    require(port(replacement_profiles["data"]["native_endpoint"]) == port(replacement["native"]["listen"])
            and replacement_profiles["data"]["resource"] == {"kind": "database", "incarnation": incarnation}
            and [int(m) for m in replacement_profiles["operator"]["administrative_members"]] == [new_id]
            and [int(m) for m in replacement_profiles["observer"]["administrative_members"]] == [new_id],
            "replacement profiles do not address the replacement node")
    limits = cap.admitted_limits([configs[n["id"]] for n in data] + [replacement], cap.corpus_bytes(corpus))
    io.record(("limits",), limits)
    io.record(("corpus",), corpus)
    measured = {n["id"]: cap.storage_roots(configs[n["id"]]) for n in data}
    measured[REPLACEMENT] = cap.storage_roots(replacement)
    driver = cap.Corpus(io, corpus)
    driver.measure(profiles["data"])

    growth = "--storage-compaction-growth-percent=" + str(plan["compaction_growth_percent"])

    def serve_argv(node):
        argv = [node["executable"]["path"], "serve", node["config"]]
        return argv + [growth] if node["role"] == "data" else argv

    io.start(measured)
    for node in nodes:
        identifier = io.serve(node["id"], serve_argv(node), node=node["id"] if node["role"] == "data" else None)
        io.member({"id": node["id"], "role": node["role"], "group": node["group"],
                   "certificate_sha256": node["certificate"]["leaf_sha256"], "process_id": identifier})
    status_path = io.input("inputs/status.json", {"operation": "status"})
    operator, control, data_path = plan["operator_profile"], plan["control_profile"], plan["data_profile"]
    status_argv = [ctl, "--profile", operator, "manage", status_path]
    io.poll("startup-leader", status_argv, settled_leader(voters, incarnation), cap.READY_POLLS)
    io.enter("measured")
    io.serve("renewal", cap.renewal_argv(io, data_path), interactive=True)
    io.command("set-limits", [ctl, "--profile", operator, "set-limits", plan["tenant_limits"]])
    io.command("create-corpus-collection", [ctl, "--profile", operator, "create-collection",
                                            io.input("inputs/corpus-collection.json",
                                                     cap.corpus_collection(corpus["collection"]))])
    io.command("create-churn-collection", [ctl, "--profile", operator, "create-collection",
                                           io.input("inputs/churn-collection.json", cap.churn_collection())])
    driver.run("load", "load", "corpus-load", profiles["data"], incarnation)
    loaded = leader_status(io.command("corpus-status", status_argv), voters, incarnation)
    corpus_index, corpus_revision = loaded["raft_applied_index"], loaded["revision"]
    io.record(("corpus_commit",), {"index": corpus_index, "revision": corpus_revision})
    rounds = plan["churn"]["rounds"]

    def status(step, members=voters):
        return leader_status(io.command(step, status_argv), members, incarnation)

    def metrics(step, member_profiles):
        return {member: cap.storage(cap.gauges(io.command(step + "-" + member,
                                                          [ctl, "--profile", path, "metrics"]).decode()), tenant)
                for member, path in member_profiles.items()}

    def verify(operation, profile, generation):
        driver.run(operation + "-verify", "verify", "ops/" + operation, profile, generation, scenario=operation)

    io.mark("snapshot", "started")
    for index in range(rounds + 1):
        observed = status(f"snapshot-status-{index}")
        if observed["raft_snapshot_index"] is not None and observed["raft_snapshot_index"] >= corpus_index:
            break
        require(index < rounds, "no Raft snapshot covered the corpus within the churn bound")
        cap.churn(io, attempt, "snapshot", index, plan, data_path, ctl)
    io.record(("operations", "snapshot", "snapshot_index"), observed["raft_snapshot_index"])
    verify("snapshot", profiles["data"], incarnation)
    io.mark("snapshot", "finished")

    io.mark("compaction", "started")
    observer_paths = dict(sorted(plan["observer_profiles"].items()))
    before = metrics("compaction-metrics-0", observer_paths)
    for index in range(rounds):
        cap.churn(io, attempt, "compaction", index, plan, data_path, ctl)
        after = metrics(f"compaction-metrics-{index + 1}", observer_paths)
        if all(cap.compacted(before[m], after[m]) for m in observer_paths):
            break
    else:
        raise ValueError("not every data voter completed a compaction cycle within the churn bound")
    io.record(("operations", "compaction", "storage"), {"before": before, "after": after})
    verify("compaction", profiles["data"], incarnation)
    io.mark("compaction", "finished")

    io.mark("restart", "started")
    for node in data:
        io.stop(node["id"])
    for node in data:
        io.serve(node["id"], serve_argv(node), node=node["id"])
    io.poll("restart-leader", status_argv, settled_leader(voters, incarnation), cap.READY_POLLS)
    reopened = status("restart-status")
    require(reopened["revision"] >= corpus_revision, "reopened data group lost the committed corpus")
    verify("restart", profiles["data"], incarnation)
    io.mark("restart", "finished")

    checkpoints = {}
    for operation, alias in (("filesystem-backup", plan["filesystem_destination"]),
                             ("s3-backup", plan["s3_destination"])):
        io.mark(operation, "started")
        checkpoints[operation] = cap.backup(io, operation, alias, kasumid, operator, tenant, incarnation,
                                            corpus_revision)
        verify(operation, profiles["data"], incarnation)
        io.mark(operation, "finished")

    operation = "retained-read-pressure"
    io.mark(operation, "started")
    pressure = plan["pressure"]
    readers = {f"pressure-reader-{r}": cap.pressure_requests(corpus, pressure, r) for r in range(pressure["readers"])}
    sessions = {name: ([ctl, "--profile", data_path, "session"], requests) for name, requests in readers.items()}
    churn = cap.churn_requests(attempt, operation, 0, cap.CHURN_REQUESTS, plan["churn"]["pad_bytes"])
    sessions["pressure-churn"] = ([ctl, "--profile", data_path, "session"], churn)
    observed = []

    def during(index):
        for member, path in observer_paths.items():
            values = cap.gauges(io.command(f"pressure-metrics-{index}-{member}",
                                           [ctl, "--profile", path, "metrics"]).decode())
            observed.append({"member": member, "reserved_bytes": values.get("kasumi_admission_reserved_bytes"),
                             "storage": cap.storage(values, tenant)})

    replies, count = io.converse(sessions, during)
    io.record(("operations", operation, "samples"), count)
    for reply, request in zip(replies["pressure-churn"], churn):
        cap.churn_reply(reply, request)
    served = {}
    for name, requests in readers.items():
        outcomes = [cap.pressure_reply(reply, request, corpus, incarnation, driver.revisions)
                    for reply, request in zip(replies[name], requests)]
        require(any(outcomes), "a retained reader never obtained a coherent snapshot")
        served[name] = {"served": sum(outcomes), "refused": len(outcomes) - sum(outcomes)}
    budget = limits["read_retention_budget_bytes"]
    require(all(isinstance(item["reserved_bytes"], float) and item["reserved_bytes"] <= budget for item in observed),
            "admitted retained reads exceeded the reservation budget")
    io.record(("operations", operation, "readers"), served)
    io.record(("operations", operation, "observations"), observed)
    verify(operation, profiles["data"], incarnation)
    io.mark(operation, "finished")

    # Replace a data follower; the new member must catch up the whole corpus.
    operation = "follower-replacement"
    io.mark(operation, "started")
    current = status("replacement-before")
    require(current["leader"] != replaced["node_id"], "the planned replaced member is the current leader")
    new_voters = sorted(set(voters) - {replaced["node_id"]} | {new_id})
    io.serve(REPLACEMENT, [kasumid, "serve", spec["configuration"], growth], node=REPLACEMENT)
    io.command("replacement-add-learner", [ctl, "--profile", operator, "manage",
                                           io.input("ops/" + operation + "/add-learner.json",
                                                    {"operation": "add_learner", "node_id": new_id})])

    def caught_up(code, raw):
        if code != 0:
            return False
        try:
            value = cap.parse_json(raw, "replacement status")
        except ValueError:
            return False
        return (value.get("node_id") == new_id and value.get("incarnation") == incarnation
                and type(value.get("raft_applied_index")) is int and value["raft_applied_index"] >= corpus_index)

    io.poll("replacement-caught-up", [ctl, "--profile", spec["operator_profile"], "manage", status_path],
            caught_up, cap.SETTLE_POLLS, interval=5.0)
    changed = cap.parse_json(io.command("replacement-membership", [
        ctl, "--profile", operator, "manage", io.input("ops/" + operation + "/membership.json",
                                                       {"operation": "change_membership", "voters": new_voters})]),
        "membership change")
    require(changed.get("changed") is True, "membership change did not commit the replacement voter set")
    if changed.get("publish_control_route_required") is True:
        io.command("replacement-publish", [ctl, "--profile", operator, "manage",
                                           io.input("ops/" + operation + "/publish.json",
                                                    {"operation": "publish_membership", "voters": new_voters})])
    io.stop(replaced["id"])
    io.poll("replacement-settled", status_argv, settled_leader(new_voters, incarnation), cap.SETTLE_POLLS)
    replaced_status = cap.parse_json(io.command("replacement-status", [
        ctl, "--profile", spec["operator_profile"], "manage", status_path]), "replacement status")
    require(replaced_status["raft_voters"] == new_voters and replaced_status["raft_applied_index"] >= corpus_index,
            "replacement member does not hold the committed corpus under the new voter set")
    io.record(("operations", operation, "voters"), {"before": voters, "after": new_voters,
                                                    "replaced": replaced["node_id"], "replacement": new_id})
    io.serve("renewal-replacement", cap.renewal_argv(io, spec["data_profile"]), interactive=True)
    verify(operation, replacement_profiles["data"], incarnation)
    io.end("renewal-replacement")
    io.mark(operation, "finished")

    # Control recoveries of each original checkpoint into a new generation.
    previous = {incarnation}
    for operation, source in RESTORES:
        restore = plan["restores"][operation]
        template = owned.read(io.config(operation + "-template", restore["template"]))
        recovered = owned.read(io.config(operation + "-data-profile", restore["data_profile"]))
        target = template.get("target_incarnation")
        require("checkpoint" not in template and "operation_id" not in template
                and template.get("tenant") == tenant and template.get("source_incarnation") == incarnation
                and target not in previous
                and recovered["resource"] == {"kind": "database", "incarnation": target}
                and recovered["tenant"] == tenant, "recovery template does not restore this tenant's checkpoint")
        previous.add(target)
        io.mark(operation, "started")
        targets = []
        for index, path in enumerate(restore["targets"]):
            name = f"{operation}-target-{index}"
            io.config(name, path)
            io.serve(name, [kasumid, "serve", path], node=None)
            targets.append(name)
        identifier = cap.operation_uuid(attempt, operation)
        request = io.input("ops/" + operation + "/request.json",
                           {**template, "operation_id": identifier, "checkpoint": checkpoints[source]})
        io.command(operation + "-start", [kasumid, "control-recovery", "start", control, request,
                                          io.path("ops/" + operation + "/attempt.json"), RECOVERY_TIMEOUT_MS],
                   cap.MAINTENANCE_TIMEOUT)
        for index in range(cap.SETTLE_POLLS):
            record = cap.parse_json(io.command(f"{operation}-resume-{index:04d}", [
                kasumid, "control-recovery", "resume", control, identifier, RECOVERY_STEPS, RECOVERY_TIMEOUT_MS],
                cap.MAINTENANCE_TIMEOUT), "recovery record")
            require(record["request"]["operation_id"] == identifier
                    and record["request"]["checkpoint"] == checkpoints[source], "recovery record differs")
            if record["phase"] in ("finished", "stopped"):
                break
            io.sleep(5)
        require(record["phase"] == "finished", "Control recovery did not finish its original checkpoint")
        io.record(("operations", operation, "recovery"), {"operation_id": identifier, "target": target,
                                                          "phase": record["phase"]})
        io.end("renewal")
        io.serve("renewal", cap.renewal_argv(io, restore["data_profile"]), interactive=True)
        verify(operation, recovered, target)
        io.mark(operation, "finished")
        for name in targets:
            io.stop(name)

    io.enter("drain")
    io.end("renewal")
    io.stop(REPLACEMENT)
    for node in reversed(nodes):
        if node["id"] != replaced["id"]:
            io.stop(node["id"])
    return cap.HA_OPERATIONS, sorted(measured)


def execute(run, plan_path):
    target = run.bind()
    require(target == cap.REFERENCE or run.report["qualification"] == domain_run.REHEARSAL,
            "nine-process qualification requires native Linux ARM64")
    functional = owned.read(run.evidence / "evidence.json")
    driver, digest = cap.driver_executable(run.evidence, functional)
    python = functional["python_executable"]
    paths = {**run.binary_paths, "driver": str(driver), "python": python["path"]}
    digests = {**run.report["binaries"], "driver": digest, "python": python["sha256"]}
    io = cap.Live(run, paths, digests, {"target": target, "paths": paths, "digests": digests,
                                        "functional_sha256": sha256(run.evidence / "evidence.json")})
    operations, nodes = procedure(io, plan_path, run.attempt_id)
    io.finish(operations, nodes)
    run.passed(io.details)


def gate_details(root, report_path):
    return cap.gate_details(root, report_path, cap.HA_OPERATIONS)


def verify_domain(root, domain, files, configs, artifacts, candidates):
    """Bind an HA capacity gate to one replayed qualifying nine-process run."""
    import verify_release_acceptance as acceptance

    root = Path(root).resolve(strict=True)
    report_path = cap.locate_report(root, domain)
    located = {**domain, "details": {"report": owned.ref(root, report_path)}}
    facts = domain_run.verify_run(root, located, files, configs, KIND, RUNNER, MODULES)
    report, custody = facts["report"], facts["custody"]
    require(report["target"] == acceptance.REFERENCE and report["invocation"]["parameters"] == PARAMETERS
            and domain["artifacts"] == {}, "HA capacity ran on another platform or contract")
    details = report["details"]
    target = domain["id"].split(":", 1)[1]
    require(details["digests"] == cap.admitted_digests(root, domain, candidates)
            and details["target"] == report["target"]
            and details["functional_sha256"] == candidates[target]["primary"]["functional"]["sha256"],
            "capacity run used other executables or functional evidence")
    replay = cap.Replay(facts, details["paths"], details["digests"])
    operations, nodes = procedure(replay, None, report["attempt_id"])
    rows = replay.finish(operations, nodes)
    replay.done()
    require(domain["topology"] == report["topology"] and len(report["topology"]) == 9,
            "gate topology differs from the nine original daemons")
    cap.verify_samples(rows, replay, facts["receipts"])
    cap.verify_renewals(facts, details)
    cap.verify_scenarios(facts, operations)
    require(domain["details"] == gate_details(root, custody / "report.json"),
            "capacity gate details differ from the original run")
    return facts["evidence"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("evidence", "journal", "output", "plan"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--attempt-id", required=True)
    args = parser.parse_args()
    plan_path = args.plan.resolve(strict=True)
    import package_release as package
    _, _, target, _ = package.verify_evidence(args.evidence.resolve(strict=True))
    qualification = cap.qualification(owned.read(plan_path), target)
    with domain_run.Run(KIND, RUNNER, MODULES, args.evidence, args.output, args.journal, args.attempt_id,
                        PARAMETERS, qualification) as run:
        execute(run, plan_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
