#!/usr/bin/env python3
"""Qualify standalone capacity on an installed native node with an incompressible corpus.

The operator installs one standalone node with explicit memory, disk, scratch
and reservation limits, a filesystem and an S3 backup destination, and names
its configuration and client profiles in a capacity plan. This runner measures
the corpus with the frozen driver, loads it through the native service, and
then runs every capacity operation in order: a snapshot covering the corpus,
a completed compaction cycle, a restart, filesystem and S3 backups, retained
read pressure, and stopped restores from each backup. The exact driver
verifies every document after each operation. ``verify_domain`` replays the
same procedure over the retained run.
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
        raise SystemExit("standalone capacity requires Python -I -B -S")
    if any(p.name == "__pycache__" or p.suffix in {".pyc", ".pyo"}
           or (p.suffix == ".py" and p.is_symlink()) for p in scripts.rglob("*")):
        raise SystemExit("standalone capacity requires source-only Python imports")
    sys.path.insert(0, str(scripts))

import capacity_domain as cap
import domain_run
from domain_run import require
import repeatable_assembly as owned
from release_gate import sha256

KIND = "capacity-standalone"
RUNNER = "scripts/run_capacity_standalone.py"
MODULES = (cap.LIBRARY,)
PARAMETERS = cap.PARAMETERS
NODE = "node"
PLAN_FIELDS = {"schema", "kind", "configuration", "data_profile", "operator_profile", "control_profile",
               "tenant_limits", "corpus", "churn", "pressure", "compaction_growth_percent",
               "filesystem_destination", "s3_destination"}


def check_plan(plan):
    cap.exact(plan, PLAN_FIELDS, "standalone capacity plan")
    corpus = cap.common_plan(plan, KIND)
    for key in ("configuration", "data_profile", "operator_profile", "control_profile", "tenant_limits"):
        cap.absolute(plan[key], key)
    return corpus


def check_installation(config, profiles, limits, plan, corpus):
    """One standalone tenant whose profiles address this installation only."""
    require(config.get("mode") == "standalone" and not config.get("replication")
            and len(config.get("tenants", [])) == 1, "capacity installation is not one standalone tenant")
    tenant = config["tenants"][0]
    name, incarnation = tenant["tenant"], tenant["incarnation"]
    cap.destinations(config, plan)
    native_port = int(config["native"]["listen"].rsplit(":", 1)[1])
    admin_port = int(config["admin"]["listen"].rsplit(":", 1)[1])
    for role in ("data", "operator"):
        profile = profiles[role]
        require(profile["tenant"] == name and profile["resource"] == {"kind": "database", "incarnation": incarnation},
                role + " profile addresses another tenant generation")
    require(profiles["control"]["resource"]["kind"] == "control", "control profile is not a Control credential")
    require(int(profiles["data"]["native_endpoint"].rsplit(":", 1)[1].rstrip("/")) == native_port,
            "data profile addresses another native listener")
    members = list(profiles["operator"]["administrative_members"].values())
    require(len(members) == 1 and int(members[0]["endpoint"].rsplit(":", 1)[1].rstrip("/")) == admin_port,
            "operator profile addresses another administrative listener")
    cap.check_corpus_limits(limits, corpus)
    return name, incarnation, tenant


def status_value(io, step, ctl, operator, status_path):
    value = cap.parse_json(io.command(step, [ctl, "--profile", operator, "manage", status_path]), "status")
    require(value["mode"] == "standalone" and value["observation"] == "local_committed_state"
            and type(value["raft_applied_index"]) is int and type(value["revision"]) is int,
            "management status is not the standalone tenant's committed state")
    return value


def procedure(io, plan_path, attempt):
    """Every capacity operation, in order; identical live and in replay."""
    plan = owned.read(io.config("capacity-plan", plan_path))
    corpus = check_plan(plan)
    config = owned.read(io.config("installation", plan["configuration"]))
    profiles = {role: owned.read(io.config(role + "-profile", plan[role + "_profile"]))
                for role in ("data", "operator", "control")}
    tenant_limits = owned.read(io.config("tenant-limits", plan["tenant_limits"]))
    tenant, incarnation, installed = check_installation(config, profiles, tenant_limits, plan, corpus)
    limits = cap.admitted_limits([config], cap.corpus_bytes(corpus))
    io.record(("limits",), limits)
    io.record(("corpus",), corpus)
    paths = io.paths
    kasumid, ctl = paths["kasumid"], paths["kasumictl"]
    operator, control, data = plan["operator_profile"], plan["control_profile"], plan["data_profile"]
    nodes = {NODE: cap.storage_roots(config)}
    driver = cap.Corpus(io, corpus)
    driver.measure(profiles["data"])

    serve = [kasumid, "serve", plan["configuration"],
             "--storage-compaction-growth-percent=" + str(plan["compaction_growth_percent"])]
    ready = [ctl, "--profile", control, "ready"]
    io.start(nodes)
    io.serve(NODE, serve, node=NODE)
    io.serve("renewal-control", cap.renewal_argv(io, control), interactive=True)
    io.poll("startup-ready", ready, cap.ready_output, cap.READY_POLLS)
    io.enter("measured")
    io.serve("renewal", cap.renewal_argv(io, data), interactive=True)
    io.serve("renewal-operator", cap.renewal_argv(io, operator), interactive=True)
    status_path = io.input("inputs/status.json", {"operation": "status"})
    io.command("set-limits", [ctl, "--profile", operator, "set-limits", plan["tenant_limits"]])
    io.command("create-corpus-collection", [ctl, "--profile", operator, "create-collection",
                                            io.input("inputs/corpus-collection.json",
                                                     cap.corpus_collection(corpus["collection"]))])
    io.command("create-churn-collection", [ctl, "--profile", operator, "create-collection",
                                           io.input("inputs/churn-collection.json", cap.churn_collection())])
    driver.run("load", "load", "corpus-load", profiles["data"], incarnation)
    loaded = status_value(io, "corpus-status", ctl, operator, status_path)
    require(loaded["incarnation"] == incarnation, "corpus loaded into another generation")
    corpus_index, corpus_revision = loaded["raft_applied_index"], loaded["revision"]
    io.record(("corpus_commit",), {"index": corpus_index, "revision": corpus_revision})
    rounds = plan["churn"]["rounds"]

    def metrics(step):
        return cap.storage(cap.gauges(io.command(step, [ctl, "--profile", control, "metrics"]).decode()), tenant)

    def verify(operation, profile, generation):
        driver.run(operation + "-verify", "verify", "ops/" + operation, profile, generation, scenario=operation)

    # A local snapshot publication whose index covers every corpus commit.
    io.mark("snapshot", "started")
    for index in range(rounds + 1):
        status = status_value(io, f"snapshot-status-{index}", ctl, operator, status_path)
        covered = status["raft_snapshot_index"] is not None and status["raft_snapshot_index"] >= corpus_index
        if covered:
            break
        require(index < rounds, "no snapshot publication covered the corpus within the churn bound")
        cap.churn(io, attempt, "snapshot", index, plan, data, ctl)
    io.record(("operations", "snapshot", "snapshot_index"), status["raft_snapshot_index"])
    verify("snapshot", profiles["data"], incarnation)
    io.mark("snapshot", "finished")

    # A storage compaction cycle that starts and completes with the corpus present.
    io.mark("compaction", "started")
    before = metrics("compaction-metrics-0")
    for index in range(rounds):
        cap.churn(io, attempt, "compaction", index, plan, data, ctl)
        after = metrics(f"compaction-metrics-{index + 1}")
        if cap.compacted(before, after):
            break
    else:
        raise ValueError("no complete compaction cycle within the churn bound")
    io.record(("operations", "compaction", "storage"), {"before": before, "after": after})
    verify("compaction", profiles["data"], incarnation)
    io.mark("compaction", "finished")

    # An orderly stop and physical reopen of the same installation.
    io.mark("restart", "started")
    io.stop(NODE)
    io.serve(NODE, serve, node=NODE)
    io.poll("restart-ready", ready, cap.ready_output, cap.READY_POLLS)
    reopened = status_value(io, "restart-status", ctl, operator, status_path)
    require(reopened["incarnation"] == incarnation and reopened["revision"] >= corpus_revision,
            "reopened installation lost the committed corpus generation")
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

    # Concurrent retained readers against the corpus while churn forces maintenance.
    operation = "retained-read-pressure"
    io.mark(operation, "started")
    pressure = plan["pressure"]
    readers = {f"pressure-reader-{r}": cap.pressure_requests(corpus, pressure, r) for r in range(pressure["readers"])}
    sessions = {name: ([ctl, "--profile", data, "session"], requests) for name, requests in readers.items()}
    churn = cap.churn_requests(attempt, operation, 0, cap.CHURN_REQUESTS, plan["churn"]["pad_bytes"])
    sessions["pressure-churn"] = ([ctl, "--profile", data, "session"], churn)
    observed = []

    def during(index):
        values = cap.gauges(io.command(f"pressure-metrics-{index}", [ctl, "--profile", control, "metrics"]).decode())
        observed.append({"reserved_bytes": values.get("kasumi_admission_reserved_bytes"),
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

    # Stopped restores of each original checkpoint into a new generation.
    # All remaining restores use the original operator's principal under
    # exclusive local recovery. Its old database bearer ends with this generation.
    io.end("renewal-operator")
    active = incarnation
    for operation, source, alias in (("filesystem-restore", "filesystem-backup", plan["filesystem_destination"]),
                                     ("s3-restore", "s3-backup", plan["s3_destination"])):
        io.mark(operation, "started")
        io.end("renewal")
        io.end("renewal-control")
        io.stop(NODE)
        identifier = cap.operation_uuid(attempt, operation)
        target = cap.operation_uuid(attempt, operation + "/target")
        request = io.input("ops/" + operation + "/request.json", {
            "operation_id": identifier, "tenant": tenant, "expected_active_incarnation": active,
            "target_incarnation": target, "checkpoint": checkpoints[source],
            "source_purpose": {"kind": "Standalone", "installation_id": installed["serving"]["installation_id"],
                               "tenant": tenant, "incarnation": incarnation},
            "source_keys": installed["keys"], "source_principal": profiles["operator"]["principal"],
            "destination": alias, "phase_timeout_ms": 600000})
        io.command(operation + "-start", [kasumid, "local-recovery", "start", plan["configuration"], request],
                   cap.MAINTENANCE_TIMEOUT, node=NODE)
        status = cap.parse_json(io.command(operation + "-status", [kasumid, "local-recovery", "status",
                                                                   plan["configuration"], identifier]),
                                "restore status")
        require(status["phase"] == "finished" and status["last_failure"] is None
                and status["request"]["operation_id"] == identifier
                and status["request"]["target_incarnation"] == target
                and status["request"]["checkpoint"] == checkpoints[source],
                "stopped restore did not activate the original checkpoint")
        restored = io.retain(operation + "-profile", status["client_profile"])
        require(restored["tenant"] == tenant and restored["resource"] == {"kind": "database", "incarnation": target},
                "restored client profile addresses another generation")
        io.serve(NODE, serve, node=NODE)
        io.serve("renewal-control", cap.renewal_argv(io, control), interactive=True)
        io.poll(operation + "-ready", ready, cap.ready_output, cap.READY_POLLS)
        io.serve("renewal", cap.renewal_argv(io, status["client_profile"]), interactive=True)
        verify(operation, restored, target)
        active = target
        io.mark(operation, "finished")

    io.enter("drain")
    io.end("renewal")
    io.end("renewal-control")
    io.stop(NODE)
    return cap.OPERATIONS, [NODE]


def execute(run, plan_path):
    target = run.bind()
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
    return cap.gate_details(root, report_path, cap.OPERATIONS)


def verify_domain(root, domain, files, configs, artifacts, candidates):
    """Bind a standalone capacity gate to one replayed qualifying run."""
    import verify_release_acceptance as acceptance

    root = Path(root).resolve(strict=True)
    report_path = cap.locate_report(root, domain)
    located = {**domain, "details": {"report": owned.ref(root, report_path)}}
    facts = domain_run.verify_run(root, located, files, configs, KIND, RUNNER, MODULES)
    report, custody = facts["report"], facts["custody"]
    require(report["target"] == acceptance.REFERENCE and report["invocation"]["parameters"] == PARAMETERS
            and domain["topology"] == report["topology"] == [] and domain["artifacts"] == {},
            "standalone capacity ran on another platform, contract or topology")
    details = report["details"]
    digests = details["digests"]
    target = domain["id"].split(":", 1)[1]
    require(digests == cap.admitted_digests(root, domain, candidates)
            and details["target"] == report["target"]
            and details["functional_sha256"] == candidates[target]["primary"]["functional"]["sha256"],
            "capacity run used other executables or functional evidence")
    replay = cap.Replay(facts, details["paths"], digests)
    operations, nodes = procedure(replay, None, report["attempt_id"])
    rows = replay.finish(operations, nodes)
    replay.done()
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
