"""Run and replay protected observations on an installed nine-process HA topology."""
import argparse
import os
from pathlib import Path
import sys
import time
from urllib.parse import urlsplit

if __name__ == "__main__":
    scripts = Path(__file__).resolve(strict=True).parent
    if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode
            and sys.pycache_prefix is None and "PYTHONPYCACHEPREFIX" not in os.environ):
        raise SystemExit("installed observations require Python -I -B -S")
    if any(p.name == "__pycache__" or p.suffix in (".pyc", ".pyo") or (p.suffix == ".py" and p.is_symlink())
           for p in scripts.rglob("*")):
        raise SystemExit("installed observations require source-only Python imports")
    sys.path.insert(0, str(scripts))

import domain_run
from domain_run import require
import installed_observation as io
import process_ha_topology as topology
import repeatable_assembly as owned
import run_concurrency as ha
import run_correctness as libtest
import run_observability_probes as probes
import verify_release_acceptance as acceptance

KIND = "observability"
RUNNER = "scripts/run_installed_observability.py"
MODULES = ("scripts/run_observability_probes.py", "scripts/installed_observation.py", "scripts/run_correctness.py",
           "scripts/run_concurrency.py", "scripts/concurrency_workloads.py")
TIMEOUT = 1200
ROLES = ("observer", "operator", "control")
NATIVE = {"readiness": "more-than-128-groups", "protection": "protected-health", "backlog": "archive-backlog",
          "authority": "authority-health", "recovery": "recovery-phases", "backup": "backup-outcomes",
          "logs": "structured-logs"}


def native(evidence, functional, original, command):
    targets = libtest.artifacts(evidence, functional, {k: [("kasumi-server", "kasumi_server", leaf)]
                                                       for k, leaf in probes.CASES.items()})
    relative, digest = targets["kasumi-server", "kasumi_server"]
    binary = str(original / "target" / relative)
    listing = libtest.test_list(command("native-list", [binary, "--list", "--format", "terse"], digest, ()))
    for name, leaf in probes.CASES.items():
        case = libtest.resolve(listing, leaf)
        raw = command("native-" + name, [binary, "--exact", case, "--test-threads=1", "--format", "pretty",
                                         "--show-output"], digest, (NATIVE[name],))
        libtest.check_pass(raw, case, len(listing))
        probes.verified(name, raw)


def check_inputs(nodes, configs, certificates, custody, profiles, plan, request):
    certs = {}
    for node in nodes:
        cfg = configs[node["id"]]
        if node["role"] == "authority":
            continue
        cert = topology.certificate(owned.check_ref(custody, certificates[node["id"]]["admin"]))
        certs[node["id"]] = cert["leaf_sha256"], int(cfg["admin"]["listen"].rsplit(":", 1)[1])
    tenant, voters, count = io.installed_inputs(plan, profiles, configs, nodes, certs, request)
    incarnation = profiles["operator"]["resource"]["incarnation"]
    controls = ha.role_bindings(configs, nodes, certificates, custody, tenant, incarnation, voters)
    observer = profiles["observer"]
    operator = profiles["operator"]
    member, = operator["administrative_members"]
    cfg = next(cfg for cfg in configs.values() if cfg["replication"]["node_id"] == int(member))
    observed_id = next(n["id"] for n in nodes if n["node_id"] == int(member))
    native_cert = owned.check_ref(custody, certificates[observed_id]["native"])
    native_pin = topology.certificate(native_cert)["leaf_sha256"]
    require(operator["native_certificate_pin"] == native_pin and urlsplit(operator["native_endpoint"]).port ==
            int(cfg["native"]["listen"].rsplit(":", 1)[1]) and observer["resource"] == profiles["control"]["resource"],
            "observer or data client addresses another actual installation")
    return tenant, voters, count, controls


def live(paths, plan, request, original, custody, inputs, command, settled):
    tenant, voters, count, controls = inputs
    ctl = [paths["kasumictl"], "--profile"]
    observer, operator, control = (plan[role + "_profile"] for role in ROLES)
    server = paths["kasumid"]
    def run(step, args, *scenarios):
        return command(step, args, None, scenarios)
    def query(step, args, *scenarios):
        return io.document(run(step, args, *scenarios))
    health = query("installed-health", [*ctl, observer, "health"], "protected-health")
    require(health["lifecycle"] == "serving", "observed daemon is not serving")
    # A tenant operator may use its own backup management endpoint. The same
    # credential must be denied protected Control observations on that endpoint.
    denied = io.document(command("tenant-denied", [*ctl, operator, "ready"], None, ("protected-readiness",), 1))
    require(denied == {"error":"protected node observation unavailable", "reason":"forbidden"},
            "non-Control observation did not fail with a protected denial")
    health = query("installed-before", [*ctl, observer, "ready"], "protected-readiness")
    prior = io.coverage(health, count, tenant)
    first = query("data-leader", [*ctl, operator, "manage", str(original / "status.json")], "authority-health")
    require(first["node_id"] == first["leader"] and first["leader"] in voters and first["control_leader"] in controls
            and first["raft_voters"] == voters, "live data does not use its own three voters and separate Control quorum")
    response = query("data-membership", [*ctl, operator, "manage", str(original / "membership.json")],
                     "membership-maintenance")
    require(response == {"changed": True, "publish_control_route_required": True}, "membership change not committed")
    actual = settled("membership-ready", [*ctl, observer, "ready"],
                     lambda value: (value["readiness_coverage"]["healthy_groups"] == count and
                                    io.coverage(value, count, tenant)["actual_membership"] > prior["actual_membership"]))
    latest = query("installed-after", [*ctl, observer, "ready"], "membership-epoch-coverage", "more-than-128-groups")
    metrics = run("installed-metrics", [*ctl, observer, "metrics"], "protected-metrics", "physical-capacity").decode()
    epoch = io.measurements(latest, metrics, count, tenant)
    require(io.coverage(actual, count, tenant) == epoch, "measured protected epoch changed")
    current = query("committed-membership", [*ctl, operator, "manage", str(original / "status.json")],
                    "membership-maintenance")
    require(current["raft_voters"] == voters and current["node_id"] == first["node_id"] == current["leader"]
            and current["control_leader"] in controls and current["raft_membership_index"] > first["raft_applied_index"],
            "membership result does not match the applied private Raft status")
    group, = (g for g in latest["groups"] if g["tenant"] == tenant)
    due = acceptance.uint(group["retention"]["archive_backlog_bytes"], "observed tenant backlog")
    require(group["audit_maintenance"] is not None and probes.gauge(metrics, "service_audit_archive_backlog_bytes") >= 0,
            "the protected release omits audit retention observations")
    before = query("control-backup-before", [*ctl, control, "health"], "backup-outcomes")["backup_sessions"]
    for field in ("claimed_without_terminal", "completed", "aborted", "last_binding_revision"):
        acceptance.uint(before[field], "pre-backup Control ledger " + field)
    created = query("backup-create", [server, "backup", "create", operator, plan["destination"],
                                     str(original / "checkpoint.json")])
    session = io.uuid_string(created["session_id"])
    result = query("backup-status", [server, "backup", "status", operator, plan["destination"], session], "backup-outcomes")
    verified = query("backup-verify", [server, "backup", "verify", operator, plan["destination"], session], "backup-outcomes")
    checkpoint = owned.read(custody / "checkpoint.json")
    require(created["checkpoint"] == str(original / "checkpoint.json") and verified == checkpoint == result["outcome"]["checkpoint"]
            and result["intent"]["session_id"] == checkpoint["backup_id"] == session and result["outcome"]["outcome"] == "complete"
            and result["intent"]["tenant"] == checkpoint["tenant"] == tenant and result["intent"]["revision"] == checkpoint["revision"]
            and result["intent"]["source_incarnation"] == checkpoint["source_incarnation"] == request["source_incarnation"],
            "protected backup resolution and verified checkpoint differ")
    for digest in ("key_lineage_digest", "manifest_ciphertext_sha256", "resident_sha256"):
        acceptance.checksum(checkpoint[digest])
    acceptance.checksum(result["outcome"]["intent_ciphertext_sha256"])
    acceptance.checksum(result["source_purpose_sha256"])
    def committed_backup(value):
        sessions = value["backup_sessions"]
        return (sessions is not None and sessions["completed"] == before["completed"] + 1
                and sessions["aborted"] == before["aborted"]
                and sessions["claimed_without_terminal"] == before["claimed_without_terminal"]
                and sessions["last_binding_revision"] > before["last_binding_revision"])
    settled("control-backup-after", [*ctl, control, "health"], committed_backup)
    counters = run("control-backup-metrics", [*ctl, control, "metrics"], "backup-outcomes").decode().splitlines()
    for state in ("claimed_without_terminal", "completed", "aborted"):
        count = before[state] + int(state == "completed")
        require(counters.count(f'kasumi_control_backup_sessions{{state="{state}"}} {count}') == 1,
                "protected metric differs from the selected Control backup ledger")

    identifier = io.uuid_string(request["operation_id"])
    committed = query("recovery-start", [server, "control-recovery", "start", control, plan["recovery_request"],
                                         str(original / "recovery-attempt.json"), "60000"])
    require(committed["phase"] == "prepare" and committed["request"] == request,
            "observation run did not start at the original recovery preparation")
    previous = committed
    phases = []
    for index in range(512):
        suffix = f"{index:03d}"
        status = query("recovery-status-" + suffix,
                       [server, "control-recovery", "status", control, identifier, "60000"])
        projection = query("protected-recovery-" + suffix,
                           [*ctl, observer, "recovery-observation", identifier], "recovery-phases")
        io.recovery(request, committed, status, projection)
        require(status["updated_revision"] >= previous["updated_revision"],
                "protected recovery moved backwards")
        if not phases or phases[-1] != status["phase"]:
            phases.append(status["phase"])
        if status["phase"] == "finished":
            break
        require(not projection["terminal"], "recovery stopped before the target became active")
        previous = query("advance-recovery-" + suffix,
                         [server, "control-recovery", "resume", control, identifier, "1", "60000"])
        require(previous["request"] == request and previous["updated_revision"] >= status["updated_revision"],
                "recovery resume returned a different committed operation")
    require(phases[0] == "prepare" and phases[-1] == "finished" and "activate" in phases,
            "protected observations did not cover preparation, activation and terminal recovery")
    return {"groups":count, "membership_epoch":epoch, "covered_epoch":epoch, "coverage_complete":True,
            "backup_session":session, "recovery_operation":identifier, "recovery_phases":phases, "archive_backlog_bytes":due}


def poll(run, details, name, cmd, predicate):
    """Keep every readiness refusal and test only successful, decoded samples."""
    steps = details["polls"][name] = []
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        run.services.assert_alive()
        step = f"{name}-{len(steps):04d}"
        item = owned.run_owned(run.output, step, cmd, str(run.source), run.environment, 60)
        record = owned.read(owned.check_ref(run.output, item["receipt"]))
        steps.append(item)
        run.save()
        if record["exit_code"] == 0:
            value = io.document(owned.check_ref(run.output, item["stdout"]).read_bytes())
            if predicate(value):
                return value
        time.sleep(1)
    raise ValueError("installed readiness failed to settle: " + name)


def execute(run, topology_file, plan_file):
    target = run.bind()
    require(target == acceptance.REFERENCE, "installed HA observations require the native ARM64 reference")
    plan = owned.read(run.configuration("observability-plan", plan_file))
    fixed = {}
    def retain_input(label, path):
        retained = run.configuration(label, path)
        fixed[Path(path)] = owned.sha256(retained)
        return owned.read(retained)

    profiles = {role: retain_input(role + "-profile", plan[role + "_profile"]) for role in ROLES}
    request = retain_input("recovery-request", plan["recovery_request"])
    run.configuration("ha-topology", topology_file)
    admitted = topology.inspect(topology_file.resolve(strict=True), run.environment)
    nodes = admitted["nodes"]
    configs, certificates = {}, {}
    for node in nodes:
        key = node["id"]
        cfg = configs[key] = owned.read(run.configuration("node-" + key, node["config"]))
        files = {"replication":cfg["replication"]["listener"]["tls"]["certificate"],
                 "native":cfg["native"]["tls"]["certificate"]}
        if node["role"] != "authority":
            files["admin"] = cfg["admin"]["tls"]["certificate"]
        certificates[key] = {k:owned.retain(run.output, Path(p)) for k,p in files.items()}
        fixed.update({Path(p):certificates[key][k]["sha256"] for k,p in files.items()})
    inputs = check_inputs(nodes, configs, certificates, run.output, profiles, plan, request)
    owned_path = run.output / "topology-admission.json"
    domain_run.durable_json(owned_path, admitted)
    domain_run.durable_json(run.output / "membership.json", {"operation":"change_membership", "voters":inputs[1]})
    domain_run.durable_json(run.output / "status.json", {"operation":"status"})
    details = {"admission":owned.ref(run.output, owned_path), "certificates":certificates, "polls":{},
               "functional_sha256":owned.sha256(run.evidence / "evidence.json"), "phases":{}, "result":None}
    run.report["details"] = details
    run.save()
    def command(step, cmd, digest, scenarios, code=0):
        path = run.command(step, cmd, TIMEOUT, expected_exit=code)
        receipt = run.report["processes"][-1]
        require(receipt["executable"]["sha256"] == (digest or run.report["binaries"][Path(cmd[0]).name]),
                "an observation executed another binary")
        for scenario in scenarios:
            run.observe(scenario, step, receipt["receipt"], code, code)
        return path.read_bytes()
    run.environment["KASUMI_CAPTURE_PROTECTED_RESPONSES"] = "1"
    native(run.evidence, owned.read(run.evidence / "evidence.json"), run.evidence, command)
    del run.environment["KASUMI_CAPTURE_PROTECTED_RESPONSES"]
    services = ha.start_cluster(run, run.binary_paths, nodes)
    def wait(name, cmd, predicate):
        return poll(run, details, name, cmd, predicate)
    wait("startup", [run.binary_paths["kasumictl"], "--profile", plan["observer_profile"], "ready"],
         lambda r: r["ready"] is True and r["readiness_coverage"]["healthy_groups"] == inputs[2])
    topology.verify_unchanged(admitted, run.environment)
    require(all(owned.sha256(path) == digest for path, digest in fixed.items()), "installed observation inputs changed")
    details["phases"]["measured"] = services.enter("measured")
    details["result"] = live(run.binary_paths, plan, request, run.output, run.output, inputs, command, wait)
    details["phases"]["drain"] = services.enter("drain")
    topology.verify_unchanged(admitted, run.environment)
    require(all(owned.sha256(path) == digest for path, digest in fixed.items()), "installed observation inputs changed")
    for n in reversed(nodes):
        services.stop(n["id"])
    run.passed(details)


def original_command(custody, item, step, cmd, source, digest, timeout):
    record = owned.read(owned.check_ref(custody, item["receipt"]))
    stdout = owned.check_ref(custody, item.get("log", item.get("stdout")))
    stderr = owned.check_ref(custody, record["stderr"])
    require(owned.check_ref(custody, item["executable"]).is_file() and item["executable"]["sha256"] == digest
            and owned.check_ref(custody, item["receipt"]) == custody / step / "process.json"
            and stdout == custody / step / "stdout.log" == owned.check_ref(custody, record["stdout"])
            and stderr == custody / step / "stderr.log" and record["executable"] == {"path":cmd[0], "sha256":digest}
            and record["command"] == cmd and record["working_directory"] == str(source)
            and record["timeout_seconds"] == timeout and record["timed_out"] is False and record["error"] is None
            and record["received_signals"] == [] and record["outputs_stable"] is True
            and record["exit_code"] == record["process_exit_code"] == record["cleanup"]["process_returncode"]
            and record["cleanup"]["drained"] and all(record["cleanup"][key] == [] for key in
                    ("before","after","signals","errors")), "substituted or incomplete native observation: " + step)
    return record["exit_code"], stdout.read_bytes()


def verify_domain(root, domain, files, configs, artifacts, candidates):
    facts = domain_run.verify_run(root, domain, files, configs, KIND, RUNNER, MODULES)
    report, custody = facts["report"], facts["custody"]
    original, evidence = Path(report["custody_root"]), Path(report["evidence_root"])
    target = report["target"]
    details = report["details"]
    require(target == acceptance.REFERENCE and report["invocation"]["parameters"] == {} and not domain["artifacts"],
            "observations were taken with another native reference or parameters")
    owned.exact(details, {"admission","certificates","polls","functional_sha256","phases","result"}, "HA observations")
    primary = candidates[target]["primary"]["functional"]
    primary_path = acceptance.reference(root, primary)
    require(primary["sha256"] == details["functional_sha256"], "incorrect functional test executables")
    retained = {c["id"]:owned.check_ref(custody, c["file"]) for c in report["configurations"]}
    plan = owned.read(retained["observability-plan"])
    profiles = {role:owned.read(retained[role+"-profile"]) for role in ROLES}
    request = owned.read(retained["recovery-request"])
    admitted = owned.read(owned.check_ref(custody, details["admission"]))
    topology_plan = owned.read(retained["ha-topology"])
    nodes = admitted["nodes"]
    require(len(nodes) == 9 and admitted["plan_sha256"] == owned.sha256(retained["ha-topology"])
            and len({n["id"] for n in nodes}) == len({n["node_id"] for n in nodes}) == 9
            and topology_plan["nodes"] == [{k:n[k] for k in ("id","role","group","config")} for n in nodes]
            and set(retained) == {"observability-plan","ha-topology","recovery-request", *(r+"-profile" for r in ROLES),
                                  *("node-"+n["id"] for n in nodes)}, "unbound installed topology or plan")
    used, configs_by_node, members = set(), {}, []
    paths = {name:str(path) for name,path in topology_plan["binaries"].items()}
    processes = {p["id"]:p for p in report["processes"]}
    phases = details["phases"]
    require(0 <= phases["measured"] < phases["drain"] <= phases["measured"] + ha.PARAMETERS["measured_seconds_limit"],
            "observations have no measured interval")
    for node, member in zip(nodes, report["topology"], strict=True):
        key = node["id"]
        cfg = configs_by_node[key] = owned.read(retained["node-"+key])
        identifier = member["process_id"]
        selected = facts["receipts"][identifier]
        record = selected["record"]
        binary = "kasumi-authority" if node["role"] == "authority" else "kasumid"
        cert = topology.certificate(owned.check_ref(custody, details["certificates"][key]["replication"]))
        voter = cfg["replication"]["node_id"]
        roster = [n["node_id"] for n in nodes if n["role"] == node["role"]]
        peer, = (v for v in cfg["replication"]["peers"] if v["node_id"] == voter)
        require(voter == node["node_id"] and sorted(cfg["replication"]["initial_voters"]) == sorted(roster)
                and peer["certificate_pins"] == [cert["leaf_sha256"]] and cert["leaf_sha256"] == node["certificate"]["leaf_sha256"]
                and owned.sha256(retained["node-"+key]) == node["config_sha256"] and selected["service"]
                and identifier not in used and selected["disposition"] == "clean-stop"
                and record["command"] == [paths[binary],"serve",node["config"]] and record["name"] == key
                and record["executable"]["sha256"] == domain["binaries"][binary]
                and record["phases"]["measured"] == phases["measured"] and record["phases"]["drain"] == phases["drain"]
                and record["started_elapsed_seconds"] <= phases["measured"] < phases["drain"] <= record["stop"]["elapsed_seconds"]
                and (node["role"] != "control" or (not cfg["tenants"] and not cfg.get("target_recovery"))),
                "native HA daemon or its original storage, identity, placement or lifetime differs")
        used.add(identifier)
        members.append({"id":key,"role":node["role"],"group":node["group"],"process_id":identifier,
                        "certificate_sha256":cert["leaf_sha256"]})
    require(members == domain["topology"] == report["topology"], "observations use another topology")
    acceptance.check_topology(members, domain["processes"], domain["binaries"], "required")
    inputs = check_inputs(nodes, configs_by_node, details["certificates"], custody, profiles, plan, request)
    paths["kasumictl"] = facts["receipts"]["installed-health"]["record"]["executable"]["path"]
    require(owned.read(custody/"membership.json") == {"operation":"change_membership","voters":inputs[1]}
            and owned.read(custody/"status.json") == {"operation":"status"}, "private management input changed")
    expected = {}
    def command(step, cmd, digest, scenarios, code=0):
        require(step not in used, "repeated command")
        rc, raw = original_command(custody, processes[step], step, cmd, evidence/"source",
                                   digest or domain["binaries"][Path(cmd[0]).name], TIMEOUT)
        require(rc == code, "original command returned an unexpected status")
        for scenario in scenarios:
            expected.setdefault(scenario, []).append((step, code))
        used.add(step)
        return raw
    seen_polls = set()
    def wait(name, cmd, predicate):
        items = details["polls"][name]
        require(name not in seen_polls and 0 < len(items) <= 601, "missing or duplicated readiness polling")
        seen_polls.add(name)
        for i,item in enumerate(items):
            step = f"{name}-{i:04d}"
            rc, raw = original_command(custody,item,step,cmd,evidence/"source",domain["binaries"]["kasumictl"],60)
            if rc == 0 and predicate(io.document(raw)):
                require(i + 1 == len(items), "successful readiness poll was ignored")
                return io.document(raw)
        raise ValueError("no successful original readiness sample")
    native(primary_path.parent, owned.read(primary_path), evidence, command)
    wait("startup", [paths["kasumictl"],"--profile",plan["observer_profile"],"ready"],
         lambda r:r["ready"] is True and r["readiness_coverage"]["healthy_groups"] == inputs[2])
    result = live(paths, plan, request, original, custody, inputs, command, wait)
    actual = {key:[(row["step"],row["expected_exit"]) for row in rows] for key,rows in facts["scenarios"].items()}
    require(expected == actual and set(expected) == acceptance.SCENARIOS[KIND] and used == set(processes)
            and seen_polls == set(details["polls"]) and details["result"] == result and
            domain["details"] == gate_details(result, domain["details"]["report"]),
            "observability verdict or original operation roster differs")
    return facts["evidence"]


def gate_details(result, report):
    return {key:result[key] for key in ("groups","membership_epoch","covered_epoch","coverage_complete")} | {"report":report}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("evidence","output","journal","topology","plan"):
        parser.add_argument("--"+name, type=Path, required=True)
    parser.add_argument("--attempt-id", required=True)
    args = parser.parse_args()
    with domain_run.Run(KIND, RUNNER, MODULES, args.evidence, args.output, args.journal,
                        args.attempt_id, {}, domain_run.QUALIFYING) as run:
        execute(run, args.topology, args.plan)
