"""Measure actual data and maintenance operations against the nine installed HA processes."""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import sys
import threading
import time
from urllib.parse import urlsplit

if __name__ == "__main__":
    scripts = Path(__file__).resolve(strict=True).parent
    if (sys.pycache_prefix is not None or "PYTHONPYCACHEPREFIX" in os.environ
            or (scripts / "__pycache__").exists() or (scripts / "__pycache__").is_symlink()
            or any(p.suffix in {".pyc", ".pyo"} or (p.suffix == ".py" and p.is_symlink())
                   for p in scripts.rglob("*"))):
        raise SystemExit("concurrency runner requires source-only Python imports")
    sys.path.insert(0, str(scripts))

import concurrency_workloads as work
import domain_run
from domain_run import require
import process_ha_topology as topology
import repeatable_assembly as owned

KIND = "concurrency"
RUNNER = "scripts/run_concurrency.py"
MODULES = ("scripts/concurrency_workloads.py",)
PARAMETERS = {"workers": 2, "measured_seconds_limit": 21600, "startup_seconds": 1800,
              "drain_seconds": 1800, "counts": {k: list(v) for k, v in work.COUNTS.items()}}


def plan_data(plan, profiles, nodes, pins):
    owned.exact(plan, {"schema", "data_profile", "operator_profile", "collection", "destination"}, "concurrency plan")
    require(plan["schema"] == "kasumi-concurrency-plan-v1" and all(isinstance(plan[k], str)
            and plan[k] for k in ("collection", "destination")) and "/" not in plan["collection"]
            and "~" not in plan["collection"], "invalid collection or backup destination")
    data = [config for config in nodes if config.get("tenants")]
    require(len(data) == 3, "three data nodes required")
    voters = sorted(config["replication"]["node_id"] for config in data)
    tenant = profiles["data"]["tenant"]
    incarnation = profiles["data"]["resource"]["incarnation"]
    for config in data:
        require(any(t["tenant"] == tenant and t["incarnation"] == incarnation for t in config["tenants"]),
                "tenant enrollment differs across original voters")
    endpoints = {(int(c["native"]["listen"].rsplit(":", 1)[-1]), pins[c["replication"]["node_id"]]["native"])
                 for c in data}
    for role, profile in profiles.items():
        endpoint = urlsplit(profile["native_endpoint"])
        require(profile["tenant"] == tenant and profile["resource"] == {"kind": "database", "incarnation": incarnation}
                and endpoint.scheme == "https" and (endpoint.port, profile["native_certificate_pin"]) in endpoints
                and Path(plan[role + "_profile"]).is_absolute(), "client is outside admitted tenant and data endpoints")
        for member, bound in profile["administrative_members"].items():
            configs = [c for c in data if str(c["replication"]["node_id"]) == member]
            require(len(configs) == 1 and urlsplit(bound["endpoint"]).scheme == "https"
                    and urlsplit(bound["endpoint"]).port == int(configs[0]["admin"]["listen"].rsplit(":", 1)[-1])
                    and bound["certificate_pins"] == [pins[int(member)]["admin"]],
                    "administrative member trust differs from enrolled data endpoint")
        if role == "operator":
            require(len(profile["administrative_members"]) == 1, "select one enrolled data leader for management")
    return voters, tenant, incarnation


def role_bindings(configurations, nodes, certificates, custody, tenant, incarnation, voters):
    issuers = {n["node_id"]: configurations[n["id"]] for n in nodes if n["role"] == "authority"}
    controls = {n["node_id"] for n in nodes if n["role"] == "control"}
    data = {n["node_id"]: n for n in nodes if n["role"] == "data"}
    for node in nodes:
        cfg = configurations[node["id"]]
        if node["role"] == "control":
            routes = cfg["control"]["remote_data"]
            require(routes["tenants"][tenant] == {"mode":"replicated", "incarnation":incarnation, "voters":voters}
                    and all(data[v]["certificate"]["leaf_sha256"] in routes["nodes"][str(v)]["certificate_pins"]
                            for v in voters), "dedicated Control route does not name the measured data population")
        if node["role"] == "data":
            serving = next(t["serving"] for t in cfg["tenants"] if t["tenant"] == tenant)
            require(serving["kind"] == "independent", "replicated tenant has no independent issuer")
            authority = cfg["serving_authorities"][serving["authority"]]
            for other in nodes:
                if other["role"] != "authority":
                    continue
                voter = other["node_id"]
                issuer = issuers[voter]
                partition = str(issuer["installation"]["partition"])
                endpoints = authority["endpoints"][partition]
                profile = endpoints[str(voter)]
                leaf = topology.certificate(owned.check_ref(custody, certificates[other["id"]]["native"]))["leaf_sha256"]
                require(authority["manifest"] == issuer["installation"]["manifest"] and set(map(int, endpoints)) == set(issuers)
                        and profile["certificate_pins"] == [leaf] and urlsplit(profile["endpoint"]).scheme == "https"
                        and urlsplit(profile["endpoint"]).port == int(issuer["native"]["listen"].rsplit(":",1)[-1]),
                        "data tenant issuer endpoints differ from the three owned native authority processes")
    return controls


def collection(plan):
    return {"name": plan["collection"], "retention_class": "operational", "write_mode": "mutable",
            "schema": {"type": "object", "required": ["step", "sha256"], "additionalProperties": False,
                       "properties": {"step": {"type": "integer"}, "sha256": {"type": "string"}}},
            "indexes": [], "strict_read_audit": False}


def bind_command(path, plan, name, directory, backup_id=None):
    ctl = path["kasumictl"]
    if name == "create-collection":
        return [ctl, "--profile", plan["operator_profile"], "create-collection", str(directory / "collection.json")]
    if name == "session":
        return [ctl, "--profile", plan["data_profile"], "session"]
    if name == "backup-writes":
        return [path["kasumid"], "backup", "create", plan["operator_profile"], plan["destination"],
                str(directory / "checkpoint.json")]
    if name == "verify-backup":
        return [path["kasumid"], "backup", "verify", plan["operator_profile"], plan["destination"], backup_id]
    request = "membership.json" if name == "membership-writes" else "status.json"
    return [ctl, "--profile", plan["operator_profile"], "manage", str(directory / request)]


def ref(root, file):
    return owned.ref(root, root / file)


def lines(path):
    return [json.loads(line) for line in path.read_bytes().splitlines()]


def write_lines(path, rows):
    with path.open("xb") as out:
        for row in rows:
            out.write((json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode())
        out.flush()
        os.fsync(out.fileno())


class Session:
    def __init__(self, run, scenario, role, plan):
        self.run, self.scenario, self.role, self.plan = run, scenario, role, plan
        self.name = scenario + "-" + role
        command = bind_command(run.binary_paths, plan, "session", run.output)
        executable = topology.gate_process.executable_identity(command, run.source, run.environment)
        self.id = run.service(self.name, command, executable, interactive=True)
        self.witness = None
        self.log = run.output / "services" / (self.id + ".log")
        self.timing = run.output / (self.name + ".jsonl")

    def loop(self, count, start=None):
        if start is not None:
            require(start.wait(180), "second worker never dispatched its operation")
        with self.log.open("rb") as replies, self.timing.open("xb") as times:
            for i in range(count):
                index = 0 if self.role == "seed" else i + 1
                request = work.request(self.run.attempt_id, self.scenario, self.role, index, self.plan["collection"])
                before = self.witness.sample() if self.witness is not None else None
                sent = time.monotonic_ns()
                self.run.services.send(self.name, (json.dumps(request, separators=(",", ":")) + "\n").encode())
                prefix = b""
                until = time.monotonic() + 60
                while time.monotonic() < until:
                    prefix += replies.readline()
                    if prefix.endswith(b"\n"):
                        break
                    time.sleep(.001)
                end = time.monotonic_ns()
                if self.witness is not None and before is not None:
                    self.witness.complete(index, before)
                times.write((json.dumps({"id": index, "sent_ns": sent, "finished_ns": end}) + "\n").encode())
                times.flush()
                require(prefix.endswith(b"\n"), "native client did not answer before its deadline")
                work.reply_result(prefix, index)
            os.fsync(times.fileno())


def start_cluster(run, path, nodes):
    services = run.start_services(PARAMETERS["measured_seconds_limit"], PARAMETERS["startup_seconds"], PARAMETERS["drain_seconds"])
    for node in nodes:
        exe = node["executable"]
        require(exe["path"] == path["kasumi-authority" if node["role"] == "authority" else "kasumid"],
                "HA node selects another executable")
        identifier = run.service(node["id"], [exe["path"], "serve", node["config"]], exe)
        run.report["topology"].append({"id": node["id"], "role": node["role"], "group": node["group"],
            "certificate_sha256": node["certificate"]["leaf_sha256"], "process_id": identifier})
    return services


class LiveMaintenance:
    """Retain Linux's own process identity on both sides of one complete write."""
    def __init__(self, directory):
        self.directory = directory
        self.pid = None
        self.saved = False

    def sample(self):
        if self.saved or self.pid is None:
            return None
        try:
            stat = (Path("/proc") / str(self.pid) / "stat").read_text().strip()
        except FileNotFoundError:
            return None
        if stat.rsplit(")", 1)[1].split()[0] in ("Z", "X", "x"):
            return None
        return {"stat": stat, "time_ns": time.monotonic_ns()}

    def complete(self, index, before):
        after = self.sample()
        if after is not None:
            domain_run.durable_json(self.directory / "maintenance-live.json",
                                    {"write_id": index, "before": before, "after": after})
            self.saved = True


def live_write(directory, rows, original):
    proof = owned.read(directory / "maintenance-live.json")
    identifier = proof["write_id"]
    require(type(identifier) is int and 1 <= identifier <= len(rows["write"]),
            "missing native write inside the original maintenance process lifetime")
    row = rows["write"][identifier - 1]
    interval, pid = rows["maintenance"][0], original["process_group"]
    for sample in (proof["before"], proof["after"]):
        stat = sample["stat"]
        fields = stat.rsplit(")", 1)[1].split()
        require(int(stat.split(" ", 1)[0]) == int(fields[2]) == pid
                and original["leader_birth"] == "linux:" + fields[19]
                and fields[0] not in ("Z", "X", "x") and type(sample["time_ns"]) is int,
                "live kernel observation selects another or exited process")
    require(row["id"] == identifier and interval["sent_ns"] <= proof["before"]["time_ns"]
            <= row["sent_ns"] < row["finished_ns"] <= proof["after"]["time_ns"] <= interval["finished_ns"],
            "the original maintenance process did not span the completed write")


def measure_command(run, scenario, command, start, directory, witness):
    timing = {}
    def observe(record):
        if not timing and record.get("process_group") and record.get("leader_birth"):
            timing.update(id=1, sent_ns=time.monotonic_ns())
            witness.pid = record["process_group"]
            start.set()
    def end(record):
        if timing:
            timing["finished_ns"] = time.monotonic_ns()
    try:
        item = owned.run_owned(run.output, scenario, command, str(run.source), run.environment, 1800,
                               observe_process=observe, before_cleanup=end)
    finally:
        start.set()
        domain_run.durable_json(directory / "maintenance-timing.json", timing)
    result = owned.read(owned.check_ref(run.output, item["receipt"]))
    run.report["processes"].append({"id": scenario, "receipt": item["receipt"], "log": item["stdout"],
                                    "executable": item["executable"]})
    run.save()
    require("finished_ns" in timing and result["exit_code"] == 0, "native maintenance failed")
    return owned.read(owned.check_ref(run.output, item["stdout"])), result


def pending(name, before, after):
    if after["raft_voters"] is None and after["raft_membership_index"] is None:
        return True
    key = {"snapshot-writes": "raft_snapshot_index", "membership-writes": "raft_membership_index"}.get(name)
    return key is not None and (after[key] is None or after[key] <= before["raft_applied_index"])


def checks(name, before, after, voters, incarnation, result=None, checkpoint=None, verify=None):
    for s in (before, after):
        work.raft_observation(s, incarnation, voters)
    require(before["node_id"] == after["node_id"], "measurements switched leaders")
    if name == "snapshot-writes":
        require(type(after["raft_snapshot_index"]) is int and after["raft_snapshot_index"] > before["raft_applied_index"],
                "no new physical Raft snapshot of the measured writes was published")
    elif name == "membership-writes":
        require(result == {"changed": True, "publish_control_route_required": True}
                and type(after["raft_membership_index"]) is int
                and after["raft_membership_index"] > before["raft_applied_index"],
                "no new committed three-voter membership entry")
    elif name == "backup-writes":
        require(verify == checkpoint and result["session_id"] == checkpoint["backup_id"]
                and checkpoint["source_incarnation"] == incarnation and type(checkpoint["revision"]) is int
                and before["revision"] <= checkpoint["revision"] <= after["revision"]
                and all(work.HASH.fullmatch(checkpoint[k]) for k in
                        ("resident_sha256", "manifest_ciphertext_sha256", "key_lineage_digest")),
                "backup does not resolve the original installed checkpoint")


def command_ref(run, step, command, *, scenario=None):
    return owned.read(run.command(step, command, 1800, scenario=scenario))


def execute(run, ha, plan_path):
    require(run.bind() == "aarch64-unknown-linux-gnu", "nine-process qualification requires native Linux ARM64")
    admitted = topology.inspect(ha.resolve(strict=True), run.environment)
    run.configuration("ha-topology", ha)
    plan = owned.read(run.configuration("concurrency-plan", plan_path))
    profiles = {role: owned.read(run.configuration(role + "-profile", plan[role + "_profile"]))
                for role in ("operator", "data")}
    nodes, pins, certificates, configurations = [], {}, {}, {}
    for n in admitted["nodes"]:
        c = owned.read(run.configuration("node-" + n["id"], n["config"]))
        configurations[n["id"]] = c
        if n["role"] == "authority":
            certificates[n["id"]] = {"native": owned.retain(run.output, Path(c["native"]["tls"]["certificate"]))}
        if n["role"] == "data":
            certificates[n["id"]] = {role: owned.retain(run.output, Path(c[role]["tls"]["certificate"]))
                                      for role in ("native", "admin")}
            pins[n["node_id"]] = {role: topology.certificate(owned.check_ref(run.output, file))["leaf_sha256"]
                                  for role, file in certificates[n["id"]].items()}
            nodes.append(c)
    voters, tenant, incarnation = plan_data(plan, profiles, nodes, pins)
    controls = role_bindings(configurations, admitted["nodes"], certificates, run.output, tenant, incarnation, voters)
    root = run.output
    domain_run.durable_json(root / "topology-admission.json", admitted)
    domain_run.durable_json(root / "status.json", {"operation": "status"})
    domain_run.durable_json(root / "collection.json", collection(plan))
    domain_run.durable_json(root / "membership.json", {"operation": "change_membership", "voters": voters})
    details = {"admission": ref(root, "topology-admission.json"), "certificates": certificates, "startup_polls": [], "workloads": {}, "phases": {}}
    run.report["details"] = details
    services = start_cluster(run, run.binary_paths, admitted["nodes"])
    status = bind_command(run.binary_paths, plan, "status", root)
    for i in range(1800):
        services.assert_alive()
        step = f"ready-{i:04d}"
        item = owned.run_owned(root, step, status, str(run.source), run.environment, 60)
        details["startup_polls"].append(item["receipt"])
        run.save()
        if owned.read(owned.check_ref(root, item["receipt"]))["exit_code"] == 0:
            observed = owned.read(owned.check_ref(root, item["stdout"]))
            if observed.get("node_id") == observed.get("leader") and observed.get("raft_voters") is not None:
                work.raft_observation(observed, incarnation, voters)
                require(observed["control_leader"] in controls, "tenant does not use its separately enrolled Control quorum")
                break
        time.sleep(1)
    else:
        raise ValueError("installed operator did not reach the original tenant leader")
    topology.verify_unchanged(admitted, run.environment)
    run.command("create-collection", bind_command(run.binary_paths, plan, "create-collection", root), 1800)
    details["clock_origin_ns"] = time.monotonic_ns() - round(services.elapsed() * 1e9)
    details["phases"]["measured"] = services.enter("measured")
    for name, counts in work.COUNTS.items():
        directory = root / ("case-" + name)
        directory.mkdir(mode=0o700)
        case = {"sessions": {}, "timings": {}, "after_status_steps": [], "samples": None}
        details["workloads"][name] = case
        run.save()
        def session(role):
            client = Session(run, name, role, plan)
            case["sessions"][role] = client.id
            run.save()
            return client
        seed = session("seed")
        seed.loop(1)
        services.end_input(seed.name)
        before = command_ref(run, name + "-before", status)
        writer = session("write")
        role = {"reads-writes": "read", "snapshot-writes": "snapshot"}.get(name)
        reader = session(role) if role else None
        started = threading.Event()
        result = proof = checkpoint = original_maintenance = None
        if reader is None:
            writer.witness = LiveMaintenance(directory)
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            job = pool.submit(writer.loop, counts[0], started)
            if reader:
                second = pool.submit(reader.loop, counts[1], started)
                started.set()
                second.result()
            else:
                cmd = bind_command(run.binary_paths, plan, name, directory if name == "backup-writes" else root)
                result, original_maintenance = measure_command(run, name, cmd, started, directory, writer.witness)
            job.result()
        for client in [writer] + ([reader] if reader else []):
            services.end_input(client.name)
        if name == "backup-writes":
            checkpoint = owned.read(directory / "checkpoint.json")
            proof = command_ref(run, "verify-backup", bind_command(run.binary_paths, plan, "verify-backup", root, result["session_id"]))
        until = time.monotonic() + 120
        for poll in range(120):
            step = f"{name}-after-{poll:03d}"
            after = command_ref(run, step, status)
            case["after_status_steps"].append(step)
            run.save()
            if not pending(name, before, after):
                break
            require(time.monotonic() < until, "original committed state did not settle in time")
            time.sleep(1)
        checks(name, before, after, voters, incarnation, result, checkpoint, proof)
        run.observe(name, step, run.report["processes"][-1]["receipt"], 0, 0)
        rows, replies = {}, {}
        for role, identifier in case["sessions"].items():
            path = root / f"{name}-{role}.jsonl"
            case["timings"][role] = owned.ref(root, path)
            rows[role] = lines(path)
            replies[role] = (root / "services" / (identifier + ".log")).read_bytes().splitlines()
        if not reader:
            case["timings"]["maintenance"] = owned.ref(root, directory / "maintenance-timing.json")
            rows["maintenance"] = [owned.read(directory / "maintenance-timing.json")]
            live_write(directory, rows, original_maintenance)
        work.replay_data(run.attempt_id, name, plan["collection"], incarnation, counts, rows, replies)
        samples = work.samples(name, rows)
        write_lines(directory / "samples.jsonl", samples)
        case["samples"] = owned.ref(root, directory / "samples.jsonl")
        run.save()
    details["phases"]["drain"] = services.enter("drain")
    topology.verify_unchanged(admitted, run.environment)
    for node in reversed(admitted["nodes"]):
        services.stop(node["id"])
    run.passed(details)


def gate_details(root, report_path):
    report_path = Path(report_path).resolve(strict=True)
    root = Path(root).resolve(strict=True)
    cases = owned.read(report_path)["details"]["workloads"]
    return {"report": owned.ref(root, report_path), "workloads": [
        {"name": name, "workers": 2, "peak_inflight": 2, "measurement": {
            "name": name, "requested_operations": sum(counts), "attempted_operations": sum(counts),
            "successful_operations": sum(counts), "failed_operations": 0, "unattempted_operations": 0,
            "samples": owned.ref(root, owned.check_ref(report_path.parent, cases[name]["samples"]))}}
        for name, counts in work.COUNTS.items()]}


def verify_domain(root, domain, files, configs, artifacts, candidates):
    import verify_release_acceptance as ac
    facts = domain_run.verify_run(root, domain, files, configs, KIND, RUNNER, MODULES)
    report, custody, receipts = facts["report"], facts["custody"], facts["receipts"]
    original = Path(report["custody_root"])
    require(report["target"] == ac.REFERENCE and report["invocation"]["parameters"] == PARAMETERS,
            "concurrency measurements used another native host or workload contract")
    details = report["details"]
    owned.exact(details, {"admission", "certificates", "startup_polls", "workloads", "phases", "clock_origin_ns"}, "native concurrency")
    retained = {c["id"]: owned.check_ref(custody, c["file"]) for c in report["configurations"]}
    admission = owned.read(owned.check_ref(custody, details["admission"]))
    plan = owned.read(retained["concurrency-plan"])
    topology_plan = owned.read(retained["ha-topology"])
    nodes = admission["nodes"]
    topology.verify_retained_control(nodes, retained)
    require(len(nodes) == 9 and admission["plan_sha256"] == ac.sha256(retained["ha-topology"])
            and topology_plan["nodes"] == [{k: n[k] for k in ("id", "role", "group", "config")} for n in nodes]
            and set(retained) == {"ha-topology", "concurrency-plan", "data-profile", "operator-profile",
                                  *("node-" + n["id"] for n in nodes)}, "wrong or incomplete HA installation")
    phases = details["phases"]
    owned.exact(phases, {"measured", "drain"}, "HA measurement phases")
    require(0 <= phases["measured"] < phases["drain"] <= phases["measured"] + PARAMETERS["measured_seconds_limit"],
            "HA measurement phase exceeds limit")
    logs = {i["id"]: owned.check_ref(custody, i["log"]) for i in report["processes"]}
    services = {i: v for i, v in receipts.items() if v["service"]}
    rosters = {role: [n["node_id"] for n in nodes if n["role"] == role] for role in ("data", "control", "authority")}
    require(all(len(set(m)) == 3 for m in rosters.values()) and len(set().union(*rosters.values())) == 9,
            "three independently enrolled members per role required")
    paths, data, pins, used, members, configurations = {}, [], {}, set(), [], {}
    for node, entry in zip(nodes, report["topology"], strict=True):
        config_path = retained["node-" + node["id"]]
        cfg = owned.read(config_path)
        configurations[node["id"]] = cfg
        base = "kasumi-authority" if node["role"] == "authority" else "kasumid"
        selected = services[entry["process_id"]]
        prod = selected["record"]
        path = topology_plan["binaries"][base]
        require(ac.sha256(config_path) == node["config_sha256"]
                and sorted(cfg["replication"]["initial_voters"]) == sorted(rosters[node["role"]])
                and cfg["replication"]["node_id"] == node["node_id"]
                and prod["command"] == [path, "serve", node["config"]]
                and prod["executable"]["sha256"] == domain["binaries"][base]
                and prod["name"] == node["id"] and prod["phases"]["measured"] == phases["measured"]
                and prod["phases"]["drain"] == phases["drain"]
                and prod["started_elapsed_seconds"] <= phases["measured"] < phases["drain"] <= prod["stop"]["elapsed_seconds"]
                and selected["disposition"] == "clean-stop", "HA daemon was substituted or exited during measurement")
        if node["role"] == "data":
            data.append(cfg)
            pins[node["node_id"]] = {role: topology.certificate(owned.check_ref(custody, f))["leaf_sha256"]
                                     for role, f in details["certificates"][node["id"]].items()}
        if node["role"] == "control":
            require(not cfg["tenants"] and not cfg.get("target_recovery"), "dedicated Control process hosts data")
        members.append({"id": node["id"], "role": node["role"], "group": node["group"],
                        "certificate_sha256": node["certificate"]["leaf_sha256"], "process_id": entry["process_id"]})
        used.add(entry["process_id"])
        paths[base] = path
    require(members == domain["topology"] == report["topology"] and len(used) == 9,
            "receipts do not match nine separately owned native daemons")
    profiles = {role: owned.read(retained[role + "-profile"]) for role in ("operator", "data")}
    voters, tenant, incarnation = plan_data(plan, profiles, data, pins)
    controls = role_bindings(configurations, nodes, details["certificates"], custody, tenant, incarnation, voters)
    require(owned.read(custody / "membership.json") == {"operation": "change_membership", "voters": voters}
            and owned.read(custody / "status.json") == {"operation": "status"}, "fixed native management inputs changed")
    def command(name, expected):
        record = receipts[name]
        require(not record["service"] and record["exit_code"] == 0
                and record["record"]["command"] == expected and record["record"]["executable"]["sha256"]
                == domain["binaries"][Path(expected[0]).name]
                and logs[name] == owned.check_ref(custody, record["record"]["stdout"])
                and logs[name] == custody / name / "stdout.log", "different native command or stdout: " + name)
        used.add(name)
        return owned.read(logs[name])
    for name, counts in work.COUNTS.items():
        case = details["workloads"][name]
        directory = custody / ("case-" + name)
        original_case = original / directory.name
        roles = {"seed", "write"} | ({"read"} if name == "reads-writes" else {"snapshot"} if name == "snapshot-writes" else set())
        require(set(case["sessions"]) == roles and set(case["timings"]) == (roles if len(roles) == 3 else roles | {"maintenance"}),
                "wrong original worker roster")
        rows, replies = {}, {}
        for role in roles:
            identifier = case["sessions"][role]
            selected = services[identifier]
            prod = selected["record"]
            paths["kasumictl"] = prod["executable"]["path"]
            require(identifier not in used and selected["disposition"] == "input-closed"
                    and prod["name"] == name + "-" + role
                    and prod["command"] == bind_command(paths, plan, "session", original)
                    and prod["executable"]["sha256"] == domain["binaries"]["kasumictl"]
                    and prod["phases"]["measured"] == phases["measured"]
                    and logs[identifier] == custody / "services" / (identifier + ".log"),
                    "session replies do not belong to the original data worker")
            used.add(identifier)
            timing = owned.check_ref(custody, case["timings"][role])
            require(timing == custody / f"{name}-{role}.jsonl", "worker timing stream substituted")
            rows[role], replies[role] = lines(timing), logs[identifier].read_bytes().splitlines()
            origin = details["clock_origin_ns"]
            require(type(origin) is int and rows[role] and
                    round(prod["started_elapsed_seconds"] * 1e9) - 1000000 <= rows[role][0]["sent_ns"] - origin
                    <= rows[role][-1]["finished_ns"] - origin <= round(prod["stop"]["elapsed_seconds"] * 1e9) + 1000000,
                    "client samples lie outside the owned original session")
        status = bind_command(paths, plan, "status", original)
        before = command(name + "-before", status)
        steps = case["after_status_steps"]
        require(1 <= len(steps) <= 120 and steps == [f"{name}-after-{i:03d}" for i in range(len(steps))],
                "settled status selection omitted an original probe")
        for i, step in enumerate(steps):
            after = command(step, status)
            require(pending(name, before, after) == (i < len(steps) - 1),
                    "settled status selection skipped a positive observation")
        require([r["step"] for r in facts["scenarios"][name]] == [steps[-1]],
                "concurrency scenario does not select the measured leader status")
        require(rows["seed"][0]["finished_ns"] <= min(r[0]["sent_ns"] for k, r in rows.items() if k != "seed"),
                "workers began before the original atomic seed")
        result = checkpoint = proof = None
        if len(roles) == 2:
            result = command(name, bind_command(paths, plan, name, original_case if name == "backup-writes" else original))
            t = owned.check_ref(custody, case["timings"]["maintenance"])
            require(t == directory / "maintenance-timing.json", "maintenance timer substituted")
            interval = owned.read(t)
            owned.exact(interval, {"id", "sent_ns", "finished_ns"}, "maintenance timing")
            require(interval["id"] == 1 and type(interval["sent_ns"]) is int and type(interval["finished_ns"]) is int
                    and 0 < interval["finished_ns"] - interval["sent_ns"] <=
                    (receipts[name]["record"]["duration_seconds"] + .002) * 1_000_000_000,
                    "maintenance interval exceeds original owned child duration")
            rows["maintenance"] = [interval]
            live_write(directory, rows, receipts[name]["record"])
        if name == "backup-writes":
            checkpoint = owned.read(directory / "checkpoint.json")
            require(result["checkpoint"] == str(original_case / "checkpoint.json") and checkpoint["tenant"] == tenant,
                    "native backup receipt belongs to another checkpoint")
            proof = command("verify-backup", bind_command(paths, plan, "verify-backup", original, result["session_id"]))
        checks(name, before, after, voters, incarnation, result, checkpoint, proof)
        work.replay_data(report["attempt_id"], name, plan["collection"], incarnation, counts, rows, replies)
        samples = owned.check_ref(custody, case["samples"])
        require(samples == directory / "samples.jsonl" and lines(samples) == work.samples(name, rows),
                "concurrency samples differ from original client/maintenance operation intervals")
    require(owned.read(custody / "collection.json") == collection(plan), "different workload collection schema")
    command("create-collection", bind_command(paths, plan, "create-collection", original))
    require(used == set(receipts) and set(details["workloads"]) == set(work.COUNTS)
            and domain["details"] == gate_details(root, custody / "report.json"), "omitted/substituted original processes or samples")
    status = bind_command(paths, plan, "status", original)
    require(details["startup_polls"], "missing actual native startup probes")
    for i, item in enumerate(details["startup_polls"]):
        selected = owned.check_ref(custody, item)
        record = owned.read(selected)
        require(selected == custody / f"ready-{i:04d}" / "process.json" and record["command"] == status
                and record["executable"]["sha256"] == domain["binaries"]["kasumictl"],
                "startup receipt was replaced")
    require(record["exit_code"] == 0, "HA startup never reached the original tenant")
    ready = work.raft_observation(owned.read(owned.check_ref(custody, record["stdout"])), incarnation, voters)
    require(ready["control_leader"] in controls, "measured data uses a different Control group")
    return facts["evidence"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("evidence", "journal", "output", "topology", "plan"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--attempt-id", required=True)
    args = parser.parse_args()
    with domain_run.Run(KIND, RUNNER, MODULES, args.evidence, args.output, args.journal,
                        args.attempt_id, PARAMETERS, domain_run.QUALIFYING) as run:
        execute(run, args.topology, args.plan)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
