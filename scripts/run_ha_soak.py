#!/usr/bin/env python3
"""Run the nine-process HA soak: a full measured day between startup and drain.

The measured interval is 86,400 seconds of continuous authenticated workload.
Starting the nine installed daemons and stopping them again each have their
own budget outside that interval. The workload is an owned candidate
``kasumictl session`` fed one write and one read-back per cycle; every reply is
retained and each heartbeat is a count over those raw rows. Credential renewal
happens before every session rotation, and archival, backup and membership
maintenance run from the operator's plan while the workload continues.

``--rehearsal-seconds`` runs the same code over a short interval. A rehearsal
is labelled non-qualifying in its report and journal outcome, and the
acceptance adapter rejects it.
"""
from __future__ import annotations

import sys
if __name__ == "__main__" and not (sys.flags.isolated and sys.flags.no_site
                                  and sys.flags.dont_write_bytecode):
    raise SystemExit("HA soak runner requires native Python -I -S -B")

import argparse
import hashlib
import json
import os
from pathlib import Path
import threading
import time

if __name__ == "__main__":
    _scripts = Path(__file__).resolve(strict=True).parent
    if sys.pycache_prefix is not None or "PYTHONPYCACHEPREFIX" in os.environ:
        raise SystemExit("HA soak runner forbids a redirected Python bytecode cache")
    if ((_scripts / "__pycache__").exists() or (_scripts / "__pycache__").is_symlink()
            or any(path.suffix in {".pyc", ".pyo"} or
                   (path.suffix == ".py" and path.is_symlink())
                   for path in _scripts.rglob("*"))):
        raise SystemExit("HA soak runner requires source-only Python imports")
    sys.path.insert(0, str(_scripts))

import domain_run
from domain_run import require
import process_ha_topology as topology
import repeatable_assembly as owned

KIND = "ha-soak"
RUNNER = "scripts/run_ha_soak.py"
MODULES = ()
PLAN_SCHEMA = "kasumi-ha-soak-plan-v1"
# The qualifying contract. A run with any other value is a rehearsal.
QUALIFYING = {"duration_seconds": 86400, "heartbeat_seconds": 60, "session_seconds": 1500,
              "startup_seconds": 3600, "drain_seconds": 3600}
# A session keeps one credential snapshot, which lives at most an hour; rotate
# well inside it, renewing the installed credential first.
KEYS = 1024
REPLY_SECONDS = 60
COMMAND_SECONDS = 3600
# Each maintenance kind runs when this fraction of the measured interval has
# passed, and may only use its own product command family.
MAINTENANCE = {
    "archival": (0.25, {("kasumid", ("audit",))}),
    "backup": (0.5, {("kasumid", ("backup",))}),
    "membership-maintenance": (0.75, {("kasumictl", ("manage",)),
                                      ("kasumictl", ("authority-maintenance",))}),
}
RENEWAL = "credential-renewal"


def absolute(value, label):
    require(isinstance(value, str) and Path(value).is_absolute()
            and Path(value).resolve(strict=True) == Path(value), label + " is not a canonical path")
    return value


def plan_command(binaries, kind, step):
    """One plan step as an exact candidate command of the kind's own family."""
    owned.exact(step, {"binary", "arguments"}, "soak maintenance step")
    binary, arguments = step["binary"], step["arguments"]
    require(binary in binaries and isinstance(arguments, list) and arguments
            and all(isinstance(argument, str) for argument in arguments),
            "soak maintenance step is malformed")
    # kasumictl names its client file before the operation.
    words = arguments[2:] if binary == "kasumictl" and arguments[0] == "--config" else arguments
    require(any(binary == family and tuple(words[:len(prefix)]) == prefix
                for family, prefix in MAINTENANCE[kind][1]),
            "soak " + kind + " step is outside its product command family")
    return [binaries[binary], *arguments]


def check_plan(plan, binaries):
    owned.exact(plan, {"schema", "profile", "collection", "readiness", "maintenance"}, "soak plan")
    require(plan["schema"] == PLAN_SCHEMA, "unsupported soak plan")
    absolute(plan["profile"], "soak client profile")
    require(isinstance(plan["collection"], str) and plan["collection"], "soak collection is absent")
    require(isinstance(plan["readiness"], list) and plan["readiness"]
            and len(set(plan["readiness"])) == len(plan["readiness"]),
            "soak readiness clients are absent or repeated")
    for client in plan["readiness"]:
        absolute(client, "soak readiness client")
    owned.exact(plan["maintenance"], set(MAINTENANCE), "soak maintenance")
    commands = {}
    for kind, steps in plan["maintenance"].items():
        require(isinstance(steps, list) and steps, "soak maintenance kind is empty: " + kind)
        commands[kind] = [plan_command(binaries, kind, step) for step in steps]
    return commands


def cycle_body(attempt_id, cycle):
    digest = hashlib.sha256(f"kasumi-ha-soak:{attempt_id}:{cycle}".encode()).hexdigest()
    return {"cycle": cycle, "sha256": digest}


def cycle_requests(attempt_id, collection, cycle):
    """The two requests of one cycle; request ids are consecutive from zero."""
    document = "soak-" + str(cycle % KEYS)
    body = json.dumps(cycle_body(attempt_id, cycle), sort_keys=True, separators=(",", ":"))
    return [{"id": cycle * 2, "argv": ["put", collection, document, body, "--if", "any"],
             "timeout_ms": REPLY_SECONDS * 500},
            {"id": cycle * 2 + 1, "argv": ["get", collection, document],
             "timeout_ms": REPLY_SECONDS * 500}]


def judge(attempt_id, request, reply):
    """Classify one reply from its raw bytes: success, error or integrity mismatch."""
    try:
        value = json.loads(reply)
    except ValueError:
        return "error"
    document = value.get("document") if isinstance(value, dict) else None
    if (not isinstance(value, dict) or value.get("id") != request["id"] or value.get("status") != 0
            or not isinstance(document, dict) or document.get("ok") is not True):
        return "error"
    if request["argv"][0] == "get":
        observed = document.get("result", {}).get("document", {})
        if observed.get("body") != cycle_body(attempt_id, request["id"] // 2):
            return "mismatch"
    return "ok"


def heartbeat_rows(rows, duration, interval):
    """Each heartbeat counts the replies received before its nominal second."""
    result, index = [], 0
    counts = {"ok": 0, "error": 0, "mismatch": 0}
    for beat in range(duration // interval + 1):
        while index < len(rows) and rows[index]["received_elapsed_seconds"] < beat * interval:
            counts[rows[index]["verdict"]] += 1
            index += 1
        result.append({"elapsed_seconds": beat * interval, "successful_operations": counts["ok"],
                       "unexpected_errors": counts["error"],
                       "integrity_mismatches": counts["mismatch"]})
    return result


class Workload:
    """One writer thread; the main thread owns every process and the schedule."""

    def __init__(self, run, plan, measured_start, duration):
        self.run, self.plan, self.measured_start = run, plan, measured_start
        self.duration = duration
        self.rows = (run.output / "workload.jsonl").open("ab")
        self.lock = threading.Lock()
        self.active = threading.Event()
        self.idle = threading.Event()
        self.idle.set()
        self.stopping = False
        self.error = None
        self.session = self.name = self.log = None
        self.cycle = self.line = self.offset = 0
        self.thread = threading.Thread(target=self.loop, name="soak-workload", daemon=True)
        self.thread.start()

    def elapsed(self):
        return self.run.services.elapsed() - self.measured_start

    def attach(self, name, identifier):
        """Select a freshly spawned session; its reply log starts empty."""
        self.session, self.name = identifier, name
        self.log = self.run.output / "services" / (identifier + ".log")
        self.line = self.offset = 0
        self.active.set()

    def pause(self):
        """Finish the cycle in flight, then hold the writer between cycles."""
        self.active.clear()
        require(self.idle.wait(REPLY_SECONDS * 3), "soak workload did not reach a cycle boundary")
        require(self.error is None, "soak workload failed: " + repr(self.error))

    def reply(self):
        until = time.monotonic() + REPLY_SECONDS
        while time.monotonic() < until:
            with self.log.open("rb") as stream:
                stream.seek(self.offset)
                line = stream.readline()
            if line.endswith(b"\n"):
                self.offset += len(line)
                return line
            time.sleep(.005)
        raise ValueError("soak session did not reply in time")

    def loop(self):
        try:
            while not self.stopping:
                if not self.active.wait(.05):
                    continue
                if self.elapsed() >= self.duration:
                    # The interval is over even if the scheduler is still busy
                    # with a command: write nothing past the measured budget.
                    self.active.clear()
                    continue
                self.idle.clear()
                try:
                    for request in cycle_requests(self.run.attempt_id, self.plan["collection"],
                                                  self.cycle):
                        sent = self.elapsed()
                        self.run.services.send(self.name, (json.dumps(
                            request, sort_keys=True, separators=(",", ":")) + "\n").encode())
                        reply = self.reply()
                        row = {"sequence": request["id"], "session": self.session,
                               "line": self.line, "sent_elapsed_seconds": sent,
                               "received_elapsed_seconds": self.elapsed(),
                               "verdict": judge(self.run.attempt_id, request, reply)}
                        self.line += 1
                        with self.lock:
                            self.rows.write((json.dumps(row, sort_keys=True,
                                                        separators=(",", ":")) + "\n").encode())
                            self.rows.flush()
                    self.cycle += 1
                finally:
                    self.idle.set()
        except BaseException as error:
            self.error = error
            self.active.clear()

    def close(self):
        self.stopping = True
        self.active.clear()
        self.thread.join(REPLY_SECONDS * 3)
        with self.lock:
            self.rows.flush()
            os.fsync(self.rows.fileno())
            self.rows.close()
        require(not self.thread.is_alive(), "soak workload thread did not stop")


def execute(run, parameters, topology_path, plan_path, pause):
    target = run.bind()
    require(target == "aarch64-unknown-linux-gnu" or run.report["qualification"]
            != domain_run.QUALIFYING, "the qualifying HA soak runs on the Linux ARM64 reference")
    binaries = run.binary_paths
    plan_file = run.configuration("soak-plan", plan_path)
    topology_file = run.configuration("ha-topology", topology_path)
    plan = owned.read(plan_file)
    maintenance = check_plan(plan, binaries)
    admitted = topology.inspect(Path(topology_path).resolve(strict=True), run.environment)
    require(owned.read(topology_file) == owned.read(Path(topology_path)),
            "HA topology plan changed while it was retained")
    for name in ("kasumid", "kasumi-authority"):
        require(admitted["binaries"][name]["path"] == binaries[name]
                and admitted["binaries"][name]["sha256"] == run.report["binaries"][name],
                "HA topology does not install the qualified candidate: " + name)
    for node in admitted["nodes"]:
        run.configuration("node-" + node["id"], node["config"])
    duration, interval = parameters["duration_seconds"], parameters["heartbeat_seconds"]
    services = run.start_services(duration + interval, parameters["startup_seconds"],
                                  parameters["drain_seconds"])
    members = {}
    for node in admitted["nodes"]:
        members[node["id"]] = run.service(node["id"], [node["executable"]["path"], "serve",
                                                       node["config"]], node["executable"])
        run.report["topology"].append({
            "id": node["id"], "role": node["role"], "group": node["group"],
            "certificate_sha256": node["certificate"]["leaf_sha256"],
            "process_id": members[node["id"]]})
    domain_run.durable_json(run.output / "topology-admission.json", admitted)
    details = {"duration_seconds": duration, "heartbeat_seconds": interval, "phases": None,
               "admission": owned.ref(run.output, run.output / "topology-admission.json"),
               "startup_polls": [], "sessions": [], "maintenance": [], "heartbeats": None,
               "workload": None}
    run.report["details"] = details
    run.save()
    control = [binaries["kasumictl"], "--config"]
    for index, client in enumerate(plan["readiness"]):
        # A refused poll is an original candidate execution too: its receipt
        # stays in custody, outside the passing process roster.
        for poll in range(100000):
            services.assert_alive()
            step = f"ready-{index}-{poll:05d}"
            item = owned.run_owned(run.output, step, [*control, client, "ready"],
                                   str(run.source), run.environment, 60)
            if owned.read(owned.check_ref(run.output, item["receipt"]))["exit_code"] == 0:
                run.report["processes"].append({"id": step, "receipt": item["receipt"],
                                                "log": item["stdout"],
                                                "executable": item["executable"]})
                break
            details["startup_polls"].append(item["receipt"])
            run.save()
            time.sleep(pause)
    kasumictl = topology.gate_process.executable_identity(
        [binaries["kasumictl"]], run.source, run.environment)
    session_command = [binaries["kasumictl"], "--profile", plan["profile"], "session"]

    def open_session(workload):
        identifier = run.service("workload", session_command, kasumictl, interactive=True)
        details["sessions"].append(identifier)
        workload.attach("workload", identifier)

    topology.verify_unchanged(admitted, run.environment)
    measured_start = services.enter("measured")
    workload = Workload(run, plan, measured_start, duration)
    try:
        open_session(workload)
        pending = sorted((fraction * duration, kind) for kind, (fraction, _) in MAINTENANCE.items())
        rotation = parameters["session_seconds"]
        events = {}
        while workload.elapsed() < duration:
            services.assert_alive()
            require(workload.error is None, "soak workload failed: " + repr(workload.error))
            now = workload.elapsed()
            if pending and now >= pending[0][0]:
                _, kind = pending.pop(0)
                started = workload.elapsed()
                steps = []
                for index, command in enumerate(maintenance[kind]):
                    steps.append(f"{kind}-{index}")
                    run.command(steps[-1], command, COMMAND_SECONDS, scenario=kind)
                events[kind] = {"id": kind, "elapsed_seconds": started,
                                "finished_elapsed_seconds": workload.elapsed(), "steps": steps}
            elif now >= rotation and now < duration - interval:
                # Renew while the old session still holds its own snapshot,
                # then hand the workload to a session that loads the new one.
                started = workload.elapsed()
                step = f"{RENEWAL}-{len(details['sessions']):04d}"
                run.command(step, [binaries["kasumid"], "credential", "renew", plan["profile"]],
                            COMMAND_SECONDS, scenario=RENEWAL)
                events.setdefault(RENEWAL, {"id": RENEWAL, "elapsed_seconds": started,
                                            "finished_elapsed_seconds": workload.elapsed(),
                                            "steps": []})["steps"].append(step)
                workload.pause()
                services.end_input("workload")
                open_session(workload)
                rotation += parameters["session_seconds"]
            else:
                time.sleep(pause)
        workload.pause()
    finally:
        workload.close()
    drain_start = services.enter("drain")
    services.end_input("workload")
    topology.verify_unchanged(admitted, run.environment)
    for node in reversed(admitted["nodes"]):
        services.stop(node["id"])
    rows = [json.loads(line) for line in (run.output / "workload.jsonl").read_bytes().splitlines()]
    beats = heartbeat_rows(rows, duration, interval)
    with (run.output / "heartbeats.jsonl").open("xb") as stream:
        stream.write(b"".join(json.dumps(row).encode() + b"\n" for row in beats))
        stream.flush()
        os.fsync(stream.fileno())
    # A failed run keeps the same raw facts as a passed one.
    details.update(phases={"measured": measured_start, "drain": drain_start},
                   maintenance=[events[kind] for kind in sorted(events)],
                   heartbeats=owned.ref(run.output, run.output / "heartbeats.jsonl"),
                   workload=owned.ref(run.output, run.output / "workload.jsonl"))
    run.save()
    require(all(row["verdict"] == "ok" for row in rows)
            and all(later["successful_operations"] > earlier["successful_operations"]
                    for earlier, later in zip(beats, beats[1:])),
            "soak workload had errors, mismatches or a stalled heartbeat")
    # Maintenance that finishes after the last measured second proves nothing
    # about the soak; the adapter applies the same bound to the same numbers.
    require(not pending and set(events) == {RENEWAL, *MAINTENANCE}
            and all(0 < event["elapsed_seconds"] <= event["finished_elapsed_seconds"] < duration
                    for event in events.values()),
            "soak ended before every maintenance kind ran inside the measured interval")
    run.passed(details)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--topology", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--rehearsal-seconds", type=int,
                        help="non-qualifying: measured seconds, a multiple of the heartbeat")
    parser.add_argument("--rehearsal-heartbeat-seconds", type=int, default=1)
    args = parser.parse_args(argv)
    parameters = dict(QUALIFYING)
    pause = 1.0
    if args.rehearsal_seconds is not None:
        beat = args.rehearsal_heartbeat_seconds
        require(1 <= beat <= 60 and 3 * beat <= args.rehearsal_seconds < QUALIFYING["duration_seconds"]
                and args.rehearsal_seconds % beat == 0, "invalid rehearsal interval")
        parameters.update(duration_seconds=args.rehearsal_seconds, heartbeat_seconds=beat,
                          session_seconds=max(beat, args.rehearsal_seconds // 3),
                          startup_seconds=120, drain_seconds=120)
        pause = .02
    qualification = (domain_run.QUALIFYING if parameters == QUALIFYING else domain_run.REHEARSAL)
    with domain_run.Run(KIND, RUNNER, MODULES, args.evidence, args.output, args.journal,
                        args.attempt_id, parameters, qualification) as run:
        execute(run, parameters, args.topology, args.plan, pause)
    label = "qualifying" if qualification == domain_run.QUALIFYING else "NON-QUALIFYING REHEARSAL"
    print("HA soak " + label + " retained: " + str(args.output))
    return 0


def gate_details(root, report_path):
    """The soak gate's details, lifted from a passed run's original report."""
    root = Path(root).resolve(strict=True)
    custody = Path(report_path).resolve(strict=True).parent
    report = owned.read(custody / "report.json")
    logs = {item["id"]: item["log"] for item in report["processes"]}
    lifted = lambda ref: owned.ref(root, owned.check_ref(custody, ref))
    return {"duration_seconds": report["details"]["duration_seconds"],
            "heartbeats": lifted(report["details"]["heartbeats"]),
            "maintenance": [{"id": event["id"], "elapsed_seconds": event["elapsed_seconds"],
                             "log": lifted(logs[event["steps"][0]])}
                            for event in report["details"]["maintenance"]],
            "report": owned.ref(root, custody / "report.json")}


# ---- Acceptance adapter: recompute the soak from retained raw evidence. ----

def verify_domain(root, domain, files, configs, artifacts, candidates):
    import verify_release_acceptance as acceptance

    facts = domain_run.verify_run(root, domain, files, configs, KIND, RUNNER, MODULES)
    report, custody, receipts = facts["report"], facts["custody"], facts["receipts"]
    require(report["invocation"]["parameters"] == QUALIFYING,
            "soak parameters differ from the qualifying contract")
    details = report["details"]
    owned.exact(details, {"duration_seconds", "heartbeat_seconds", "phases", "admission",
                          "startup_polls", "sessions", "maintenance", "heartbeats", "workload"},
                "soak run details")
    duration, interval = QUALIFYING["duration_seconds"], QUALIFYING["heartbeat_seconds"]
    require(details["duration_seconds"] == duration and details["heartbeat_seconds"] == interval,
            "soak run details differ from its parameters")
    retained = {item["id"]: acceptance.reference(custody, item["file"])
                for item in report["configurations"]}
    admission = acceptance.json_reference(custody, details["admission"])
    nodes = admission["nodes"]
    require(len(nodes) == 9 and set(retained) == {
                "soak-plan", "ha-topology", *("node-" + node["id"] for node in nodes)}
            and admission["plan_sha256"] == acceptance.sha256(retained["ha-topology"])
            and acceptance.read_json(retained["ha-topology"])["nodes"] == [
                {key: node[key] for key in ("id", "role", "group", "config")} for node in nodes],
            "soak run retained another topology or configuration roster")
    plan = acceptance.read_json(retained["soak-plan"])
    phases = details["phases"]
    owned.exact(phases, {"measured", "drain"}, "soak phases")
    measured = acceptance.number(phases["drain"], "drain start") - \
        acceptance.number(phases["measured"], "measured start")
    require(measured >= duration, "measured soak interval is shorter than the contract")
    # Nine daemons: one original execution each, alive across the whole
    # measured interval and stopped on request during the drain phase.
    names = [original["record"]["name"] for original in receipts.values() if original["service"]]
    paths, members = {}, []
    for node, member in zip(nodes, report["topology"]):
        original = receipts.get(member["process_id"])
        binary = "kasumi-authority" if node["role"] == "authority" else "kasumid"
        require(original is not None and original["disposition"] == "clean-stop"
                and names.count(node["id"]) == 1,
                "soak daemon was faulted, restarted or not stopped cleanly: " + node["id"])
        record = original["record"]
        require(record["name"] == node["id"]
                and record["command"] == [record["executable"]["path"], "serve", node["config"]]
                and record["executable"] == node["executable"]
                and record["executable"]["sha256"] == domain["binaries"][binary]
                and acceptance.sha256(retained["node-" + node["id"]]) == node["config_sha256"]
                and record["started_elapsed_seconds"] <= phases["measured"]
                and record["stop"]["elapsed_seconds"] >= phases["drain"]
                and record["phases"].get("measured") == phases["measured"]
                and record["phases"].get("drain") == phases["drain"],
                "soak daemon did not serve its installed configuration for the measured interval: "
                + node["id"])
        paths[binary] = record["executable"]["path"]
        members.append({"id": node["id"], "role": node["role"], "group": node["group"],
                        "certificate_sha256": node["certificate"]["leaf_sha256"],
                        "process_id": member["process_id"]})
    require(report["topology"] == members and domain["topology"] == members,
            "soak topology differs from the nine original daemons")
    # Sessions: candidate kasumictl, each ended by closing its input.
    logs = {item["id"]: item["log"] for item in report["processes"]}
    replies = {}
    for identifier in details["sessions"]:
        original = receipts.get(identifier)
        require(original is not None and identifier not in replies
                and original["disposition"] == "input-closed"
                and original["record"]["executable"]["sha256"] == domain["binaries"]["kasumictl"]
                and original["record"]["command"] == [original["record"]["executable"]["path"],
                                                      "--profile", plan["profile"], "session"],
                "soak workload session is not an original candidate kasumictl session")
        paths["kasumictl"] = original["record"]["executable"]["path"]
        replies[identifier] = acceptance.reference(custody, logs[identifier]).read_bytes() \
            .splitlines(keepends=True)
    require(len(replies) >= 2 and names.count("workload") == len(replies),
            "soak workload never rotated its session or ran an unlisted one")
    # Recompute every verdict and heartbeat from the raw replies.
    rows = list(acceptance.rows(custody, details["workload"]))
    previous = 0.0
    for index, row in enumerate(rows):
        owned.exact(row, {"sequence", "session", "line", "sent_elapsed_seconds",
                          "received_elapsed_seconds", "verdict"}, "soak workload row")
        lines = replies.get(row["session"])
        request = cycle_requests(report["attempt_id"], plan["collection"], index // 2)[index % 2]
        require(row["sequence"] == index and lines is not None
                and type(row["line"]) is int and 0 <= row["line"] < len(lines)
                and 0 <= row["sent_elapsed_seconds"] <= row["received_elapsed_seconds"]
                and row["received_elapsed_seconds"] >= previous
                and row["verdict"] == judge(report["attempt_id"], request, lines[row["line"]]),
                "soak workload row differs from its original session reply")
        previous = row["received_elapsed_seconds"]
    require(sum(len(lines) for lines in replies.values()) == len(rows),
            "soak session replies are not all accounted for")
    require(list(acceptance.rows(custody, details["heartbeats"]))
            == heartbeat_rows(rows, duration, interval),
            "soak heartbeats differ from the recomputed raw workload")
    # Maintenance: the plan's exact candidate commands, inside the interval.
    commands = check_plan(plan, paths)
    require([event["id"] for event in details["maintenance"]] == sorted([RENEWAL, *commands]),
            "soak maintenance roster differs")
    events = []
    for event in details["maintenance"]:
        owned.exact(event, {"id", "elapsed_seconds", "finished_elapsed_seconds", "steps"},
                    "soak maintenance event")
        kind = event["id"]
        observed = [row["step"] for row in facts["scenarios"][kind]]
        expected = commands[kind] if kind != RENEWAL else [
            [paths["kasumid"], "credential", "renew", plan["profile"]]] * len(observed)
        require(0 < event["elapsed_seconds"] <= event["finished_elapsed_seconds"] < duration
                and event["steps"] == observed and len(observed) == len(expected)
                and all(receipts[step]["record"]["command"] == command
                        and receipts[step]["exit_code"] == 0
                        and receipts[step]["record"]["executable"]["sha256"]
                        == domain["binaries"][Path(command[0]).name]
                        for step, command in zip(observed, expected)),
                "soak maintenance did not run its planned candidate commands in the interval: "
                + kind)
        first = next(item for item in domain["processes"] if item["id"] == observed[0])
        events.append({"id": kind, "elapsed_seconds": event["elapsed_seconds"],
                       "log": first["log"]})
    require(len(facts["scenarios"][RENEWAL]) == len(replies) - 1,
            "a soak session rotated without a credential renewal")
    heartbeats = acceptance.reference(custody, details["heartbeats"])
    require(domain["details"] == {
                "duration_seconds": duration, "maintenance": events,
                "heartbeats": owned.ref(Path(root).resolve(strict=True), heartbeats),
                "report": domain["details"]["report"]},
            "soak gate details differ from the original run")
    return facts["evidence"]


if __name__ == "__main__":
    raise SystemExit(main())
