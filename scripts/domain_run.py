"""Shared owned custody for release-domain producers and their adapters.

One runner family serves several acceptance domains. A producer executes
frozen-source code against the frozen functional evidence. Its attempt is
admitted to the native journal before anything is dispatched. Every child is
an owned process with an original receipt, every scenario verdict is a raw row
naming those receipts, and the terminal report records the exact parameters.

The adapter half recomputes each verdict from the retained receipts and rows.
It never accepts the report's own status, counts or labels. A rehearsal is the
same code with other parameters; it is labelled in the report and the journal
outcome and no adapter accepts it.
"""
from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
import sys
import time

import attempt_index
import gate_process
import package_release as package
from process_ha_owned import SCHEMA as SERVICE_SCHEMA, OwnedProcesses, durable_json
import repeatable_assembly as owned
from release_gate import sha256

SCHEMA = "kasumi-domain-run-v1"
QUALIFYING = "qualifying"
REHEARSAL = "rehearsal-not-release-evidence"
LIBRARY = "scripts/domain_run.py"
# Local modules every domain runner executes; a runner adds its own.
SHARED = (LIBRARY, "scripts/assembly_inputs.py", "scripts/attempt_index.py",
          "scripts/gate_process.py", "scripts/package_release.py", "scripts/process_ha_owned.py",
          "scripts/process_ha_topology.py", "scripts/release_gate.py",
          "scripts/repeatable_assembly.py", "scripts/verify_release_acceptance.py")
REPORT_FIELDS = {"schema", "kind", "target", "qualification", "status", "attempt_id",
                 "started_at", "finished_at", "custody_root", "evidence_root", "invocation",
                 "source", "source_scripts", "binaries", "configurations", "dispatch_started",
                 "processes", "topology", "scenarios", "details", "error"}
ROW_FIELDS = {"sequence", "step", "process", "expected_exit", "exit_code", "elapsed_seconds"}


def require(value, message):
    if not value:
        raise ValueError(message)


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def frozen_scripts(source, files, modules):
    """Bind the executing module bytes to the frozen source inventory."""
    scripts = Path(__file__).resolve(strict=True).parent
    result = {}
    for relative in sorted({*SHARED, *modules}):
        executing = scripts / Path(relative).name
        entry = files.get(relative)
        require(isinstance(entry, dict) and entry.get("sha256") == sha256(executing)
                and sha256(Path(source) / relative) == entry["sha256"],
                "domain runner differs from frozen source: " + relative)
        loaded = sys.modules.get(Path(relative).stem)
        require(loaded is None or Path(loaded.__file__).resolve(strict=True) == executing,
                "domain runner imported another module copy: " + relative)
        result[relative] = entry["sha256"]
    return result


class Run:
    """One journaled attempt of one domain kind; use as a context manager."""

    def __init__(self, kind, runner, modules, evidence, output, journal, attempt_id,
                 parameters, qualification):
        require(kind in attempt_index.DOMAIN_KINDS, "unknown release domain: " + str(kind))
        require(qualification in (QUALIFYING, REHEARSAL), "unknown domain qualification")
        require(gate_process.GROUP_LEDGER_ENV not in os.environ,
                "domain runner cannot inherit a process group ledger")
        self.kind, self.runner, self.attempt_id = kind, runner, attempt_id
        self.journal = Path(journal).resolve(strict=True)
        self.evidence = Path(evidence).resolve(strict=True)
        output = Path(output)
        require(output.is_absolute(), "domain output must be absolute")
        self.output = output.resolve()
        require(not self.output.is_relative_to(self.evidence),
                "domain output must be outside the frozen evidence")
        self.source = self.evidence / "source"
        self.started = time.monotonic()
        started_at = now()
        # Admit before any output exists: an interrupted run is then an
        # unfinished admission, never an absent attempt.
        attempt_index.begin(self.journal, attempt_id, kind, self.output, started_at)
        self.output.mkdir(exist_ok=False)
        (self.output / "scenarios").mkdir()
        (self.output / "home").mkdir(mode=0o700)
        self.report = {
            "schema": SCHEMA, "kind": kind, "target": None, "qualification": qualification,
            "status": "running", "attempt_id": attempt_id, "started_at": started_at,
            "finished_at": None, "custody_root": str(self.output),
            "evidence_root": str(self.evidence),
            "invocation": {"runner": {"source_path": runner, "sha256": None},
                           "parameters": parameters},
            "source": None, "source_scripts": None, "binaries": None, "configurations": [],
            "dispatch_started": False, "processes": [], "topology": [], "scenarios": [],
            "details": None, "error": None}
        self.modules = modules
        self.binary_paths = {}
        self.scenarios = {}
        self.services = None
        self.environment = {"PATH": "/usr/bin:/bin", "HOME": str(self.output / "home"),
                            "TMPDIR": str(self.output / "home"), "LC_ALL": "C", "TZ": "UTC"}
        self.save()

    def save(self):
        durable_json(self.output / "report.json", self.report)

    def elapsed(self):
        return time.monotonic() - self.started

    def __enter__(self):
        return self

    def bind(self):
        """Verify the frozen functional evidence and this runner's own bytes."""
        functional, _, target, binaries = package.verify_evidence(self.evidence)
        files = owned.read(self.evidence / "source-files.json")
        scripts = frozen_scripts(self.source, files, {self.runner, *self.modules})
        self.binary_paths = {name: str(path) for name, (path, _) in binaries.items()}
        self.report.update(
            target=target, source_scripts=scripts,
            binaries={name: digest for name, (_, digest) in binaries.items()},
            source={"commit": functional["source_commit"], "tree": functional["source_tree"],
                    "archive_sha256": functional["source_archive_sha256"],
                    "source_files_sha256": functional["source_files_sha256"],
                    "lockfile_sha256": functional["lockfile_sha256"]})
        self.report["invocation"]["runner"]["sha256"] = scripts[self.runner]
        require(attempt_index.head(self.journal)["target"] == target,
                "attempt journal belongs to another native target")
        self.save()
        return target

    def configuration(self, identifier, path):
        """Retain an input file by exact bytes; the manifest must name the same hash."""
        retained = owned.retain(self.output, Path(path).resolve(strict=True))
        require(identifier not in {item["id"] for item in self.report["configurations"]},
                "duplicate domain configuration")
        self.report["configurations"].append({"id": identifier, "file": retained})
        self.save()
        return owned.check_ref(self.output, retained)

    def dispatch(self):
        if not self.report["dispatch_started"]:
            self.report["dispatch_started"] = True
            self.save()

    def command(self, step, command, timeout, *, scenario=None, expected_exit=0, cwd=None):
        """Run one owned child to completion and record its original outcome."""
        self.dispatch()
        item = owned.run_owned(self.output, step, command, str(cwd or self.source),
                               self.environment, timeout)
        receipt = owned.read(owned.check_ref(self.output, item["receipt"]))
        self.report["processes"].append({"id": step, "receipt": item["receipt"],
                                         "log": item["stdout"], "executable": item["executable"]})
        self.save()
        if scenario is not None:
            self.observe(scenario, step, item["receipt"], expected_exit, receipt["exit_code"])
        require(receipt["exit_code"] == expected_exit and receipt["status"] ==
                ("passed" if receipt["exit_code"] == 0 else "failed"),
                "domain command failed: " + step)
        return owned.check_ref(self.output, item["stdout"])

    def observe(self, scenario, step, process, expected_exit, exit_code):
        """Append one raw verdict row; the adapter recounts these rows itself."""
        path = self.output / "scenarios" / (scenario + ".jsonl")
        rows = self.scenarios.setdefault(scenario, [])
        row = {"sequence": len(rows), "step": step, "process": process,
               "expected_exit": expected_exit, "exit_code": exit_code,
               "elapsed_seconds": round(self.elapsed(), 3)}
        rows.append(row)
        with path.open("ab") as stream:
            stream.write((json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode())
            stream.flush()
            os.fsync(stream.fileno())

    def start_services(self, measured_seconds, startup_seconds, drain_seconds):
        self.dispatch()
        self.services = OwnedProcesses(self.output / "services", self.source, self.environment,
                                       measured_seconds, startup_seconds=startup_seconds,
                                       drain_seconds=drain_seconds)
        self.services.__enter__()
        return self.services

    def service(self, name, command, expected_executable, *, interactive=False):
        """Spawn an owned daemon and retain the exact bytes it executes."""
        retained = owned.retain(self.output, Path(expected_executable["path"]))
        require(retained["sha256"] == expected_executable["sha256"],
                "service executable changed before dispatch")
        identifier = self.services.spawn(name, command, expected_executable,
                                         interactive=interactive)
        self.report["processes"].append({
            "id": identifier, "receipt": {"path": "services/" + identifier + ".json"},
            "log": {"path": "services/" + identifier + ".log"}, "executable": retained})
        self.save()
        return identifier

    def close_services(self):
        """Drain every owned daemon, then bind each terminal receipt and log."""
        if self.services is None:
            return
        try:
            self.services.close()
        finally:
            for item in self.report["processes"]:
                if set(item["receipt"]) == {"path"} and (self.output / item["receipt"]["path"]).is_file():
                    item["receipt"] = owned.ref(self.output, self.output / item["receipt"]["path"])
                    item["log"] = owned.ref(self.output, self.output / item["log"]["path"])
            self.save()

    def finish(self, status, details, error):
        self.report["scenarios"] = [
            {"id": name, "iterations": len(rows),
             "failures": sum(row["exit_code"] != row["expected_exit"] for row in rows),
             "log": owned.ref(self.output, self.output / "scenarios" / (name + ".jsonl"))}
            for name, rows in sorted(self.scenarios.items())]
        self.report.update(status=status, details=details, error=error, finished_at=now())
        self.save()
        finished = [item for item in self.report["processes"] if "sha256" in item["receipt"]]
        relative = self.output.relative_to(self.journal).as_posix()
        attempt_index.finish_outcome(
            self.journal, self.attempt_id, status, self.report["finished_at"],
            products={"report": "report.json"},
            processes=[{"id": item["id"], **{
                key: {**item[key], "path": relative + "/" + item[key]["path"]}
                for key in ("receipt", "log", "executable")}} for item in finished],
            dispatch_started=self.report["dispatch_started"],
            facts={"qualification": self.report["qualification"]})

    def __exit__(self, kind, error, _):
        """Always drain, then publish one terminal report and journal row."""
        failure = error
        try:
            self.close_services()
        except BaseException as cleanup:
            failure = failure or cleanup
        if self.report["status"] == "running":
            status = ("interrupted" if isinstance(failure, KeyboardInterrupt) else "failed")
            self.finish(status, self.report["details"], repr(failure) if failure else
                        "domain runner returned without a terminal result")
        if error is None:
            if failure is not None:
                raise failure
            require(self.report["status"] == "passed", "domain run ended without a pass")
        return False

    def passed(self, details):
        """Call last, inside the context: drains services, then seals a pass."""
        self.close_services()
        require(all("sha256" in item["receipt"] for item in self.report["processes"]),
                "a domain service has no terminal receipt")
        self.finish("passed", details, None)


def gate_record(root, report_path, identity, host, configs, artifacts, details):
    """Compose a passed run's acceptance gate record from its original report.

    The bundle composer supplies what a run cannot know: the manifest's source
    identity, the attested host, the manifest configurations and the delivered
    artifacts it consumed. Everything else is lifted from the report, and the
    adapter rejects a record that differs from it.
    """
    root = Path(root).resolve(strict=True)
    custody = Path(report_path).resolve(strict=True).parent
    report = owned.read(custody / "report.json")

    def lifted(ref):
        return owned.ref(root, owned.check_ref(custody, ref))

    hashes = {item["file"]["sha256"] for item in report["configurations"]}
    return {
        "schema": attempt_index.ACCEPTANCE_SCHEMA, "id": report["kind"] + ":" + report["target"],
        "status": "passed", "identity": identity, "binaries": report["binaries"],
        "configuration_ids": sorted(key for key, value in configs.items()
                                    if value["file"]["sha256"] in hashes),
        "runner": report["invocation"]["runner"], "started_at": report["started_at"],
        "finished_at": report["finished_at"], "host": host,
        "processes": [{"id": item["id"], **{key: lifted(item[key])
                                           for key in ("receipt", "log", "executable")}}
                      for item in report["processes"]],
        "topology": report["topology"],
        "scenarios": [{"id": item["id"], "status": "failed" if item["failures"] else "passed",
                       "iterations": item["iterations"], "failures": item["failures"],
                       "unattempted": 0, "log": lifted(item["log"])}
                      for item in report["scenarios"]],
        "details": details, "artifacts": artifacts}


# ---- Adapter half: nothing below writes evidence. ----

def service_disposition(record):
    """Classify one terminal daemon receipt by what its owner did to it."""
    cleanup = record.get("cleanup")
    group = record.get("process_group")
    require(record.get("schema") == SERVICE_SCHEMA and record.get("status") == "drained"
            and record.get("outputs_stable") is True and record.get("error") is None
            and record.get("received_signals") == []
            and type(group) is int and group > 0 and isinstance(cleanup, dict)
            and cleanup.get("group") == group and cleanup.get("drained") is True
            and cleanup.get("after") == [] and cleanup.get("errors") == []
            and type(record.get("process_exit_code")) is int
            and cleanup.get("process_returncode") == record["process_exit_code"],
            "owned service is not terminal and drained")
    fault, stop = record.get("fault"), record.get("stop")
    require((fault is None) != (stop is None), "owned service has no single terminal cause")
    if fault is not None:
        # A SIGKILL the controller sent after retaining its own observation.
        require(fault.get("signal") == "SIGKILL" and fault.get("target") == "owned-leader"
                and fault.get("sent") is True and record["process_exit_code"] == -9
                and "SIGTERM" not in cleanup.get("signals", ["SIGTERM"]),
                "injected service fault is not the recorded controller SIGKILL")
        return "fault"
    require(stop.get("signal") in ("SIGTERM", "EOF") and stop.get("target") == "owned-leader"
            and stop.get("sent") is True and record["process_exit_code"] == 0
            and cleanup.get("signals") == [] and cleanup.get("before") == [],
            "owned service did not exit cleanly on its requested stop")
    return "clean-stop" if stop["signal"] == "SIGTERM" else "input-closed"


def scenario_rows(acceptance, custody, scenario, receipts):
    """Recount one scenario from its raw rows and the receipts they name."""
    exact = acceptance.exact
    exact(scenario, {"id", "iterations", "failures", "log"}, "domain run scenario")
    require(scenario["log"]["path"] == "scenarios/" + scenario["id"] + ".jsonl",
            "scenario log is not the runner's original row stream")
    rows = list(acceptance.rows(custody, scenario["log"]))
    failures = 0
    for index, row in enumerate(rows):
        exact(row, ROW_FIELDS, "scenario row")
        original = receipts.get(row["step"])
        require(row["sequence"] == index and type(row["sequence"]) is int
                and original is not None and row["process"] == original["ref"]
                and type(row["exit_code"]) is int and type(row["expected_exit"]) is int
                and row["exit_code"] == original["exit_code"],
                "scenario row differs from its original process receipt")
        acceptance.number(row["elapsed_seconds"], "scenario time")
        failures += row["exit_code"] != row["expected_exit"]
    require(rows and scenario["iterations"] == len(rows) and scenario["failures"] == failures,
            "scenario counts differ from its raw rows")
    return rows


def verify_run(root, domain, files, configs, kind, runner, modules):
    """Bind a domain gate to one original qualifying run; return its facts.

    The caller supplies the kind's registered runner and module roster. The
    gate's processes, scenarios, interval and configurations must be exactly
    what the retained run produced.
    """
    import verify_release_acceptance as acceptance

    root = Path(root).resolve(strict=True)
    report_path = acceptance.reference(root, domain["details"]["report"])
    custody = report_path.parent
    require(report_path.name == "report.json", "domain report is not the runner's original report")
    report = acceptance.read_json(report_path)
    acceptance.exact(report, REPORT_FIELDS, "domain run report")
    target = domain["id"].split(":", 1)[1]
    require(report["schema"] == SCHEMA and report["kind"] == kind and report["target"] == target
            and report["status"] == "passed" and report["error"] is None
            and report["dispatch_started"] is True, "domain run did not pass its own contract")
    # A rehearsal is the same code with other parameters; it is never evidence.
    require(report["qualification"] == QUALIFYING, "domain run is a non-qualifying rehearsal")
    frozen = {name: files.get(name, {}).get("sha256") for name in sorted({*SHARED, runner, *modules})}
    require(all(frozen.values()) and report["source_scripts"] == frozen
            and report["invocation"]["runner"] == {"source_path": runner, "sha256": frozen[runner]}
            and domain["runner"] == report["invocation"]["runner"],
            "domain run did not execute the registered frozen runner")
    require(report["source"] == {
                "commit": domain["identity"]["source_commit"],
                "tree": domain["identity"]["source_tree"],
                "archive_sha256": domain["identity"]["source_archive_sha256"],
                "source_files_sha256": domain["identity"]["source_files_sha256"],
                "lockfile_sha256": domain["identity"]["lockfile_sha256"]}
            and report["binaries"] == domain["binaries"],
            "domain run consumed another frozen source or candidate")
    require(domain["started_at"] == report["started_at"]
            and domain["finished_at"] == report["finished_at"],
            "domain interval differs from the original run")
    consumed = set()
    for item in report["configurations"]:
        acceptance.exact(item, {"id", "file"}, "domain run configuration")
        acceptance.reference(custody, item["file"])
        matching = [key for key, value in configs.items()
                    if value["file"]["sha256"] == item["file"]["sha256"]]
        require(len(matching) == 1 and matching[0] not in consumed,
                "domain run configuration is not exactly one manifest configuration")
        consumed.add(matching[0])
    require(consumed and domain["configuration_ids"] == sorted(consumed),
            "domain configurations differ from the files the run consumed")

    def lifted(ref):
        path = acceptance.reference(custody, ref)
        return {"path": path.relative_to(root).as_posix(), "sha256": ref["sha256"],
                "bytes": ref["bytes"]}

    receipts, processes = {}, []
    for item in report["processes"]:
        acceptance.exact(item, {"id", "receipt", "log", "executable"}, "domain run process")
        require(item["id"] not in receipts, "duplicate domain run process")
        record = acceptance.json_reference(custody, item["receipt"])
        service = record.get("schema") == SERVICE_SCHEMA
        receipts[item["id"]] = {
            "ref": item["receipt"], "record": record, "service": service,
            "exit_code": record.get("process_exit_code") if service else record.get("exit_code"),
            "disposition": service_disposition(record) if service else "command"}
        processes.append({"id": item["id"], "receipt": lifted(item["receipt"]),
                          "log": lifted(item["log"]), "executable": lifted(item["executable"])})
    require(processes and domain["processes"] == processes,
            "domain gate omitted or substituted an original owned process")
    scenarios = {}
    expected = []
    for scenario in report["scenarios"]:
        rows = scenario_rows(acceptance, custody, scenario, receipts)
        require(scenario["id"] not in scenarios, "duplicate domain run scenario")
        scenarios[scenario["id"]] = rows
        expected.append({"id": scenario["id"],
                         "status": "failed" if scenario["failures"] else "passed",
                         "iterations": scenario["iterations"], "failures": scenario["failures"],
                         "unattempted": 0, "log": lifted(scenario["log"])})
    require(domain["scenarios"] == expected,
            "domain scenarios differ from the run's recounted raw rows")
    outcome = custody / "outcome.json"
    require(acceptance.read_json(outcome).get("products") == [
                {"id": "report", "file": owned.ref(custody, report_path)}],
            "journaled outcome selected another report")
    # Join every retained byte to the enclosing verifier's final observation.
    for path in custody.rglob("*"):
        require(not path.is_symlink(), "domain run custody contains a symlink")
        if path.is_file():
            acceptance.reference(root, owned.ref(root, path))
    return {"report": report, "custody": custody, "receipts": receipts, "scenarios": scenarios,
            "evidence": outcome.relative_to(root).as_posix()}
