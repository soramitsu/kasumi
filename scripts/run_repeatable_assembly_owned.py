#!/usr/bin/env python3
"""Launch the frozen repeatable-assembly runner as an owned native process.

The launcher retains the original runner outcome and never converts a failed,
timed-out, signalled, or incompletely drained run into acceptance evidence.
Nested packager/probe/metadata children retain their own original groups.
"""
from __future__ import annotations

import argparse
import datetime as dt
import os
from pathlib import Path
import signal
import sys
import time

import assembly_inputs
import repeatable_assembly as assembly
from release_gate import sha256, write_json

SCHEMA = "kasumi-owned-repeatable-assembly-v1"
LAUNCHER = "scripts/run_repeatable_assembly_owned.py"
RUNNER = assembly.RUNNER
TIMEOUT_SECONDS = 7200
GROUP_LEDGER = "descendant-groups.jsonl"
TERMINAL_CENSUS = "descendant-census.json"


def require(value, message):
    if not value:
        raise ValueError(message)


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def command(inputs, source, evidence, declaration, output):
    return [inputs["tools"]["python"]["path"], "-B", "-S", str(Path(source) / RUNNER),
            "--evidence", str(evidence), "--native-inputs", str(declaration),
            "--output", str(Path(output) / "assembly")]


def source_scripts(evidence, source):
    files = assembly.read(Path(evidence) / "source-files.json")
    require(isinstance(files, dict), "frozen source inventory is absent")
    scripts = {}
    for relative in assembly.SCRIPTS:
        entry = files.get(relative)
        require(isinstance(entry, dict) and entry.get("sha256") == sha256(Path(source) / relative),
                "frozen launcher dependency differs: " + relative)
        scripts[relative] = entry["sha256"]
    require(Path(__file__).resolve(strict=True) == Path(source) / LAUNCHER,
            "owned launcher is not the frozen source executable")
    return scripts


def check_runner(root, item, inputs, source, evidence, declaration, output):
    """The outer runner must be a distinct, original, fully drained process."""
    selected = command(inputs, source, evidence, declaration, output)
    require(item["id"] == "runner", "original assembly runner process is missing")
    receipt = assembly.check_owned(root, item, selected, str(source), TIMEOUT_SECONDS)
    require(item["executable"]["sha256"] == inputs["tools"]["python"]["sha256"],
            "assembly runner used another Python executable")
    return receipt


def child_ledger(root, parsed, runner_group):
    """Reconstruct the original seven spawns, including their actual parents.

    Every gate child starts a new session, so its process group is its original
    PID. Probes and packagers belong to the runner; each metadata process belongs
    to its own packager. All identities come from the separately verified
    original receipts, not from the ledger or its terminal-census copy.
    """
    inner = Path(root) / "assembly"
    record = parsed["record"]
    require([item["id"] for item in record["probes"]] ==
            ["cargo-version", "rustc-version", "python-version"]
            and [item["id"] for item in record["assemblies"]] == ["assembly-a", "assembly-b"],
            "nested assembly child roster differs")
    groups = {runner_group}
    entries = []

    def original(ref, owner_pid):
        process = assembly.read(assembly.check_ref(inner, ref))
        group = process.get("process_group")
        cleanup = process.get("cleanup", {})
        require(type(group) is int and group > 0 and group not in groups
                and process.get("status") == "passed" and process.get("timed_out") is False
                and process.get("received_signals") == [] and cleanup.get("group") == group
                and cleanup.get("before") == [] and cleanup.get("after") == []
                and cleanup.get("signals") == [] and cleanup.get("errors") == []
                and cleanup.get("drained") is True,
                "nested child group was reused, interrupted, or not drained")
        executable = process.get("executable")
        require(isinstance(executable, dict) and isinstance(executable.get("sha256"), str),
                "nested child executable identity is absent")
        require("leader_birth" in process, "nested child birth observation is absent")
        entries.append({"schema": 1, "kind": "group", "group": group,
                        "owner_pid": owner_pid, "executable_sha256": executable["sha256"],
                        "leader_birth": process["leader_birth"]})
        groups.add(group)
        return group

    for item in record["probes"]:
        original(item["receipt"], runner_group)
    for item in record["assemblies"]:
        packager_group = original(item["process"]["receipt"], runner_group)
        receipt = inner / (item["id"] + "-output") / "metadata-custody" / "process.json"
        original(assembly.ref(inner, receipt), packager_group)
    require(len(entries) == 7 and len(groups) == 8,
            "outer and nested process ownership is ambiguous")
    return entries


def child_groups(root, parsed, runner_group):
    return sorted([runner_group, *(entry["group"] for entry in child_ledger(root, parsed, runner_group))])


def terminal_census(root, ledger_path):
    """Terminate every registered nested group after admissions are sealed."""
    rows, closed = assembly.gate_process.read_group_ledger(ledger_path)
    entries = [row for row in rows if row["kind"] == "group"]
    results = []
    for entry in entries:
        group = entry["group"]
        item = {"group": group, "owner_pid": entry["owner_pid"],
                "executable_sha256": entry["executable_sha256"],
                "leader_birth": entry["leader_birth"], "identity_before": None,
                "before": None, "after": None, "signals": [], "errors": [], "terminal": False}
        try:
            item["before"] = assembly.gate_process.group_members(group)
        except Exception as error:
            item["errors"].append("before census: " + repr(error))
        # Never send a group signal to the launcher's own process group, even
        # when a damaged ledger advertises that group as one of its children.
        # Such a row makes the census incomplete and cannot qualify a release.
        if group == os.getpgrp():
            item["errors"].append("registered descendant equals launcher process group")
        elif item["before"] != []:
            expected = {"group": group, "birth": entry["leader_birth"]}
            try:
                item["identity_before"] = assembly.gate_process.leader_identity(group)
            except Exception as error:
                item["errors"].append("leader identity: " + repr(error))
            if entry["leader_birth"] is None or item["identity_before"] != expected:
                item["errors"].append("registered group leader identity is unavailable or changed")
            else:
                observed = item["before"]
                for number in (signal.SIGTERM, signal.SIGKILL):
                    try:
                        if assembly.gate_process.leader_identity(group) != expected:
                            item["errors"].append("registered group leader identity changed before signal")
                            break
                    except Exception as error:
                        item["errors"].append("leader identity before signal: " + repr(error))
                        break
                    try:
                        os.killpg(group, number)
                        item["signals"].append(signal.Signals(number).name)
                    except ProcessLookupError:
                        pass
                    except OSError as error:
                        item["errors"].append(signal.Signals(number).name + ": " + repr(error))
                    until = time.monotonic() + 5
                    while time.monotonic() < until:
                        try:
                            observed = assembly.gate_process.group_members(group)
                        except Exception as error:
                            item["errors"].append("drain census: " + repr(error))
                            break
                        if observed == []:
                            break
                        time.sleep(.05)
                    if observed == []:
                        break
        try:
            item["after"] = assembly.gate_process.group_members(group)
        except Exception as error:
            item["errors"].append("after census: " + repr(error))
        item["terminal"] = item["after"] == [] and not item["errors"]
        results.append(item)
    census = {"schema": 1, "ledger_closed": closed, "groups": results,
              "complete": closed and all(item["terminal"] for item in results)}
    write_json(Path(root) / TERMINAL_CENSUS, census)
    return census


def launch(evidence, declaration, output):
    require(assembly.gate_process.GROUP_LEDGER_ENV not in os.environ,
            "owned launcher cannot inherit a nested process group ledger")
    evidence = Path(evidence).resolve(strict=True)
    declaration = Path(declaration).resolve(strict=True)
    output = Path(output)
    require(output.is_absolute(), "owned assembly output must be absolute")
    output = output.resolve()
    require(not output.is_relative_to(evidence), "owned assembly output must be fresh and outside evidence")
    output.mkdir(exist_ok=False)
    source = evidence / "source"
    result_path = output / "launcher.json"
    result = {"schema": SCHEMA, "status": "running", "started_at": now(), "finished_at": None,
              "evidence_root": str(evidence), "source_root": str(source),
              "declaration_path": str(declaration), "custody_root": str(output),
              "source_files_sha256": None, "source_scripts": None, "tools": None,
              "declaration": None, "runner_process": None, "inner_report": None,
              "group_ledger": None, "descendant_census": None,
              "error": None}
    write_json(result_path, result)
    try:
        inputs = assembly_inputs.validate_declaration(assembly.read(declaration))
        require(str(Path(sys.executable).resolve(strict=True)) == inputs["tools"]["python"]["path"],
                "launcher interpreter differs from declared native Python")
        result["source_files_sha256"] = sha256(evidence / "source-files.json")
        result["source_scripts"] = source_scripts(evidence, source)
        result["tools"] = inputs["tools"]
        result["declaration"] = assembly.retain(output, declaration)
        write_json(result_path, result)
        home = output / "home"
        home.mkdir()
        environment = assembly_inputs.environment(inputs, home)
        ledger_path = output / GROUP_LEDGER
        ledger_path.open("xb").close()
        environment[assembly.gate_process.GROUP_LEDGER_ENV] = str(ledger_path)
        def seal(record):
            assembly.gate_process.seal_group_ledger(ledger_path)
            record["group_ledger"] = assembly.ref(output, ledger_path)
            result["group_ledger"] = record["group_ledger"]
            write_json(result_path, result)
        def finish_descendants(record):
            census = terminal_census(output, ledger_path)
            record["descendant_census"] = assembly.ref(output, output / TERMINAL_CENSUS)
            result["descendant_census"] = record["descendant_census"]
            write_json(result_path, result)
            if not census["complete"] or any(item["signals"] for item in census["groups"]):
                raise ValueError("nested process groups required cleanup or did not drain")
        selected = command(inputs, source, evidence, declaration, output)
        item = assembly.run_owned(output, "runner", selected, str(source), environment, TIMEOUT_SECONDS,
                                  before_cleanup=seal, after_cleanup=finish_descendants)
        result["runner_process"] = item
        write_json(result_path, result)
        check_runner(output, item, inputs, source, evidence, declaration, output)
        inner_path = output / "assembly" / "attempt.json"
        result["inner_report"] = assembly.ref(output, inner_path)
        parsed = assembly.verify(output / "assembly", assembly.ref(output / "assembly", inner_path))
        runner_receipt = assembly.read(assembly.check_ref(output, item["receipt"]))
        child_groups(output, parsed, runner_receipt["process_group"])
        result["status"] = "passed"
        result["finished_at"] = now()
        write_json(result_path, result)
        verify(output, assembly.ref(output, result_path))
        return result
    except BaseException as error:
        result["status"] = "failed"
        result["error"] = repr(error)
        result["finished_at"] = now()
        write_json(result_path, result)
        raise


def verify(root, ref):
    """Read-only check; receipt paths may have been copied into an evidence bundle."""
    root = Path(root).resolve(strict=True)
    record = assembly.read(assembly.check_ref(root, ref))
    assembly.exact(record, {"schema", "status", "started_at", "finished_at", "evidence_root",
                            "source_root", "declaration_path", "custody_root", "source_files_sha256",
                            "source_scripts", "tools", "declaration", "runner_process", "inner_report",
                            "group_ledger", "descendant_census", "error"}, "owned assembly launcher")
    require(record["schema"] == SCHEMA and record["status"] == "passed" and record["error"] is None,
            "owned assembly launcher did not pass")
    started = dt.datetime.fromisoformat(record["started_at"])
    finished = dt.datetime.fromisoformat(record["finished_at"])
    require(started.tzinfo is not None and finished.tzinfo is not None and finished > started,
            "owned assembly interval is invalid")
    original = Path(record["custody_root"])
    require(original.is_absolute() and Path(record["source_root"]) == Path(record["evidence_root"]) / "source"
            and Path(record["declaration_path"]).is_absolute(), "owned assembly path identity differs")
    inner_ref = assembly.ref(root, root / "assembly" / "attempt.json")
    require(record["inner_report"] == inner_ref, "owned launcher did not select the original inner report")
    parsed = assembly.verify(root / "assembly", assembly.ref(root / "assembly", root / "assembly" / "attempt.json"))
    inner = parsed["record"]
    require(inner["evidence_root"] == record["evidence_root"]
            and inner["source_root"] == record["source_root"]
            and inner["declaration_path"] == record["declaration_path"]
            and inner["custody_root"] == str(original / "assembly"),
            "inner assembly did not belong to the owned runner")
    require(started <= dt.datetime.fromisoformat(inner["started_at"])
            and dt.datetime.fromisoformat(inner["finished_at"]) <= finished,
            "inner assembly interval escapes the owned launcher")
    source_files = assembly.read(assembly.check_ref(root / "assembly", parsed["frozen"]["source-files.json"]["file"]))
    require(record["source_files_sha256"] == parsed["frozen"]["source-files.json"]["file"]["sha256"]
            and record["source_scripts"] == {name: source_files[name]["sha256"] for name in assembly.SCRIPTS}
            and record["source_scripts"][LAUNCHER] == sha256(Path(__file__)),
            "owned launcher source identity differs from frozen source")
    inputs = parsed["inputs"]
    require(record["tools"] == inputs["tools"] and record["declaration"]["sha256"] == inner["declaration"]["sha256"],
            "owned launcher tool or declaration identity differs")
    assembly.check_ref(root, record["declaration"])
    process = check_runner(root, record["runner_process"], inputs, record["source_root"],
                           record["evidence_root"], record["declaration_path"], original)
    ledger_path = assembly.check_ref(root, record["group_ledger"])
    require(ledger_path == root / GROUP_LEDGER and
            process.get("group_ledger") == record["group_ledger"] and
            process.get("descendant_census") == record["descendant_census"],
            "runner group ledger or terminal census differs")
    census_path = assembly.check_ref(root, record["descendant_census"])
    require(census_path == root / TERMINAL_CENSUS, "descendant census path differs")
    census = assembly.read(census_path)
    assembly.exact(census, {"schema", "ledger_closed", "groups", "complete"}, "descendant census")
    require(isinstance(census["groups"], list), "descendant census groups are missing")
    for item in census["groups"]:
        assembly.exact(item, {"group", "owner_pid", "executable_sha256", "leader_birth",
                              "identity_before", "before", "after", "signals", "errors",
                              "terminal"}, "descendant census row")
    rows, closed = assembly.gate_process.read_group_ledger(ledger_path)
    entries = [row for row in rows if row["kind"] == "group"]
    require(closed and len(entries) == 7 and len(census["groups"]) == 7
            and census["schema"] == 1 and census["ledger_closed"] is True
            and census["complete"] is True and
            [{key: entry[key] for key in ("group", "owner_pid", "executable_sha256", "leader_birth")}
             for entry in entries] ==
            [{key: item[key] for key in ("group", "owner_pid", "executable_sha256", "leader_birth")}
             for item in census["groups"]]
            and all(item["before"] == item["after"] == [] and item["signals"] == []
                    and item["errors"] == [] and item["terminal"] is True for item in census["groups"]),
            "nested descendant terminal census is incomplete or used cleanup")
    require(process["duration_seconds"] <= (finished - started).total_seconds() + 1,
            "runner process exceeds launcher interval")
    expected = child_ledger(root, parsed, process["process_group"])
    require(entries == expected,
            "descendant ledger differs from original process ownership")
    groups = sorted([process["process_group"], *(entry["group"] for entry in expected)])
    return {"record": record, "inner": parsed, "groups": groups}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--native-inputs", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    launch(args.evidence, args.native_inputs, args.output)
    print("Owned repeatable assembly verified: " + str(args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
