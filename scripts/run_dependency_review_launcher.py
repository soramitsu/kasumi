#!/usr/bin/env python3
"""Own the frozen native dependency-review runner and all its child groups.

No release acceptance adapter is registered by this prerequisite.
"""
from __future__ import annotations

import sys
if __name__ == "__main__" and not (sys.flags.isolated and sys.flags.no_site
                                  and sys.flags.dont_write_bytecode):
    raise SystemExit("dependency launcher requires native Python -I -S -B")

import argparse
import datetime as dt
import os
from pathlib import Path

if __name__ == "__main__":
    _scripts = Path(__file__).resolve(strict=True).parent
    if sys.pycache_prefix is not None or "PYTHONPYCACHEPREFIX" in os.environ:
        raise SystemExit("dependency launcher forbids a redirected Python bytecode cache")
    if ((_scripts / "__pycache__").exists() or (_scripts / "__pycache__").is_symlink()
            or any(path.suffix in {".pyc", ".pyo"} or
                   (path.suffix == ".py" and path.is_symlink())
                   for path in _scripts.rglob("*"))):
        raise SystemExit("dependency launcher requires source-only Python imports")
    sys.path.insert(0, str(_scripts))

import attempt_index
import assembly_inputs
import check_dependency_patches
import dependency_advisory
import dependency_git
import path_patch_projection
import repeatable_assembly as owned
import run_dependency_review_owned as review
import run_repeatable_assembly_owned as shared
import release_gate
from release_gate import inventory, sha256, write_json

SCHEMA = "kasumi-owned-dependency-launcher-v2"
LAUNCHER = "scripts/run_dependency_review_launcher.py"
TIMEOUT = 86400
GROUP_LEDGER = "descendant-groups.jsonl"
TERMINAL_CENSUS = "descendant-census.json"


def require(value, message):
    if not value:
        raise ValueError(message)


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def command(inputs, source, evidence, declaration, advisory, output):
    return [inputs["tools"]["python"]["path"], "-I", "-B", "-S", str(Path(source) / review.RUNNER),
            "--evidence", str(evidence), "--native-inputs", str(declaration),
            "--advisory-inputs", str(advisory), "--output", str(Path(output) / "review")]


def source_scripts(evidence, source):
    files = owned.read(Path(evidence) / "source-files.json")
    require(isinstance(files, dict), "frozen source inventory is absent")
    scripts = {}
    for relative in review.SCRIPTS:
        entry = files.get(relative)
        require(isinstance(entry, dict) and entry.get("sha256") == sha256(Path(source) / relative),
                "frozen dependency launcher source differs: " + relative)
        scripts[relative] = entry["sha256"]
    require(Path(__file__).resolve(strict=True) == Path(source) / LAUNCHER,
            "dependency launcher is not the frozen source executable")
    loaded = {"scripts/assembly_inputs.py": assembly_inputs,
              "scripts/attempt_index.py": attempt_index,
              "scripts/check_dependency_patches.py": check_dependency_patches,
              "scripts/dependency_advisory.py": dependency_advisory,
              "scripts/dependency_git.py": dependency_git,
              "scripts/path_patch_projection.py": path_patch_projection,
              "scripts/repeatable_assembly.py": owned,
              "scripts/run_dependency_review_owned.py": review,
              "scripts/run_repeatable_assembly_owned.py": shared,
              "scripts/release_gate.py": release_gate}
    for relative, module in loaded.items():
        require(Path(module.__file__).resolve(strict=True) == Path(source) / relative,
                "dependency launcher imported an unfrozen module: " + relative)
    return scripts


def check_child_receipt(root, step, selected, source, allowed_exits):
    """Bind displayed child fields and retained output to one original process."""
    require(step["command"] == selected and step["owned_clean"] is True,
            "dependency child selection or ownership differs")
    item = step["process"]
    owned.exact(item, {"id", "receipt", "stdout", "stderr", "executable"},
                "dependency child process")
    paths = {name: owned.check_ref(root, item[name])
             for name in ("receipt", "stdout", "stderr", "executable")}
    directory = root / step["id"]
    require(item["id"] == step["id"]
            and paths["receipt"] == directory / "process.json"
            and paths["stdout"] == directory / "stdout.log"
            and paths["stderr"] == directory / "stderr.log"
            and paths["executable"] == root / "blobs" / item["executable"]["sha256"],
            "dependency child original artifact paths differ")
    receipt = owned.read(paths["receipt"])
    exit_code = receipt.get("exit_code")
    cleanup = receipt.get("cleanup")
    group = receipt.get("process_group")
    require(type(exit_code) is int and exit_code in allowed_exits
            and receipt.get("command") == selected
            and receipt.get("working_directory") == source
            and receipt.get("executable") == {
                "path": selected[0], "sha256": item["executable"]["sha256"]}
            and receipt.get("stdout") == item["stdout"]
            and receipt.get("stderr") == item["stderr"]
            and receipt.get("timeout_seconds") == review.TIMEOUT
            and receipt.get("process_exit_code") == exit_code
            and receipt.get("status") == ("passed" if exit_code == 0 else "failed")
            and receipt.get("outputs_stable") is True
            and receipt.get("timed_out") is False
            and receipt.get("received_signals") == []
            and receipt.get("error") is None
            and type(group) is int and group > 0
            and isinstance(cleanup, dict) and cleanup.get("group") == group
            and cleanup.get("process_returncode") == exit_code
            and cleanup.get("drained") is True
            and cleanup.get("before") == cleanup.get("after") == []
            and cleanup.get("signals") == cleanup.get("errors") == []
            and step.get("exit_code") == exit_code
            and step.get("tool_sha256") == item["executable"]["sha256"]
            and step.get("drain") == cleanup
            and step.get("timed_out") is False
            and step.get("received_signals") == []
            and step.get("process_error") is None,
            "dependency child receipt or displayed fields differ")
    if exit_code == 0:
        require(owned.check_owned(root, item, selected, source, review.TIMEOUT) == receipt,
                "passing dependency child differs from owned process receipt")
    return receipt, paths


def original_child_entry(receipt, runner_group):
    """Reconstruct a nested ledger row from its original process receipt."""
    group = receipt["process_group"]
    require(type(runner_group) is int and runner_group > 0
            and type(group) is int and group > 0 and group != runner_group
            and "leader_birth" in receipt,
            "dependency child original process identity is missing")
    return {"schema": 1, "kind": "group", "group": group,
            "owner_pid": runner_group,
            "executable_sha256": receipt["executable"]["sha256"],
            "leader_birth": receipt["leader_birth"]}


def child_processes(root, inner, selected, runner_group):
    nested = Path(root) / "review"
    require(len(inner["steps"]) == len(selected) == 25,
            "dependency child command roster differs")
    suite_entries = []
    for step, (name, command_, kind) in zip(inner["steps"], selected):
        require(step["id"] == name and step["kind"] == kind and step["command"] == command_,
                "dependency child command differs")
        receipt, _ = check_child_receipt(nested, step, command_, inner["source_root"], {0})
        stdout = owned.check_ref(nested, step["process"]["stdout"]).read_text(errors="replace")
        stderr = owned.check_ref(nested, step["process"]["stderr"]).read_text(errors="replace")
        mode = "doc" if name.endswith("-doctests") else "targets" if kind == "rust" else None
        packages = []
        if kind == "verifier":
            manifest = check_dependency_patches.read_json(Path(inner["source_root"]) / "vendor/patch-manifest.json")
            packages = [(p["name"], p["version"], p["path"])
                        for item in manifest["inventories"] for p in item["packages"]]
        require(step["counts"] == review.parse_counts(kind, stdout, stderr, packages, rust_mode=mode)
                and step["counts"]["complete"], "dependency child summary differs from original logs")
        suite_entries.append(original_child_entry(receipt, runner_group))
    scan = inner["advisory_scan"]["step"]
    advisory = owned.read(owned.check_ref(root, inner["advisory_declaration"]))
    projection = nested / "advisory-projection" / "Cargo.lock"
    selected_scan = dependency_advisory.command(advisory, projection, nested / "advisory-db")
    require(scan["id"] == "advisory-scan" and scan["kind"] == "advisory"
            and scan["command"] == selected_scan and scan["owned_clean"] is True
            and scan["exit_code"] in {0, 1}, "advisory scanner process differs")
    receipt, _ = check_child_receipt(nested, scan, selected_scan, inner["source_root"], {0, 1})
    require(scan["counts"] == {"complete": True}
            and scan["tool_sha256"] == advisory["scanner"]["sha256"],
            "advisory scanner displayed fields differ")
    scan_entry = original_child_entry(receipt, runner_group)
    git_steps = inner["advisory_git"]["steps"]
    require(len(git_steps) == 4, "advisory Git command roster differs")
    git_operations = (dependency_git.OBJECT_FORMAT, dependency_git.HEAD,
                      dependency_git.COMMIT, dependency_git.TREE)
    tree = inner["advisory_git"]["result"]["tree"]
    git_entries = []
    for step, operation in zip(git_steps, git_operations):
        argument = (advisory["database"]["commit"] if operation == dependency_git.COMMIT
                    else tree if operation == dependency_git.TREE else None)
        selected_git = dependency_git.command(advisory["git"]["path"],
                                               advisory["database"]["path"], operation, argument)
        require(step["id"] == operation and step["kind"] == "git"
                and step["command"] == selected_git and step["owned_clean"] is True
                and step["exit_code"] == 0 and step["tool_sha256"] == advisory["git"]["sha256"],
                "advisory Git child differs")
        process, _ = check_child_receipt(nested, step, selected_git, inner["source_root"], {0})
        require(step["tool_sha256"] == advisory["git"]["sha256"]
                and owned.check_ref(nested, step["process"]["stderr"]).read_bytes() == b""
                and step["counts"] == {"complete": True},
                "advisory Git child was interrupted")
        git_entries.append(original_child_entry(process, runner_group))
    # Git attestation ran before the upstream suites; the advisory scan ran
    # after them. The ledger must preserve that original admission order.
    expected = [*git_entries, *suite_entries, scan_entry]
    require(len(expected) == len({row["group"] for row in expected}) == 30,
            "dependency process groups are not distinct")
    return expected


def check_child_custody(rows, closed, census, expected):
    """Join every terminal census row to the corresponding original child."""
    entries = [row for row in rows if row["kind"] == "group"]
    require(closed and len(entries) == len(expected) == len(census["groups"]) == 30
            and entries == expected
            and census["schema"] == 1 and census["ledger_closed"] is True
            and census["complete"] is True
            and [(row["group"], row["owner_pid"], row["executable_sha256"], row["leader_birth"])
                 for row in entries] ==
                [(item["group"], item["owner_pid"], item["executable_sha256"], item["leader_birth"])
                 for item in census["groups"]]
            and all(item["before"] == item["after"] == [] and item["signals"] == []
                    and item["errors"] == [] and item["terminal"] is True for item in census["groups"]),
            "dependency child census or original process ownership differs")


def check_selected_primary(root, inner, evidence, source_files_sha256):
    """Reopen the native primary bytes that the child retained before dispatch."""
    root = Path(root).resolve(strict=True)
    evidence = Path(evidence).resolve(strict=True)
    primary_path = owned.check_ref(root / "review", inner["selected_primary"])
    require(primary_path == root / "review" / "blobs" / inner["selected_primary"]["sha256"]
            and inner["selected_primary"]["sha256"] == sha256(evidence / "evidence.json"),
            "dependency runner did not retain its selected native primary")
    functional = owned.read(primary_path)
    require(inner["source"] == {
                "commit": functional["source_commit"],
                "tree": functional["source_tree"],
                "archive_sha256": functional["source_archive_sha256"],
                "source_files_sha256": functional["source_files_sha256"],
                "lockfile_sha256": functional["lockfile_sha256"]}
            and functional["source_files_sha256"] == source_files_sha256,
            "dependency source identity differs from retained native primary")
    return functional


def verify(root):
    """Recalculate verdicts from retained bytes and original process receipts."""
    root = Path(root).resolve(strict=True)
    record = owned.read(root / "launcher.json")
    owned.exact(record, {"schema", "status", "started_at", "finished_at", "evidence_root",
                         "source_root", "custody_root", "declaration_path", "advisory_declaration_path",
                         "source_files_sha256", "source_scripts", "tools", "declaration",
                         "advisory_declaration", "runner_process", "inner_report", "group_ledger",
                         "descendant_census", "error"}, "dependency launcher")
    require(record["schema"] == SCHEMA and record["status"] == "passed" and record["error"] is None,
            "dependency launcher did not pass")
    started = dt.datetime.fromisoformat(record["started_at"])
    finished = dt.datetime.fromisoformat(record["finished_at"])
    require(started.tzinfo is not None and finished.tzinfo is not None and finished > started,
            "dependency launcher interval differs")
    source = Path(record["source_root"])
    evidence = Path(record["evidence_root"])
    require(source == evidence / "source" and Path(record["custody_root"]).is_absolute(),
            "dependency source or custody root differs")
    files = owned.read(evidence / "source-files.json")
    require(record["source_files_sha256"] == sha256(evidence / "source-files.json")
            and inventory(source) == files and
            record["source_scripts"] == {name: files[name]["sha256"] for name in review.SCRIPTS},
            "dependency frozen source differs")
    for name, checksum in record["source_scripts"].items():
        require(sha256(source / name) == checksum, "dependency script changed")
    require(sha256(Path(__file__)) == record["source_scripts"][LAUNCHER],
            "dependency launcher verifier is not the frozen script")
    inputs = owned.read(owned.check_ref(root, record["declaration"]))
    advisory = owned.read(owned.check_ref(root, record["advisory_declaration"]))
    require(record["tools"] == inputs["tools"], "dependency native tools differ")
    selected = command(inputs, source, evidence, record["declaration_path"],
                       record["advisory_declaration_path"], root)
    runner = record["runner_process"]
    process = owned.check_owned(root, runner, selected, str(source), TIMEOUT)
    require(runner["id"] == "runner" and runner["executable"]["sha256"] == inputs["tools"]["python"]["sha256"],
            "dependency top-level Python differs")
    require(record["inner_report"] == owned.ref(root, root / "review" / "attempt.json"),
            "dependency inner report differs")
    inner = owned.read(owned.check_ref(root, record["inner_report"]))
    require(inner["schema"] == review.SCHEMA and inner["status"] == "passed-reviewed-native-dependencies"
            and inner["error"] is None and inner["source_root"] == str(source)
            and inner["evidence_root"] == str(evidence)
            and inner["custody_root"] == str(root / "review")
            and inner["declaration_path"] == record["declaration_path"]
            and inner["advisory_declaration_path"] == record["advisory_declaration_path"]
            and inner["source_scripts"] == record["source_scripts"]
            and inner["declaration"]["sha256"] == record["declaration"]["sha256"]
            and inner["advisory_declaration"]["sha256"] == record["advisory_declaration"]["sha256"],
            "dependency inner run differs from launched source and inputs")
    check_selected_primary(root, inner, evidence, record["source_files_sha256"])
    require(started <= dt.datetime.fromisoformat(inner["started_at"])
            and dt.datetime.fromisoformat(inner["finished_at"]) <= finished,
            "dependency inner interval escapes launcher")
    manifest = check_dependency_patches.read_json(source / "vendor/patch-manifest.json")
    suites = review.suite_roster(source, manifest)
    require(inner["suites"] == suites and inner["manifest_sha256"] == sha256(source / "vendor/patch-manifest.json"),
            "dependency upstream suite roster differs")
    selected_children = review.commands(inputs, source, suites)
    expected_children = child_processes(root, inner, selected_children, process["process_group"])
    totals = review.totals_from_steps(inner["steps"])
    require(inner["totals"] == totals and totals["commands"] == 25
            and totals["test_commands"] == 21 and totals["failed"] == 0
            and totals["incomplete_commands"] == totals["failed_commands"] == [],
            "dependency upstream totals differ from original test receipts")
    toolchain = inner["toolchain"]
    require(toolchain["target"] == review.REFERENCE and toolchain["tools"] == inputs["tools"]
            and toolchain["pinned_version"] == review.TOOLCHAIN
            and toolchain["runtime"] == {"sys_platform": "linux", "uname_system": "Linux",
                                           "uname_machine": "aarch64"},
            "dependency native toolchain identity differs")
    probes = {step["id"]: review.check_probe(step, root / "review", review.REFERENCE)
              for step in inner["steps"] if step["kind"] == "probe"}
    require(toolchain["probes"] == probes and len(probes) == 3,
            "dependency native probes differ from original logs")
    memory = review.named_memory_safety(source, files, inner["steps"], root / "review")
    require(inner["memory_safety"] == memory, "named memory-safety results differ from test logs")
    projection_dir = root / "review" / "advisory-projection"
    projection_lock = owned.check_ref(root / "review", inner["advisory_projection"]["lock"])
    projection_binding = owned.check_ref(root / "review", inner["advisory_projection"]["binding"])
    require(projection_lock == projection_dir / "Cargo.lock" and
            projection_binding == projection_dir / "binding.json",
            "advisory projection custody path differs")
    check_dependency_patches.verify_sources(source)
    binding = path_patch_projection.verify_projection(source, projection_lock, projection_binding)
    require(binding["projected_lock_sha256"] == sha256(projection_lock),
            "advisory projected lock digest differs")
    copied = dict(advisory)
    copied["scanner"] = {**advisory["scanner"], "path": str(owned.check_ref(root / "review", inner["advisory_scan"]["step"]["process"]["executable"]))}
    copied["git"] = {**advisory["git"], "path": str(owned.check_ref(root / "review", inner["advisory_git"]["steps"][0]["process"]["executable"]))}
    copied["database"] = {**advisory["database"], "path": str(root / "review" / "advisory-db")}
    git_outputs = {step["id"]: owned.check_ref(root / "review", step["process"]["stdout"]).read_bytes()
                   for step in inner["advisory_git"]["steps"]}
    require(dependency_git.verify_outputs(copied["database"]["path"],
                                          advisory["database"]["commit"], git_outputs)
            == inner["advisory_git"]["result"],
            "retained advisory Git attestation differs")
    scan_started = dt.datetime.fromisoformat(inner["advisory_scan"]["started_at"])
    scan_finished = dt.datetime.fromisoformat(inner["advisory_scan"]["finished_at"])
    require(scan_started.tzinfo is not None and scan_finished.tzinfo is not None
            and dt.datetime.fromisoformat(inner["started_at"]) <= scan_started < scan_finished
            <= dt.datetime.fromisoformat(inner["finished_at"]),
            "advisory scan interval differs from owned runner")
    database_files, decisions, packages = dependency_advisory.inspect_declaration(
        copied, source, projection_lock, inner["advisory_scan"]["started_at"],
        {case["id"] for case in review.MEMORY_SAFETY},
        inner["advisory_git"]["result"]["commit"],
        require_executable=False)
    require(owned.read(owned.check_ref(root / "review", inner["advisory_scan"]["database_files"])) == database_files,
            "retained advisory database inventory differs")
    scan = inner["advisory_scan"]["step"]
    report = owned.read(owned.check_ref(root / "review", scan["process"]["stdout"]))
    findings = dependency_advisory.parse_report(report, packages)
    resolved = dependency_advisory.reconcile(
        findings, decisions, {case["id"]: case["verdict"] for case in memory})
    require(inner["advisory_scan"]["findings"] == resolved
            and inner["advisory_scan"]["dispositions"] == list(decisions.values())
            and scan["exit_code"] == (1 if report["vulnerabilities"]["found"] else 0),
            "advisory findings, decisions or scanner outcome differ")
    ledger = owned.check_ref(root, record["group_ledger"])
    census_path = owned.check_ref(root, record["descendant_census"])
    require(ledger == root / GROUP_LEDGER and census_path == root / TERMINAL_CENSUS
            and process["group_ledger"] == record["group_ledger"]
            and process["descendant_census"] == record["descendant_census"],
            "dependency group ledger or census differs")
    rows, closed = owned.gate_process.read_group_ledger(ledger)
    census = owned.read(census_path)
    check_child_custody(rows, closed, census, expected_children)
    require(process["cleanup"]["before"] == []
            and process["cleanup"]["after"] == [] and process["cleanup"]["signals"] == [],
            "dependency top-level group was interrupted or reused")
    return {"record": record, "inner": inner,
            "groups": [process["process_group"], *(row["group"] for row in expected_children)]}


def launch(evidence, declaration, advisory_declaration, output):
    require(sys.version_info >= (3, 11) and sys.flags.isolated and sys.dont_write_bytecode
            and sys.flags.no_site, "dependency launcher requires native Python 3.11+ -I -B -S")
    require(not os.environ.get("PYTHONPATH") and not os.environ.get("PYTHONHOME"),
            "dependency launcher cannot inherit Python import overrides")
    require(owned.gate_process.GROUP_LEDGER_ENV not in os.environ,
            "dependency launcher cannot inherit a process group ledger")
    evidence = Path(evidence).resolve(strict=True)
    declaration = Path(declaration).resolve(strict=True)
    advisory_declaration = Path(advisory_declaration).resolve(strict=True)
    output = Path(output)
    require(output.is_absolute(), "dependency launch output must be absolute")
    output = output.resolve()
    require(not output.is_relative_to(evidence), "dependency launch output overlaps frozen evidence")
    output.mkdir(exist_ok=False)
    source = evidence / "source"
    path = output / "launcher.json"
    record = {"schema": SCHEMA, "status": "running", "started_at": now(), "finished_at": None,
              "evidence_root": str(evidence), "source_root": str(source), "custody_root": str(output),
              "declaration_path": str(declaration), "advisory_declaration_path": str(advisory_declaration),
              "source_files_sha256": None, "source_scripts": None, "tools": None,
              "declaration": None, "advisory_declaration": None, "runner_process": None,
              "inner_report": None, "group_ledger": None, "descendant_census": None, "error": None}
    write_json(path, record)
    try:
        inputs = assembly_inputs.validate_declaration(owned.read(declaration))
        require(str(Path(sys.executable).resolve(strict=True)) == inputs["tools"]["python"]["path"],
                "dependency launcher interpreter differs from native declaration")
        record["source_files_sha256"] = sha256(evidence / "source-files.json")
        record["source_scripts"] = source_scripts(evidence, source)
        record["tools"] = inputs["tools"]
        record["declaration"] = owned.retain(output, declaration)
        record["advisory_declaration"] = owned.retain(output, advisory_declaration)
        write_json(path, record)
        home = output / "home"
        home.mkdir()
        environment = assembly_inputs.environment(inputs, home)
        ledger = output / GROUP_LEDGER
        ledger.open("xb").close()
        environment[owned.gate_process.GROUP_LEDGER_ENV] = str(ledger)
        def seal(process):
            owned.gate_process.seal_group_ledger(ledger)
            process["group_ledger"] = owned.ref(output, ledger)
            record["group_ledger"] = process["group_ledger"]
            write_json(path, record)
        def drain_children(process):
            census = shared.terminal_census(output, ledger)
            process["descendant_census"] = owned.ref(output, output / TERMINAL_CENSUS)
            record["descendant_census"] = process["descendant_census"]
            write_json(path, record)
            if not census["complete"] or any(row["signals"] for row in census["groups"]):
                raise ValueError("dependency descendants needed cleanup or were not drained")
        selected = command(inputs, source, evidence, declaration, advisory_declaration, output)
        record["runner_process"] = owned.run_owned(
            output, "runner", selected, str(source), environment, TIMEOUT,
            before_cleanup=seal, after_cleanup=drain_children)
        write_json(path, record)
        owned.check_owned(output, record["runner_process"], selected, str(source), TIMEOUT)
        record["inner_report"] = owned.ref(output, output / "review" / "attempt.json")
        record["status"] = "passed"
        record["finished_at"] = now()
        write_json(path, record)
        verify(output)
        return record
    except BaseException as error:
        record["status"] = "failed"
        record["error"] = repr(error)
        record["finished_at"] = now()
        write_json(path, record)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--native-inputs", type=Path, required=True)
    parser.add_argument("--advisory-inputs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    launch(args.evidence, args.native_inputs, args.advisory_inputs, args.output)
    print("Owned dependency review verified: " + str(args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
