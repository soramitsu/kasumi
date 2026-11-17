#!/usr/bin/env python3
"""Retain native dependency tests, upstream provenance, regressions and a scan.

The upstream suites are the explicit stable matrix in dependency_matrix; a
suite that needs nightly Rust or an external runtime is recorded as excluded
and never counted as passed. The source is the frozen native primary's source,
never a replacement checkout.
"""
from __future__ import annotations

import sys
if __name__ == "__main__" and not (sys.flags.isolated and sys.flags.no_site
                                  and sys.flags.dont_write_bytecode):
    raise SystemExit("dependency runner requires native Python -I -S -B")

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import shutil
import stat

if __name__ == "__main__":
    _scripts = Path(__file__).resolve(strict=True).parent
    if sys.pycache_prefix is not None or "PYTHONPYCACHEPREFIX" in os.environ:
        raise SystemExit("dependency runner forbids a redirected Python bytecode cache")
    if ((_scripts / "__pycache__").exists() or (_scripts / "__pycache__").is_symlink()
            or any(path.suffix in {".pyc", ".pyo"} or
                   (path.suffix == ".py" and path.is_symlink())
                   for path in _scripts.rglob("*"))):
        raise SystemExit("dependency runner requires source-only Python imports")
    sys.path.insert(0, str(_scripts))

import assembly_inputs
import check_dependency_patches
import dependency_advisory
import dependency_git
import dependency_matrix
import dependency_provenance
import gate_process
import package_release
import path_patch_projection
import repeatable_assembly as owned
import release_gate
from release_gate import TOOLCHAIN, inventory, sha256, write_json

SCHEMA = "kasumi-owned-dependency-review-v4"
RUNNER = "scripts/run_dependency_review_owned.py"
SCRIPTS = {
    RUNNER, "scripts/assembly_inputs.py", "scripts/check_dependency_patches.py",
    "scripts/package_release.py", "scripts/repeatable_assembly.py",
    "scripts/release_gate.py", "scripts/gate_process.py",
    "scripts/verify_release_acceptance.py", "scripts/test_check_dependency_patches.py",
    "scripts/test_run_dependency_review_owned.py", "scripts/dependency_advisory.py",
    "scripts/dependency_git.py", "scripts/dependency_matrix.py",
    "scripts/dependency_provenance.py", "scripts/path_patch_projection.py",
    "scripts/run_dependency_review_launcher.py", "scripts/run_repeatable_assembly_owned.py",
    "scripts/attempt_index.py",
}
REFERENCE = "aarch64-unknown-linux-gnu"
JOBS = 2
TIMEOUT = 14400
ARCHIVES = "upstream-archives"
RUST_RESULT = re.compile(
    r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; "
    r"(\d+) ignored; (\d+) measured; (\d+) filtered out;", re.M)
RUST_LAUNCH = re.compile(r"^ {3,}Running (.+) \([^)]+\)$", re.M)
DOC_LAUNCH = re.compile(r"^ {3,}Doc-tests ([\w-]+)$", re.M)
PYTHON_RESULT = re.compile(r"^Ran (\d+) tests? in [0-9.]+s$", re.M)
VERIFIED = re.compile(r"^verified ([\w-]+) (\S+) \((vendor/[^)]+)\)$", re.M)
TEST_VERDICT = re.compile(r"^test (.+?) \.\.\. (ok|FAILED|ignored)(?: .*)?$", re.M)
MEMORY_SAFETY = (
    {"id": "bitmaps-invalid-bool", "step": "bitmaps-3-2-1-product-targets",
     "name": "bitmap::test::one_bit_decode_rejects_all_invalid_bool_representations",
     "source": "vendor/bitmaps-3.2.1/src/bitmap.rs", "advisory": "RUSTSEC-2025-0167"},
    {"id": "bitmaps-no-mutable-bytes", "step": "bitmaps-3-2-1-product-doctests",
     "name": "src/lib.rs - (line {line})", "source": "vendor/bitmaps-3.2.1/src/lib.rs",
     "advisory": "RUSTSEC-2025-0167"},
    {"id": "lru-panicking-drop", "step": "lru-0-16-4-product-targets",
     "name": "tests::pop_panicking_key_drop_preserves_list",
     "source": "vendor/lru-0.16.4/src/lib.rs", "advisory": "RUSTSEC-2026-0253"},
    {"id": "lru-mut-iterator", "step": "lru-0-16-4-product-targets",
     "name": "tests::iter_mut_stacked_borrows_violation",
     "source": "vendor/lru-0.16.4/src/lib.rs", "advisory": "RUSTSEC-2026-0253"},
)


def require(value, message):
    if not value:
        raise ValueError(message)


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def source_scripts(evidence, source, files):
    require(Path(__file__).resolve(strict=True) == source / RUNNER,
            "dependency runner is not the frozen source executable")
    loaded = {"scripts/assembly_inputs.py": assembly_inputs,
              "scripts/check_dependency_patches.py": check_dependency_patches,
              "scripts/dependency_advisory.py": dependency_advisory,
              "scripts/dependency_git.py": dependency_git,
              "scripts/dependency_matrix.py": dependency_matrix,
              "scripts/dependency_provenance.py": dependency_provenance,
              "scripts/gate_process.py": gate_process,
              "scripts/path_patch_projection.py": path_patch_projection,
              "scripts/package_release.py": package_release,
              "scripts/repeatable_assembly.py": owned,
              "scripts/release_gate.py": release_gate}
    for relative, module in loaded.items():
        require(Path(module.__file__).resolve(strict=True) == source / relative,
                "dependency runner imported an unfrozen module: " + relative)
    result = {}
    for relative in sorted(SCRIPTS):
        expected = files.get(relative)
        require(isinstance(expected, dict) and expected.get("sha256") == sha256(source / relative),
                "dependency runner source differs: " + relative)
        result[relative] = expected["sha256"]
    require(sha256(evidence / "source-files.json") ==
            json.loads((evidence / "evidence.json").read_text())["source_files_sha256"],
            "source inventory differs from the native primary")
    return result


def commands(inputs, source, suites, archives):
    """Every owned child in dispatch order: probes, verifiers, then the matrix."""
    python = inputs["tools"]["python"]["path"]
    cargo = inputs["tools"]["cargo"]["path"]
    rustc = inputs["tools"]["rustc"]["path"]
    fixed = [
        ("cargo-version", [cargo, "-Vv"], "probe"),
        ("rustc-version", [rustc, "-vV"], "probe"),
        ("python-version", [python, "-B", "-S", "--version"], "probe"),
        ("official-verifier", [python, "-B", "-S", str(source / "scripts/check_dependency_patches.py")], "verifier"),
        ("upstream-provenance", [python, "-B", "-S", str(source / dependency_provenance.VERIFIER),
                                 "--archives", str(archives)], "provenance"),
        ("python-regressions", [python, "-B", "-S", "-m", "unittest", "discover",
                                 "-s", "scripts", "-p", "test_check_dependency_patches.py", "-v"], "python"),
    ]
    return [*({"id": name, "kind": kind, "command": command, "mode": None, "launches": None,
               "generated_output": None} for name, command, kind in fixed),
            *dependency_matrix.steps(cargo, source, suites, JOBS)]


def parse_counts(kind, stdout, stderr, expected_packages, *, rust_mode=None, launches=None,
                 expected_output=None):
    combined = stdout + "\n" + stderr
    if kind == "provenance":
        # The child repeats the in-process comparison; its stdout is exact.
        return {"complete": bool(expected_output) and stdout == expected_output and stderr == ""}
    if kind == "verifier":
        found = [(name, version, path) for name, version, path in VERIFIED.findall(stdout)]
        expected_output = "".join(f"verified {name} {version} ({path})\n"
                                  for name, version, path in expected_packages)
        return {"verified_packages": found,
                "complete": bool(expected_packages) and stdout == expected_output and stderr == ""}
    if kind == "python":
        values = PYTHON_RESULT.findall(combined)
        failures = re.findall(r"(?:failures|errors)=(\d+)", combined)
        return {"tests": int(values[0]) if len(values) == 1 else None,
                "failures": sum(map(int, failures)), "complete": len(values) == 1 and int(values[0]) > 0
                and bool(re.search(r"(?m)^(?:OK(?: \([^\n]*\))?|FAILED \([^\n]*\))$", combined))}
    if kind == "rust":
        rows = RUST_RESULT.findall(combined)
        targets = RUST_LAUNCH.findall(combined)
        doctests = DOC_LAUNCH.findall(combined)
        require(rust_mode in {"targets", "doc"}, "unknown Rust suite mode")
        observed = targets if rust_mode == "targets" else doctests
        unexpected = doctests if rust_mode == "targets" else targets
        totals = {"suites": len(rows), "passed": 0, "failed": 0, "ignored": 0,
                  "measured": 0, "filtered": 0, "launched": len(observed),
                  "targets": targets, "doctests": doctests}
        for status, passed, failed, ignored, measured, filtered in rows:
            for key, value in zip(("passed", "failed", "ignored", "measured", "filtered"),
                                  (passed, failed, ignored, measured, filtered)):
                totals[key] += int(value)
            if status == "FAILED" and int(failed) == 0:
                totals["failed"] += 1
        # A matrix command names its test executables; a target Cargo skipped
        # (for example over a missing required feature) is an incomplete run.
        totals["complete"] = (bool(rows) and len(rows) == len(observed) and not unexpected
                              and type(launches) is int and len(observed) == launches
                              and all((status == "ok") == (int(failed) == 0)
                                      for status, _, failed, _, _, _ in rows))
        totals["tests"] = totals["passed"] + totals["failed"]
        totals["failed_names"] = sorted(set(re.findall(r"(?m)^test (\S+) \.\.\. FAILED$", combined)))
        return totals
    return {"complete": True}


def retain_generated(step, source, output):
    """Move a suite's one declared output directory out of the frozen source.

    Call only after the step's process group drained. Every other write stays
    in place for the caller's source comparison and fails the run.
    """
    relative = step["generated_output"]
    if relative is None:
        return None
    path = Path(source)
    for part in Path(relative).parts:
        path = path / part
        require(not path.is_symlink(), "generated suite output path is aliased: " + relative)
    if not os.path.lexists(path):
        return None
    require(stat.S_ISDIR(os.lstat(path).st_mode),
            "generated suite output is not an owned directory: " + relative)
    directory = Path(output) / "generated"
    directory.mkdir(exist_ok=True)
    shutil.move(str(path), str(directory / step["id"]))
    write_json(directory / (step["id"] + "-files.json"), inventory(directory / step["id"]))
    return {"source": relative, "path": "generated/" + step["id"],
            "files": owned.ref(output, directory / (step["id"] + "-files.json"))}


def retain_archives(output, archives):
    """Copy the supplied upstream archives into custody under their own names."""
    archives = Path(archives)
    require(archives.is_absolute() and not archives.is_symlink() and archives.is_dir(),
            "upstream archive directory is absent or aliased")
    directory = Path(output) / ARCHIVES
    directory.mkdir()
    retained = {}
    with os.scandir(archives) as entries:
        names = sorted(entry.name for entry in entries)
    for name in names:
        selected = dependency_provenance.archive_file(archives, name)
        with selected.open("rb") as stream, (directory / name).open("xb") as copy:
            shutil.copyfileobj(stream, copy)
            copy.flush()
            os.fsync(copy.fileno())
        retained[name] = owned.ref(output, directory / name)
        require(retained[name]["sha256"] == sha256(selected),
                "upstream archive changed while retaining bytes")
    return directory, retained


def run_step(output, source, environment, step, expected_packages, expected_output=None):
    name, command, kind = step["id"], step["command"], step["kind"]
    item = owned.run_owned(output, name, command, str(source), environment, TIMEOUT)
    receipt = owned.read(owned.check_ref(output, item["receipt"]))
    owned.check_ref(output, item["executable"])
    require(receipt["command"] == command and receipt["working_directory"] == str(source)
            and receipt["executable"] == {"path": command[0], "sha256": item["executable"]["sha256"]}
            and receipt.get("stdout") == item["stdout"] and receipt.get("stderr") == item["stderr"]
            and receipt.get("timeout_seconds") == TIMEOUT,
            "owned dependency command differs")
    cleanup = receipt["cleanup"]
    group = receipt.get("process_group")
    clean = (type(group) is int and group > 0 and cleanup["group"] == group
             and cleanup["process_returncode"] == receipt["process_exit_code"]
             and receipt["process_exit_code"] == receipt["exit_code"]
             and receipt["status"] == ("passed" if receipt["exit_code"] == 0 else "failed")
             and receipt.get("outputs_stable") is True
             and cleanup["drained"] is True and cleanup["before"] == [] and cleanup["after"] == []
             and cleanup["signals"] == [] and cleanup["errors"] == [] and
             receipt["received_signals"] == [] and receipt["timed_out"] is False and
             receipt["error"] is None)
    if receipt["exit_code"] == 0 and clean:
        owned.check_owned(output, item, command, str(source), TIMEOUT)
    stdout = owned.check_ref(output, item["stdout"]).read_text(errors="replace")
    stderr = owned.check_ref(output, item["stderr"]).read_text(errors="replace")
    counts = (parse_counts(kind, stdout, stderr, expected_packages, rust_mode=step["mode"],
                           launches=step["launches"], expected_output=expected_output)
              if clean else {"complete": False})
    return {"id": name, "kind": kind, "command": command, "process": item,
            "generated": retain_generated(step, source, output) if clean else None,
            "exit_code": receipt["exit_code"], "tool_sha256": item["executable"]["sha256"],
            "drain": cleanup, "owned_clean": clean, "timed_out": receipt["timed_out"],
            "received_signals": receipt["received_signals"], "process_error": receipt["error"],
            "counts": counts}


def named_memory_safety(source, files, steps, output):
    """Map fixed patch cases to one original passing Rust test line each."""
    by_id = {item["id"]: item for item in steps}
    require(len(by_id) == len(steps), "duplicate dependency command")
    results = []
    for case in MEMORY_SAFETY:
        step = by_id.get(case["step"])
        require(step is not None and step["owned_clean"] and step["exit_code"] == 0
                and step["counts"]["complete"], "memory-safety suite is incomplete")
        source_file = source / case["source"]
        require(files[case["source"]]["sha256"] == sha256(source_file),
                "memory-safety regression source differs")
        name = case["name"]
        if "{line}" in name:
            lines = source_file.read_text().splitlines()
            markers = [index + 1 for index, line in enumerate(lines)
                       if line.strip() == "//! ```compile_fail" and
                       any("Kasumi's security patch removes mutable byte access" in previous
                           for previous in lines[max(0, index - 5):index])]
            require(len(markers) == 1, "bitmap compile-fail regression is absent")
            name = name.format(line=markers[0])
        log = step["process"]["stdout"]
        transcript = owned.check_ref(output, log).read_text(errors="replace") + "\n" + \
            owned.check_ref(output, step["process"]["stderr"]).read_text(errors="replace")
        found = [status for test, status in TEST_VERDICT.findall(transcript)
                 if test == name or test == name + " - compile fail"]
        require(found == ["ok"], "named memory-safety regression did not pass exactly once: " + case["id"])
        results.append({**case, "name": name, "source_sha256": files[case["source"]]["sha256"],
                        "log": log, "verdict": "passed"})
    return results


def totals_from_steps(steps):
    tests = [step for step in steps if step["kind"] in {"python", "rust"}]
    rust = [step for step in tests if step["kind"] == "rust"]
    python = [step for step in tests if step["kind"] == "python"]
    require(len(python) == 1, "dependency Python regression step differs")
    return {"commands": len(steps), "test_commands": len(tests),
            "tests": sum(step["counts"].get("tests") or 0 for step in tests),
            "failed": sum(step["counts"].get("failed", 0) or 0 for step in rust)
                      + python[0]["counts"].get("failures", 0),
            "incomplete_commands": [step["id"] for step in tests
                                    if not step["counts"]["complete"]],
            "failed_commands": [step["id"] for step in steps if step["exit_code"] != 0]}


def check_probe(step, output, target):
    stdout = owned.check_ref(output, step["process"]["stdout"]).read_text()
    stderr = owned.check_ref(output, step["process"]["stderr"]).read_text()
    observed = stdout + stderr
    if step["id"] == "python-version":
        matched = re.fullmatch(r"Python (\d+)\.(\d+)\.(\d+)\s*", observed)
        require(matched and tuple(map(int, matched.groups())) >= (3, 11, 0),
                "native Python is not at least 3.11")
    else:
        name = "cargo" if step["id"] == "cargo-version" else "rustc"
        require(observed.splitlines()[0].startswith(name + " " + TOOLCHAIN + " ") and
                re.findall(r"(?m)^host: (\S+)$", observed) == [target],
                "native Rust toolchain or host differs")
    return observed.strip()


def attest_git(output, source, environment, advisory_inputs):
    database = Path(advisory_inputs["database"]["path"])
    dependency_git.prepare(database)
    git = advisory_inputs["git"]["path"]
    declared = advisory_inputs["database"]["commit"]
    steps, outputs = [], {}
    tree = None
    for operation in (dependency_git.OBJECT_FORMAT, dependency_git.HEAD,
                      dependency_git.COMMIT, dependency_git.TREE):
        argument = declared if operation == dependency_git.COMMIT else tree
        selected = dependency_git.command(git, database, operation, argument)
        step = run_step(output, source, dependency_git.environment(environment),
                        {"id": operation, "kind": "git", "command": selected, "mode": None,
                         "launches": None, "generated_output": None}, [])
        steps.append(step)
        require(step["owned_clean"] and step["exit_code"] == 0
                and step["tool_sha256"] == advisory_inputs["git"]["sha256"],
                "advisory Git verification was interrupted or changed")
        stdout = owned.check_ref(output, step["process"]["stdout"]).read_bytes()
        stderr = owned.check_ref(output, step["process"]["stderr"]).read_bytes()
        require(not stderr, "advisory Git verifier wrote stderr")
        outputs[operation] = stdout
        if operation == dependency_git.COMMIT:
            tree = dependency_git.commit_tree(stdout, declared)
    result = dependency_git.verify_outputs(database, declared, outputs)
    return {"steps": steps, "result": result}


def run(evidence, declaration, advisory_declaration, upstream_archives, output):
    require(sys.version_info >= (3, 11) and sys.flags.isolated and sys.dont_write_bytecode
            and sys.flags.no_site, "run with native Python 3.11+ -I -B -S")
    require(not os.environ.get("PYTHONPATH") and not os.environ.get("PYTHONHOME"),
            "dependency runner cannot inherit Python import overrides")
    evidence = Path(evidence).resolve(strict=True)
    declaration = Path(declaration).resolve(strict=True)
    advisory_declaration = Path(advisory_declaration).resolve(strict=True)
    upstream_archives = Path(upstream_archives).resolve(strict=True)
    output = Path(output)
    require(output.is_absolute(), "dependency output must be absolute")
    output = output.resolve()
    source = evidence / "source"
    require(not output.is_relative_to(evidence) and not output.is_relative_to(source),
            "dependency output must be outside the frozen source and evidence")
    output.mkdir(exist_ok=False)
    ledger = os.environ.get(gate_process.GROUP_LEDGER_ENV)
    require(ledger == str(output.parent / "descendant-groups.jsonl") and
            Path(ledger).is_file() and not Path(ledger).is_symlink(),
            "dependency review requires its owned launcher process ledger")
    record = {"schema": SCHEMA, "status": "running", "started_at": now(), "finished_at": None,
              "evidence_root": str(evidence), "source_root": str(source), "custody_root": str(output),
              "declaration_path": str(declaration), "declaration": None,
              "advisory_declaration_path": str(advisory_declaration), "advisory_declaration": None,
              "upstream_archives_path": str(upstream_archives), "upstream_archives": None,
              "upstream_provenance": None,
              "source": None, "selected_primary": None, "source_scripts": None,
              "manifest_sha256": None, "suites": None, "excluded": None, "toolchain": None,
              "steps": [], "totals": None, "memory_safety": None,
              "advisory_projection": None, "advisory_git": None,
              "advisory_scan": None, "error": None}
    attempt = output / "attempt.json"
    write_json(attempt, record)
    try:
        runtime = os.uname()
        require(sys.platform == "linux" and runtime.sysname == "Linux" and
                runtime.machine == "aarch64", "dependency review requires a native Linux ARM64 runtime")
        functional, _, target, _ = package_release.verify_evidence(evidence)
        require(target == REFERENCE, "dependency review requires native Linux ARM64 reference")
        record["selected_primary"] = owned.retain(output, evidence / "evidence.json")
        require(owned.read(owned.check_ref(output, record["selected_primary"])) == functional,
                "retained dependency primary differs from verified functional evidence")
        inputs = assembly_inputs.validate_declaration(owned.read(declaration))
        advisory_inputs = owned.read(advisory_declaration)
        require(inputs["target"] == target and
                str(Path(sys.executable).resolve(strict=True)) == inputs["tools"]["python"]["path"],
                "declared native interpreter or target differs")
        for tool in inputs["tools"].values():
            package_release.verify_architecture(tool["path"], target)
        owned.check_config_ancestry(source, inputs["cargo_home"])
        files = owned.read(evidence / "source-files.json")
        require(inventory(source) == files, "frozen source inventory differs")
        record["source_scripts"] = source_scripts(evidence, source, files)
        record["declaration"] = owned.retain(output, declaration)
        record["advisory_declaration"] = owned.retain(output, advisory_declaration)
        require(sha256(declaration) == record["declaration"]["sha256"]
                and sha256(advisory_declaration) == record["advisory_declaration"]["sha256"],
                "dependency input declaration changed")
        package_release.verify_architecture(advisory_inputs["scanner"]["path"], target)
        package_release.verify_architecture(advisory_inputs["git"]["path"], target)
        record["source"] = {"commit": functional["source_commit"], "tree": functional["source_tree"],
                            "archive_sha256": functional["source_archive_sha256"],
                            "source_files_sha256": functional["source_files_sha256"],
                            "lockfile_sha256": functional["lockfile_sha256"]}
        manifest = check_dependency_patches.read_json(source / "vendor/patch-manifest.json")
        check_dependency_patches.verify_sources(source)
        projected, binding = path_patch_projection.project(source)
        projection = output / "advisory-projection"
        projection.mkdir()
        (projection / "Cargo.lock").write_text(projected)
        write_json(projection / "binding.json", binding)
        require(path_patch_projection.verify_projection(
                    source, projection / "Cargo.lock", projection / "binding.json") == binding,
                "advisory projection differs from frozen lock")
        record["advisory_projection"] = {
            "lock": owned.ref(output, projection / "Cargo.lock"),
            "binding": owned.ref(output, projection / "binding.json")}
        suites = dependency_matrix.roster(source, manifest)
        expected_packages = [(p["name"], p["version"], p["path"])
                             for item in manifest["inventories"] for p in item["packages"]]
        record["manifest_sha256"] = sha256(source / "vendor/patch-manifest.json")
        record["suites"] = suites
        record["excluded"] = dependency_matrix.exclusions(suites)
        archives, record["upstream_archives"] = retain_archives(output, upstream_archives)
        record["upstream_provenance"] = dependency_provenance.verify(source, archives)
        provenance_output = dependency_provenance.summary(record["upstream_provenance"])
        write_json(attempt, record)
        home = output / "home"
        home.mkdir()
        environment = assembly_inputs.environment(inputs, home)
        environment["CARGO_TARGET_DIR"] = str(output / "target")
        record["advisory_git"] = attest_git(output, source, environment, advisory_inputs)
        database_files, decisions, packages = dependency_advisory.inspect_declaration(
            advisory_inputs, source, projection / "Cargo.lock", now(),
            {case["id"] for case in MEMORY_SAFETY},
            record["advisory_git"]["result"]["commit"])
        record["toolchain"] = {"target": target, "runtime": {"sys_platform": sys.platform,
                               "uname_system": runtime.sysname, "uname_machine": runtime.machine},
                               "pinned_version": TOOLCHAIN,
                               "tools": inputs["tools"], "probes": {}}
        write_json(attempt, record)
        selected = commands(inputs, source, suites, archives)
        for planned in selected:
            name, kind = planned["id"], planned["kind"]
            record["steps"].append({"id": name, "kind": kind, "command": planned["command"],
                                    "status": "dispatching", "process": None})
            write_json(attempt, record)
            step = run_step(output, source, environment, planned, expected_packages,
                            provenance_output)
            record["steps"][-1] = step
            write_json(attempt, record)
            if kind == "probe" and step["exit_code"] == 0:
                record["toolchain"]["probes"][name] = check_probe(step, output, target)
                write_json(attempt, record)
            require(step["owned_clean"], "dependency child was interrupted or not fully drained")
            require(inventory(source) == files and
                    sha256(source / "vendor/patch-manifest.json") == record["manifest_sha256"],
                    "test changed frozen source inputs")
            if kind in {"probe", "verifier", "provenance"}:
                require(step["exit_code"] == 0 and step["counts"]["complete"],
                        "native probe, patch verifier or upstream provenance check failed")
        record["totals"] = totals_from_steps(record["steps"])
        require(len(record["steps"]) == len(selected) and not record["totals"]["incomplete_commands"]
                and not record["totals"]["failed_commands"] and record["totals"]["failed"] == 0,
                "one or more dependency upstream suites failed or had no test summary")
        record["memory_safety"] = named_memory_safety(source, files, record["steps"], output)
        write_json(attempt, record)
        scan_started = now()
        latest_files, latest_decisions, latest_packages = dependency_advisory.inspect_declaration(
            advisory_inputs, source, projection / "Cargo.lock", scan_started,
            {case["id"] for case in MEMORY_SAFETY},
            record["advisory_git"]["result"]["commit"])
        require(latest_files == database_files and latest_decisions == decisions
                and latest_packages == packages,
                "advisory inputs changed during dependency suites")
        db_copy = dependency_advisory.retain_database(output, advisory_inputs["database"]["path"], database_files)
        git_outputs = {step["id"]: owned.check_ref(output, step["process"]["stdout"]).read_bytes()
                       for step in record["advisory_git"]["steps"]}
        require(dependency_git.verify_outputs(db_copy, advisory_inputs["database"]["commit"], git_outputs)
                == record["advisory_git"]["result"],
                "retained advisory Git tree differs")
        require(dependency_advisory.canonical_hash(inventory(advisory_inputs["database"]["path"])) ==
                advisory_inputs["database"]["files_sha256"], "advisory database changed before scan")
        selected_scan = dependency_advisory.command(advisory_inputs, projection / "Cargo.lock", db_copy)
        scan = run_step(output, source, environment,
                        {"id": "advisory-scan", "kind": "advisory", "command": selected_scan,
                         "mode": None, "launches": None, "generated_output": None}, [])
        record["advisory_scan"] = {"step": scan, "started_at": scan_started, "finished_at": None,
                                   "database_files": owned.ref(output, output / "advisory-db-files.json"),
                                   "findings": None, "dispositions": None}
        write_json(attempt, record)
        require(scan["owned_clean"] and scan["exit_code"] in {0, 1} and
                scan["tool_sha256"] == advisory_inputs["scanner"]["sha256"],
                "advisory scanner was interrupted, changed or returned an unsupported code")
        report = owned.read(owned.check_ref(output, scan["process"]["stdout"]))
        findings = dependency_advisory.parse_report(report, packages)
        resolved = dependency_advisory.reconcile(
            findings, decisions, {case["id"]: case["verdict"] for case in record["memory_safety"]})
        require(scan["exit_code"] == (1 if report["vulnerabilities"]["found"] else 0),
                "scanner exit code differs from its findings")
        require(dependency_advisory.canonical_hash(inventory(db_copy)) ==
                advisory_inputs["database"]["files_sha256"] and
                dependency_advisory.canonical_hash(inventory(advisory_inputs["database"]["path"])) ==
                advisory_inputs["database"]["files_sha256"] and
                path_patch_projection.verify_projection(
                    source, projection / "Cargo.lock", projection / "binding.json") == binding,
                "advisory database or projected lock changed during scan")
        require(sha256(declaration) == record["declaration"]["sha256"] and
                sha256(advisory_declaration) == record["advisory_declaration"]["sha256"] and
                inventory(source) == files, "dependency source or input declaration changed")
        require(dependency_provenance.verify(source, archives) == record["upstream_provenance"],
                "retained upstream archives changed during dependency review")
        record["advisory_scan"]["findings"] = resolved
        record["advisory_scan"]["dispositions"] = list(decisions.values())
        record["advisory_scan"]["finished_at"] = now()
        record["status"] = "passed-reviewed-native-dependencies"
    except BaseException as error:
        record["status"] = "interrupted" if isinstance(error, KeyboardInterrupt) else "failed"
        record["error"] = repr(error)
        raise
    finally:
        record["finished_at"] = now()
        write_json(attempt, record)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--native-inputs", type=Path, required=True)
    parser.add_argument("--advisory-inputs", type=Path, required=True)
    parser.add_argument("--upstream-archives", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run(args.evidence, args.native_inputs, args.advisory_inputs, args.upstream_archives, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
