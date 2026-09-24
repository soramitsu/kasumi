#!/usr/bin/env python3
"""Retain native dependency tests, named regressions and a reviewed scan.

This is an unregistered G11 prerequisite, not a release acceptance gate.
The source is the frozen native primary's source, never a replacement checkout.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import sys
import tomllib

import assembly_inputs
import check_dependency_patches
import dependency_advisory
import dependency_git
import gate_process
import package_release
import path_patch_projection
import repeatable_assembly as owned
import release_gate
from release_gate import TOOLCHAIN, inventory, sha256, write_json

SCHEMA = "kasumi-owned-dependency-review-v3"
RUNNER = "scripts/run_dependency_review_owned.py"
SCRIPTS = {
    RUNNER, "scripts/assembly_inputs.py", "scripts/check_dependency_patches.py",
    "scripts/package_release.py", "scripts/repeatable_assembly.py",
    "scripts/release_gate.py", "scripts/gate_process.py",
    "scripts/verify_release_acceptance.py", "scripts/test_check_dependency_patches.py",
    "scripts/test_run_dependency_review_owned.py", "scripts/dependency_advisory.py",
    "scripts/dependency_git.py", "scripts/path_patch_projection.py",
    "scripts/run_dependency_review_launcher.py", "scripts/run_repeatable_assembly_owned.py",
}
REFERENCE = "aarch64-unknown-linux-gnu"
JOBS = 2
TIMEOUT = 14400
EXPECTED = {
    "vendor/bitmaps-3.2.1": {"bitmaps"},
    "vendor/lru-0.16.4": {"lru"},
    "vendor/serde_json-1.0.151": {"serde_json"},
    "vendor/rmcp-3.2.0": {"rmcp"},
    "vendor/redb-4.2.0": {"redb"},
    "vendor/openraft-0.9.25": {"openraft", "openraft-macros"},
}
RUST_RESULT = re.compile(
    r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; "
    r"(\d+) ignored; (\d+) measured; (\d+) filtered out;", re.M)
RUST_LAUNCH = re.compile(r"^ {3,}Running (.+) \([^)]+\)$", re.M)
DOC_LAUNCH = re.compile(r"^ {3,}Doc-tests ([\w-]+)$", re.M)
PYTHON_RESULT = re.compile(r"^Ran (\d+) tests? in [0-9.]+s$", re.M)
VERIFIED = re.compile(r"^verified ([\w-]+) (\S+) \((vendor/[^)]+)\)$", re.M)
TEST_VERDICT = re.compile(r"^test (.+?) \.\.\. (ok|FAILED|ignored)(?: .*)?$", re.M)
MEMORY_SAFETY = (
    {"id": "bitmaps-invalid-bool", "step": "bitmaps-3-2-1-all-targets",
     "name": "bitmap::test::one_bit_decode_rejects_all_invalid_bool_representations",
     "source": "vendor/bitmaps-3.2.1/src/bitmap.rs", "advisory": "RUSTSEC-2025-0167"},
    {"id": "bitmaps-no-mutable-bytes", "step": "bitmaps-3-2-1-doctests",
     "name": "src/lib.rs - (line {line})", "source": "vendor/bitmaps-3.2.1/src/lib.rs",
     "advisory": "RUSTSEC-2025-0167"},
    {"id": "lru-panicking-drop", "step": "lru-0-16-4-all-targets",
     "name": "tests::pop_panicking_key_drop_preserves_list",
     "source": "vendor/lru-0.16.4/src/lib.rs", "advisory": "RUSTSEC-2026-0253"},
    {"id": "lru-mut-iterator", "step": "lru-0-16-4-all-targets",
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


def suite_roster(source, manifest):
    """Select lock-backed reviewed crates; expose excluded unlocked manifests."""
    require(manifest.get("format") == 2 and isinstance(manifest.get("inventories"), list),
            "unsupported reviewed vendor manifest")
    suites = []
    seen = set()
    for item in manifest["inventories"]:
        root = item.get("path")
        require(root in EXPECTED and root not in seen, "unknown or duplicate reviewed vendor root")
        seen.add(root)
        packages = item.get("packages")
        require(isinstance(packages, list) and
                {package.get("name") for package in packages} == EXPECTED[root] and
                len(packages) == len(EXPECTED[root]), "reviewed package roster differs")
        files = item.get("files")
        require(isinstance(files, dict) and {"Cargo.toml", "Cargo.lock"}.issubset(files),
                "reviewed vendor root manifest is absent")
        cargo = tomllib.loads((source / root / "Cargo.toml").read_text())
        workspace = root == "vendor/openraft-0.9.25"
        excluded_unlocked = []
        if workspace:
            workspace_table = cargo.get("workspace", {})
            members = workspace_table.get("members")
            excluded = workspace_table.get("exclude", [])
            require(isinstance(members, list) and members and
                    all(isinstance(member, str) and member and
                        "/" not in member and "*" not in member and
                        member + "/Cargo.toml" in files for member in members),
                    "OpenRaft workspace members are not all reviewed")
            require({"openraft", "macros", "tests"}.issubset(members),
                    "OpenRaft upstream integration suites are absent")
            require(isinstance(excluded, list) and all(isinstance(name, str) and
                    name + "/Cargo.toml" in files and name + "/Cargo.lock" not in files
                    for name in excluded), "OpenRaft excluded manifests need separate lock review")
            expected_manifests = {"Cargo.toml"} | {name + "/Cargo.toml"
                                                   for name in members + excluded}
            require({name for name in files if name.endswith("Cargo.toml")} == expected_manifests,
                    "unclassified reviewed OpenRaft package manifest")
            excluded_unlocked = sorted(excluded)
        else:
            require(cargo.get("package", {}).get("name") in EXPECTED[root] and
                    "workspace" not in cargo, "vendored package suite selection differs")
            expected_manifests = {"Cargo.toml"}
            if root == "vendor/redb-4.2.0":
                expected_manifests.add("crates/redb-derive/Cargo.toml")
            require({name for name in files if name.endswith("Cargo.toml")} == expected_manifests,
                    "unclassified reviewed vendor package manifest")
        suites.append({"root": root, "packages": sorted(EXPECTED[root]),
                       "workspace": workspace, "manifest_sha256": sha256(source / root / "Cargo.toml"),
                       "declared_tests": len(cargo.get("test", [])),
                       "excluded_unlocked": excluded_unlocked})
        if root == "vendor/redb-4.2.0":
            relative = "crates/redb-derive"
            require(relative + "/Cargo.lock" in files,
                    "reviewed redb-derive test suite lacks a lockfile")
            derive = tomllib.loads((source / root / relative / "Cargo.toml").read_text())
            require(derive.get("package", {}).get("name") == "redb-derive" and
                    derive["package"].get("version") == "0.1.0" and "workspace" not in derive,
                    "reviewed redb-derive suite identity differs")
            suites.append({"root": root + "/" + relative, "packages": ["redb-derive"],
                           "workspace": False,
                           "manifest_sha256": sha256(source / root / relative / "Cargo.toml"),
                           "declared_tests": len(derive.get("test", [])),
                           "excluded_unlocked": []})
    require(seen == set(EXPECTED), "reviewed vendor suites are incomplete")
    return sorted(suites, key=lambda item: item["root"])


def commands(inputs, source, suites):
    python = inputs["tools"]["python"]["path"]
    cargo = inputs["tools"]["cargo"]["path"]
    rustc = inputs["tools"]["rustc"]["path"]
    result = [
        ("cargo-version", [cargo, "-Vv"], "probe"),
        ("rustc-version", [rustc, "-vV"], "probe"),
        ("python-version", [python, "-B", "-S", "--version"], "probe"),
        ("official-verifier", [python, "-B", "-S", str(source / "scripts/check_dependency_patches.py")], "verifier"),
        ("python-regressions", [python, "-B", "-S", "-m", "unittest", "discover",
                                 "-s", "scripts", "-p", "test_check_dependency_patches.py", "-v"], "python"),
    ]
    for suite in suites:
        root = suite["root"]
        name = Path(root).name.replace(".", "-").replace("_", "-")
        modes = [("", ["--all-features"])]
        if root == "vendor/serde_json-1.0.151":
            modes = [
                ("default", []),
                ("arbitrary-precision", ["--features", "arbitrary_precision"]),
                ("raw-value", ["--features", "raw_value"]),
                ("combined", ["--features", "arbitrary_precision,raw_value,float_roundtrip,preserve_order"]),
            ]
        for label, features in modes:
            case = name + ("-" + label if label else "")
            base = [cargo, "test", "--manifest-path", str(source / root / "Cargo.toml")]
            if suite["workspace"]:
                base += ["--workspace"]
            base += ["--locked", "--offline", *features, "--no-fail-fast", "-j", str(JOBS)]
            result.append((case + "-all-targets", base + ["--all-targets", "--", "--test-threads=2"], "rust"))
            result.append((case + "-doctests", base + ["--doc", "--", "--test-threads=2"], "rust"))
    return result


def parse_counts(kind, stdout, stderr, expected_packages, *, rust_mode=None):
    combined = stdout + "\n" + stderr
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
        launches = targets if rust_mode == "targets" else doctests
        unexpected = doctests if rust_mode == "targets" else targets
        totals = {"suites": len(rows), "passed": 0, "failed": 0, "ignored": 0,
                  "measured": 0, "filtered": 0, "launched": len(launches),
                  "targets": targets, "doctests": doctests}
        for status, passed, failed, ignored, measured, filtered in rows:
            for key, value in zip(("passed", "failed", "ignored", "measured", "filtered"),
                                  (passed, failed, ignored, measured, filtered)):
                totals[key] += int(value)
            if status == "FAILED" and int(failed) == 0:
                totals["failed"] += 1
        totals["complete"] = (bool(rows) and len(rows) == len(launches) and not unexpected
                              and all((status == "ok") == (int(failed) == 0)
                                      for status, _, failed, _, _, _ in rows))
        totals["tests"] = totals["passed"] + totals["failed"]
        totals["failed_names"] = sorted(set(re.findall(r"(?m)^test (\S+) \.\.\. FAILED$", combined)))
        return totals
    return {"complete": True}


def run_step(output, source, environment, name, command, kind, expected_packages):
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
    mode = "doc" if name.endswith("-doctests") else "targets" if kind == "rust" else None
    counts = (parse_counts(kind, stdout, stderr, expected_packages, rust_mode=mode)
              if clean else {"complete": False})
    return {"id": name, "kind": kind, "command": command, "process": item,
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
                        operation, selected, "git", [])
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


def run(evidence, declaration, advisory_declaration, output):
    require(sys.version_info >= (3, 11) and sys.dont_write_bytecode and sys.flags.no_site,
            "run with native Python 3.11+ -B -S")
    require(not os.environ.get("PYTHONPATH") and not os.environ.get("PYTHONHOME"),
            "dependency runner cannot inherit Python import overrides")
    evidence = Path(evidence).resolve(strict=True)
    declaration = Path(declaration).resolve(strict=True)
    advisory_declaration = Path(advisory_declaration).resolve(strict=True)
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
              "source": None, "source_scripts": None,
              "manifest_sha256": None, "suites": None, "toolchain": None,
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
        suites = suite_roster(source, manifest)
        expected_packages = [(p["name"], p["version"], p["path"])
                             for item in manifest["inventories"] for p in item["packages"]]
        record["manifest_sha256"] = sha256(source / "vendor/patch-manifest.json")
        record["suites"] = suites
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
        selected = commands(inputs, source, suites)
        for name, command, kind in selected:
            record["steps"].append({"id": name, "kind": kind, "command": command,
                                    "status": "dispatching", "process": None})
            write_json(attempt, record)
            step = run_step(output, source, environment, name, command, kind, expected_packages)
            record["steps"][-1] = step
            write_json(attempt, record)
            if kind == "probe" and step["exit_code"] == 0:
                record["toolchain"]["probes"][name] = check_probe(step, output, target)
                write_json(attempt, record)
            require(step["owned_clean"], "dependency child was interrupted or not fully drained")
            require(inventory(source) == files and
                    sha256(source / "vendor/patch-manifest.json") == record["manifest_sha256"],
                    "test changed frozen source inputs")
            if kind in {"probe", "verifier"}:
                require(step["exit_code"] == 0 and step["counts"]["complete"],
                        "native probe or official patch verifier failed")
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
        scan = run_step(output, source, environment, "advisory-scan", selected_scan, "advisory", [])
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
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run(args.evidence, args.native_inputs, args.advisory_inputs, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
