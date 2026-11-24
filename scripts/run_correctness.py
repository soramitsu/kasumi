#!/usr/bin/env python3
"""Run the reviewed fault scenarios against test binaries from the primary native build."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import sys
import tomllib

if __name__ == "__main__":
    scripts = Path(__file__).resolve().parent
    if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode
            and sys.pycache_prefix is None and "PYTHONPYCACHEPREFIX" not in os.environ):
        raise SystemExit("correctness requires Python -I -B -S")
    if any(path.name == "__pycache__" or path.suffix in {".pyc", ".pyo"}
           or (path.suffix == ".py" and path.is_symlink()) for path in scripts.rglob("*")):
        raise SystemExit("correctness requires source-only Python imports")
    sys.path.insert(0, str(scripts))

import domain_run
from domain_run import require
import package_release as package
import repeatable_assembly as owned
from release_gate import sha256
import verify_release_acceptance as acceptance

KIND = "correctness"
RUNNER = "scripts/run_correctness.py"
CONFIG = "release/correctness-cases.json"
TIMEOUT = 1200


def load_cases(path):
    cases = owned.read(path)
    require(isinstance(cases, dict) and set(cases) == acceptance.SCENARIOS[KIND],
            "correctness scenario roster differs")
    seen = set()
    for rows in cases.values():
        require(isinstance(rows, list) and rows, "correctness scenario has no tests")
        for row in rows:
            require(isinstance(row, list) and len(row) == 3
                    and re.fullmatch(r"kasumi-[a-z]+", row[0])
                    and all(re.fullmatch(r"[a-z0-9_]+", name) for name in row[1:])
                    and tuple(row) not in seen, "invalid or repeated correctness test")
            seen.add(tuple(row))
    return cases


def artifacts(evidence, functional, cases):
    workspace, = (gate for gate in functional["gates"] if gate["name"] == "workspace")
    process = owned.read(package.verify_file(evidence, workspace["process"], workspace["process_sha256"]))
    original = Path(process["working_directory"])
    version = tomllib.loads((evidence / "source/Cargo.toml").read_text())["workspace"]["package"]["version"]
    result = {}
    for crate, target in sorted({tuple(row[:2]) for rows in cases.values() for row in rows}):
        crate_id = "path+" + (original / "crates" / crate).as_uri() + "#"
        matches = [(path, item) for path, item in workspace["executables"].items()
                   if item["target"] == target and item["test"] is True
                   and item["package_id"] in {crate_id + version, crate_id + crate + "@" + version}]
        require(len(matches) == 1, "correctness test target missing or ambiguous: " + target)
        path, item = matches[0]
        package.verify_file(evidence / "target", path, item["sha256"])
        result[crate, target] = (path, item["sha256"])
    return result


def test_list(raw):
    items = {}
    for line in raw.decode().splitlines():
        match = re.fullmatch(r"(\S+): (test|benchmark)", line)
        require(match and match[1] not in items, "invalid or duplicate libtest listing")
        items[match[1]] = match[2]
    require(items, "empty libtest listing")
    return items


def resolve(items, leaf):
    matches = [name for name, kind in items.items() if kind == "test" and name.split("::")[-1] == leaf]
    require(len(matches) == 1, "correctness test missing or ambiguous: " + leaf)
    return matches[0]


def check_pass(raw, name, total):
    output = raw.decode().splitlines()
    require(output.count("running 1 test") == 1 and output.count("test " + name + " ... ok") == 1,
            "exact correctness test did not pass: " + name)
    summaries = [line for line in output if line.startswith("test result:")]
    require(len(summaries) == 1 and re.fullmatch(
        rf"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; {total - 1} filtered out; finished in [0-9.]+s",
        summaries[0]), "incorrect libtest totals: " + name)


def replay(cases, selected, evidence_path, perform):
    listings, rows = {}, {}
    for index, (target, (relative, digest)) in enumerate(sorted(selected.items())):
        binary = str(evidence_path / "target" / relative)
        raw = perform(f"list-{index:02}", [binary, "--list", "--format", "terse"], digest, None)
        listings[target] = test_list(raw)
    for scenario, tests in sorted(cases.items()):
        rows[scenario] = []
        for index, (crate, target, leaf) in enumerate(tests):
            relative, digest = selected[crate, target]
            listing = listings[crate, target]
            name = resolve(listing, leaf)
            binary = str(evidence_path / "target" / relative)
            step = f"{scenario}-{index:02}"
            command = [binary, "--exact", name, "--test-threads=1", "--format", "pretty"]
            check_pass(perform(step, command, digest, scenario), name, len(listing))
            rows[scenario].append(step)
    return rows


def execute(run):
    run.bind()
    config = run.configuration("correctness-cases", run.source / CONFIG)
    cases = load_cases(config)
    primary = run.evidence / "evidence.json"
    selected = artifacts(run.evidence, owned.read(primary), cases)

    def perform(step, command, digest, scenario):
        output = run.command(step, command, TIMEOUT, scenario=scenario)
        require(run.report["processes"][-1]["executable"]["sha256"] == digest,
                "correctness executed another binary: " + step)
        return output.read_bytes()

    replay(cases, selected, run.evidence, perform)
    run.passed({"functional_sha256": sha256(primary)})


def verify_domain(root, domain, files, configs, _, candidates):
    facts = domain_run.verify_run(root, domain, files, configs, KIND, RUNNER, ())
    report, custody = facts["report"], facts["custody"]
    name = domain["id"].split(":")[1]
    primary = candidates[name]["primary"]["functional"]
    primary_path = acceptance.reference(root, primary)
    require(report["details"] == {"functional_sha256": primary["sha256"]}
            and report["invocation"]["parameters"] == {} and domain["artifacts"] == {},
            "correctness run differs from the selected functional evidence")
    configuration = report["configurations"]
    require(len(configuration) == 1 and configuration[0]["id"] == "correctness-cases"
            and configuration[0]["file"]["sha256"] == files[CONFIG]["sha256"],
            "correctness test roster differs from frozen source")
    cases = load_cases(acceptance.reference(custody, configuration[0]["file"]))
    selected = artifacts(primary_path.parent, owned.read(primary_path), cases)
    original = Path(report["evidence_root"])
    processes = iter(report["processes"])

    def perform(step, command, digest, _scenario):
        item = next(processes, None)
        require(item and item["id"] == step and item["executable"]["sha256"] == digest
                and item["receipt"]["path"] == step + "/process.json"
                and item["log"]["path"] == step + "/stdout.log", "correctness process changed: " + step)
        record = facts["receipts"][step]["record"]
        owned.check_owned(custody, {"id": step, "receipt": item["receipt"], "stdout": item["log"],
                                   "stderr": record["stderr"], "executable": item["executable"]},
                          command, str(original / "source"), TIMEOUT)
        return acceptance.reference(custody, item["log"]).read_bytes()

    expected = replay(cases, selected, original, perform)
    require(next(processes, None) is None and all(
        row["expected_exit"] == 0 for rows in facts["scenarios"].values() for row in rows
    ) and expected == {scenario: [row["step"] for row in rows]
                       for scenario, rows in facts["scenarios"].items()},
            "correctness scenarios or process roster differs")
    return facts["evidence"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("evidence", "journal", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--attempt-id", required=True)
    args = parser.parse_args()
    with domain_run.Run(KIND, RUNNER, (), args.evidence, args.output, args.journal,
                        args.attempt_id, {}, domain_run.QUALIFYING) as run:
        execute(run)


if __name__ == "__main__":
    main()
