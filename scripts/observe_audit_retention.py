"""Capture and replay the measured audit-retention scenarios on the native reference installation."""
import argparse
import json
import os
from pathlib import Path
import sys

if __name__ == "__main__":
    scripts = Path(__file__).resolve(strict=True).parent
    if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode
            and sys.pycache_prefix is None and "PYTHONPYCACHEPREFIX" not in os.environ):
        raise SystemExit("audit observation requires -I -B -S")
    if any(path.name == "__pycache__" or path.suffix in {".pyc", ".pyo"}
           or (path.suffix == ".py" and path.is_symlink()) for path in scripts.rglob("*")):
        raise SystemExit("audit observation requires source-only Python")
    sys.path.insert(0, str(scripts))

import audit_retention_components as native
import domain_run
import package_release
import repeatable_assembly as owned
import run_audit_replica_observation as replicas
import verify_release_acceptance as acceptance

RUNNER = "scripts/observe_audit_retention.py"
SCHEMA = "kasumi-audit-retention-observations-v1"
SCENARIOS = {"hot-budget-crossing", "verified-contiguous-archives", "archive-outage",
             "replica-dependency-before-prune", "replacement-dependencies"}
OPEN_CATEGORIES = ["incarnations", "sessions"]


def source(evidence):
    functional, _, target, _ = package_release.verify_evidence(evidence)
    files = owned.read(evidence / "source-files.json")
    domain_run.frozen_scripts(evidence / "source", files,
                              {RUNNER, native.RUNNER, replicas.RUNNER, *native.MODULES, *replicas.MODULES})
    domain_run.require(target == acceptance.REFERENCE, "audit installation must use the native reference target")
    return functional


def combined(evidence, directory):
    domain_run.require(acceptance.SCENARIOS["audit-retention"] == SCENARIOS | {"permanent-identity-lifetime-ceiling"},
                       "the release audit scenario contract changed")
    functional = source(evidence)
    native_custody = package_release.owned_directory(directory, "native")
    replica_custody = package_release.owned_directory(directory, "replicas")
    library = native.verify_components(evidence, native_custody)
    installation = replicas.replay(evidence, replica_custody)
    return {
        "schema": SCHEMA, "status": "measured", "qualification": "component",
        "target": acceptance.REFERENCE, "source_commit": functional["source_commit"],
        "functional_sha256": owned.sha256(evidence / "evidence.json"),
        "native_report_sha256": owned.sha256(package_release.owned_file(native_custody, "report.json")),
        "replica_report_sha256": owned.sha256(package_release.owned_file(replica_custody, "report.json")),
        "verified_scenarios": sorted(SCENARIOS),
        "replica_observations": installation,
        "lifetime_counts": {
            "commands": library["custody-1"]["commands"],
            "receipts": library["receipts-1"]["restored_count"],
            "lifecycle": library["lifecycle-1"]["selected_intents"],
        },
        "outstanding_lifetime_categories": OPEN_CATEGORIES,
    }


def collect(evidence, directory, journal, attempt, plan, topology):
    source(evidence)
    domain_run.require(not directory.is_relative_to(evidence), "keep original audit custody outside frozen evidence")
    directory.mkdir(mode=0o700)
    progress = {"schema": SCHEMA, "status": "running", "qualification": "component", "stages": {}}
    domain_run.durable_json(directory / "report.json", progress)
    steps = (("replicas", lambda: replicas.capture(evidence, directory / "replicas", journal, attempt, plan, topology)),
             ("native", lambda: native.capture(evidence, directory / "native")))
    for name, run in steps:
        try:
            run()
        except BaseException as error:
            progress["stages"][name] = {"status": "failed", "error": repr(error)}
            if not isinstance(error, Exception):
                progress["status"] = "interrupted"
                domain_run.durable_json(directory / "report.json", progress)
                raise
        else:
            progress["stages"][name] = {"status": "complete"}
        domain_run.durable_json(directory / "report.json", progress)
    try:
        domain_run.require(all(row["status"] == "complete" for row in progress["stages"].values()),
                           "incomplete audit observation; see the original component receipts")
        verified = combined(evidence, directory)
    except BaseException as error:
        progress.update(status="failed", error=repr(error))
        domain_run.durable_json(directory / "report.json", progress)
        raise
    domain_run.durable_json(directory / "report.json", verified)
    return verified


def verify(evidence, directory):
    expected = combined(evidence, directory)
    original = owned.read(package_release.owned_file(directory, "report.json"))
    domain_run.require(original == expected, "combined audit observations differ from original component receipts")
    return expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    for name in ("collect", "replay"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--evidence", required=True, type=Path)
        cmd.add_argument("--custody", required=True, type=Path)
        if name == "collect":
            for item in ("journal", "plan", "topology"):
                cmd.add_argument("--" + item, required=True, type=Path)
            cmd.add_argument("--attempt-id", required=True)
    args = parser.parse_args()
    evidence = args.evidence.resolve(strict=True)
    directory = args.custody.resolve()
    if args.operation == "collect":
        result = collect(evidence, directory, args.journal, args.attempt_id, args.plan, args.topology)
    else:
        result = verify(evidence, directory.resolve(strict=True))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
