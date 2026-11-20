"""Qualify all six audit-retention scenarios on a fresh native Linux ARM64 installation.

Invoke from the frozen functional source with Python -I -B -S, --evidence,
--output, --journal, --attempt-id, --plan and --topology. Run output includes
the original nine services, native tests and backup session installation.
"""
import argparse
import math
import os
from pathlib import Path
import re
import shutil
import sys

if __name__ == "__main__":
    scripts = Path(__file__).resolve(strict=True).parent
    if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode
            and sys.pycache_prefix is None and "PYTHONPYCACHEPREFIX" not in os.environ):
        raise SystemExit("audit qualification requires -I -B -S")
    if any(p.name == "__pycache__" or p.suffix in {".pyc", ".pyo"} or
           (p.suffix == ".py" and p.is_symlink()) for p in scripts.rglob("*")):
        raise SystemExit("audit qualification requires frozen Python sources")
    sys.path.insert(0, str(scripts))

import audit_domain_evidence as audit
import domain_run
from domain_run import require
import package_release as package
import repeatable_assembly as owned
import run_correctness as libtest
import run_installed_observability as processes
import verify_release_acceptance as acceptance

KIND = "audit-retention"
RUNNER = "scripts/run_audit_retention.py"
MODULES = {"scripts/audit_domain_evidence.py", "scripts/backup_session_acceptance.py",
           "scripts/probe_session_floor_filesystem.py", *audit.MODULES}
SESSIONS = "session-full"
SESSION_TEST = "backup_session_floor_full_cohort"
SESSION_PREFIX = "KASUMI_BACKUP_SESSION_FLOOR "
SESSION_TIMEOUT = 86400


def session_command(original, evidence, functional, custody, rows):
    target = audit.native.ENGINE
    relative, checksum = libtest.artifacts(evidence, functional, {"session": [(*target, SESSION_TEST)]})[target]
    listing, = [row for row in rows if row["id"] == "list-kasumi-engine"]
    path = str(original / "target" / relative)
    code, raw = processes.original_command(custody, listing, listing["id"], [path, "--list", "--format", "terse"],
                                           original / "source", checksum, audit.TIMEOUT)
    require(code == 0, "backup session test did not appear in a successful native listing")
    tests = libtest.test_list(raw)
    test = libtest.resolve(tests, SESSION_TEST)
    args = [path, "--exact", test, "--include-ignored", "--test-threads=1", "--show-output", "--format", "pretty"]
    return args, checksum, len(tests)


def session_installation(original, custody, raw, command, checksum, total, receipt, commit):
    libtest.check_pass(raw, command[2], total)
    summaries = [package._metadata_json(line[len(SESSION_PREFIX):].encode()) for line in raw.decode().splitlines()
                 if line.startswith(SESSION_PREFIX)]
    require(len(summaries) == 1, "expected one original full-cohort session observation")
    summary = summaries[0]
    pid = receipt["process_group"]
    require(type(pid) is int and pid > 0, "original session witness has no owned process identity")
    path = Path(summary["witness"])
    require(path.is_absolute() and path.parent.parent == original / "sessions"
            and re.fullmatch(rf"full-{pid}-[0-9]+", path.parent.name) and path.name == "witness.json",
            "session log references an unrelated installation")
    base = package.owned_directory(custody, path.parent.relative_to(original))
    file = package.verify_file(base, "witness.json", summary["witness_sha256"])
    witness = owned.read(file)
    require(witness["schema"] == "kasumi-backup-session-floor-v1" and witness["qualification"] == "component"
            and witness["architecture"] == {"arch": "aarch64", "os": "linux", "family": "unix"}
            and witness["test"] == {"name": command[2], "executable": command[0],
                                     "executable_sha256": checksum, "source_commit": commit, "parent_process_id": pid}
            and all(summary[name] == witness[name] for name in ("case", "cohort", "floor", "observed_distinct_sessions",
                                                                 "failed_terminal_outcomes"))
            and witness["case"] == "backup-sessions" and witness["cohort"] == "full"
            and witness["floor"] == acceptance.BACKUP_SESSION_FLOOR and witness["crosses_floor"] is True
            and type(witness["observed_distinct_sessions"]) is int
            and witness["observed_distinct_sessions"] >= acceptance.BACKUP_SESSION_FLOOR
            and type(witness["failed_terminal_outcomes"]) is int and witness["failed_terminal_outcomes"] >= 257,
            "wrong backup-session cohort, original process, installation or source")
    args = [command[0], "--exact", command[2], "--include-ignored", "--nocapture", "--test-threads=1"]
    children = witness["processes"]
    require(isinstance(children, list) and children and
            all(p["argv"] == args and type(p["process_id"]) is int and p["process_id"] > 0
                and p["process_id"] != pid and type(p["seconds"]) in (int, float)
                and math.isfinite(p["seconds"]) and 0 <= p["seconds"] <= receipt["duration_seconds"]
                for p in children), "backup history child ran a different test, executable or process")
    require(sum(p["seconds"] for p in children) <= receipt["duration_seconds"] + 0.01,
            "sequential backup history children exceeded their original parent interval")
    streams = witness["independent"]["streams"]
    require(summary["pre_restart_stream_sha256"] == streams["pre-restart"]["sha256"]
            == summary["post_restart_stream_sha256"] == streams["post-restart"]["sha256"]
            == summary["post_replay_stream_sha256"] == streams["post-replay"]["sha256"]
            and summary["head"] == witness["verify"]["head_after"], "session summary differs from original reopen")
    return base, witness


def verify_session(original, custody, raw, command, checksum, total, receipt, commit):
    import backup_session_acceptance

    base, witness = session_installation(original, custody, raw, command, checksum, total, receipt, commit)
    count = backup_session_acceptance.verify(base, witness)
    require(type(count) is int and count == witness["observed_distinct_sessions"],
            "native count differs from independently read backup sessions")
    return {"witness": owned.ref(custody, base / "witness.json"), "observed": count}


def execute(run, plan, topology, session_profile=None):
    if session_profile is not None:
        path = run.configuration("session-profile", session_profile)
        probe = run.configuration("session-filesystem-probe", session_profile.with_name("filesystem-probe.json"))
        require(owned.sha256(path) == run.report["invocation"]["parameters"]["session_profile_sha256"]
                and owned.sha256(probe) == owned.read(path)["probe_sha256"], "session profile or filesystem probe changed")
        inputs = run.output / "session-inputs"
        inputs.mkdir()
        shutil.copyfile(path, inputs / "session-profile.json")
        shutil.copyfile(probe, inputs / "filesystem-probe.json")
        run.environment["KASUMI_BACKUP_FLOOR_PROFILE"] = str(inputs / "session-profile.json")
    details = audit.collect(run, plan, topology)
    functional = owned.read(run.evidence / "evidence.json")
    args, checksum, total = session_command(run.evidence, run.evidence, functional, run.output, run.report["processes"])
    run.environment["KASUMI_BACKUP_FLOOR_EVIDENCE"] = str(run.output / "sessions")
    run.environment["KASUMI_SOURCE_COMMIT"] = run.report["source"]["commit"]
    raw = run.command(SESSIONS, args, SESSION_TIMEOUT).read_bytes()
    item = run.report["processes"][-1]
    require(item["executable"]["sha256"] == checksum, "session process changed from the frozen native listing")
    receipt = owned.read(owned.check_ref(run.output, item["receipt"]))
    details["session"] = verify_session(run.output, run.output, raw, args, checksum, total, receipt,
                                        run.report["source"]["commit"])
    audit.record_scenarios(run, SESSIONS)
    run.passed(details)


def gate_details(root, custody, installed, measured, rows, session_count):
    return {**audit.archive_measurements(installed, measured),
            "lifetime_counts": audit.original_counts(root, custody, rows, measured, SESSIONS, session_count),
            "report": owned.ref(root, custody / "report.json")}


def verify_domain(root, domain, files, configs, _artifacts, candidates):
    facts = domain_run.verify_run(root, domain, files, configs, KIND, RUNNER, MODULES)
    report, custody = facts["report"], facts["custody"]
    details = report["details"]
    owned.exact(details, {"installation", "native", "session"}, "audit-retention run")
    parameters = report["invocation"]["parameters"]
    require(report["target"] == acceptance.REFERENCE and set(parameters) in (set(), {"session_profile_sha256"})
            and domain["artifacts"] == {} and report["topology"] == domain["topology"],
            "audit qualification requires the original native installation and nine processes")
    primary = candidates[acceptance.REFERENCE]["primary"]["functional"]
    evidence = acceptance.reference(root, primary).parent
    functional, _, target, binaries = package.verify_evidence(evidence)
    require(target == acceptance.REFERENCE and primary["sha256"] == details["installation"]["functional_sha256"]
            and report["binaries"] == {name: checksum for name, (_, checksum) in binaries.items()},
            "audit qualification selected another functional candidate")
    installation_report = report
    if parameters:
        installation_report = {**report, "configurations": [row for row in report["configurations"]
                               if row["id"] not in {"session-profile", "session-filesystem-probe"}]}
    installed, measured, remaining = audit.replay(custody, installation_report, evidence, functional, binaries)
    require([row["id"] for row in remaining] == [SESSIONS], "original full backup-session process missing or reordered")
    row = remaining[0]
    original = Path(report["evidence_root"])
    args, checksum, total = session_command(original, evidence, functional, custody, report["processes"])
    code, raw = processes.original_command(custody, row, SESSIONS, args, original / "source", checksum, SESSION_TIMEOUT)
    require(code == 0, "full session cohort failed")
    result = verify_session(Path(report["custody_root"]), custody, raw, args, checksum, total,
                            facts["receipts"][SESSIONS]["record"], report["source"]["commit"])
    require(result == details["session"], "session summary differs from the original permanent history")
    witness = owned.read(owned.check_ref(custody, result["witness"]))
    if parameters:
        inputs = {row["id"]: owned.check_ref(custody, row["file"]) for row in report["configurations"]}
        profile = inputs["session-profile"]
        require(owned.sha256(profile) == parameters["session_profile_sha256"]
                and owned.read(profile) == witness["plan"]["profile"]
                and owned.sha256(inputs["session-filesystem-probe"]) == witness["plan"]["profile"]["probe_sha256"],
                "applied backup-session profile differs from original inputs")
    else:
        require(witness["plan"].get("profile") is None, "undeclared session workload profile")
    audit.compare_scenarios(facts["scenarios"], SESSIONS)
    expected = gate_details(root, custody, installed, measured, report["processes"], result["observed"])
    expected_counts = {r["id"]: r for r in expected.pop("lifetime_counts")}
    supplied = dict(domain["details"])
    require(acceptance.unique(supplied.pop("lifetime_counts"), "id", "original audit counts") == expected_counts
            and supplied == expected, "audit counts, original raw logs, or archive measurements differ")
    return facts["evidence"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("evidence", "output", "journal", "plan", "topology"):
        parser.add_argument("--" + option, type=Path, required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--session-profile", type=Path, help="prospective workload and measured physical filesystem limits")
    args = parser.parse_args()
    previous = os.umask(0o077)
    try:
        with domain_run.Run(KIND, RUNNER, MODULES, args.evidence, args.output, args.journal,
                            args.attempt_id, {"session_profile_sha256": owned.sha256(args.session_profile)}
                            if args.session_profile else {}, domain_run.QUALIFYING) as run:
            execute(run, args.plan, args.topology, args.session_profile)
    finally:
        os.umask(previous)


if __name__ == "__main__":
    main()
