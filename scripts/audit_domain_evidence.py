"""Capture and replay the installed nine-process and original libtest parts of audit qualification."""
from pathlib import Path

import audit_retention_components as native
import domain_run
from domain_run import require
import repeatable_assembly as owned
import run_audit_replica_observation as replicas
import run_correctness as libtest
import run_installed_observability as processes
import verify_release_acceptance as acceptance

MODULES = {native.RUNNER, replicas.RUNNER, *native.MODULES, *replicas.MODULES}
TIMEOUT = 7200
HISTORIES = {
    "commands": ("custody-1", "commands"),
    "receipts": ("receipts-1", "restored_count"),
    "incarnations": ("incarnations-1", "reopened"),
    "lifecycle": ("lifecycle-1", "selected_intents"),
}


def scenarios(session_step):
    """Name the original commands that established each scenario's assertions."""
    return {
        "hot-budget-crossing": ["maintenance-1", "capacity"],
        "verified-contiguous-archives": ["replacement-1", "membership-after"],
        "archive-outage": ["outage-1", "outage-2", "outage-3"],
        "replica-dependency-before-prune": ["staged-1", "membership-after"],
        "replacement-dependencies": ["replacement-1", "incomplete-1"],
        "permanent-identity-lifetime-ceiling": [step for step, _ in HISTORIES.values()] + [session_step],
    }


def collect(run, plan, topology):
    installed = replicas.measure_installed(run, plan, topology)
    run.close_services()
    details = {"installation": installed, "native": {}}
    run.report["details"] = details
    run.save()
    functional = owned.read(run.evidence / "evidence.json")
    selected = libtest.artifacts(run.evidence, functional, native.CASES_BY_CRATE)

    def command(step, args, checksum):
        raw = run.command(step, args, TIMEOUT)
        require(run.report["processes"][-1]["executable"]["sha256"] == checksum,
                "audit executable changed during dispatch: " + step)
        return raw.read_bytes()

    details["native"] = native.replay(run.evidence, selected, command)
    run.save()
    return details


def original_stages(rows):
    """Split at fixed original command boundaries. The session driver owns the remaining rows."""
    names = [row["id"] for row in rows]
    require(len(set(names)) == len(names), "duplicate audit process name")
    ids = ["list-" + crate for crate, _ in (native.ENGINE, native.RAFT, native.AUTHORITY)]
    ids.extend(f"{case}-{iteration}" for case, _, _, repeats in native.CASES
               for iteration in range(1, repeats + 1))
    require(ids[0] in names, "missing original audit native listing")
    start = names.index(ids[0])
    stop = start + len(ids)
    require(start > 9 and names[start - 1] == "membership-after" and names[start:stop] == ids,
            "audit installation or original native process roster is incomplete or reordered")
    return rows[:start], rows[start:stop], rows[stop:]


def replay(custody, report, evidence, functional, binaries):
    installed, targets, remaining = original_stages(report["processes"])
    details = report["details"]
    require(details["installation"]["functional_sha256"] == owned.sha256(evidence / "evidence.json"),
            "installed audit ran against another functional build")
    original = Path(report["evidence_root"])
    paths = {name: str(original / path.relative_to(evidence)) for name, (path, _) in binaries.items()}
    projected = {**report, "processes": installed, "details": details["installation"]}
    installation = replicas.replay_installed(custody, projected, functional, paths)
    selected = libtest.artifacts(evidence, functional, native.CASES_BY_CRATE)
    inventory = iter(targets)

    def command(step, args, checksum):
        row = next(inventory, None)
        require(row and row["id"] == step, "missing original audit command: " + step)
        code, raw = processes.original_command(custody, row, step, args, original / "source", checksum, TIMEOUT)
        require(code == 0, "native audit command failed: " + step)
        return raw

    measured = native.replay(original, selected, command)
    require(next(inventory, None) is None and measured == details["native"],
            "reported audit measurements differ from the frozen libtests")
    return installation, measured, remaining


def archive_measurements(installed, measured):
    """Derive the largest observed ciphertext and verify deployed and native worker thresholds."""
    c = installed["capacity"]["capacity"]
    budgets = [(c["hot_budget_bytes"], c["starts_at_bytes"], c["drains_to_bytes"])]
    sizes = [ref["reference"]["ciphertext_bytes"] for ref in installed["objects"]]
    require(sizes and c["max_segment_bytes"] == 8 << 20, "installed archive proof missing")
    sizes += [ref["ciphertext_bytes"] for ref in measured["replacement-1"]["chain"]]
    for name in ("maintenance-1", "outage-1", "outage-2", "outage-3"):
        row = measured[name]
        sizes.append(row["after"]["archive_head"]["ciphertext_bytes"])
        budgets.append((row["budget"]["hot_bytes"], row["starts_at"], row["drains_to"]))
    require(all(type(n) is int and 0 < n <= c["max_segment_bytes"] for n in sizes)
            and all(type(b) is int and b > 0 and start == b - b // 4 and target == b // 2
                    for b, start, target in budgets), "installed archive bytes or maintenance watermarks differ")
    return {"maximum_segment_bytes": max(sizes), "maintenance_start_percent": 75,
            "maintenance_target_percent": 50}


def original_counts(root, custody, rows, measured, session_step, session_count):
    """Tie every category and its measured count to that command's original stdout."""
    logs = {row["id"]: row["log"] for row in rows}
    require(len(logs) == len(rows) and set(HISTORIES) == set(acceptance.PERMANENT_HISTORY_LIMITS)
            and session_step not in {step for step, _ in HISTORIES.values()},
            "permanent audit history roster differs")
    counts = [{"id": name, "former_limit": acceptance.PERMANENT_HISTORY_LIMITS[name],
               "observed": measured[step][key], "log": owned.ref(root, owned.check_ref(custody, logs[step]))}
              for name, (step, key) in HISTORIES.items()]
    counts.append({"id": "sessions", "acceptance_floor": acceptance.BACKUP_SESSION_FLOOR,
                   "observed": session_count, "log": owned.ref(root, owned.check_ref(custody, logs[session_step]))})
    acceptance.check_lifetime_counts(root, counts)
    return counts


def compare_scenarios(facts, session_step):
    expected = scenarios(session_step)
    require(set(expected) == acceptance.SCENARIOS["audit-retention"] and
            {name: [row["step"] for row in rows] for name, rows in facts.items()} == expected and
            all(row["expected_exit"] == row["exit_code"] == 0 for rows in facts.values() for row in rows),
            "audit scenarios differ from the original successful command measurements")


def record_scenarios(run, session_step):
    processes = {row["id"]: row for row in run.report["processes"]}
    for scenario, steps in scenarios(session_step).items():
        for step in steps:
            entry = processes[step]
            receipt = owned.read(owned.check_ref(run.output, entry["receipt"]))
            require(receipt["exit_code"] == 0, "audit scenario selected a failed command")
            run.observe(scenario, step, entry["receipt"], 0, receipt["exit_code"])
