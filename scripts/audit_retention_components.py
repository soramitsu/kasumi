"""Measure native audit-retention components with original library-test process receipts.

These components cover archive boundaries, replication and history counting.
Full audit-retention acceptance also requires the installed HA observations and
all five measured permanent record categories.
"""

import argparse
import json
import math
import os
from pathlib import Path
import re
import sys
import time

if __name__ == "__main__":
    scripts = Path(__file__).resolve(strict=True).parent
    if not (
        sys.flags.isolated
        and sys.flags.no_site
        and sys.flags.dont_write_bytecode
        and sys.pycache_prefix is None
        and "PYTHONPYCACHEPREFIX" not in os.environ
    ):
        raise SystemExit("audit components require -I -B -S")
    if any(
        path.name == "__pycache__"
        or path.suffix in {".pyc", ".pyo"}
        or (path.suffix == ".py" and path.is_symlink())
        for path in scripts.rglob("*")
    ):
        raise SystemExit("audit components require source-only Python")
    sys.path.insert(0, str(scripts))

import domain_run
from domain_run import require
import package_release
import repeatable_assembly as owned
import run_correctness as libtest

CASES = (
    (
        "maintenance",
        "kasumi-engine",
        "encrypted_worker_drains_hot_history_when_ordinary_capacity_is_full",
        1,
    ),
    (
        "outage",
        "kasumi-engine",
        "external_archive_outage_before_proposal_preserves_hot_history_and_raft_availability",
        3,
    ),
    (
        "replacement",
        "kasumi-engine",
        "replacement_receives_complete_chain_and_restart_uses_local_dependencies",
        1,
    ),
    (
        "incomplete",
        "kasumi-engine",
        "incomplete_or_corrupt_bundle_never_publishes_pruned_state",
        1,
    ),
    (
        "custody",
        "kasumi-raft",
        "permanent_custody_exceeds_former_count_and_snapshot_ceilings_and_reopens",
        1,
    ),
    (
        "lifecycle",
        "kasumi-engine",
        "lifecycle_history_crosses_ten_thousand_ordered_control_intents",
        1,
    ),
    (
        "incarnations",
        "kasumi-authority",
        "authoritative_incarnations_cross_the_former_receipt_ceiling_and_reopen",
        1,
    ),
    (
        "receipts",
        "kasumi-engine",
        "verified_point_history_crosses_former_count_limit_before_a_real_new_mutation",
        1,
    ),
)
ENGINE = ("kasumi-engine", "kasumi_engine")
RAFT = ("kasumi-raft", "kasumi_raft")
AUTHORITY = ("kasumi-authority", "kasumi_authority")
CASES_BY_CRATE = {
    "audit": [(crate, crate.replace("-", "_"), test) for _, crate, test, _ in CASES]
}
PREFIX = "KASUMI_AUDIT_COMPONENT "
FORMER_CUSTODY_COMMAND_LIMIT = 4096
FORMER_MUTATION_RECEIPT_LIMIT = 100_000


def digest(value):
    require(
        isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value),
        "invalid component digest",
    )
    return value


def count(value):
    require(type(value) is int and value >= 0, "invalid original component count")
    return value


def observation(case, raw):
    prefix = "KASUMI_LIFECYCLE_HISTORY " if case == "lifecycle" else PREFIX
    rows = [
        json.loads(line[len(prefix) :])
        for line in raw.decode().splitlines()
        if line.startswith(prefix)
    ]
    if case == "incomplete":
        require(not rows, "unexpected independent observation")
        return None
    require(len(rows) == 1, "expected one original audit component observation")
    value = rows[0]
    if case in {"maintenance", "outage"}:
        require(value["case"] == "maintenance", "wrong audited native worker")
        before, after = value["before"], value["after"]
        budget = count(value["budget"]["hot_bytes"])
        require(
            budget > 0
            and value["starts_at"] == budget - budget // 4
            and value["drains_to"] == budget // 2
            and count(before["hot_bytes"]) >= value["starts_at"]
            and count(after["hot_bytes"]) <= value["drains_to"],
            "hot storage did not cross both actual maintenance watermarks",
        )
        require(
            before["stream_id"] == after["stream_id"]
            and before["next_sequence"] == after["next_sequence"] == 50
            and before["pruned_before"]
            < after["pruned_before"]
            <= after["next_sequence"]
            and count(after["archive_segments"]) > count(before["archive_segments"])
            and count(value["committed_segments"]) > 0,
            "audit stream continuity or pruning differ",
        )
        head = after["archive_head"]
        require(
            head["stream_id"] == after["stream_id"]
            and 0 < count(head["ciphertext_bytes"]) <= 8 << 20,
            "actual archive head is outside the encrypted segment budget",
        )
        if case == "outage":
            outage = value["outage"]
            require(
                outage["position"] == before
                and count(outage["revision"]) == outage["committed_index"]
                and count(outage["failures"]) > 0
                and count(value["failures"]) >= outage["failures"],
                "external outage pruned history, lost its original barrier or lacked a failed attempt",
            )
        else:
            require(
                value["outage"] is None and value["failures"] == 0,
                "unperturbed archival failed",
            )
    elif case == "replacement":
        require(
            value["case"] == "replacement"
            and digest(value["source_bundle_sha256"])
            == digest(value["replacement_bundle_sha256"]),
            "replacement recapture differs from the source closed snapshot",
        )
        cursor = None
        position = value["replacement"]
        chain = value["chain"]
        require(
            len(chain) == count(position["archive_segments"]) and len(chain) >= 2,
            "replacement lacks a verified contiguous chain",
        )
        ciphertext = 0
        for ref in chain:
            link = ref["object"]
            require(
                ref["stream_id"] == position["stream_id"]
                and ref["previous"] == cursor
                and count(link["first_sequence"])
                == (cursor["next_sequence"] if cursor else 0)
                and link["next_sequence"] - link["first_sequence"]
                == count(ref["record_count"])
                > 0
                and 0 < count(ref["ciphertext_bytes"]) <= 8 << 20,
                "gap or invalid object in replacement archive",
            )
            digest(link["ciphertext_sha256"])
            cursor = link
            ciphertext += ref["ciphertext_bytes"]
        require(
            position["archive_head"] == chain[-1]
            and cursor["next_sequence"] == position["pruned_before"]
            and ciphertext == position["archive_bytes"],
            "replacement published a different archive position",
        )
    elif case == "custody":
        require(
            value["case"] == "custody"
            and count(value["commands"]) > FORMER_CUSTODY_COMMAND_LIMIT
            and count(value["audit_events"]) >= 2 * value["commands"]
            and value["reopened_command"]
            == value["replayed_command"]
            == "command-00000000",
            "original command did not survive the previous lifetime ceiling and restart",
        )
    elif case == "lifecycle":
        owned.exact(value, {"selected_intents", "resident_legacy_intents", "previous_max_intents",
                            "installed_max_intents", "bytes", "sha256", "replayed_first_revision",
                            "fresh_store_reopen", "both_stores_drained"}, "original lifecycle history crossing")
        selected = count(value["selected_intents"])
        require(count(value["previous_max_intents"]) == 10_000 and selected == 10_001
                and count(value["resident_legacy_intents"]) == count(value["installed_max_intents"]) == 1
                and count(value["bytes"]) > selected and count(value["replayed_first_revision"]) == 3
                and value["fresh_store_reopen"] is True and value["both_stores_drained"] is True
                and digest(value["sha256"]), "lifecycle witness did not retain a full permanent history")
    elif case == "incarnations":
        owned.exact(value, {"case", "prior_limit", "selected", "reopened", "verified_receipts",
                            "replayed_first_revision", "replayed_last_revision", "ordered_receipts_sha256",
                            "selected_bytes", "physical_reopen", "drained"}, "original authority history crossing")
        selected = count(value["selected"])
        require(value["case"] == "permanent-incarnations" and count(value["prior_limit"]) == 100_000
                and selected > value["prior_limit"] and count(value["reopened"]) == selected
                and count(value["verified_receipts"]) == selected and count(value["replayed_first_revision"]) == 1
                and count(value["replayed_last_revision"]) == selected and count(value["selected_bytes"]) > selected
                and value["physical_reopen"] is True and value["drained"] is True
                and digest(value["ordered_receipts_sha256"]), "original authority history was not preserved")
    elif case == "receipts":
        require(
            value["case"] == "mutation-receipts"
            and count(value["prior_count"]) == FORMER_MUTATION_RECEIPT_LIMIT
            and count(value["restored_count"]) > value["prior_count"],
            "receipt history did not exceed the previous stored ceiling",
        )
    else:
        raise ValueError("unknown native audit component")
    return value


def replay(evidence, selected, perform):
    listing = {}
    for crate, target in (ENGINE, RAFT, AUTHORITY):
        relative, checksum = selected[crate, target]
        path = str(evidence / "target" / relative)
        listing[crate] = libtest.test_list(
            perform("list-" + crate, [path, "--list", "--format", "terse"], checksum)
        )
    outcomes = {}
    for case, crate, leaf, repeats in CASES:
        path, checksum = selected[crate, crate.replace("-", "_")]
        test = libtest.resolve(listing[crate], leaf)
        for i in range(1, repeats + 1):
            name = f"{case}-{i}"
            raw = perform(
                name,
                [
                    str(evidence / "target" / path),
                    "--exact",
                    test,
                    *(["--include-ignored"] if case in {"receipts", "lifecycle", "incarnations"} else []),
                    "--test-threads=1",
                    "--show-output",
                    "--format",
                    "pretty",
                ],
                checksum,
            )
            libtest.check_pass(raw, test, len(listing[crate]))
            outcomes[name] = observation(case, raw)
    outages = [
        value["before"]["stream_id"]
        for name, value in outcomes.items()
        if name.startswith("outage-")
    ]
    require(
        len(set(outages)) == 3,
        "archive outages must use three independent real installations",
    )
    return outcomes


RUNNER = "scripts/audit_retention_components.py"
MODULES = {"scripts/run_correctness.py"}
COMPONENT_FIELDS = {
    "schema", "qualification", "status", "evidence", "processes", "native",
    "source_commit", "source_tree", "runner_sha256", "functional_sha256",
    "observed", "seconds",
}


def replay_retained(custody, report, original, selected):
    """Reparse and cross-check the exact original native processes in dispatch order."""
    queue = iter(report["processes"])

    def perform(name, command, checksum):
        row = next(queue, None)
        require(isinstance(row, dict) and row.get("id") == name,
                "missing or reordered native audit component process: " + name)
        require(row["executable"]["sha256"] == checksum,
                "native audit executable differs from frozen workspace target")
        owned.check_owned(custody, row, command, str(original / "source"), 7200)
        return owned.check_ref(custody, row["stdout"]).read_bytes()

    measured = replay(original, selected, perform)
    require(next(queue, None) is None, "unexpected trailing native audit process")
    require(measured == report["observed"], "audit observations differ from original process output")
    return measured


def verify_components(evidence, custody):
    """Verify a transported component against an independently supplied functional candidate."""
    evidence = Path(evidence).resolve(strict=True)
    custody = Path(custody).resolve(strict=True)
    functional, _, native, _ = package_release.verify_evidence(evidence)
    report = owned.read(package_release.owned_file(custody, "report.json"))
    owned.exact(report, COMPONENT_FIELDS, "native audit component report")
    files = owned.read(evidence / "source-files.json")
    scripts = domain_run.frozen_scripts(evidence / "source", files, {RUNNER, *MODULES})
    original = Path(report["evidence"])
    require(original.is_absolute() and ".." not in original.parts
            and report["schema"] == "kasumi-audit-retention-components-v1"
            and report["qualification"] == "component" and report["status"] == "passed"
            and type(report["seconds"]) in {float, int} and math.isfinite(report["seconds"])
            and report["seconds"] > 0 and report["native"] == native
            and report["source_commit"] == functional["source_commit"]
            and report["source_tree"] == functional["source_tree"]
            and report["functional_sha256"] == owned.sha256(evidence / "evidence.json")
            and report["runner_sha256"] == scripts[RUNNER],
            "native audit component differs from its frozen functional candidate")
    selected = libtest.artifacts(evidence, functional, CASES_BY_CRATE)
    return replay_retained(custody, report, original, selected)


def main():
    if sys.argv[1:2] == ["replay"]:
        cli = argparse.ArgumentParser(description="Verify transported native audit components")
        cli.add_argument("--evidence", type=Path, required=True)
        cli.add_argument("--custody", type=Path, required=True)
        args = cli.parse_args(sys.argv[2:])
        print(json.dumps(verify_components(args.evidence, args.custody), sort_keys=True))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    capture(args.evidence, args.output)


def capture(evidence, directory):
    evidence = evidence.resolve(strict=True)
    directory = directory.resolve()
    require(
        not directory.is_relative_to(evidence),
        "keep component evidence independent of the frozen tree",
    )
    directory.mkdir(mode=0o700)
    started = time.monotonic()
    report = {
        "schema": "kasumi-audit-retention-components-v1",
        "qualification": "component",
        "status": "running",
        "evidence": str(evidence),
        "processes": [],
    }
    try:
        (directory / "tmp").mkdir(mode=0o700)
        functional, _, native, _ = package_release.verify_evidence(evidence)
        source = evidence / "source"
        selected = libtest.artifacts(evidence, functional, CASES_BY_CRATE)
        files = owned.read(evidence / "source-files.json")
        domain_run.frozen_scripts(source, files, {RUNNER, *MODULES})
        report.update(
            native=native,
            source_commit=functional["source_commit"],
            source_tree=functional["source_tree"],
            runner_sha256=files[RUNNER]["sha256"],
            functional_sha256=owned.sha256(evidence / "evidence.json"),
        )
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(directory / "tmp"),
            "TMPDIR": str(directory / "tmp"),
            "LC_ALL": "C",
            "TZ": "UTC",
        }

        def perform(name, command, checksum):
            row = owned.run_owned(directory, name, command, str(source), env, 7200)
            report["processes"].append(row)
            domain_run.durable_json(directory / "report.json", report)
            require(
                row["executable"]["sha256"] == checksum,
                "audit test binary differs from native input",
            )
            owned.check_owned(directory, row, command, str(source), 7200)
            return owned.check_ref(directory, row["stdout"]).read_bytes()

        report["observed"] = replay(evidence, selected, perform)
        report["status"] = "passed"
    except BaseException as err:
        report.update(status="failed", error=repr(err))
        raise
    finally:
        report["seconds"] = time.monotonic() - started
        domain_run.durable_json(directory / "report.json", report)


if __name__ == "__main__":
    main()
