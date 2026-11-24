#!/usr/bin/env python3
"""Collect protected native test replies for G10. The full nine-process observability gate stays open."""
import argparse
import json
import os
from pathlib import Path
import re
import sys
import uuid

if __name__ == "__main__":
    scripts = Path(__file__).resolve().parent
    if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode
            and sys.pycache_prefix is None and "PYTHONPYCACHEPREFIX" not in os.environ):
        raise SystemExit("observability probes require Python -I -B -S")
    if any(path.name == "__pycache__" or path.suffix in {".pyc", ".pyo"}
           or (path.suffix == ".py" and path.is_symlink()) for path in scripts.rglob("*")):
        raise SystemExit("observability probes require source-only Python imports")
    sys.path.insert(0, str(scripts))

import domain_run
from domain_run import require
import repeatable_assembly as owned
import run_correctness as libtest
import verify_release_acceptance as acceptance
from release_gate import sha256

RUNNER = "scripts/run_observability_probes.py"
MODULES = ("scripts/run_correctness.py",)
CASES = {
    "readiness": "protected_tls_certifies_all_129_installed_healthy_groups_and_rejects_raft_membership",
    "protection": "protected_observability_tls_reports_actual_state_and_fences_release",
    "backlog": "protected_tls_reports_real_archive_outage_and_due_backlog",
    "recovery": "three_runtime_nodes_report_committed_recovery_prepare_over_protected_tls",
    "backup": "native_backup_proof_is_admin_only_configured_and_verified_through_secure_sdk",
    "authority": "actual_tls_peer_readiness_enrolls_replaces_and_fences_revoked_member",
    "logs": "json_diagnostics_exclude_dependency_payloads_and_span_fields",
}
PREFIX = {"http": "kasumi-protected-response ", "native": "kasumi-native-observation "}


def rows(log):
    result = {"http": {}, "native": {}}
    for line in log.decode().splitlines():
        for kind, prefix in PREFIX.items():
            if line.startswith(prefix):
                row = json.loads(line.removeprefix(prefix), object_pairs_hook=unique_json)
                identifier = row["id"]
                require(isinstance(identifier, str) and identifier not in result[kind], "duplicate protected observation")
                if kind == "http":
                    acceptance.exact(row, {"id", "status", "cache_control", "content_type", "body"}, "protected reply")
                    require(row["status"] == 200 and row["cache_control"] == "no-store"
                            and type(row["body"]) is str and len(row["body"].encode()) <= 1 << 20
                            and type(row["content_type"]) is str, "invalid protected reply")
                    media = row["content_type"].split(";")[0]
                    require(media in ("application/json", "text/plain"), "invalid protected media type")
                    value = json.loads(row["body"], object_pairs_hook=unique_json) if media == "application/json" else row["body"]
                else:
                    acceptance.exact(row, {"id", "fields"}, "native observation")
                    value = row["fields"]
                result[kind][identifier] = value
    return result


def unique_json(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate observation field")
        result[key] = value
    return result


def gauge(metrics, name):
    matches = [line.rsplit(" ", 1)[-1] for line in metrics.splitlines() if line.startswith("kasumi_" + name + " ")]
    require(len(matches) == 1 and re.fullmatch(r"[0-9]+", matches[0]), "missing or ambiguous integer metric: " + name)
    return int(matches[0])


def installed_coverage(reply, healthy):
    coverage = reply["readiness_coverage"]
    current = acceptance.check_readiness_epoch(coverage["membership_epoch"])
    covered = acceptance.check_readiness_epoch(coverage["covered_epoch"])
    require(reply["ready"] is True and current == covered and coverage["complete"] is True
            and coverage["fresh"] is True and coverage["detail_limit"] == 128
            and coverage["expected_groups"] == coverage["examined_groups"] == 129
            and coverage["healthy_groups"] == healthy
            and acceptance.number(coverage["oldest_probe_age_seconds"], "oldest readiness probe") < 30,
            "incomplete or expired installed readiness")
    groups = reply["groups"]
    require(isinstance(groups, list) and len({entry["tenant"] for entry in groups}) == len(groups) == 128
            and all(entry["quorum"] is True for entry in groups), "diagnostic page differs from installed coverage")
    return current


def issuer_maintenance(observed):
    previous = 0
    operations = set()
    digests = set()
    original = [1, 2, 3]
    requested = observed["issuer-replace"]["requested_voters"]
    require(type(requested) is list and len(set(requested)) == len(requested) == 3
            and 4 in requested and set(requested) <= {1, 2, 3, 4}, "invalid replacement voter set")
    removed, = set(original) - set(requested)
    for step in ("issuer-capacity", "issuer-enroll", "issuer-replace", "issuer-revoke"):
        entry = observed[step]
        op = uuid.UUID(entry["operation_id"])
        digest = acceptance.checksum(entry["command_sha256"])
        require(op.int > 0 and op not in operations and digest not in digests
                and previous < acceptance.uint(entry["admitted_revision"], "authority admission", 1)
                <= acceptance.uint(entry["progress_revision"], "authority progress", 1)
                and entry["leader"] == entry["observer"] and entry["observer"] in entry["effective_voters"]
                and acceptance.uint(entry["term"], "authority leader term", 1)
                and entry["phase"] == {"kind": "draining" if step == "issuer-revoke" else "completed"},
                "authority majority or durable maintenance phase differs")
        operations.add(op)
        digests.add(digest)
        previous = entry["progress_revision"]
        require(entry["voters_before"] == (requested if step == "issuer-revoke" else original)
                and entry["effective_voters"] == (requested if step in ("issuer-replace", "issuer-revoke") else original),
                "authority configuration differs from actual effective voters")
    require(observed["issuer-enroll"]["target"] == 4 and observed["issuer-revoke"]["target"] == removed
            and observed["issuer-peer-denial"] == {"removed": removed, "remaining_refusals": 3},
            "issuer peer revocation did not reach surviving members")
    return {"original_voters": original, "replaced_voters": requested, "revoked": removed,
            "progress_revision": previous}


def verified(stage, log):
    seen = rows(log)
    replies, native = seen["http"], seen["native"]
    required_http = {"readiness": {"healthy-129", "metrics-129", "after-rejected-membership", "negative-group-129"},
                     "protection": {"initial-ready", "initial-metrics", "health"},
                     "backlog": {"archive-outage", "archive-outage-metrics"},
                     "recovery": {"recovery-status"}, "backup": set(), "authority": set(), "logs": set()}
    required_native = {"recovery": {"recovery-status"}, "backup": {"completed-session-status"},
                       "logs": {"structured-events"}, "authority": {"issuer-capacity", "issuer-enroll", "issuer-replace",
                                                                    "issuer-revoke", "issuer-peer-denial"}}
    require(set(replies) == required_http[stage] and set(native) == required_native.get(stage, set()),
            "protected case did not retain its own exact observations")
    if stage == "readiness":
        first = installed_coverage(replies["healthy-129"], 129)
        stable = installed_coverage(replies["after-rejected-membership"], 129)
        require(first == stable == installed_coverage(replies["negative-group-129"], 128),
                "standalone rejection changed membership")
        metrics = replies["metrics-129"]
        require(gauge(metrics, "ready") == 1 and gauge(metrics, "local_group_details") == 128
                and all(gauge(metrics, "readiness_groups_" + key) == 129 for key in ("examined", "expected", "healthy")),
                "protected metrics lost whole-node coverage")
        for key, value in first.items():
            require(gauge(metrics, "readiness_epoch_" + key) == value
                    and gauge(metrics, "readiness_covered_epoch_" + key) == value,
                    "metrics and TLS readiness disagree about the membership epoch")
        return {"installed_groups": 129, "membership_epoch": first, "covered_epoch": stable,
                "negative_group_examined": True}
    if stage == "backlog":
        receipt = replies["archive-outage"]
        group, = (item for item in receipt["groups"] if item["tenant"] == "tenant-a")
        retention = group["retention"]
        due = acceptance.uint(retention["archive_backlog_bytes"], "actual due bytes", 1)
        require(due == retention["hot_bytes"] - retention["hot_budget_bytes"] // 2
                and group["audit_maintenance"]["failures"] > 0 and group["audit_maintenance"]["committed_segments"] == 0,
                "archive failure or retained backlog is missing")
        metrics = replies["archive-outage-metrics"]
        require(gauge(metrics, 'local_group_audit_archive_backlog_bytes{tenant="tenant-a"}') == due
                and gauge(metrics, "service_audit_archive_backlog_bytes") == receipt["service_audit"]["retention"]["archive_backlog_bytes"],
                "archive backlog differs between protected outputs")
        return {"archive_backlog_bytes": due, "failed_worker_attempts": group["audit_maintenance"]["failures"]}
    if stage == "protection":
        require(replies["initial-ready"]["ready"] is True and replies["health"]["lifecycle"] == "serving",
                "installed protected node did not serve")
        disk = replies["initial-ready"]["persistent_disk"]
        charge = acceptance.uint(disk["charged_bytes"], "physical disk charge")
        require(charge <= disk["max_bytes"] and gauge(replies["initial-metrics"], "persistent_disk_charged_bytes") >= 0,
                "physical capacity outside configured budget")
        return {"physical_charged_bytes": charge, "maximum_bytes": disk["max_bytes"]}
    if stage == "recovery":
        current = replies["recovery-status"]
        acceptance.exact(current, {"operation_id", "phase", "updated_revision", "phase_pending", "terminal"},
                         "protected recovery result")
        require(current == native["recovery-status"] and current["phase"] == "prepare"
                and current["terminal"] is False and type(current["phase_pending"]) is bool
                and uuid.UUID(current["operation_id"]).int > 0 and current["updated_revision"] > 0,
                "protected result differs from committed Prepare")
        return current
    if stage == "authority":
        return issuer_maintenance(native)
    if stage == "logs":
        events = native["structured-events"]
        require(isinstance(events, list) and [row["fields"]["event"] for row in events] == [
            "tls_reload_failed", "engine_warning", "original_engine_open_failed"]
            and events[2]["fields"]["failure_class"] == "io_storage_full" and all(
                marker not in json.dumps(events) for marker in ("private-", "secret-span-token")),
                "structured diagnostics lost their failure class or disclosed fixture secrets")
        return {"events": [row["fields"]["event"] for row in events]}
    value = native["completed-session-status"]
    require(uuid.UUID(value["session_id"]).int > 0 and value["session_id"] == value["backup_id"]
            and acceptance.uint(value["revision"], "completed revision") == value["checkpoint_revision"]
            and value["source_incarnation"] and value["source_incarnation"] == value["checkpoint_incarnation"],
            "durable readback differs from the verified checkpoint")
    for key in ("intent_ciphertext_sha256", "source_purpose_sha256", "manifest_ciphertext_sha256"):
        acceptance.checksum(value[key])
    return value


def execute(run):
    run.bind()
    source = run.evidence / "evidence.json"
    selected = libtest.artifacts(run.evidence, owned.read(source), {
        key: [("kasumi-server", "kasumi_server", leaf)] for key, leaf in CASES.items()})
    relative, digest = selected["kasumi-server", "kasumi_server"]
    binary = str(run.evidence / "target" / relative)
    state = run.command("list", [binary, "--list", "--format", "terse"], 180).read_bytes()
    listing = libtest.test_list(state)
    checks = {}
    run.environment["KASUMI_CAPTURE_PROTECTED_RESPONSES"] = "1"
    for key, leaf in CASES.items():
        name = libtest.resolve(listing, leaf)
        output = run.command(key, [binary, "--exact", name, "--test-threads=1", "--format", "pretty", "--show-output"],
                             1200, scenario=key).read_bytes()
        require(run.report["processes"][-1]["executable"]["sha256"] == digest, "another native unit binary was run")
        libtest.check_pass(output, name, len(listing))
        checks[key] = verified(key, output)
    run.passed({"functional_sha256": sha256(source), "observations": checks})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("evidence", "journal", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--attempt-id", required=True)
    args = parser.parse_args()
    with domain_run.Run("observability", RUNNER, MODULES, args.evidence, args.output, args.journal,
                        args.attempt_id, {}, domain_run.REHEARSAL) as run:
        execute(run)
