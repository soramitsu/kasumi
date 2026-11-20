#!/usr/bin/env python3
"""Qualify installed wrapping-key rotation, paged coverage and the final retirement fence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import uuid

if __name__ == "__main__":
    scripts = Path(__file__).resolve().parent
    if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode
            and sys.pycache_prefix is None and "PYTHONPYCACHEPREFIX" not in os.environ):
        raise SystemExit("key retention requires Python -I -B -S")
    if any(p.name == "__pycache__" or p.suffix in {".pyc", ".pyo"} or
           (p.suffix == ".py" and p.is_symlink()) for p in scripts.rglob("*")):
        raise SystemExit("key retention requires source-only Python imports")
    sys.path.insert(0, str(scripts))

import domain_run
from domain_run import require
import repeatable_assembly as owned
import run_backup_cleanup as backup
import run_correctness as libtest
import run_installed as installed
import run_oci_smoke as install
import verify_release_acceptance as acceptance

KIND = "key-retention"
RUNNER = "scripts/run_key_retention.py"
MODULES = tuple(sorted({installed.RUNNER, *installed.MODULES, backup.RUNNER, *backup.MODULES}))
REFUSALS = {"referenced-version": 1, "stale-coverage": 1}
CASES = {
    "exact-historical-resolution": [("kasumi-store", "kasumi_store",
                                     "historical_object_uses_its_source_and_reopen_requires_the_same_roster")],
    "recovery-provider-bindings": [("kasumi-server", "kasumi_server",
                                   "restart_keeps_exact_historical_reads_and_rejects_substituted_sources")],
    "incomplete-dependency-rejection": [("kasumi-engine", "kasumi_engine",
                                         "completed_backup_inventory_discards_partial_key_evidence_when_the_root_is_missing")],
    "race-safe-retirement": [("kasumi-engine", "kasumi_engine",
                              "retirement_decision_rechecks_the_ordered_membership_and_dependency_position")],
}


def digest(value):
    return hashlib.sha256(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def read_catalogs(io, prefix, scope, limit, profile):
    """Read each cursor from the daemon and bind it to the same coverage and last row."""
    cursor = coverage = None
    entries = []
    previous_order = None
    maximum = 0
    for index in range(16):
        name = f"{prefix}-{index}"
        path = io.input(name + "-request", {"scope": scope, "cursor": cursor, "limit": limit})
        page = json.loads(io.command(name, [io.binary["kasumid"], "key-retention", "read", profile, path],
                                     scenario="paged-coverage"))
        owned.exact(page, {"entries", "coverage", "next_cursor"}, "key retention page")
        current = page["coverage"]
        owned.exact(current, {"kind", "coverage_revision", "membership_epoch", "coverage_sha256"}, "key coverage")
        require(current["kind"] == "complete" and (coverage is None or coverage == current),
                "retirement coverage is incomplete or changed between pages")
        acceptance.checksum(current["coverage_sha256"])
        acceptance.uint(current["coverage_revision"], "coverage revision")
        acceptance.uint(current["membership_epoch"], "membership epoch")
        coverage = current
        rows = page["entries"]
        require(isinstance(rows, list) and 0 < len(rows) <= limit, "key page exceeded its requested limit or was empty")
        maximum = max(maximum, len(rows))
        for row in rows:
            owned.exact(row, {"key", "reference"}, "key dependency")
            owned.exact(row["key"], {"provider", "key_ref", "version"}, "wrapping key")
            owned.exact(row["reference"], {"kind", "node_id", "catalog_id", "domain"}, "pristine catalog")
            require(row not in entries and row["reference"]["kind"] == "catalog"
                    and row["key"]["provider"] == "file" and row["key"]["key_ref"],
                    "standalone key inventory repeated or substituted its catalog")
            acceptance.uint(row["key"]["version"], "wrapping version", 1)
            key, ref = row["key"], row["reference"]
            acceptance.uint(ref["node_id"], "catalog node", 1)
            catalog = uuid.UUID(ref["catalog_id"])
            require(catalog.int > 0 and str(catalog) == ref["catalog_id"]
                    and ref["domain"] in ("node_control", "retirement_custody"), "invalid installed catalog identity")
            order = (key["provider"], key["key_ref"], key["version"], ref["node_id"], catalog.int,
                     0 if ref["domain"] == "retirement_custody" else 1)
            require(previous_order is None or previous_order < order, "key pages are out of order")
            previous_order = order
            entries.append(row)
        following = page["next_cursor"]
        if following is None:
            require({row["reference"]["domain"] for row in entries} == {"node_control", "retirement_custody"},
                    "pristine Control inventory omitted an installed catalog")
            return entries, coverage, maximum
        owned.exact(following, {"scope_sha256", "inventory_sha256", "coverage_revision", "membership_epoch", "after"},
                    "key retention continuation")
        require(following["scope_sha256"] == digest(["kasumi.key-retention-scope.v1", scope])
                and following["coverage_revision"] == coverage["coverage_revision"]
                and following["membership_epoch"] == coverage["membership_epoch"]
                and following["after"] == rows[-1] and following != cursor
                and (cursor is None or following["inventory_sha256"] == cursor["inventory_sha256"]),
                "key continuation lost its scope, last dependency or inventory")
        acceptance.checksum(following["inventory_sha256"])
        cursor = following
    raise ValueError("pristine installation returned an unbounded key inventory")


def protocol(io):
    private = Path(io.params["private_root"])
    daemon = io.binary["kasumid"]
    installation = private / "installation"
    io.config = installation / "kasumi.json"
    profile = str(installation / "profiles/control.json")
    scope = {"kind": "control"}
    io.command("initialize", [daemon, "init", "--mode", "standalone", str(installation),
               *[arg for k in sorted(io.inputs) for arg in ("--" + k, io.inputs[k])], "--tenant", install.TENANT])

    def open_node(number):
        io.serve()
        port = io.params["base_port"]
        result = io.command(f"listeners-{number}", [io.params["python"], "-I", "-B", "-S",
                            str(io.source / backup.RUNNER), "listeners", str(port)])
        require(json.loads(result) == {"listeners": list(range(port, port + 3))}, "installed listeners differ")
        ready = io.command(f"ready-{number}", [io.binary["kasumictl"], "--profile", profile, "ready"])
        require(json.loads(ready).get("ready") is True, "installed Control is not ready")

    def retire(step, data, reason=None):
        path = io.input(step + "-request", data)
        raw = io.command(step, [daemon, "key-retention", "retire", profile, path],
                         scenario="race-safe-retirement", expected=REFUSALS.get(step, 0))
        if reason:
            require(reason in io.stderr(step), "retirement did not preserve the expected refusal")
            return None
        return json.loads(raw)

    open_node(1)
    before, initial, first_max = read_catalogs(io, "initial", scope, 1, profile)
    chosen, = (row["key"] for row in before if row["reference"]["domain"] == "node_control")
    require(chosen["version"] == 1, "fresh Control did not start with wrapping version one")
    request = {"retirement_id": "1", "scope": scope,
               "identity": {k: chosen[k] for k in ("provider", "key_ref")},
               "retire_below_version": 2, "expected_coverage_sha256": initial["coverage_sha256"]}
    retire("referenced-version", request, "still referenced")
    io.stop()
    io.command("rotate", [daemon, "maintenance", "rotate-wrapping-keys", str(io.config)])
    open_node(2)
    after, current, second_max = read_catalogs(io, "rotated", scope, 256, profile)
    require(current["coverage_sha256"] != initial["coverage_sha256"]
            and all(row["key"]["version"] == 2 for row in after)
            and [{**row, "key": {**row["key"], "version": 2}} for row in before] == after,
            "rotation changed the catalog identities or failed to move every original key")
    retire("stale-coverage", request, "coverage differs")
    request["expected_coverage_sha256"] = current["coverage_sha256"]
    decision = retire("decide", request)
    owned.exact(decision, {"kind", "record"}, "key retirement decision")
    record = decision["record"]
    owned.exact(record, {"fence", "completed_revision", "completed_coverage_sha256"}, "key retirement record")
    fence = record["fence"]
    owned.exact(fence, {"request", "request_sha256", "fence_revision", "membership_epoch"}, "key retirement fence")
    require(decision["kind"] == "completed" and fence["request"] == request
            and fence["request_sha256"] == digest(["kasumi.retire-key-versions.v1", request])
            and fence["membership_epoch"] == current["membership_epoch"]
            and record["completed_revision"] > fence["fence_revision"] > current["coverage_revision"],
            "retirement did not commit after the original coverage and its fence")
    acceptance.checksum(record["completed_coverage_sha256"])
    io.stop()
    open_node(3)
    path = io.input("status-request", {"scope": scope, "retirement_id": "1"})
    status = json.loads(io.command("reopen-status", [daemon, "key-retention", "status", profile, path],
                                   scenario="race-safe-retirement"))
    require(status == {"last_ordinal": 1, "status": decision}
            and retire("repeat", request) == decision, "reopened retirement lost its exact decision")
    io.stop()
    return {"coverage_complete": True, "maximum_page_entries": max(first_max, second_max)}


class Replay(installed.Replay):
    expected_refusals = REFUSALS


def native_cases(io, functional_dir, original, functional):
    selected = libtest.artifacts(functional_dir, functional, CASES)
    for path, sha in selected.values():
        if isinstance(io, Replay):
            io.hashes[str(original / "target" / path)] = sha

    def run(step, command, sha, scenario):
        raw = io.command(step, command, scenario=scenario)
        if isinstance(io, installed.Live):
            require(io.run.report["processes"][-1]["executable"]["sha256"] == sha, "native key test binary differs")
        return raw

    libtest.replay(CASES, selected, original, run)


def execute(run, params):
    run.bind()
    functional = owned.read(run.evidence / "evidence.json")
    require(functional["python_executable"]["path"] == params["python"]
            and functional["python_executable"]["sha256"] == owned.sha256(params["python"]),
            "native interpreter differs")
    inputs = {}
    for name, value in sorted(install.init_inputs(params["base_port"]).items()):
        path = run.output / (name + ".json")
        domain_run.durable_json(path, value)
        inputs[name] = str(run.configuration(name, path))
    run.start_services(7200, 0, 0)
    io = installed.Live(run, params, inputs, None)
    measurements = protocol(io)
    native_cases(io, run.evidence, run.evidence, functional)
    require(set(run.scenarios) == acceptance.SCENARIOS[KIND], "key domain omitted a scenario")
    run.passed({**measurements, "functional_sha256": owned.sha256(run.evidence / "evidence.json")})


def verify_domain(root, domain, files, configs, artifacts, candidates):
    facts = domain_run.verify_run(root, domain, files, configs, KIND, RUNNER, MODULES)
    custody, report = facts["custody"], facts["report"]
    params = report["invocation"]["parameters"]
    owned.exact(params, {"base_port", "private_root", "python"}, "key-retention parameters")
    require(not domain["artifacts"] and not report["topology"] and not domain["topology"]
            and Path(params["private_root"]).is_absolute() and 1024 <= params["base_port"] <= 65532,
            "key retention requires an original standalone installation")
    primary = candidates[report["target"]]["primary"]["functional"]
    functional_path = acceptance.reference(root, primary)
    functional = owned.read(functional_path)
    require(functional["python_executable"]["path"] == params["python"], "key-retention interpreter changed")
    original = Path(report["evidence_root"])
    production, = (g for g in functional["gates"] if g["name"] == "production")
    binaries = {x["target"]: str(original / "target" / path) for path, x in production["executables"].items()
                if not x["test"] and domain["binaries"].get(x["target"]) == x["sha256"]}
    require(set(binaries) == set(domain["binaries"]), "key-retention production binaries differ")
    hashes = {path: domain["binaries"][name] for name, path in binaries.items()}
    hashes[params["python"]] = functional["python_executable"]["sha256"]
    settings = install.init_inputs(params["base_port"])
    require([c["id"] for c in report["configurations"]] == sorted(settings), "key-retention configuration roster differs")
    inputs = {}
    for c in report["configurations"]:
        require(acceptance.json_reference(custody, c["file"]) == settings[c["id"]], "key-retention setting differs")
        inputs[c["id"]] = str(Path(report["custody_root"]) / c["file"]["path"])
    io = Replay(facts, params, binaries, hashes, inputs, None)
    measured = protocol(io)
    native_cases(io, functional_path.parent, original, functional)
    require(next(io.sequence, None) is None and io.scenarios ==
            {key: [row["step"] for row in rows] for key, rows in facts["scenarios"].items()},
            "key-retention original process or scenario roster differs")
    require(report["details"] == {**measured, "functional_sha256": primary["sha256"]}
            and domain["details"] == {**measured, "report": owned.ref(root, custody / "report.json")},
            "key-retention gate differs from measured originals")
    return facts["evidence"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("evidence", "journal", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--base-port", type=int, required=True)
    args = parser.parse_args()
    require(1024 <= args.base_port <= 65532, "four free unprivileged loopback ports required")
    with tempfile.TemporaryDirectory(prefix="kasumi-key-retention-") as private:
        params = {"private_root": str(Path(private).resolve()), "base_port": args.base_port,
                  "python": str(Path(sys.executable).resolve())}
        with domain_run.Run(KIND, RUNNER, MODULES, args.evidence, args.output, args.journal,
                            args.attempt_id, params, domain_run.QUALIFYING) as run:
            execute(run, params)


if __name__ == "__main__":
    main()
