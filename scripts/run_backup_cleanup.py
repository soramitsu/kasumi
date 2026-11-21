#!/usr/bin/env python3
"""Exercise a restarted installed backup and the native storage uncertainty and late-upload cases."""
import argparse
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import time
import uuid

if __name__ == "__main__":
    scripts = Path(__file__).resolve().parent
    if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode
            and sys.pycache_prefix is None and "PYTHONPYCACHEPREFIX" not in os.environ):
        raise SystemExit("backup cleanup requires Python -I -B -S")
    if any(path.name == "__pycache__" or path.suffix in {".pyc", ".pyo"}
           or (path.suffix == ".py" and path.is_symlink()) for path in scripts.rglob("*")):
        raise SystemExit("backup cleanup requires source-only Python imports")
    sys.path.insert(0, str(scripts))

import domain_run
from domain_run import require
import repeatable_assembly as owned
import run_correctness as libtest
import run_oci_smoke as install
import verify_release_acceptance as acceptance
from release_gate import sha256

KIND = "backup-cleanup"
RUNNER = "scripts/run_backup_cleanup.py"
MODULES = ("scripts/run_correctness.py", "scripts/run_oci_smoke.py", "scripts/oci_image.py")
TIMEOUT = 600
SERVICE_TIMEOUT = 1800
# Each row is a distinct native operation. Repeated late arrivals and empty
# namespace sweeps run in three fresh installations of the detailed test.
CASES = (
    ("lost-ack", "kasumi-engine", "backup_checkpoint", "durable_session_resolves_lost_ack_and_never_reclaims_completed_graph",
     1, ("completion-uncertainty", "completed-backup-isolation")),
    ("abort-root", "kasumi-engine", "backup_checkpoint", "abort_resolves_published_root_before_considering_cleanup",
     1, ("abort-resolution",)),
    ("late-upload", "kasumi-engine", "backup_checkpoint", "aborted_session_cleanup_is_bounded_and_catches_late_uploads",
     3, ("repeated-namespace-cleanup", "late-upload", "permanent-tombstones")),
    ("archive-isolation", "kasumi-store", "kasumi_store",
     "filesystem_abort_cleanup_is_bounded_repeatable_and_retains_control_and_other_namespaces",
     1, ("archive-isolation", "completed-backup-isolation", "repeated-namespace-cleanup", "permanent-tombstones")),
    ("durable-readback", "kasumi-store", "kasumi_store", "visible_session_outcomes_require_durable_readback_before_resolution_or_cleanup",
     1, ("completion-uncertainty", "abort-resolution")),
    ("cli-retry", "kasumi-server", "kasumi_server", "backup_cli_persists_session_before_connect_and_resolves_original_completion",
     1, ("completion-uncertainty",)),
)


def native_targets(evidence, functional):
    return libtest.artifacts(evidence, functional, {case: [(crate, target, leaf)]
                             for case, crate, target, leaf, _, _ in CASES})


def validate_checkpoints(created, checkpoint, status, verified, private, *, tenant=install.TENANT,
                         checkpoint_name="checkpoint.json"):
    acceptance.exact(created, {"checkpoint", "session_id"}, "backup create response")
    session = created["session_id"]
    require(uuid.UUID(session).int > 0 and created["checkpoint"] == str(private / checkpoint_name),
            "backup create returned another checkpoint location")
    acceptance.exact(checkpoint, {"tenant", "source_incarnation", "revision", "resident_sha256", "backup_id",
                                 "manifest_ciphertext_sha256", "key_lineage_digest"}, "full checkpoint")
    require(checkpoint == verified and checkpoint["backup_id"] == session and checkpoint["tenant"] == tenant
            and isinstance(checkpoint["source_incarnation"], str) and checkpoint["source_incarnation"],
            "verified backup differs from the original checkpoint")
    acceptance.uint(checkpoint["revision"], "backup revision")
    for name in ("resident_sha256", "manifest_ciphertext_sha256", "key_lineage_digest"):
        acceptance.checksum(checkpoint[name])
    require(status["intent"]["session_id"] == session and status["intent"]["tenant"] == checkpoint["tenant"]
            and status["intent"]["source_incarnation"] == checkpoint["source_incarnation"]
            and status["intent"]["revision"] == checkpoint["revision"] and status["outcome"]["outcome"] == "complete"
            and status["outcome"]["checkpoint"] == checkpoint, "durable session differs from verified checkpoint")
    acceptance.checksum(status["outcome"]["intent_ciphertext_sha256"])
    acceptance.checksum(status["source_purpose_sha256"])


def wait_listeners(port):
    deadline = time.monotonic() + 90
    for selected in range(port, port + 3):
        while True:
            try:
                with socket.create_connection(("127.0.0.1", selected), timeout=.5):
                    break
            except OSError:
                require(time.monotonic() < deadline, "installed listener did not start")
                time.sleep(.1)
    print(json.dumps({"listeners": list(range(port, port + 3))}))


def run_protocol(private, port, python, binaries, source, configs, command, start, stop, checkpoint, bind):
    require(private.is_absolute() and type(port) is int and 1024 <= port <= 65533, "invalid backup installation")
    daemon = binaries["kasumid"]
    installation = private / "installation"
    operator = str(installation / "profiles/operator.json")
    control = str(installation / "profiles/control.json")
    output = str(private / "checkpoint.json")
    command("initialize", [daemon, "init", "--mode", "standalone", str(installation),
                           *[arg for key in sorted(configs) for arg in ("--" + key, configs[key])],
                           "--tenant", install.TENANT], "kasumid")
    create = previous = None
    cases = {"completed-backup-isolation": [], "completion-uncertainty": []}
    for iteration in (1, 2):
        suffix = "-" + str(iteration)
        start(iteration, [daemon, "serve", str(installation / "kasumi.json")])
        raw = command("listeners" + suffix, [python, "-I", "-B", "-S", str(source / RUNNER), "listeners", str(port)], "python")
        require(json.loads(raw) == {"listeners": list(range(port, port + 3))}, "another endpoint was observed")
        health = json.loads(command("health" + suffix, [binaries["kasumictl"], "--profile", control, "health"], "kasumictl"))
        require(health["lifecycle"] == "serving", "authenticated backup installation is not serving")
        if iteration == 1:
            create = json.loads(command("create", [daemon, "backup", "create", operator, "local", output], "kasumid"))
        saved = checkpoint()
        session = create["session_id"]
        status = json.loads(command("status" + suffix, [daemon, "backup", "status", operator, "local", session], "kasumid"))
        verified = json.loads(command("verify" + suffix, [daemon, "backup", "verify", operator, "local", session], "kasumid"))
        validate_checkpoints(create, saved, status, verified, private)
        if previous is not None:
            require(previous == status, "restarted installation returned another permanent outcome")
            result = json.loads(command("resolve-abort", [daemon, "backup", "abort", operator, "local", session,
                                                        "resolve permanent completion"], "kasumid"))
            require(result == status, "restarted abort changed a completed backup")
            for scenario, step in (("completion-uncertainty", "resolve-abort"), ("completed-backup-isolation", "verify-2")):
                bind(scenario, step)
                cases[scenario].append(step)
        previous = status
        stop(iteration)
    return cases


def run_cases(selected, original, command, bind, scenarios):
    listings = {}
    for i, ((crate, target), (path, digest)) in enumerate(sorted(selected.items())):
        binary = str(original / "target" / path)
        listings[crate, target] = libtest.test_list(command(f"list-{i}", [binary, "--list", "--format", "terse"], digest))
    for case, crate, target, leaf, repeats, covers in CASES:
        relative, digest = selected[crate, target]
        listing = listings[crate, target]
        name = libtest.resolve(listing, leaf)
        binary = str(original / "target" / relative)
        for i in range(repeats):
            step = case + "-" + str(i + 1)
            data = command(step, [binary, "--exact", name, "--test-threads=1", "--format", "pretty"], digest)
            libtest.check_pass(data, name, len(listing))
            for scenario in covers:
                bind(scenario, step)
                scenarios.setdefault(scenario, []).append(step)
    require(set(scenarios) == acceptance.SCENARIOS[KIND] and all(
        len(scenarios[key]) >= 3 for key in ("repeated-namespace-cleanup", "late-upload")), "backup scenario coverage differs")
    return scenarios


def execute(run, private, port):
    run.bind()
    functional = owned.read(run.evidence / "evidence.json")
    python = functional["python_executable"]["path"]
    params = run.report["invocation"]["parameters"]
    require(params == {"private_root": str(private), "base_port": port, "python": python}
            and sha256(python) == functional["python_executable"]["sha256"], "native interpreter differs")
    configs = {}
    for name, value in sorted(install.init_inputs(port).items()):
        path = run.output / (name + ".json")
        with path.open("x") as stream:
            json.dump(value, stream, sort_keys=True)
        configs[name] = str(run.configuration(name, path))
    ids = {**run.report["binaries"], "python": functional["python_executable"]["sha256"]}
    selected = native_targets(run.evidence, functional)
    state = {}

    def command(step, cmd, key):
        data = run.command(step, cmd, TIMEOUT)
        item = run.report["processes"][-1]
        require(item["executable"]["sha256"] == ids.get(key, key), "backup process selected another executable")
        state[step] = item
        return data.read_bytes()

    def bind(scenario, step):
        run.observe(scenario, step, state[step]["receipt"], 0, 0)

    def start(i, cmd):
        identifier = run.service("daemon", cmd, {"path": cmd[0], "sha256": ids["kasumid"]})
        require(identifier == f"daemon-{i:04}", "unexpected daemon ordinal")

    def stop(_i):
        require(domain_run.service_disposition(run.services.stop("daemon", 90)) == "clean-stop",
                "backup daemon failed to drain")

    checkpoint_ref = None

    def checkpoint():
        nonlocal checkpoint_ref
        current = owned.retain(run.output, private / "checkpoint.json")
        require(checkpoint_ref in (None, current), "installed checkpoint bytes changed")
        checkpoint_ref = current
        return owned.read(owned.check_ref(run.output, current))

    run.start_services(SERVICE_TIMEOUT, 0, 0)
    scenarios = run_protocol(private, port, python, run.binary_paths, run.source, configs, command, start, stop, checkpoint, bind)
    run_cases(selected, run.evidence, command, bind, scenarios)
    run.passed({"functional_sha256": sha256(run.evidence / "evidence.json"), "checkpoint": checkpoint_ref})


def verify_domain(root, domain, files, configs, _artifacts, candidates):
    facts = domain_run.verify_run(root, domain, files, configs, KIND, RUNNER, MODULES)
    report, custody = facts["report"], facts["custody"]
    target = domain["id"].split(":")[1]
    primary = candidates[target]["primary"]["functional"]
    evidence_path = acceptance.reference(root, primary)
    functional = owned.read(evidence_path)
    details = report["details"]
    acceptance.exact(details, {"functional_sha256", "checkpoint"}, "backup cleanup report")
    require(details["functional_sha256"] == primary["sha256"] and domain["artifacts"] == {}
            and domain["topology"] == [], "backup cleanup does not refer to this functional build")
    params = report["invocation"]["parameters"]
    acceptance.exact(params, {"private_root", "base_port", "python"}, "backup cleanup parameters")
    port, private = params["base_port"], Path(params["private_root"])
    require(params["python"] == functional["python_executable"]["path"], "backup interpreter differs")
    original = Path(report["evidence_root"])
    source = original / "source"
    production, = (gate for gate in functional["gates"] if gate["name"] == "production")
    binaries = {item["target"]: str(original / "target" / path) for path, item in production["executables"].items()
                if item["test"] is False and item["sha256"] == domain["binaries"][item["target"]]}
    hashes = {**domain["binaries"], "python": functional["python_executable"]["sha256"]}
    settings = install.init_inputs(port)
    require([entry["id"] for entry in report["configurations"]] == sorted(settings),
            "backup cleanup configuration roster differs")
    paths = {}
    for entry in report["configurations"]:
        require(acceptance.json_reference(custody, entry["file"]) == settings[entry["id"]],
                "backup cleanup used different installation settings")
        paths[entry["id"]] = str(Path(report["custody_root"]) / entry["file"]["path"])
    inventory = iter(report["processes"])
    generations = []

    def take(step):
        item = next(inventory, None)
        require(item and item["id"] == step, "backup process missing or reordered: " + step)
        return item, facts["receipts"][step]["record"]

    def command(step, cmd, key):
        item, record = take(step)
        require(item["executable"]["sha256"] == hashes.get(key, key)
                and item["receipt"]["path"] == step + "/process.json" and item["log"]["path"] == step + "/stdout.log",
                "backup command receipt was substituted")
        owned.check_owned(custody, {"id": step, "receipt": item["receipt"], "stdout": item["log"],
                                    "stderr": record["stderr"], "executable": item["executable"]},
                          cmd, str(source), TIMEOUT)
        return acceptance.reference(custody, item["log"]).read_bytes()

    def start(i, cmd):
        step = f"daemon-{i:04}"
        item, record = take(step)
        require(record["id"] == step and record["name"] == "daemon" and record["command"] == cmd
                and record["working_directory"] == str(source) and record["timeout_seconds"] == SERVICE_TIMEOUT
                and record["executable"] == {"path": cmd[0], "sha256": hashes["kasumid"]}
                and item["executable"]["sha256"] == hashes["kasumid"]
                and item["receipt"]["path"] == "services/" + step + ".json" and item["log"]["path"] == "services/" + step + ".log"
                and facts["receipts"][step]["disposition"] == "clean-stop", "backup daemon was substituted")
        generations.append(record)

    saved = acceptance.json_reference(custody, details["checkpoint"])
    scenarios = run_protocol(private, port, params["python"], binaries, source, paths, command, start,
                             lambda _i: None, lambda: saved, lambda _scenario, _step: None)
    selected = native_targets(evidence_path.parent, functional)
    run_cases(selected, original, command, lambda _scenario, _step: None, scenarios)
    first, second = generations
    require(first["finished_elapsed_seconds"] <= second["started_elapsed_seconds"]
            and (first["process_group"], first["leader_birth"]) != (second["process_group"], second["leader_birth"]),
            "backup installation did not stop and start a new daemon")
    require(next(inventory, None) is None and scenarios == {
        key: [row["step"] for row in rows] for key, rows in facts["scenarios"].items()
    } and all(row["expected_exit"] == 0 for rows in facts["scenarios"].values() for row in rows),
            "backup cleanup outcome or native scenario roster differs")
    return facts["evidence"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("evidence", "journal", "output"):
        parser.add_argument("--" + key, type=Path, required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--base-port", type=int, required=True)
    args = parser.parse_args()
    previous = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix="kasumi-cleanup-") as directory:
            private = Path(directory).resolve(strict=True)
            params = {"private_root": str(private), "base_port": args.base_port,
                      "python": str(Path(sys.executable).resolve(strict=True))}
            with domain_run.Run(KIND, RUNNER, MODULES, args.evidence, args.output, args.journal,
                                args.attempt_id, params, domain_run.QUALIFYING) as run:
                execute(run, private, args.base_port)
    finally:
        os.umask(previous)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "listeners":
        wait_listeners(int(sys.argv[2]))
    else:
        main()
