#!/usr/bin/env python3
"""Run native provider services and exact frozen store clients with independently retained receipts."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
import platform
from pathlib import Path
from urllib.parse import urlsplit
import secrets
import sys
import tempfile
import time

if __name__ == "__main__":
    scripts = Path(__file__).resolve().parent
    if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode
            and sys.pycache_prefix is None and "PYTHONPYCACHEPREFIX" not in os.environ):
        raise SystemExit("providers requires Python -I -B -S")
    if any(path.name == "__pycache__" or path.suffix in {".pyc", ".pyo"}
           or (path.suffix == ".py" and path.is_symlink()) for path in scripts.rglob("*")):
        raise SystemExit("providers requires source-only Python imports")
    sys.path.insert(0, str(scripts))

import domain_run
from domain_run import require
import provider_artifacts as providers
import package_release as package
import repeatable_assembly as owned
import run_correctness as libtest
import verify_release_acceptance as acceptance
from release_gate import sha256

KIND = "providers"
RUNNER = "scripts/run_providers.py"
MODULES = ("scripts/run_correctness.py", "scripts/provider_artifacts.py", "scripts/fetch_openbao.py")
CASES = {"openbao": ("openbao_live", "actual_openbao_transit_roundtrip_rotation_backups_and_warm_revocation"),
         "minio": ("kasumi_store", "actual_minio_tls_sigv4_encrypted_roundtrip_create_only_and_access_denial")}
TIMEOUT = 120
VERSION = {"openbao": providers.fetch_openbao.VERSION, "minio": providers.MINIO_RELEASE}


def exact_keys(mapping, keys, label):
    require(isinstance(mapping, dict) and set(mapping) == set(keys), "invalid " + label)


def target_arch(target):
    require(target in providers.TARGETS, "providers requires a native Linux host for the pinned MinIO executable")
    return providers.TARGETS[target]


def check_configuration(path):
    config = owned.read(path)
    require(any(tenant["keys"]["kind"] == "transit" for tenant in config["tenants"])
            and any(dest["kind"] == "s3" for dest in config["backup_destinations"].values()),
            "installed configuration must select a tenant Transit key and S3 backup destination")


def clients(evidence, functional):
    return libtest.artifacts(evidence, functional, {
        kind: [("kasumi-store", target, test)] for kind, (target, test) in CASES.items()})


def extract(archive, target):
    operating_system, arch = target_arch(target)
    return {"openbao": providers.openbao(archive["openbao"], (operating_system, arch)),
            "minio": providers.minio(archive["minio"], arch)}


def check_bao_listener(config, path):
    exact_keys(config, {"api_addr", "disable_mlock", "storage", "listener"}, "OpenBao fixture configuration")
    require(config["disable_mlock"] is True and config["storage"] == {"file": {"path": str(path.parent / "bao-storage")}}
            and isinstance(config["listener"], list) and len(config["listener"]) == 1, "OpenBao must reopen its own filesystem store")
    endpoint = urlsplit(config["api_addr"])
    require(endpoint.scheme == "https" and endpoint.hostname == "127.0.0.1" and 1024 <= endpoint.port <= 65535
            and config["api_addr"] == f"https://127.0.0.1:{endpoint.port}", "OpenBao must bind TLS on loopback")
    require(config["listener"] == [{"tcp": {"address": f"127.0.0.1:{endpoint.port}",
            "tls_cert_file": str(path.parent / "bao.pem"), "tls_key_file": str(path.parent / "bao.key"),
            "tls_min_version": "tls13", "tls_disable_client_certs": True, "cluster_address":"127.0.0.1:0"}}],
            "OpenBao TLS listener differs")


def server_command(kind, binary, request, private):
    if kind == "openbao":
        exact_keys(request, {"config"}, "OpenBao start request")
        child = Path(request["config"])
        paths = [child]
        require(child.name == "bao.json", "unexpected OpenBao configuration")
        cmd = [binary, "server", "-config", str(child), "-log-level=error"]
    else:
        exact_keys(request, {"port", "objects", "certs"}, "MinIO start request")
        data, certs, port = Path(request["objects"]), Path(request["certs"]), request["port"]
        paths = [data, certs]
        require(data.name == "objects" and certs.name == "certs" and data.parent == certs.parent
                and type(port) is int and 1024 <= port <= 65535, "invalid MinIO storage/endpoint")
        cmd = [binary, "server", str(data), "--address", "127.0.0.1:" + str(port),
               "--console-address", "127.0.0.1:0", "--certs-dir", str(certs), "--quiet"]
    for child in paths:
        require(child.is_absolute() and child.is_relative_to(private / "work")
                and ".." not in child.parts, "provider fixture is outside its private root")
    return cmd


@contextmanager
def environment(controller, additions):
    original = controller.environment
    controller.environment = {**original, **additions}
    try:
        yield
    finally:
        controller.environment = original


def await_event(controller, name, request, deadline):
    while not request.is_file():
        controller.check()
        require(controller.active[name]["process"].poll() is None, name + " exited before " + request.name)
        require(time.monotonic() < deadline, "timed out waiting for " + name + "/" + request.name)
        time.sleep(.04)
    data = request.read_bytes()
    require(len(data) <= 8192 and not request.is_symlink(), "invalid live provider event")
    return json.loads(data)


def live_test(run, kind, private, binaries, selected, full_name):
    probe = kind + "-probe"
    relative, expected = selected["kasumi-store", CASES[kind][0]]
    client = str(run.evidence / "target" / relative)
    command = [client, "--exact", full_name, "--ignored", "--test-threads=1", "--format", "pretty"]
    control = private / probe
    control.mkdir(mode=0o700)
    work = private / "work"
    common = {"KASUMI_PROVIDER_CONTROL": str(control), "TMPDIR": str(work),
              "KASUMI_MINIO_WORKDIR": str(work), "KASUMI_OPENBAO_BIN": str(binaries["openbao"])}
    user, first, second = ("kasumi" + secrets.token_hex(12), secrets.token_hex(32), secrets.token_hex(32))
    if kind == "minio":
        common.update(KASUMI_MINIO_USER=user, KASUMI_MINIO_FIRST=first, KASUMI_MINIO_SECOND=second)
    controller = run.services
    with environment(controller, common):
        probe_id = run.service(probe, command, {"path": client, "sha256": expected}, interactive=True)
    deadline = time.monotonic() + TIMEOUT
    original = None
    bao_listener = None
    identifiers = []
    for gen in (1, 2):
        event = "start-" + str(gen)
        req = await_event(controller, probe, control / event, deadline)
        if gen == 1:
            original = req
        require(req == original, "provider restart changed its storage or listener")
        cmd = server_command(kind, str(binaries[kind]), req, private)
        for candidate in [Path(item) for item in cmd[1:] if item.startswith("/")]:
            require(candidate.resolve(strict=True) == candidate, "provider selected a noncanonical path")
        if kind == "openbao":
            config = Path(req["config"])
            check_bao_listener(owned.read(config), config)
            retained = owned.retain(run.output, config)
            require(bao_listener in (None, retained), "OpenBao configuration changed during restart")
            bao_listener = retained
        settings = {"MINIO_ROOT_USER": user, "MINIO_ROOT_PASSWORD": first if gen == 1 else second,
                    "MINIO_BROWSER": "off"} if kind == "minio" else {}
        with environment(controller, settings):
            identifier = run.service(kind, cmd, {"path": cmd[0], "sha256": sha256(cmd[0])})
        identifiers.append(identifier)
        controller.send(probe, (event + "\n").encode())
        stop = "stop-" + str(gen)
        require(await_event(controller, probe, control / stop, deadline) is None, "invalid provider stop")
        record = controller.stop(kind)
        require(domain_run.service_disposition(record) == "clean-stop", "provider failed to stop cleanly")
        controller.send(probe, (stop + "\n").encode())
    require(await_event(controller, probe, control / "complete", deadline) is None,
            "provider test did not finish its assertions")
    record = controller.end_input(probe)
    require(domain_run.service_disposition(record) == "input-closed", "provider test failed to exit")
    receipt = owned.ref(run.output, run.output / "services" / (probe_id + ".json"))
    for scenario in ("real-" + kind, "credential-refresh", "provider-restart"):
        run.observe(scenario, probe_id, receipt, 0, record["process_exit_code"])
    return {"probe": probe_id, "incarnations": identifiers, "request": original, "bao_listener": bao_listener}


def execute(run, private, paths):
    target = run.bind()
    _, arch = target_arch(target)
    require(platform.system() == "Linux" and {"aarch64": "arm64", "x86_64": "amd64"}.get(platform.machine()) == arch,
            "provider services must run on the native functional target")
    inputs = {name: run.configuration(name, path) for name, path in paths.items()}
    check_configuration(inputs["runtime"])
    (private / "work").mkdir(mode=0o700)
    binaries = {}
    for name, data in extract(inputs, target).items():
        path = private / name
        path.write_bytes(data)
        path.chmod(0o700)
        package.verify_architecture(path, target)
        binaries[name] = path
    source = run.evidence / "evidence.json"
    selected = clients(run.evidence, owned.read(source))
    output = run.command("daemon-config", [run.binary_paths["kasumid"], "check-config", str(inputs["runtime"])], TIMEOUT)
    require("Configuration structure is valid" in output.read_text(), "daemon rejected provider configuration")
    run.start_services(2 * TIMEOUT + 60, 0, 0)
    details = {}
    for kind, (target_name, leaf) in CASES.items():
        client, digest = selected["kasumi-store", target_name]
        command = [str(run.evidence / "target" / client), "--list", "--format", "terse"]
        listing = libtest.test_list(run.command("list-" + kind, command, TIMEOUT).read_bytes())
        require(run.report["processes"][-1]["executable"]["sha256"] == digest, "another test was listed")
        name = libtest.resolve(listing, leaf)
        details[kind] = live_test(run, kind, private, binaries, selected, name)
        libtest.check_pass((run.output / "services" / (details[kind]["probe"] + ".log")).read_bytes(), name, len(listing))
    run.passed({"functional_sha256": sha256(source), "services": details})


def verify_domain(root, domain, files, configs, _artifacts, candidates):
    facts = domain_run.verify_run(root, domain, files, configs, KIND, RUNNER, MODULES)
    report, custody = facts["report"], facts["custody"]
    target = domain["id"].split(":")[1]
    target_arch(target)
    primary = candidates[target]["primary"]["functional"]
    functional_path = acceptance.reference(root, primary)
    functional = owned.read(functional_path)
    details = report["details"]
    exact_keys(details, {"functional_sha256", "services"}, "provider report")
    exact_keys(details["services"], CASES, "provider service roster")
    exact_keys(report["invocation"]["parameters"], {"private_root"}, "provider parameters")
    private = Path(report["invocation"]["parameters"]["private_root"])
    require(private.is_absolute() and ".." not in private.parts and details["functional_sha256"] == primary["sha256"]
            and domain["artifacts"] == {}, "provider run has inconsistent inputs")
    actual = {item["id"]: acceptance.reference(custody, item["file"]) for item in report["configurations"]}
    exact_keys(actual, {"openbao", "minio", "runtime"}, "provider inputs")
    check_configuration(actual["runtime"])
    digests = {name: providers.digest(data) for name, data in extract(actual, target).items()}
    original = Path(report["evidence_root"])
    source = str(original / "source")
    selected = clients(functional_path.parent, functional)
    inventory = iter(report["processes"])
    scenarios = {"real-openbao": [], "real-minio": [], "credential-refresh": [], "provider-restart": []}
    published = {item["id"]: item for item in domain["details"]["services"]}
    exact_keys(published, CASES, "published providers")

    def next_item(step, hash_, cmd, service=False, disposition=None):
        item = next(inventory, None)
        require(item and item["id"] == step and item["executable"]["sha256"] == hash_,
                "provider process missing or changed: " + step)
        record = facts["receipts"][step]["record"]
        if service:
            require(item["receipt"]["path"] == "services/" + step + ".json"
                    and item["log"]["path"] == "services/" + step + ".log"
                    and record["id"] == step and record["name"] == step.rsplit("-", 1)[0]
                    and record["command"] == cmd and record["working_directory"] == source
                    and record["executable"] == {"path": cmd[0], "sha256": hash_}
                    and record["timeout_seconds"] == 2 * TIMEOUT + 60
                    and facts["receipts"][step]["disposition"] == disposition,
                    "provider service command or disposition differs: " + step)
        else:
            require(item["receipt"]["path"] == step + "/process.json"
                    and item["log"]["path"] == step + "/stdout.log", "provider command output was substituted")
            owned.check_owned(custody, {"id": step, "receipt": item["receipt"], "stdout": item["log"],
                                       "stderr": record["stderr"], "executable": item["executable"]},
                              cmd, source, TIMEOUT)
        return record, acceptance.reference(custody, item["log"]).read_bytes()

    production, = (gate for gate in functional["gates"] if gate["name"] == "production")
    daemon, = (relative for relative, artifact in production["executables"].items()
               if artifact["target"] == "kasumid" and not artifact["test"]
               and artifact["sha256"] == domain["binaries"]["kasumid"])
    runtime = str(Path(report["custody_root"]) / actual["runtime"].relative_to(custody))
    _, output = next_item("daemon-config", domain["binaries"]["kasumid"],
                          [str(original / "target" / daemon), "check-config", runtime])
    require(b"Configuration structure is valid" in output, "missing daemon configuration result")
    for i, (kind, (test_target, leaf)) in enumerate(CASES.items()):
        relative, digest = selected["kasumi-store", test_target]
        client = str(original / "target" / relative)
        _, raw = next_item("list-" + kind, digest, [client, "--list", "--format", "terse"])
        listing = libtest.test_list(raw)
        name = libtest.resolve(listing, leaf)
        data = details["services"][kind]
        exact_keys(data, {"probe", "incarnations", "request", "bao_listener"}, "provider observation")
        probe = f"{kind}-probe-{i * 3 + 1:04}"
        service_ids = [f"{kind}-{i * 3 + j:04}" for j in (2, 3)]
        require(data["probe"] == probe and data["incarnations"] == service_ids, "provider run changed incarnations")
        probe_receipt, raw = next_item(probe, digest, [client, "--exact", name, "--ignored", "--test-threads=1",
                                                       "--format", "pretty"], True, "input-closed")
        libtest.check_pass(raw, name, len(listing))
        command = server_command(kind, str(private / kind), data["request"], private)
        if kind == "openbao":
            check_bao_listener(acceptance.json_reference(custody, data["bao_listener"]), Path(data["request"]["config"]))
        else:
            require(data["bao_listener"] is None, "unexpected OpenBao configuration for MinIO")
        records = [next_item(step, digests[kind], command, True, "clean-stop")[0] for step in service_ids]
        first, second = records
        require(probe_receipt["started_elapsed_seconds"] <= first["started_elapsed_seconds"]
                < first["finished_elapsed_seconds"] <= second["started_elapsed_seconds"]
                < second["finished_elapsed_seconds"] <= probe_receipt["finished_elapsed_seconds"]
                and (first["leader_birth"], first["process_group"]) != (second["leader_birth"], second["process_group"]),
                "provider restart does not have two sequential, independent owned lifetimes")
        identity = published[kind]
        require(identity["version"] == VERSION[kind] and identity["process_id"] == service_ids[0]
                and identity["executable"]["sha256"] == digests[kind],
                "provider service identity is not the published native release")
        for scenario in ("real-" + kind, "credential-refresh", "provider-restart"):
            scenarios[scenario].append(probe)
    require(next(inventory, None) is None and scenarios == {
        scenario: [row["step"] for row in rows] for scenario, rows in facts["scenarios"].items()
    } and all(row["expected_exit"] == 0 for rows in facts["scenarios"].values() for row in rows),
            "provider process or scenario roster differs")
    return facts["evidence"]


def project_gate(root, report_path, identity, host, configs):
    """Project this run for the enclosing acceptance bundle; verify_domain replays the result."""
    root = Path(root).resolve(strict=True)
    report_path = Path(report_path).resolve(strict=True)
    original = owned.read(report_path)
    processes = {item["id"]: item for item in original["processes"]}
    services = []
    for kind in CASES:
        step = original["details"]["services"][kind]["incarnations"][0]
        item = processes[step]
        executable = owned.check_ref(report_path.parent, item["executable"])
        services.append({"id": kind, "version": VERSION[kind], "process_id": step,
                         "executable": owned.ref(root, executable)})
    return domain_run.gate_record(root, report_path, identity, host, configs, {},
                                  {"report": owned.ref(root, report_path), "services": services})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("evidence", "journal", "output", "openbao", "minio", "runtime"):
        parser.add_argument("--" + key, type=Path, required=True)
    parser.add_argument("--attempt-id", required=True)
    args = parser.parse_args()
    previous = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix="kasumi-providers-") as directory:
            private = Path(directory).resolve(strict=True)
            with domain_run.Run(KIND, RUNNER, MODULES, args.evidence, args.output, args.journal,
                                args.attempt_id, {"private_root": str(private)}, domain_run.QUALIFYING) as run:
                execute(run, private, {name: getattr(args, name) for name in ("openbao", "minio", "runtime")})
    finally:
        os.umask(previous)


if __name__ == "__main__":
    main()
