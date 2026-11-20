#!/usr/bin/env python3
"""Smoke-test the delivered OCI image through a native container runtime.

The image archive is first verified against the pinned base, the candidate
binaries and its image SBOM. It is then loaded, a fresh standalone installation
is initialised inside a new volume, and the default entrypoint serves it. An
authenticated native request and an MCP request must succeed before and after
a restart, and the daemon must exit zero on the runtime's stop signal.

Every runtime invocation is an owned process; the command list is a pure
function of the retained parameters, so the adapter rebuilds and compares it.
"""
from __future__ import annotations

import sys
if __name__ == "__main__" and not (sys.flags.isolated and sys.flags.no_site
                                  and sys.flags.dont_write_bytecode):
    raise SystemExit("OCI smoke runner requires native Python -I -S -B")

import argparse
import json
import os
from pathlib import Path
import tempfile
import time

if __name__ == "__main__":
    _scripts = Path(__file__).resolve(strict=True).parent
    if sys.pycache_prefix is not None or "PYTHONPYCACHEPREFIX" in os.environ:
        raise SystemExit("OCI smoke runner forbids a redirected Python bytecode cache")
    if ((_scripts / "__pycache__").exists() or (_scripts / "__pycache__").is_symlink()
            or any(path.suffix in {".pyc", ".pyo"} or
                   (path.suffix == ".py" and path.is_symlink())
                   for path in _scripts.rglob("*"))):
        raise SystemExit("OCI smoke runner requires source-only Python imports")
    sys.path.insert(0, str(_scripts))

import domain_run
from domain_run import require
import gate_process
import oci_image
import repeatable_assembly as owned
from release_gate import sha256

KIND = "oci-smoke"
RUNNER = "scripts/run_oci_smoke.py"
MODULES = ("scripts/oci_image.py", "scripts/mcp_probe.py")
INSTALLATION = "/var/lib/kasumi/installation"
INPUTS = "/var/lib/kasumi/inputs"
CONTROL = "/opt/kasumi/bin/kasumictl"
TENANT = "smoke"
TIMEOUT = 600
READY_POLLS = 300
MCP_FILES = ("kasumi.json", "profiles/mcp.json", "profiles/mcp.token",
             "profiles/client.pem", "profiles/client-key.pem", "tls/ca.pem", "tls/mcp.pem")
POLICIES = {"directory-policy": {"extent_bytes": 10485760, "max_entries": 32768},
            "file-allocation-policy": {"maximum_extra_extent_bytes": 1048576},
            "tenant-audit-placements": {"__kasumi_control": {"kind": "local_replica_only"},
                                        TENANT: {"kind": "local_replica_only"}}}


def init_inputs(port):
    return {**POLICIES, "network": {
        "mcp_listen": f"127.0.0.1:{port}", "mcp_public_url": f"https://localhost:{port}/mcp",
        "native_listen": f"127.0.0.1:{port + 1}", "admin_listen": f"127.0.0.1:{port + 2}"}}


def plan(parameters, image, python, probe):
    """Every step in order: (id, scenario, command). ``ready-*`` steps are polled."""
    runtime, port = parameters["runtime"], parameters["base_port"]
    name = "kasumi-smoke-" + parameters["attempt_id"].lower()
    volume = name + ":/var/lib/kasumi"
    reference = image["reference"]
    inputs = init_inputs(port)
    write = "umask 077 && mkdir " + INPUTS + " && " + " && ".join(
        "printf '%s' '" + json.dumps(inputs[key], sort_keys=True, separators=(",", ":"))
        + "' > " + INPUTS + "/" + key + ".json" for key in sorted(inputs))
    profile = INSTALLATION + "/profiles/"
    ready = [runtime, "exec", name, CONTROL, "--profile", profile + "control.json", "ready"]
    native = [runtime, "exec", name, CONTROL, "--profile", profile + "default.json", "collections"]
    def mcp_steps(stage, scenario, step):
        mapped = Path(parameters["export"]) / stage
        copies = [(f"copy-{stage}-{relative.replace('/', '-').replace('.', '-')}", scenario,
                   [runtime, "cp", name + ":" + INSTALLATION + "/" + relative,
                    str(mapped / relative)]) for relative in MCP_FILES]
        return [*copies, (step, scenario, [python, "-I", "-B", "-S", probe, "--installation",
                                          INSTALLATION, "--mapped", str(mapped)])]
    return [
        ("load", "load-image", [runtime, "load", "--input", parameters["image"]]),
        ("identify", "load-image", [runtime, "image", "inspect", "--format", "{{.Id}}", reference]),
        ("volume", "fresh-install", [runtime, "volume", "create", name]),
        ("inputs", "fresh-install", [runtime, "run", "--rm", "--network", "none", "--volume", volume,
                                     "--entrypoint", "/bin/sh", reference, "-c", write]),
        ("init", "fresh-install", [
            runtime, "run", "--rm", "--network", "none", "--volume", volume, reference,
            "init", "--mode", "standalone", INSTALLATION,
            *[part for key in sorted(inputs) for part in ("--" + key, INPUTS + "/" + key + ".json")],
            "--tenant", TENANT]),
        ("start", "native", [runtime, "run", "--detach", "--name", name, "--network", "host",
                             "--volume", volume, reference]),
        ("ready-start", None, ready),
        ("native", "native", native),
        *mcp_steps("start", "mcp", "mcp"),
        ("restart", "restart", [runtime, "restart", "--time", "60", name]),
        ("ready-restart", None, ready),
        ("native-restarted", "restart", native),
        *mcp_steps("restart", "restart", "mcp-restarted"),
        ("stop", "clean-stop", [runtime, "stop", "--time", "60", name]),
        ("exit", "clean-stop", [runtime, "inspect", "--format",
                                "{{.State.ExitCode}} {{.State.OOMKilled}}", name]),
        ("remove", None, [runtime, "rm", name]),
        ("remove-volume", None, [runtime, "volume", "rm", name]),
    ]


def check_outputs(image, outputs):
    """The domain verdicts read from the original standard outputs."""
    require(outputs["identify"].decode().strip() in (image["manifest_digest"], image["config_digest"]),
            "runtime loaded another image than the verified archive")
    for step in ("native", "native-restarted"):
        document = json.loads(outputs[step])
        require(document.get("ok") is True and isinstance(document.get("result"), dict),
                "authenticated native request did not succeed: " + step)
    for step in ("mcp", "mcp-restarted"):
        summary = json.loads(outputs[step])
        require(summary.get("status") == 200 and summary.get("tls") == "TLSv1.3"
                and "kasumi_get" in summary.get("tools", []),
                "MCP request did not succeed: " + step)
    require(json.loads(outputs["mcp"])["certificate_sha256"]
            == json.loads(outputs["mcp-restarted"])["certificate_sha256"],
            "MCP TLS identity changed across the restart")
    require(outputs["exit"].decode().split() == ["0", "false"],
            "container daemon did not exit zero on its stop signal")


def check_record(record, image, target, image_sha256, sbom_sha256):
    """The assembly record names exactly the verified image and SBOM bytes."""
    require(isinstance(record, dict) and record.get("schema") == oci_image.SCHEMA
            and record.get("target") == target
            and all(record.get(key) == value for key, value in image.items())
            and record.get("image", {}).get("sha256") == image_sha256
            and record.get("image_sbom", {}).get("sha256") == sbom_sha256,
            "image assembly record differs from the verified image")


def execute(run, parameters, image_path, sbom_path, record_path, pause):
    target = run.bind()
    require(target in oci_image.ARCHITECTURES, "OCI smoke runs on a native Linux target")
    image = oci_image.verify(run.source, image_path, sbom_path, target, run.report["binaries"])
    check_record(owned.read(run.configuration("oci-image", record_path)), image, target,
                 sha256(image_path), sha256(sbom_path))
    for tool in (parameters["runtime"], sys.executable):
        require(Path(tool).is_absolute(), "smoke tools must be absolute executables")
    details = {"image": image,
               "image_file": {"sha256": sha256(image_path), "bytes": Path(image_path).stat().st_size},
               "image_sbom": {"sha256": sha256(sbom_path), "bytes": Path(sbom_path).stat().st_size},
               "tools": {name: gate_process.executable_identity([path], run.source, run.environment)
                         for name, path in (("runtime", parameters["runtime"]),
                                            ("python", str(Path(sys.executable).resolve())))},
               "ready_polls": []}
    run.report["details"] = details
    run.environment["PATH"] = str(Path(parameters["runtime"]).parent) + os.pathsep + "/usr/bin:/bin"
    run.save()
    outputs = {}
    export = Path(parameters["export"])
    require(export.is_absolute() and not export.is_symlink()
            and export.is_dir() and export.stat().st_uid == os.getuid()
            and export.stat().st_mode & 0o777 == 0o700,
            "MCP inputs require a private directory owned by the smoke runner")
    for stage in ("start", "restart"):
        mapped = export / stage
        mapped.mkdir(mode=0o700)
        for subdir in ("profiles", "tls"):
            (mapped / subdir).mkdir(mode=0o700)
    steps = plan(parameters, image, details["tools"]["python"]["path"],
                 str(run.source / "scripts/mcp_probe.py"))
    for step, scenario, command in steps:
        if step.startswith("ready-"):
            for poll in range(READY_POLLS):
                item = owned.run_owned(run.output, f"{step}-{poll:04d}", command, str(run.source),
                                       run.environment, TIMEOUT)
                if owned.read(owned.check_ref(run.output, item["receipt"]))["exit_code"] == 0:
                    run.report["processes"].append({
                        "id": step, "receipt": item["receipt"], "log": item["stdout"],
                        "executable": item["executable"]})
                    run.save()
                    break
                details["ready_polls"].append(item["receipt"])
                time.sleep(pause)
            else:
                raise ValueError("container daemon never became ready: " + step)
        else:
            outputs[step] = run.command(step, command, TIMEOUT, scenario=scenario).read_bytes()
    check_outputs(image, outputs)
    run.passed(details)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--journal", type=Path, required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--image-sbom", type=Path, required=True)
    parser.add_argument("--image-record", type=Path, required=True,
                        help="image.json written by oci_image.py")
    parser.add_argument("--runtime", type=Path, required=True,
                        help="absolute docker-compatible runtime executable")
    parser.add_argument("--base-port", type=int, required=True,
                        help="first of three free loopback ports")
    args = parser.parse_args(argv)
    require(1024 <= args.base_port <= 65533, "base port must leave three unprivileged ports")
    with tempfile.TemporaryDirectory(prefix="kasumi-oci-smoke-") as export:
        parameters = {"attempt_id": args.attempt_id, "runtime": str(args.runtime.resolve(strict=True)),
                      "base_port": args.base_port, "image": str(args.image.resolve(strict=True)),
                      "export": str(Path(export).resolve(strict=True))}
        with domain_run.Run(KIND, RUNNER, MODULES, args.evidence, args.output, args.journal,
                            args.attempt_id, parameters, domain_run.QUALIFYING) as run:
            execute(run, parameters, args.image.resolve(strict=True),
                    args.image_sbom.resolve(strict=True), args.image_record, 1.0)
    print("OCI smoke retained: " + str(args.output))
    return 0


# ---- Acceptance adapter ----

def verify_domain(root, domain, files, configs, artifacts, candidates):
    import verify_release_acceptance as acceptance

    root = Path(root).resolve(strict=True)
    target = domain["id"].split(":", 1)[1]
    facts = domain_run.verify_run(root, domain, files, configs, KIND, RUNNER, MODULES)
    report, receipts = facts["report"], facts["receipts"]
    details, parameters = report["details"], report["invocation"]["parameters"]
    owned.exact(details, {"image", "image_file", "image_sbom", "tools", "ready_polls"},
                "OCI smoke details")
    owned.exact(parameters, {"attempt_id", "runtime", "base_port", "image", "export"},
                "OCI smoke parameters")
    require(parameters["attempt_id"] == report["attempt_id"], "OCI smoke names another attempt")
    # The delivered artifacts are the bytes that were loaded and inspected.
    image_ref = artifacts["oci:" + target]["file"]
    sbom_ref = artifacts["image-sbom:" + target]["file"]
    require(domain["artifacts"] == {"oci:" + target: image_ref["sha256"],
                                    "image-sbom:" + target: sbom_ref["sha256"]}
            and details["image_file"] == {"sha256": image_ref["sha256"], "bytes": image_ref["bytes"]}
            and details["image_sbom"] == {"sha256": sbom_ref["sha256"], "bytes": sbom_ref["bytes"]},
            "OCI smoke did not run the delivered image and SBOM")
    source = acceptance.reference(root, candidates[target]["primary"]["functional"]).parent / "source"
    require(files[oci_image.BASE_PIN]["sha256"] == sha256(source / oci_image.BASE_PIN),
            "pinned base image record differs from frozen source")
    image = oci_image.verify(source, acceptance.reference(root, image_ref),
                             acceptance.reference(root, sbom_ref), target, domain["binaries"])
    require(image == details["image"], "delivered image differs from the smoked image")
    require([item["id"] for item in report["configurations"]] == ["oci-image"],
            "OCI smoke retained another configuration roster")
    check_record(acceptance.json_reference(facts["custody"], report["configurations"][0]["file"]),
                 image, target, image_ref["sha256"], sbom_ref["sha256"])
    tools = details["tools"]
    steps = plan(parameters, image, tools["python"]["path"],
                 str(Path(report["evidence_root"]) / "source/scripts/mcp_probe.py"))
    custody = facts["custody"]
    roster = [item["id"] for item in report["processes"]]
    require(roster == [step for step, _, _ in steps], "OCI smoke process roster differs from its plan")
    outputs, attributed = {}, {}
    logs = {item["id"]: item["log"] for item in report["processes"]}
    for step, scenario, command in steps:
        record = receipts[step]["record"]
        tool = tools["python"] if step.startswith("mcp") else tools["runtime"]
        require(record["command"] == command and record["executable"] == tool
                and receipts[step]["exit_code"] == 0,
                "OCI smoke step differs from its planned runtime command: " + step)
        outputs[step] = acceptance.reference(custody, logs[step]).read_bytes()
        if scenario is not None:
            attributed.setdefault(scenario, []).append(step)
    require({name: [row["step"] for row in rows] for name, rows in facts["scenarios"].items()}
            == attributed, "OCI smoke scenarios differ from the planned steps")
    check_outputs(image, outputs)
    return facts["evidence"]


if __name__ == "__main__":
    raise SystemExit(main())
