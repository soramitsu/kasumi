#!/usr/bin/env python3
"""Exercise an actual release package across a fresh install, restart and clean stop."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import socket
import sys
import tarfile
import tempfile
import time

if __name__ == "__main__":
    scripts = Path(__file__).resolve().parent
    if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode
            and sys.pycache_prefix is None and "PYTHONPYCACHEPREFIX" not in os.environ):
        raise SystemExit("package smoke requires native Python -I -B -S")
    if any(path.name == "__pycache__" or path.suffix in {".pyc", ".pyo"}
           or (path.suffix == ".py" and path.is_symlink()) for path in scripts.rglob("*")):
        raise SystemExit("package smoke requires source-only Python imports")
    sys.path.insert(0, str(scripts))

import domain_run
from domain_run import require
import package_release as package
import repeatable_assembly as owned
from run_oci_smoke import init_inputs, TENANT
from release_gate import sha256

KIND = "package-smoke"
RUNNER = "scripts/run_package_smoke.py"
MODULES = ("scripts/run_oci_smoke.py", "scripts/oci_image.py", "scripts/mcp_probe.py")
TIMEOUT = 180
DAEMON_COMMAND = "daemon"


def unpack(archive, destination):
    """Copy only the three executable members from the delivered package into a fresh directory."""
    destination = Path(destination)
    require(not destination.exists() and not (destination.parent / "installation").exists(),
            "package smoke requires a fresh installation and binary directory")
    destination.mkdir(mode=0o700)
    binaries = {}
    digest = sha256(archive)
    with tarfile.open(archive, "r:gz") as handle:
        prefix = None
        for entry in handle:
            relative = PurePosixPath(entry.name)
            require(relative.parts and relative.as_posix() == entry.name.rstrip("/")
                    and not relative.is_absolute() and ".." not in relative.parts
                    and (entry.isfile() or entry.isdir()), "unsafe package member")
            prefix = prefix or relative.parts[0]
            require(relative.parts[0] == prefix, "package contains multiple roots")
            if len(relative.parts) != 3 or relative.parts[1] != "bin":
                continue
            name = relative.parts[2]
            require(name in package.BINARIES and name not in binaries and entry.isfile()
                    and entry.mode & 0o111 and 0 < entry.size <= 1 << 30,
                    "package executable is absent, ambiguous or outside its work bound")
            path = destination / name
            with path.open("xb") as out, handle.extractfile(entry) as src:
                shutil.copyfileobj(src, out)
            path.chmod(0o700)
            binaries[name] = sha256(path)
    require(set(binaries) == package.BINARIES and sha256(archive) == digest,
            "release package changed or omitted an executable")
    return {"package_sha256": digest, "binaries": binaries}


def wait_for_listeners(port):
    """Wait for loopback listeners. Subsequent native and MCP calls authenticate both peers."""
    deadline = time.monotonic() + 90
    for selected in [port, port + 1]:
        while True:
            try:
                with socket.create_connection(("127.0.0.1", selected), timeout=.5):
                    break
            except OSError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(.1)
    return {"listeners": [port, port + 1]}


def steps(parameters, source, configurations):
    private = Path(parameters["private_root"])
    installation = private / "installation"
    binaries = private / "bin"
    port = parameters["base_port"]
    require(type(port) is int and 1024 <= port <= 65533 and private.is_absolute()
            and Path(parameters["package"]).is_absolute(), "invalid package smoke parameters")
    python = [parameters["python"], "-I", "-B", "-S"]
    helper = python + [str(Path(source) / RUNNER)]
    daemon = str(binaries / "kasumid")
    result = [("unpack", "fresh-install", helper + ["unpack", parameters["package"], str(binaries)]),
              ("init", "initialize", [daemon, "init", "--mode", "standalone", str(installation),
                                      *[arg for key in sorted(configurations)
                                        for arg in ("--" + key, configurations[key])],
                                      "--tenant", TENANT])]
    for i in (1, 2):
        result.extend([
            (f"daemon-{i:04}", "restart" if i == 1 else "clean-stop",
             [daemon, "serve", str(installation / "kasumi.json")]),
            (f"listeners-{i}", None, helper + ["listeners", str(port)]),
            (f"native-{i}", "native" if i == 1 else "restart",
             [str(binaries / "kasumictl"), "--profile", str(installation / "profiles/default.json"),
              "collections"]),
            (f"mcp-{i}", "mcp" if i == 1 else "restart",
             python + [str(Path(source) / "scripts/mcp_probe.py"), "--installation", str(installation),
                       "--mapped", str(installation)])])
    return result


def check_output(step, output, parameters, binaries):
    if step == "init":
        return
    value = json.loads(output)
    if step == "unpack":
        require(value == {"package_sha256": parameters["package_sha256"], "binaries": binaries},
                "package extraction differs from the selected candidate")
    elif step.startswith("listeners-"):
        port = parameters["base_port"]
        require(value == {"listeners": [port, port + 1]}, "package listeners differ")
    elif step.startswith("native-"):
        require(value.get("ok") is True and isinstance(value.get("result"), dict)
                and isinstance(value["result"].get("collections"), list),
                "native collection listing failed")
    else:
        require(value.get("status") == 200 and value.get("tls") == "TLSv1.3"
                and isinstance(value.get("tools"), list) and "kasumi_get" in value["tools"]
                and isinstance(value.get("certificate_sha256"), str)
                and re.fullmatch(r"[0-9a-f]{64}", value["certificate_sha256"]),
                "MCP package probe failed")


def check_restart(before, after):
    require(json.loads(before)["certificate_sha256"] == json.loads(after)["certificate_sha256"],
            "package MCP identity changed across restart")


def execute(run, params):
    run.bind()
    functional = owned.read(run.evidence / "evidence.json")
    require(sha256(params["python"]) == functional["python_executable"]["sha256"],
            "package smoke interpreter differs from the selected functional input")
    retained = {}
    for key, value in sorted(init_inputs(params["base_port"]).items()):
        path = run.output / (key + ".json")
        with path.open("x") as stream:
            json.dump(value, stream, sort_keys=True)
        retained[key] = str(run.configuration(key, path))
    run.start_services(1200, 0, 0)
    outputs = {}
    for step, scenario, command in steps(params, run.source, retained):
        if step.startswith("daemon-"):
            identifier = run.service(DAEMON_COMMAND, command, {"path": command[0],
                                      "sha256": run.report["binaries"]["kasumid"]})
            require(identifier == step, "unexpected daemon execution ordinal")
            continue
        outputs[step] = run.command(step, command, TIMEOUT, scenario=scenario).read_bytes()
        check_output(step, outputs[step], params, run.report["binaries"])
        if step.startswith("mcp-"):
            ordinal = int(step[-1])
            daemon_id = f"daemon-{ordinal:04}"
            stopped = run.services.stop(DAEMON_COMMAND, 90)
            require(domain_run.service_disposition(stopped) == "clean-stop", "package daemon failed to drain")
            run.observe("restart" if ordinal == 1 else "clean-stop", daemon_id,
                        owned.ref(run.output, run.output / "services" / (daemon_id + ".json")), 0,
                        stopped["process_exit_code"])
    check_restart(outputs["mcp-1"], outputs["mcp-2"])
    run.passed({"functional_sha256": sha256(run.evidence / "evidence.json")})


def verify_domain(root, domain, files, configs, artifacts, candidates):
    import verify_release_acceptance as acceptance

    target = domain["id"].split(":")[1]
    facts = domain_run.verify_run(root, domain, files, configs, KIND, RUNNER, MODULES)
    report, custody = facts["report"], facts["custody"]
    params = report["invocation"]["parameters"]
    owned.exact(params, {"private_root", "base_port", "package", "package_sha256", "python"},
                "package smoke parameters")
    primary = candidates[target]["primary"]["functional"]
    require(report["details"] == {"functional_sha256": primary["sha256"]},
            "package smoke did not use the selected functional build")
    functional = acceptance.json_reference(root, primary)
    artifact = artifacts["package:" + target]["file"]
    require(domain["artifacts"] == {"package:" + target: artifact["sha256"]}
            and params["package_sha256"] == artifact["sha256"], "smoked another package")
    expected = init_inputs(params["base_port"])
    require([item["id"] for item in report["configurations"]] == sorted(expected),
            "package smoke configuration roster differs")
    paths = {}
    for item in report["configurations"]:
        name = item["id"]
        require(acceptance.json_reference(custody, item["file"]) == expected[name],
                "package smoke configuration changed: " + name)
        paths[name] = str(Path(report["custody_root"]) / item["file"]["path"])
    source = Path(report["evidence_root"]) / "source"
    planned = steps(params, source, paths)
    require([item["id"] for item in report["processes"]] == [item[0] for item in planned],
            "package smoke omitted, reordered or added a process")
    outputs, daemons = {}, []
    scenarios = {"fresh-install": ["unpack"], "initialize": ["init"], "native": ["native-1"],
                 "mcp": ["mcp-1"], "restart": ["daemon-0001", "native-2", "mcp-2"],
                 "clean-stop": ["daemon-0002"]}
    for (step, _, command), item in zip(planned, report["processes"], strict=True):
        record = facts["receipts"][step]["record"]
        name = Path(command[0]).name
        expected_hash = (domain["binaries"][name] if name in package.BINARIES
                         else functional["python_executable"]["sha256"])
        require(record["command"] == command and record["working_directory"] == str(source)
                and record["executable"] == {"path": command[0], "sha256": expected_hash}
                and item["executable"]["sha256"] == expected_hash,
                "package smoke command or tool differs: " + step)
        if step.startswith("daemon-"):
            require(record["id"] == step and record["name"] == DAEMON_COMMAND
                    and domain_run.service_disposition(record) == "clean-stop"
                    and item["receipt"]["path"] == "services/" + step + ".json"
                    and item["log"]["path"] == "services/" + step + ".log",
                    "package daemon did not stop cleanly")
            daemons.append(record)
        else:
            require(item["receipt"]["path"] == step + "/process.json"
                    and item["log"]["path"] == step + "/stdout.log" and item["log"] == record["stdout"],
                    "package probe output is not its original stdout")
            owned.check_owned(custody, {"id": step, "receipt": item["receipt"], "stdout": item["log"],
                                       "stderr": record["stderr"], "executable": item["executable"]},
                              command, str(source), TIMEOUT)
            outputs[step] = acceptance.reference(custody, item["log"]).read_bytes()
            check_output(step, outputs[step], params, domain["binaries"])
    check_restart(outputs["mcp-1"], outputs["mcp-2"])
    require(daemons[0]["finished_elapsed_seconds"] <= daemons[1]["started_elapsed_seconds"]
            and (daemons[0]["process_group"], daemons[0]["leader_birth"])
            != (daemons[1]["process_group"], daemons[1]["leader_birth"]),
            "package restart lacks two distinct, sequential daemon lifetimes")
    require({name: [row["step"] for row in rows] for name, rows in facts["scenarios"].items()}
            == scenarios, "package smoke scenarios differ from original execution")
    return facts["evidence"]


def main():
    if sys.argv[1:2] == ["unpack"] and len(sys.argv) == 4:
        print(json.dumps(unpack(sys.argv[2], sys.argv[3]), sort_keys=True))
        return
    if sys.argv[1:2] == ["listeners"] and len(sys.argv) == 3:
        print(json.dumps(wait_for_listeners(int(sys.argv[2]))))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("evidence", "journal", "output", "package"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--base-port", type=int, required=True, help="first of three free loopback ports")
    args = parser.parse_args()
    require(1024 <= args.base_port <= 65533, "three unprivileged loopback ports are required")
    with tempfile.TemporaryDirectory(prefix="kasumi-package-smoke-") as private:
        params = {"private_root": str(Path(private).resolve()), "base_port": args.base_port,
                  "package": str(args.package.resolve()), "package_sha256": None,
                  "python": str(Path(sys.executable).resolve())}
        with domain_run.Run(KIND, RUNNER, MODULES, args.evidence, args.output, args.journal,
                            args.attempt_id, params, domain_run.QUALIFYING) as run:
            params["package_sha256"] = sha256(args.package)
            execute(run, params)


if __name__ == "__main__":
    main()
