#!/usr/bin/env python3
"""Disposable loopback standalone Kasumi for development and integration tests.

  dev_standalone.py start DIRECTORY --base-port PORT [--bin-dir DIR] [--collection FILE]...
  dev_standalone.py stop DIRECTORY [--remove]

`start` creates DIRECTORY (it must not exist), checks that 127.0.0.1 ports
PORT (MCP), PORT+1 (native) and PORT+2 (admin) are free, initializes a
standalone installation listening on them, starts `kasumid serve` and
`kasumid credential watch` detached, waits for an authenticated data read,
creates each collection definition through the administrative endpoint and
reads the definitions back. It prints one JSON document: paths, ports, process
IDs and the profile's SHA-256 and database binding for `kasumictl --expect-*`.
If `start` fails, it stops what it started and deletes DIRECTORY, after
quoting the end of the server log in its error. `stop` interrupts the watcher,
terminates the server and, with --remove, deletes the directory.

Credentials stay in owner-only files under DIRECTORY and are never printed or
passed as arguments. The processes' temporary files, including startup
diagnostics, also stay under DIRECTORY. The generated profile is the tenant
administrator; this is a development installation, not a release deployment.
Failures go to stderr with exit status 1.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time

STATE = "dev-standalone.json"
MAX_JSON = 1 << 20
TENANT = "default"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def private_write(path, value):
    """Create a new owner-only JSON file; never replace or follow an existing one."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(value, output, sort_keys=True)
        output.write("\n")


def read_json(path):
    with Path(path).open("rb") as source:
        data = source.read(MAX_JSON + 1)
    require(len(data) <= MAX_JSON, f"{path} exceeds its bounded input limit")
    return json.loads(data)


def ports(base):
    require(isinstance(base, int) and 1024 <= base <= 65533, "base port must be 1024 to 65533")
    return {"mcp": base, "native": base + 1, "admin": base + 2}


def require_free(selected):
    """Refuse ports that already have a loopback listener, before initializing."""
    for name, port in selected.items():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError as error:
                raise ValueError(f"{name} port {port} is not free: {error.strerror}") from None


def network(selected):
    return {
        "mcp_listen": f"127.0.0.1:{selected['mcp']}",
        "mcp_public_url": f"https://localhost:{selected['mcp']}/mcp",
        "native_listen": f"127.0.0.1:{selected['native']}",
        "admin_listen": f"127.0.0.1:{selected['admin']}",
    }


def admin_client(profile):
    """The administrative client configuration names the profile's token file."""
    require(len(profile["administrative_members"]) == 1, "expected one administrative member")
    member = next(iter(profile["administrative_members"].values()))
    return {
        "endpoint": member["endpoint"],
        "identity": profile["identity"],
        "server_ca": profile["server_ca"],
        "server_certificate_pins": sorted(member["certificate_pins"]),
        "token_file": profile["bearer_file"],
    }


def binding(profile_path):
    """The values `kasumictl --expect-*` compares; identifiers only, no secrets."""
    data = Path(profile_path).read_bytes()
    profile = json.loads(data)
    require(profile["resource"]["kind"] == "database", "profile is not a database credential")
    return {
        "profile_sha256": hashlib.sha256(data).hexdigest(),
        "tenant": profile["tenant"],
        "incarnation": profile["resource"]["incarnation"],
        "principal": profile["principal"],
        "family_id": profile["family_id"],
    }


def children(directory):
    """The environment for kasumid and kasumictl: temporary files stay inside."""
    return {**os.environ, "TMPDIR": str(directory / "tmp")}


def run(command, **options):
    return subprocess.run([str(part) for part in command], stdin=subprocess.DEVNULL,
                          capture_output=True, timeout=120, **options)


def data(binaries, profile, *command, env=None):
    """One kasumictl data command; returns its exit status and JSON document."""
    result = run([binaries / "kasumictl", "--profile", profile, *command], env=env)
    try:
        return result.returncode, json.loads(result.stdout)
    except json.JSONDecodeError:
        return result.returncode, None


def owned(pid, executable, argument):
    """Signal only a live process whose command line is the one this script started."""
    result = subprocess.run(["ps", "-ww", "-o", "command=", "-p", str(pid)], capture_output=True, text=True)
    line = result.stdout.strip()
    return result.returncode == 0 and line.startswith(str(executable)) and str(argument) in line


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def stop_process(entry, kind, wait):
    pid = entry.get(kind)
    if pid is None:
        return "absent"
    if not alive(pid):
        return "exited"
    if not owned(pid, entry["kasumid"], entry["profile" if kind == "watcher" else "configuration"]):
        return "not_owned"
    os.kill(pid, signal.SIGINT if kind == "watcher" else signal.SIGTERM)
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        if not alive(pid):
            return "stopped"
        time.sleep(0.1)
    os.kill(pid, signal.SIGKILL)
    return "killed"


def stop_child(process, kind, wait):
    """Stop and reap a process this invocation started and still holds."""
    if process is None:
        return "absent"
    if process.poll() is not None:
        return "exited"
    process.send_signal(signal.SIGINT if kind == "watcher" else signal.SIGTERM)
    try:
        process.wait(timeout=wait)
        return "stopped"
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        return "killed"


def log_tail(path, limit=2000):
    """The end of a process log, which holds no credentials, for an error."""
    try:
        with Path(path).open("rb") as log:
            log.seek(0, os.SEEK_END)
            log.seek(max(0, log.tell() - limit))
            return log.read().decode(errors="replace").strip()
    except OSError:
        return ""


def save(directory, state):
    path = directory / STATE
    temporary = directory / (STATE + ".pending")
    private_write(temporary, state)
    os.replace(temporary, path)


def start(arguments):
    os.umask(0o077)
    directory = Path(arguments.directory)
    require(directory.is_absolute(), "directory must be absolute")
    require(directory.parent.is_dir(), "the directory's parent must exist")
    binaries = Path(arguments.bin_dir).resolve()
    for binary in ("kasumid", "kasumictl"):
        require(os.access(binaries / binary, os.X_OK), f"{binaries / binary} is not executable")
    definitions = [Path(path).resolve() for path in arguments.collection]
    names = [read_json(path)["name"] for path in definitions]
    require(len(set(names)) == len(names), "collection names must be unique")
    selected = ports(arguments.base_port)
    require_free(selected)
    directory.mkdir(mode=0o700)
    (directory / "tmp").mkdir(mode=0o700)
    environment = children(directory)
    installation = directory / "installation"
    state = {"directory": str(directory), "kasumid": str(binaries / "kasumid"),
             "configuration": str(installation / "kasumi.json"),
             "profile": str(installation / "profiles/default.json")}
    save(directory, state)
    # Handles to this invocation's own children, so a failed start reaps them
    # instead of judging an exited server's zombie by its process ID.
    started = {}
    try:
        inputs = {
            "directory-policy": {"extent_bytes": 10485760, "max_entries": 32768},
            "file-allocation-policy": {"maximum_extra_extent_bytes": 1048576},
            "network": network(selected),
            "tenant-audit-placements": {"__kasumi_control": {"kind": "local_replica_only"},
                                        TENANT: {"kind": "local_replica_only"}},
        }
        for name, value in inputs.items():
            private_write(directory / f"{name}.json", value)
        init = run([binaries / "kasumid", "init", "--mode", "standalone", installation,
                    *[part for name in inputs for part in (f"--{name}", directory / f"{name}.json")],
                    "--tenant", TENANT], env=environment)
        require(init.returncode == 0, "kasumid init failed: " + init.stderr.decode(errors="replace")[-2000:])
        profile = Path(state["profile"])
        with (directory / "server.log").open("ab") as log:
            started["server"] = subprocess.Popen(
                [binaries / "kasumid", "serve", state["configuration"]], stdin=subprocess.DEVNULL,
                stdout=log, stderr=log, start_new_session=True, env=environment)
        state["server"] = started["server"].pid
        save(directory, state)
        deadline = time.monotonic() + arguments.ready_timeout
        while True:
            require(started["server"].poll() is None, "kasumid serve exited; see server.log")
            status, document = data(binaries, profile, "collections", env=environment)
            if status == 0 and document and document.get("ok"):
                break
            require(time.monotonic() < deadline, f"no authenticated data read before the deadline: {document}")
            time.sleep(0.25)
        with (directory / "credential.log").open("ab") as log:
            started["watcher"] = subprocess.Popen(
                [binaries / "kasumid", "credential", "watch", profile], stdin=subprocess.DEVNULL,
                stdout=log, stderr=log, start_new_session=True, env=environment)
        state["watcher"] = started["watcher"].pid
        save(directory, state)
        admin = directory / "admin-client.json"
        private_write(admin, admin_client(read_json(profile)))
        for definition in definitions:
            created = run([binaries / "kasumictl", "--config", admin, "create-collection", definition],
                          env=environment)
            require(created.returncode == 0,
                    f"create-collection {definition} failed: " + created.stderr.decode(errors="replace")[-2000:])
        status, document = data(binaries, profile, "collections", env=environment)
        require(status == 0, f"collection readback failed: {document}")
        installed = {entry["name"]: entry for entry in document["result"]["collections"]}
        for name, definition in zip(names, definitions):
            expected = read_json(definition)
            expected.setdefault("indexes", [])
            expected.setdefault("strict_read_audit", False)
            require(installed.get(name) == expected, f"collection {name} reads back differently")
        state.update({
            "ports": selected,
            "endpoints": {"native": f"https://localhost:{selected['native']}",
                          "admin": f"https://localhost:{selected['admin']}",
                          "mcp": network(selected)["mcp_public_url"]},
            "admin_client": str(admin),
            "binding": binding(profile),
            "collections": names,
            "logs": {"server": str(directory / "server.log"),
                     "credential_watch": str(directory / "credential.log")},
        })
        save(directory, state)
    except BaseException as error:
        for kind, wait in (("watcher", 10), ("server", 30)):
            stop_child(started.get(kind), kind, wait)
        tail = log_tail(directory / "server.log")
        # The directory holds keys and tokens, and nothing started here still runs.
        shutil.rmtree(directory)
        if isinstance(error, ValueError) and tail:
            raise ValueError(f"{error}\nserver.log ends:\n{tail}") from error
        raise
    return state


def stop(arguments):
    directory = Path(arguments.directory)
    require(directory.is_absolute(), "directory must be absolute")
    state = read_json(directory / STATE)
    require(state.get("directory") == str(directory), "state file belongs to another directory")
    result = {"directory": str(directory),
              "watcher": stop_process(state, "watcher", 10),
              "server": stop_process(state, "server", 30)}
    require("not_owned" not in result.values(), f"refusing to signal processes this script did not start: {result}")
    if arguments.remove:
        shutil.rmtree(directory)
    result["removed"] = arguments.remove
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    starting = commands.add_parser("start")
    starting.add_argument("directory")
    starting.add_argument("--base-port", type=int, required=True)
    starting.add_argument("--bin-dir", default=str(Path(__file__).resolve().parent.parent / "target/debug"))
    starting.add_argument("--collection", action="append", default=[])
    starting.add_argument("--ready-timeout", type=float, default=60)
    stopping = commands.add_parser("stop")
    stopping.add_argument("directory")
    stopping.add_argument("--remove", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        result = start(arguments) if arguments.command == "start" else stop(arguments)
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        print(f"dev_standalone: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
