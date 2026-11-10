#!/usr/bin/env python3
"""Exercise the development helper against already-built, real Kasumi binaries.

  python3 scripts/smoke_dev_standalone.py --bin-dir target/debug

Creates a private temporary installation on three unused loopback ports. Checks
optional collection/index defaults, authenticated conditional writes, exact
idempotent replay, stop/resume persistence, and owned process/file cleanup.
The real `kasumid init` invocation deliberately interleaves its directory and
options. No software is compiled and no release/performance claim is made.

Prints one JSON result, never credentials or raw subprocess output. SIGINT,
SIGTERM and ordinary failures also attempt cleanup. Failed runs retain private
diagnostics and available server/supervisor logs, while removing the stopped
installation. Startup failures may retain only the helper's error and log tail.
If cleanup fails, the installation is retained too. The report names the private
directory; do not publish its contents without reviewing them.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import signal
import sys
import tempfile
import time
from types import SimpleNamespace
import warnings

import dev_standalone as dev


class SmokeFailure(ValueError):
    """A fixed smoke-test assertion that is safe to include in the report."""


def require(condition, message):
    if not condition:
        raise SmokeFailure(message)


def failure(result, step, error):
    result.update(status="failed", failed_step=step, error_type=type(error).__name__)
    if isinstance(error, SmokeFailure):
        result["error"] = str(error)


def preserve_failure(root, directory, result, error, name):
    """Retain useful failure evidence privately, never in the console report."""
    result["retained_private_directory"] = str(root)
    try:
        diagnostics = root / "diagnostics"
        diagnostics.mkdir(mode=0o700, exist_ok=True)
        dev.private_write(diagnostics / f"{name}.json", {
            "result": result, "exception_type": type(error).__name__, "exception": str(error),
        })
        for log in ("server.log", "supervisor.log"):
            source = directory / log
            if source.is_file():
                shutil.copyfile(source, diagnostics / log)
    except Exception as diagnostic_error:
        result["diagnostics_error_type"] = type(diagnostic_error).__name__


def free_base_port():
    # Below common ephemeral port ranges; start checks again before use.
    for base in random.sample(range(20000, 32000), 200):
        try:
            dev.require_free(dev.ports(base))
            return base
        except ValueError:
            pass
    raise SmokeFailure("no three consecutive loopback ports are available")


@contextlib.contextmanager
def reordered_init():
    """Change argument order, while still executing the real init subprocess."""
    original = dev.run
    observed = []

    def run(command, **options):
        command = list(command)
        if len(command) > 1 and command[1] == "init":
            require(command[2:4] == ["--mode", "standalone"], "unexpected helper init command")
            directory = command[4]
            pairs = dict(zip(command[5::2], command[6::2], strict=True))
            command = [command[0], "init", "--tenant", pairs.pop("--tenant"),
                       "--network", pairs.pop("--network"), directory, "--mode", "standalone",
                       *[part for pair in pairs.items() for part in pair]]
            observed.append(True)
        return original(command, **options)

    dev.run = run
    try:
        yield observed
    finally:
        dev.run = original


def stopped(directory, remove):
    """Drain recorded owned processes before allowing removal of their state."""
    state = dev.read_json(directory / dev.STATE)
    result = dev.stop(SimpleNamespace(directory=str(directory), remove=False))
    deadline = time.monotonic() + 10
    while any(state.get(kind) and dev.alive(state[kind])
              and dev.recorded(state, kind, state[kind]) for kind in dev.RECORDED):
        require(time.monotonic() < deadline, "an owned process survived stop")
        time.sleep(0.1)
    require("killed" not in result.values(), "stop needed forced termination")
    if remove:
        dev.stop(SimpleNamespace(directory=str(directory), remove=True))
        require(not directory.exists(), "stop --remove left the installation behind")


def exercise(arguments):
    binaries = Path(arguments.bin_dir).resolve()
    for name in ("kasumid", "kasumictl"):
        require(os.access(binaries / name, os.X_OK), f"missing executable: {name}")
    result = {"status": "failed", "checks": [], "binaries_sha256": {}}
    for name in ("kasumid", "kasumictl"):
        with (binaries / name).open("rb") as source:
            result["binaries_sha256"][name] = hashlib.file_digest(source, "sha256").hexdigest()
    root = Path(tempfile.mkdtemp(prefix="kasumi-dev-smoke-")).resolve()
    directory = root / "database"
    step = "start"
    try:
        definition = {
            "name": "smoke", "write_mode": "mutable", "retention_class": "operational",
            "schema": {"type": "object", "required": ["status", "amount"],
                       "properties": {"status": {"type": "string"}, "amount": {"type": "integer"}}},
            # Omit strict_read_audit and the index's unique/text defaults.
            "indexes": [{"name": "status", "fields": [{"path": "/status", "kind": "string"}]}],
        }
        collection = root / "collection.json"
        dev.private_write(collection, definition)
        with reordered_init() as initialized:
            state = dev.start(SimpleNamespace(
                directory=str(directory), bin_dir=str(binaries), collection=[str(collection)],
                base_port=free_base_port() if arguments.base_port is None else arguments.base_port,
                ready_timeout=arguments.ready_timeout, allow_sleep=True))
        require(initialized == [True], "the real reordered init command was not exercised")
        result["checks"].append("reordered_init_and_collection_defaults")
        profile = Path(state["profile"])

        def data(*command):
            status, document = dev.data(binaries, profile, *command, env=dev.children(directory))
            require(status == 0 and isinstance(document, dict) and document.get("ok") is True,
                    "authenticated data command failed")
            return document["result"]

        step = "write_and_replay"
        body = {"status": "open", "amount": 42}
        write = ("put", "smoke", "invoice-1", json.dumps(body), "--if", "absent",
                 "--key", "smoke:invoice-1")
        first = data(*write)
        require(first["receipt"]["revision"] > 0, "write has no committed revision")
        require(data(*write) == first, "replay changed the original request or receipt")
        document = data("get", "smoke", "invoice-1")["document"]
        require(document["id"] == "invoice-1" and document["body"] == body
                and document["version"] > 0, "readback differs from the committed document")
        result["checks"].append("authenticated_write_read_and_idempotent_replay")

        step = "stop_preserving_data"
        stopped(directory, remove=False)
        require(profile.is_file(), "stop without remove deleted the installation")
        result["checks"].append("stop_preserving_data")

        step = "resume"
        dev.resume(SimpleNamespace(directory=str(directory), bin_dir=str(binaries), allow_sleep=True))
        deadline = time.monotonic() + arguments.ready_timeout
        while True:
            status, ready = dev.data(binaries, profile, "collections", env=dev.children(directory))
            if status == 0 and ready and ready.get("ok") is True:
                break
            require(time.monotonic() < deadline, "resume did not reach authenticated readiness")
            time.sleep(0.25)
        require(data("get", "smoke", "invoice-1")["document"] == document,
                "restart changed the committed document")
        require(data(*write) == first, "restart lost the original idempotency receipt")
        result["checks"].append("resume_document_and_receipt_persistence")

        step = "stop_and_remove"
        stopped(directory, remove=True)
        result["checks"].append("stop_and_remove")
        result["status"] = "passed"
    except (Exception, KeyboardInterrupt) as error:
        failure(result, step, error)
        preserve_failure(root, directory, result, error, "failure")
    finally:
        try:
            if (directory / dev.STATE).exists():
                stopped(directory, remove=True)
            result["cleanup"] = "passed"
            if result["status"] == "passed":
                shutil.rmtree(root)
        except (Exception, KeyboardInterrupt) as error:
            result.update(status="failed", cleanup="failed", cleanup_error_type=type(error).__name__,
                          retained_private_directory=str(root))
            if isinstance(error, SmokeFailure):
                result["cleanup_error"] = str(error)
            preserve_failure(root, directory, result, error, "cleanup-failure")
        if root.exists():
            try:
                dev.private_write(root / "result.json", result)
            except Exception as error:
                result["diagnostics_error_type"] = type(error).__name__
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bin-dir", default=str(Path(__file__).resolve().parent.parent / "target/debug"))
    parser.add_argument("--base-port", type=int, help="use these three consecutive ports instead of choosing unused ports")
    parser.add_argument("--ready-timeout", type=float, default=120)
    arguments = parser.parse_args()
    os.umask(0o077)
    # The helper intentionally leaves its supervisor alive until stop reaps it.
    warnings.filterwarnings("ignore", r"subprocess \d+ is still running", ResourceWarning)

    def interrupted(_signal, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    try:
        require(1 <= arguments.ready_timeout <= 600, "ready timeout must be between 1 and 600 seconds")
        require(arguments.base_port is None or 1024 <= arguments.base_port <= 65533,
                "base port must be between 1024 and 65533")
        result = exercise(arguments)
    except (Exception, KeyboardInterrupt) as error:
        result = {}
        failure(result, "preflight", error)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
