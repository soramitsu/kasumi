#!/usr/bin/env python3
"""Run functional release gates against a frozen source with retained evidence.

This does not certify capacity, recovery drills, external services or endurance.
The output directory is exclusive and keeps failed/partial runs for inspection.

With --attempt-root and --attempt-id the run is a native primary functional
attempt: it is admitted to the host's append-only attempt journal before any
output exists, checks its prerequisites before dispatch, runs its gates through
one owned runner process, and always terminates the admission with the original
evidence.json as its build evidence. Without them it is a development run.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import resource
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time

import gate_process

TOOLCHAIN = "1.97.1"
CARGO_JSON = "--message-format=json-render-diagnostics"
FORBIDDEN_FIXTURE_FEATURES = frozenset({"test-utils", "embedded-fixture", "loopback-fixture"})

_SERDE_JSON = ("--manifest-path", "vendor/serde_json-1.0.151/Cargo.toml")
_RMCP = ("--manifest-path", "vendor/rmcp-3.11.0/Cargo.toml")
_OPENRAFT = ("--manifest-path", "vendor/openraft-0.9.25/Cargo.toml")
_OPENRAFT_FEATURES = "serde,storage-v2,single-term-leader,generic-snapshot-data"

# Upstream suites of every reviewed vendor fork, as (gate, Cargo subcommand,
# selection, trailing arguments). The pinned toolchain, --locked, jobs and
# JSON encoding (except for Clippy) are added by functional_gates. The OpenRaft
# rows repeat the custody commands retained by
# docs/evidence/openraft-canonical-20260920 attempts 46-49.
VENDOR_SUITES = (
    ("lru", "test", ("--manifest-path", "vendor/lru-0.16.4/Cargo.toml"), ()),
    ("serde-json-default", "test", _SERDE_JSON, ()),
    ("serde-json-number", "test", _SERDE_JSON + ("--features", "arbitrary_precision"), ()),
    ("serde-json-raw", "test", _SERDE_JSON + ("--features", "raw_value"), ()),
    ("serde-json-combined", "test", _SERDE_JSON + (
        "--features", "arbitrary_precision,raw_value,float_roundtrip,preserve_order"), ()),
    ("rmcp-terminal-ownership", "test", _RMCP + (
        "--features", "transport-streamable-http-server", "--lib"), ("terminal_stateless_tests",)),
    ("rmcp-upstream-protocol", "test", _RMCP + (
        "--features", "client,transport-streamable-http-server,reqwest",
        "--test", "test_streamable_http_json_response", "--test", "test_streamable_http_standard_headers",
        "--test", "test_streamable_http_protocol_version", "--test", "test_stateless_protocol_version",
        "--test", "test_protocol_version_negotiation", "--test", "test_server_discover"), ()),
    ("openraft-units", "test", _OPENRAFT + ("-p", "openraft", "--lib", "--features", _OPENRAFT_FEATURES), ()),
    ("openraft-integration", "test", _OPENRAFT + (
        "-p", "tests", "--test", "life_cycle", "--test", "client_api",
        "--test", "membership", "--test", "snapshot_streaming"), ()),
    ("openraft-singlethreaded", "check", _OPENRAFT + (
        "-p", "openraft", "--all-targets", "--features", "singlethreaded," + _OPENRAFT_FEATURES), ()),
    ("openraft-clippy", "clippy", _OPENRAFT + (
        "-p", "openraft", "--all-targets", "--features", _OPENRAFT_FEATURES), ("--", "-D", "warnings")),
)

# Test output that an upstream suite writes inside its own package. After the
# gate's process group drains, it is moved out of the frozen source; any other
# gate that creates it, like any other write, invalidates the run.
GENERATED_OUTPUTS = {"openraft-integration": "vendor/openraft-0.9.25/tests/_log"}

PRODUCTION_BINARIES = ("kasumid", "kasumictl", "kasumi-authority")
# A journaled attempt's products, relative to its admitted output. The
# acceptance verifier selects evidence.json beside exactly these paths.
FUNCTIONAL_PRODUCTS = {**{name: "target/release/" + name for name in PRODUCTION_BINARIES},
                       "source-archive": "source.tar", "source-inventory": "source-files.json"}
# The journaled launcher's one owned child: the frozen copy of this script.
PREPARED_COMMAND = "run-prepared"
RUNNER = "runner"
# Names the attempt a runner was launched for; gates never inherit it.
RUNNER_ENV = "KASUMI_FUNCTIONAL_RUNNER_ATTEMPT"
RUNNER_TIMEOUT_SECONDS = 86400
NATIVE_TARGETS = {("Linux", "x86_64"): "x86_64-unknown-linux-gnu",
                  ("Linux", "aarch64"): "aarch64-unknown-linux-gnu",
                  ("Darwin", "arm64"): "aarch64-apple-darwin"}


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


MAX_CARGO_LOG_LINE_BYTES = 16 << 20


def _unique_cargo_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate Cargo JSON key: " + key)
        result[key] = value
    return result


def _reject_nonfinite_cargo(value):
    raise ValueError("nonfinite Cargo JSON value: " + value)


def compiler_artifact_messages(log, command=None):
    """Parse bounded Cargo JSON lines only for commands requesting that format."""
    if command is not None and CARGO_JSON not in command:
        return
    with Path(log).open("rb") as stream:
        while line := stream.readline(MAX_CARGO_LOG_LINE_BYTES + 1):
            if len(line) > MAX_CARGO_LOG_LINE_BYTES:
                raise ValueError("oversized Cargo gate log line")
            try:
                message = json.loads(line, object_pairs_hook=_unique_cargo_object,
                                     parse_constant=_reject_nonfinite_cargo)
            except (UnicodeDecodeError, ValueError) as error:
                if line.lstrip().startswith(b"{"):
                    raise ValueError("malformed JSON-looking Cargo gate log line") from error
                continue
            if isinstance(message, dict) and message.get("reason") == "compiler-artifact":
                yield message


def compiler_executable_identity(message):
    target = message.get("target")
    profile = message.get("profile")
    package_id = message.get("package_id")
    if (not isinstance(target, dict) or not isinstance(target.get("name"), str)
            or not target["name"] or not isinstance(profile, dict)
            or type(profile.get("test")) is not bool
            or not isinstance(package_id, str) or not package_id):
        raise ValueError("compiler-artifact executable metadata is malformed")
    return {"target": target["name"], "test": profile["test"], "package_id": package_id}


def record_compiled_package(packages, message):
    """Build the exact Cargo package/feature/target inventory from its log."""
    package_id = message.get("package_id")
    target = message.get("target")
    features = message.get("features")
    if (not isinstance(package_id, str) or not package_id
            or not isinstance(target, dict)
            or not isinstance(target.get("name"), str) or not target["name"]
            or any(not isinstance(target.get(field), list)
                   or not target[field]
                   or any(not isinstance(value, str) or not value for value in target[field])
                   for field in ("kind", "crate_types"))
            or not isinstance(features, list)
            or any(not isinstance(value, str) or not value for value in features)):
        raise ValueError("compiler-artifact package metadata is malformed")
    package = packages.setdefault(package_id, {"features": [], "targets": []})
    package["features"] = sorted(set(package["features"]) | set(features))
    target_record = {field: target[field] for field in ("name", "kind", "crate_types")}
    if target_record not in package["targets"]:
        package["targets"].append(target_record)


def write_json(path, value):
    path = Path(path)
    staged = path.with_suffix(path.suffix + ".pending")
    with staged.open("w") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    staged.replace(path)
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def extract_source(archive, destination):
    """Accept only regular source files/directories inside the new source root."""
    destination = Path(destination)
    destination.mkdir()
    with tarfile.open(archive, "r:") as source:
        for member in source:
            relative = PurePosixPath(member.name)
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError("source archive path escapes its root")
            if not (member.isdir() or member.isfile()):
                raise ValueError("source archive contains a link or special file")
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with source.extractfile(member) as data, target.open("xb") as output:
                for block in iter(lambda: data.read(1 << 20), b""):
                    output.write(block)
            target.chmod(0o755 if member.mode & 0o111 else 0o644)


def inventory(directory):
    result = {}
    for path in sorted(Path(directory).rglob("*")):
        if path.is_symlink():
            raise ValueError("source gained a symbolic link")
        if path.is_file():
            result[path.relative_to(directory).as_posix()] = {
                "sha256": sha256(path), "bytes": path.stat().st_size,
                "executable": bool(path.stat().st_mode & 0o111),
            }
        elif not path.is_dir():
            raise ValueError("source gained a special file")
    return result


def verify_export(repository, commit, directory, files):
    """Compare every exported file and mode with the committed Git tree."""
    listing = subprocess.check_output(["git", "-C", str(repository), "ls-tree", "-rz", commit])
    expected = {}
    for entry in listing.split(b"\0"):
        if not entry:
            continue
        metadata, name = entry.split(b"\t", 1)
        mode, kind, oid = metadata.split()
        path = os.fsdecode(name)
        if path.startswith("docs/evidence/"):
            continue
        if kind != b"blob" or mode not in (b"100644", b"100755"):
            raise ValueError("unsupported committed source entry: " + path)
        expected[path] = (mode == b"100755", oid.decode("ascii"))
    if expected.keys() != files.keys():
        raise ValueError("archive paths differ from Git tree: "
                         + repr(sorted(expected.keys() ^ files.keys())[:20]))
    for path, (executable, oid) in expected.items():
        entry = files[path]
        digest = hashlib.new("sha1" if len(oid) == 40 else "sha256")
        digest.update(f"blob {entry['bytes']}\0".encode("ascii"))
        with (Path(directory) / path).open("rb") as source:
            for block in iter(lambda: source.read(1 << 20), b""):
                digest.update(block)
        if digest.hexdigest() != oid or entry["executable"] != executable:
            raise ValueError("archive bytes or mode differ from Git tree: " + path)


def memory_observation(membership=Path("/proc/self/cgroup"), root=Path("/sys/fs/cgroup")):
    """Record the runner's inherited process limits and visible cgroup counters.

    These reads are not atomic. Ancestor counters can include other workloads;
    a cumulative peak is not a per-gate peak. Missing counters are explicit and
    cannot be interpreted as zero pressure or absence of an OOM kill.
    """
    record = {"observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "scope": "raw visible cgroup counters; non-atomic and possibly shared",
              "runner_rlimits": {}, "rlim_infinity": resource.RLIM_INFINITY,
              "membership": None, "cgroups": {}, "errors": []}
    for name in ("AS", "CPU", "FSIZE", "NOFILE", "STACK"):
        soft, hard = resource.getrlimit(getattr(resource, "RLIMIT_" + name))
        record["runner_rlimits"][name] = {"soft": soft, "hard": hard}
    try:
        with Path(membership).open() as source:
            value = source.read(65537)
        if len(value) > 65536:
            raise ValueError("cgroup membership exceeds work limit")
        record["membership"] = value
        for line in value.splitlines():
            fields = line.split(":", 2)
            if len(fields) != 3 or ".." in Path(fields[2]).parts:
                raise ValueError("invalid cgroup membership")
            if not fields[1]:
                controller = Path(root)
                names = ("memory.current", "memory.peak", "memory.max", "memory.events",
                         "memory.events.local", "memory.swap.current", "memory.swap.max")
            elif "memory" in fields[1].split(","):
                controller = Path(root) / "memory"
                names = ("memory.usage_in_bytes", "memory.max_usage_in_bytes",
                         "memory.limit_in_bytes", "memory.failcnt", "memory.oom_control")
            else:
                continue
            directory = controller.joinpath(*[p for p in Path(fields[2]).parts if p not in ("/", ".")])
            while directory.is_relative_to(controller):
                counters = record["cgroups"].setdefault(str(directory), {})
                for name in names:
                    path = directory / name
                    try:
                        with path.open() as source:
                            content = source.read(65537)
                        if len(content) > 65536:
                            raise ValueError("cgroup counter exceeds work limit")
                        counters[name] = content
                    except FileNotFoundError:
                        continue
                    except (OSError, ValueError) as error:
                        record["errors"].append(str(path) + ": " + str(error))
                if directory == controller:
                    break
                directory = directory.parent
    except (OSError, ValueError) as error:
        record["errors"].append(str(error))
    record["available"] = any(record["cgroups"].values())
    return record


def collect_compiler_outputs(log, command, target):
    artifacts = {}
    compiled_packages = {}
    for message in compiler_artifact_messages(log, command):
        record_compiled_package(compiled_packages, message)
        raw = message.get("executable")
        if raw is not None:
            if (not isinstance(raw, str) or not Path(raw).is_absolute()
                    or os.path.normpath(raw) != raw):
                raise ValueError("compiler-artifact executable path is malformed")
            identity = compiler_executable_identity(message)
            executable = Path(raw).resolve()
            relative = str(executable.relative_to(target))
            if relative in artifacts:
                raise ValueError("duplicate compiler-artifact executable identity")
            artifacts[relative] = identity
    for relative, artifact in artifacts.items():
        path = target / relative
        artifact.update(sha256=sha256(path), bytes=path.stat().st_size)
    return artifacts, compiled_packages


def run_gate(name, command, source, output, environment, timeout_seconds=14400):
    """Hash actual executable outputs only after the original process group drains."""
    log = Path(output) / (name + ".log")
    process_path = Path(output) / (name + "-process.json")
    target = (Path(output) / "target").resolve()
    inventory_error = None
    memory_before = memory_observation()
    resources = Path(output) / (name + "-resources.json")
    write_json(resources, {"before": memory_before, "after": None})
    process = None
    try:
        with log.open("wb") as stream:
            process = gate_process.run(command, source, environment, stream, timeout_seconds,
                                       lambda value: write_json(process_path, value),
                                       stderr=subprocess.STDOUT)
        process["outputs_stable"] = process["cleanup"]["drained"] and not process["cleanup"]["errors"]
        write_json(process_path, process)
        if not process["outputs_stable"]:
            raise RuntimeError("gate process custody is uncertain; logs and artifacts remain unverified")
        # Read the retained file after command ownership closes. A silent child
        # cannot hold a pipe open beyond the command's original deadline.
        try:
            artifacts, compiled_packages = collect_compiler_outputs(log, command, target)
        except (ValueError, OSError) as error:
            if process["exit_code"] == 0:
                raise
            # Keep the child's actual failure even if its compiler stream is incomplete.
            inventory_error = str(error)
            artifacts, compiled_packages = {}, {}
    except BaseException as error:
        if process is not None:
            for cleanup_error in process["cleanup"]["errors"]:
                error.add_note(cleanup_error)
            if not process["cleanup"]["drained"]:
                error.add_note("original gate process group has not drained")
        raise
    finally:
        write_json(resources, {"before": memory_before, "after": memory_observation()})
    return {
        "name": name, "command": command, "exit_code": process["exit_code"],
        "duration_seconds": process["duration_seconds"],
        "log": log.name, "log_sha256": sha256(log), "executables": artifacts,
        "compiled_packages": compiled_packages,
        **({"inventory_error": inventory_error} if inventory_error is not None else {}),
        "process": process_path.name, "process_sha256": sha256(process_path),
        "process_cleanup": process["cleanup"], "timed_out": process["timed_out"],
        "received_signals": process["received_signals"], "process_error": process["error"],
        "timeout_seconds": timeout_seconds,
        "resources": resources.name, "resources_sha256": sha256(resources),
    }


def functional_gates(jobs, python_executable):
    cargo = ["cargo", "+" + TOOLCHAIN]
    locked = ["--locked", "-j", str(jobs)]
    encoded = [CARGO_JSON]
    return [
        ("toolchain", ["rustc", "+" + TOOLCHAIN, "-Vv"]),
        ("format", cargo + ["fmt", "--all", "--", "--check"]),
        ("python", [python_executable, "-m", "unittest", "discover", "-s", "scripts", "-p", "test_*.py", "-v"]),
        ("dependency-patches", [python_executable, "scripts/check_dependency_patches.py"]),
        *((name, cargo + [subcommand, *selection] + locked
           + ([] if subcommand == "clippy" else encoded) + list(trailing))
          for name, subcommand, selection, trailing in VENDOR_SUITES),
        ("workspace", cargo + ["test", "--workspace", "--all-features", "--all-targets", "--no-fail-fast"]
         + locked + encoded + ["--", "--test-threads=2"]),
        ("workspace-docs", cargo + ["test", "--workspace", "--all-features", "--doc", "--no-fail-fast"]
         + locked + encoded + ["--", "--test-threads=2"]),
        ("clippy", cargo + ["clippy", "--workspace", "--all-features", "--all-targets"]
         + locked + ["--", "-D", "warnings"]),
        ("network-features", cargo + ["tree", "--locked", "-p", "kasumi-bench", "--no-default-features",
         "--features", "installed-embedded", "--edges", "normal,build", "--prefix", "none", "--format", "{p} {f}"]),
        ("network-driver", cargo + ["build", "--release", "-p", "kasumi-bench", "--no-default-features",
         "--features", "installed-embedded", "--bin", "kasumi-bench-network", "--bin", "kasumi-bench-capacity"]
         + locked + encoded),
        ("production-features", cargo + ["tree", "--locked", "-p", "kasumi-server", "--no-default-features",
         "--edges", "normal,build", "--prefix", "none", "--format", "{p} {f}"]),
        ("production", cargo + ["build", "--release", "-p", "kasumi-server", "--bins", "--no-default-features"]
         + locked + encoded),
    ]


def validate_production_artifacts(name, result):
    """Check the actual compilation, independently of the earlier feature tree."""
    required = {"production": {"kasumid", "kasumictl", "kasumi-authority"},
                "network-driver": {"kasumi-bench-network", "kasumi-bench-capacity"}}.get(name)
    if required is None:
        return
    artifacts = list(result["executables"].values())
    if ({artifact["target"] for artifact in artifacts} != required
            or len(artifacts) != len(required) or any(artifact["test"] for artifact in artifacts)):
        result["missing_production_executables"] = True
        result["exit_code"] = result["exit_code"] or 1
    if not result["compiled_packages"] or any(
            set(package["features"]) & FORBIDDEN_FIXTURE_FEATURES
            for package in result["compiled_packages"].values()):
        result["fixture_feature_violation"] = True
        result["exit_code"] = result["exit_code"] or 1


def generated_output_paths(name):
    """Return a gate's declared source output and its retained evidence paths."""
    relative = GENERATED_OUTPUTS[name]
    retained = "generated/" + name + "/" + PurePosixPath(relative).name
    return {"source": relative, "path": retained, "files": retained + "-files.json"}


def _sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def retain_generated_outputs(name, source, output):
    """Move the gate's declared, drained test output out of the frozen source.

    Call only after the gate's process group drained. The directory is renamed,
    never copied or merged, into a new generated/<gate>/ evidence directory and
    its hashed inventory is retained. A declared output created by any other
    gate, a linked or non-directory output, or a linked parent is rejected in
    place. Every other write remains for the caller's source comparison.
    """
    retained = []
    for gate, relative in GENERATED_OUTPUTS.items():
        path = Path(source)
        for part in PurePosixPath(relative).parts:
            path = path / part
            if path.is_symlink():
                raise ValueError("generated gate output path contains a symbolic link: " + relative)
        if not os.path.lexists(path):
            continue
        if gate != name:
            raise ValueError("gate wrote another gate's declared output: " + relative)
        if not stat.S_ISDIR(os.lstat(path).st_mode):
            raise ValueError("generated gate output is not an owned directory: " + relative)
        paths = generated_output_paths(name)
        (Path(output) / "generated").mkdir(exist_ok=True)
        directory = Path(output) / "generated" / name
        directory.mkdir()
        os.rename(path, Path(output) / paths["path"])
        _sync_directory(path.parent)
        _sync_directory(directory)
        write_json(Path(output) / paths["files"], inventory(Path(output) / paths["path"]))
        retained.append({**paths, "files_sha256": sha256(Path(output) / paths["files"])})
    return retained


def production_environment(environment, source, target):
    """Give generated Rust sources and registry dependencies stable paths in native products."""
    source = Path(source).resolve()
    cargo_home = environment.get("CARGO_HOME") or str(Path(environment.get("HOME", Path.home())) / ".cargo")
    registry = source / cargo_home / "registry"
    locations = ((source, "source"), (Path(target).resolve(), "target"), (registry, "registry"))
    if "CARGO_ENCODED_RUSTFLAGS" in environment:
        encoded = environment["CARGO_ENCODED_RUSTFLAGS"]
        flags = encoded.split("\x1f") if encoded else []
    else:
        flags = environment.get("RUSTFLAGS", "").split()
    for location, name in locations:
        for spelling in dict.fromkeys((location, location.resolve())):
            flags.append(f"--remap-path-prefix={spelling}=/kasumi-build/{name}")
    if sys.platform == "darwin":
        # Remove linker debug-map entries before ld hashes the image's UUID.
        # Stripping them afterwards leaves a build-location-dependent UUID.
        flags.extend(("-C", "link-arg=-Wl,-S,-reproducible"))
    return {**environment, "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(flags)}


def dispatch_gates(gates, source, output, environment, timeout_seconds, record, original):
    """Run gates in order and set the terminal status only after the last one.

    A gate may change the frozen source only through its declared generated
    output. Changed inputs, uncertain process custody or cancellation stop
    dispatch after the drained gate's evidence is recorded.
    """
    for relative in GENERATED_OUTPUTS.values():
        if os.path.lexists(Path(source) / relative) or any(
                path == relative or path.startswith(relative + "/") for path in original):
            raise ValueError("frozen source contains a generated gate output: " + relative)
    for name, command in gates:
        print("Running " + name + " (" + str(Path(output) / (name + ".log")) + ")", flush=True)
        child_environment = environment
        if name in ("network-driver", "production"):
            child_environment = production_environment(environment, source, Path(output) / "target")
            record["release_rustflags"] = child_environment["CARGO_ENCODED_RUSTFLAGS"].split("\x1f")
        result = run_gate(name, command, source, output, child_environment, timeout_seconds)
        if name in ("production-features", "network-features") and re.search(r"kasumi-[^\n]*\btest-utils\b", (Path(output) / result["log"]).read_text()):
            result["fixture_feature_violation"] = True
            result["exit_code"] = result["exit_code"] or 1
        validate_production_artifacts(name, result)
        record["gates"].append(result)
        result["generated_outputs"] = retain_generated_outputs(name, source, output)
        if inventory(source) != original:
            raise RuntimeError("a gate changed frozen source inputs; results are invalid")
        write_json(Path(output) / "evidence.json", record)
        if not result["process_cleanup"]["drained"] or result["process_cleanup"]["errors"]:
            raise RuntimeError("gate process custody is uncertain; no later gate was dispatched")
        if result["received_signals"]:
            raise KeyboardInterrupt("functional run cancelled after owned gate cleanup")
    record["status"] = "passed" if all(g["exit_code"] == 0 for g in record["gates"]) else "failed"


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def record_failure(record, error):
    record["status"] = "interrupted" if isinstance(error, KeyboardInterrupt) else "failed"
    record["runner_error"] = str(error)
    record["runner_error_notes"] = getattr(error, "__notes__", [])


@contextlib.contextmanager
def terminal_record(record, output):
    """Persist a failed or interrupted status for any error, then re-raise it."""
    try:
        yield record
    except BaseException as error:
        record_failure(record, error)
        raise
    finally:
        record["finished_at"] = now()
        write_json(Path(output) / "evidence.json", record)


def verify_runner_inputs(source):
    """The executing Python modules must be the archived first-release inputs."""
    actual = {"scripts/release_gate.py": Path(__file__).resolve(),
              "scripts/gate_process.py": Path(gate_process.__file__).resolve()}
    result = {}
    for relative, path in actual.items():
        checksum = sha256(path)
        if checksum != sha256(Path(source) / relative):
            raise ValueError("executing release tool differs from frozen source: " + relative)
        result[relative] = checksum
    return result


def verify_journal_inputs(source):
    """The executing journal writer must be the archived first-release input.

    Kept apart from runner_inputs, whose exact roster the candidate verifier pins.
    """
    import attempt_index

    checksum = sha256(Path(attempt_index.__file__).resolve())
    if checksum != sha256(Path(source) / "scripts/attempt_index.py"):
        raise ValueError("executing attempt journal differs from frozen source: scripts/attempt_index.py")
    return {"scripts/attempt_index.py": checksum}


def prepare_source(record, repository, commit, output):
    """Capture the interpreter and the frozen source. Nothing is dispatched here."""
    (output / "tools").mkdir()
    shutil.copyfile(sys.executable, output / record["python_executable"]["artifact"])
    if sha256(output / record["python_executable"]["artifact"]) != record["python_executable"]["sha256"]:
        raise ValueError("Python interpreter changed before evidence capture")
    archive = output / "source.tar"
    subprocess.run(["git", "-C", str(repository), "archive", "--format=tar", "--output=" + str(archive), commit], check=True)
    record["source_archive_sha256"] = sha256(archive)
    source = output / "source"
    extract_source(archive, source)
    record["runner_inputs"] = verify_runner_inputs(source)
    write_json(output / "evidence.json", record)
    original = inventory(source)
    verify_export(repository, commit, source, original)
    write_json(output / "source-files.json", original)
    record["source_files_sha256"] = sha256(output / "source-files.json")
    record["lockfile_sha256"] = sha256(source / "Cargo.lock")
    epoch = subprocess.check_output(["git", "-C", str(repository), "show", "-s", "--format=%ct", commit],
                                    text=True).strip()
    environment = os.environ.copy()
    environment.update(CARGO_TARGET_DIR=str(output / "target"), RUSTUP_TOOLCHAIN=TOOLCHAIN,
                       PYTHONDONTWRITEBYTECODE="1", SOURCE_DATE_EPOCH=epoch)
    record["build_environment"] = {name: environment.get(name) for name in
                                   ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CC", "CXX", "AR", "SOURCE_DATE_EPOCH"]}
    return source, original, environment


def file_identity(root, path):
    return {"path": Path(path).relative_to(root).as_posix(), "sha256": sha256(path),
            "bytes": Path(path).stat().st_size}


def census_gate_groups(output, path):
    """Terminate any gate group its runner did not finish draining.

    The runner retains each gate's process group and leader birth on disk
    right after spawning it. A gate whose receipt shows a completed drain needs
    nothing more; its numeric group may already belong to someone else. Any
    other gate group that still has members, or cannot be inspected, makes the
    census incomplete and fails the runner's receipt. The runner's own gate
    receipts name every group, so gates need no enclosing group ledger.
    """
    groups = []
    for receipt in sorted(Path(output).glob("*-process.json")):
        item = {"receipt": receipt.name, "group": None, "leader_birth": None, "drained_by_runner": False,
                "before": None, "after": None, "signals": [], "errors": []}
        try:
            process = json.loads(receipt.read_bytes())
            item["group"], item["leader_birth"] = process["process_group"], process["leader_birth"]
            cleanup = process.get("cleanup")
            item["drained_by_runner"] = (isinstance(cleanup, dict) and cleanup.get("drained") is True
                                         and cleanup.get("after") == [])
        except (OSError, ValueError, KeyError, TypeError) as error:
            item["errors"].append("gate receipt: " + repr(error))
        group = item["group"]
        if item["drained_by_runner"] or (group is None and not item["errors"]):
            item["terminal"] = not item["errors"]
            groups.append(item)
            continue
        if type(group) is not int or group <= 0 or group == os.getpgrp():
            item["errors"].append("gate receipt names no separately owned process group")
            item["terminal"] = False
            groups.append(item)
            continue
        try:
            item["before"] = gate_process.group_members(group)
        except Exception as error:
            item["errors"].append("before census: " + repr(error))
        if item["before"]:
            # Signal a numeric group only while its original leader is alive.
            expected = {"group": group, "birth": item["leader_birth"]}
            for number in (signal.SIGTERM, signal.SIGKILL):
                try:
                    if item["leader_birth"] is None or gate_process.leader_identity(group) != expected:
                        item["errors"].append("gate group leader is unavailable or changed")
                        break
                    os.killpg(group, number)
                    item["signals"].append(signal.Signals(number).name)
                except ProcessLookupError:
                    pass
                except Exception as error:
                    item["errors"].append(signal.Signals(number).name + ": " + repr(error))
                    break
                remaining = None
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    try:
                        remaining = gate_process.group_members(group)
                    except Exception as error:
                        item["errors"].append("drain census: " + repr(error))
                        break
                    if remaining == []:
                        break
                    time.sleep(.05)
                if remaining == []:
                    break
        try:
            item["after"] = gate_process.group_members(group)
        except Exception as error:
            item["errors"].append("after census: " + repr(error))
        item["terminal"] = item["after"] == [] and not item["errors"]
        groups.append(item)
    census = {"schema": 1, "groups": groups, "complete": all(item["terminal"] for item in groups)}
    write_json(path, census)
    if not census["complete"] or any(item["signals"] for item in groups):
        raise RuntimeError("functional gate groups outlived their runner or could not be inspected")
    return census


def check_functional_products(record, output):
    """A passed attempt's products are the production gate's own retained outputs."""
    production = [gate for gate in record["gates"] if gate.get("name") == "production"]
    executables = production[0].get("executables") if len(production) == 1 else None
    if not isinstance(executables, dict):
        raise ValueError("functional evidence has no single production gate")
    for name in PRODUCTION_BINARIES:
        artifact = executables.get("release/" + name)
        if (not isinstance(artifact, dict) or artifact.get("target") != name or artifact.get("test") is not False
                or artifact.get("sha256") != sha256(output / FUNCTIONAL_PRODUCTS[name])):
            raise ValueError("functional product differs from its production gate output: " + name)
    if (sha256(output / FUNCTIONAL_PRODUCTS["source-archive"]) != record["source_archive_sha256"]
            or sha256(output / FUNCTIONAL_PRODUCTS["source-inventory"]) != record["source_files_sha256"]):
        raise ValueError("functional source products differ from their evidence")


def retained_product(output, relative):
    """Name a failed attempt's product only if it is an owned regular file."""
    path = Path(output)
    for part in PurePosixPath(relative).parts:
        path = path / part
        if path.is_symlink():
            return False
    return path.is_file()


def admission_preflight(parser, attempt_root, attempt_id, output):
    """Static prerequisites; a refusal here admits nothing and writes nothing."""
    import attempt_index

    if gate_process.GROUP_LEDGER_ENV in os.environ:
        parser.error("a journaled functional run cannot inherit a process group ledger")
    if not attempt_root.is_absolute():
        parser.error("attempt root must be absolute")
    try:
        root = attempt_index.custody(attempt_root)
        attempt_index.name(attempt_id)
        with attempt_index.locked_index(root, shared=True) as (_, _, _, journal):
            head = attempt_index.journal_head(journal)
            admitted = journal["entries"]
    except (OSError, ValueError) as error:
        parser.error("native attempt journal rejected: " + str(error))
    if (output == root or not output.is_relative_to(root) or output.is_relative_to(root / "attempts")
            or os.path.lexists(output)):
        parser.error("journaled output must be a new directory inside the attempt root")
    # The journal re-checks both under its lock; this only refuses early.
    if attempt_id in admitted or not attempt_index.disjoint_output(
            output.relative_to(root).as_posix(), (entry["begin"]["output"] for entry in admitted.values())):
        parser.error("native attempt id or output was already admitted")
    native = NATIVE_TARGETS.get((platform.system(), platform.machine()))
    if head["target"] != native:
        parser.error("attempt journal target " + head["target"] + " is not this native host ("
                     + str(native) + ")")
    return root, head


def run_journaled(root, attempt_id, head, record, repository, commit, output):
    """Admit, prepare and dispatch one primary functional attempt, then terminate it.

    Before dispatch the launcher owns evidence.json. From dispatch on, the
    frozen runner owns it and the launcher only reads its original bytes.
    """
    import attempt_index

    signals = (signal.SIGINT, signal.SIGTERM)
    previous = {number: signal.getsignal(number) for number in signals}
    received = []

    def interrupted(number, _frame):
        received.append(number)
        if len(received) == 1:
            raise KeyboardInterrupt("functional launcher received signal " + str(number) + " before dispatch")

    def recorded(number, _frame):
        received.append(number)

    blocked = signal.pthread_sigmask(signal.SIG_BLOCK, set(signals))
    try:
        for number in signals:
            signal.signal(number, interrupted)
        # Admission precedes every output byte: an interruption after it is an
        # unfinished admission, never an absent attempt.
        attempt_index.begin(root, attempt_id, "functional", output, record["started_at"])
        output.mkdir()
        record["attempt"] = {"id": attempt_id, "kind": "functional", "custody_root": str(root),
                             "output": output.relative_to(root).as_posix(), **{
                                 key: head[key] for key in ("journal_id", "host", "target")}}
        record["dispatch_started"] = False
        write_json(output / "evidence.json", record)
    except BaseException:
        for number, handler in previous.items():
            signal.signal(number, handler)
        signal.pthread_sigmask(signal.SIG_SETMASK, blocked)
        raise

    evidence = output / "evidence.json"
    runner = output / RUNNER
    receipt, log, census_path = runner / "process.json", runner / "output.log", runner / "gate-census.json"
    errors = []
    dispatch_started = False
    process = None
    try:
        signal.pthread_sigmask(signal.SIG_SETMASK, blocked)
        source, _, environment = prepare_source(record, repository, commit, output)
        record["journal_inputs"] = verify_journal_inputs(source)
        command = [record["python_executable"]["path"], "-B", "-S", str(source / "scripts" / "release_gate.py"),
                   PREPARED_COMMAND, "--output", str(output)]
        runner_environment = {**environment, RUNNER_ENV: attempt_id}
        selected = gate_process.executable_identity(command, source, runner_environment)
        if selected != {"path": command[0], "sha256": record["python_executable"]["sha256"]}:
            raise ValueError("functional runner interpreter differs from its retained bytes")
        runner.mkdir()
        # From here a signal is recorded, never raised mid-boundary; one that
        # already arrived ends the attempt before dispatch.
        for number in signals:
            signal.signal(number, recorded)
        if received:
            raise KeyboardInterrupt("functional launcher received signal " + str(received[0]) + " before dispatch")
        # Publish the boundary before any child can exist. A missing receipt
        # after this point is uncertainty, never a pre-dispatch failure.
        record["dispatch_started"] = True
        write_json(evidence, record)
        dispatch_started = True
    except BaseException as error:
        errors.append(repr(error))
        record["dispatch_started"] = dispatch_started
        record_failure(record, error)
        record["finished_at"] = now()
        try:
            write_json(evidence, record)
        except BaseException as write_error:
            errors.append("pre-dispatch evidence was not written: " + repr(write_error))
        for number in signals:
            signal.signal(number, recorded)
        if isinstance(error, KeyboardInterrupt) and not received:
            received.append(signal.SIGINT)

    if dispatch_started:
        def census(value):
            try:
                census_gate_groups(output, census_path)
            finally:
                if census_path.is_file():
                    value["gate_census"] = file_identity(output, census_path)

        print("Functional runner log: " + str(log), flush=True)
        try:
            with log.open("xb") as stream:
                process = gate_process.run(command, source, runner_environment, stream, RUNNER_TIMEOUT_SECONDS,
                                           lambda value: write_json(receipt, value), stderr=subprocess.STDOUT,
                                           after_cleanup=census)
            process["outputs_stable"] = process["cleanup"]["drained"] and not process["cleanup"]["errors"]
            write_json(receipt, process)
        except BaseException as error:
            errors.append("functional runner dispatch: " + repr(error))

    # The terminal decision reads the original evidence bytes and never
    # rewrites them; the outcome binds exactly those bytes.
    final = data = None
    try:
        if retained_product(output, "evidence.json"):
            data = evidence.read_bytes()
            final = json.loads(data, object_pairs_hook=_unique_cargo_object,
                               parse_constant=_reject_nonfinite_cargo)
    except (OSError, ValueError) as error:
        errors.append("functional evidence is unreadable: " + repr(error))
    final_status = final.get("status") if isinstance(final, dict) else None
    runner_passed = (process is not None and process["status"] == "passed" and process["outputs_stable"]
                     and process["exit_code"] == 0)
    if process is not None and not runner_passed:
        errors.append("functional runner did not pass with drained custody: exit "
                      + str(process["exit_code"]) + ", error " + str(process["error"]))
    if isinstance(final, dict) and dispatch_started:
        for key, value in record.items():
            if key not in {"gates", "status", "finished_at", "runner_error", "runner_error_notes"} \
                    and final.get(key) != value:
                errors.append("functional runner changed launcher-owned evidence: " + key)
    if final_status != "passed":
        errors.append("functional evidence status is " + str(final_status)
                      + ("" if not isinstance(final, dict) or "runner_error" not in final
                         else ": " + str(final["runner_error"])))
    if not errors:
        try:
            check_functional_products(final, output)
        except (OSError, ValueError, KeyError, TypeError) as error:
            errors.append(str(error))
    if received or (process is not None and process["received_signals"]) or final_status == "interrupted":
        status = "interrupted"
    else:
        status = "failed" if errors else "passed"
    products = {name: relative for name, relative in FUNCTIONAL_PRODUCTS.items()
                if status == "passed" or retained_product(output, relative)}
    processes = []
    if process is not None and process.get("process_group") is not None:
        processes.append({"id": RUNNER, "receipt": attempt_index.file_ref(root, receipt),
                          "log": attempt_index.file_ref(root, log),
                          "executable": attempt_index.file_ref(
                              root, output / record["python_executable"]["artifact"])})
    try:
        attempt_index.finish_outcome(
            root, attempt_id, status, now(), products=products, processes=processes,
            dispatch_started=dispatch_started,
            facts={"functional_status": final_status, "error": "; ".join(errors) or None},
            build_evidence="evidence.json" if data is not None else None)
        if data is not None:
            outcome = json.loads((output / "outcome.json").read_bytes())
            if outcome["build_evidence"]["sha256"] != hashlib.sha256(data).hexdigest():
                raise RuntimeError("functional evidence changed while its attempt terminated")
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
    print("Native functional attempt " + attempt_id + ": " + status, flush=True)
    for error in errors:
        print("  " + error, flush=True)
    return 0 if status == "passed" else 130 if status == "interrupted" else 1


def run_prepared(argv):
    """The journaled launcher's owned runner: dispatch the gates of a prepared run."""
    parser = argparse.ArgumentParser(prog="release_gate.py " + PREPARED_COMMAND,
                                     description="Dispatch the gates of a journaled functional run.")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if not args.output.is_absolute():
        parser.error("prepared output must be absolute")
    output = args.output.resolve(strict=True)
    source = output / "source"
    record = json.loads((output / "evidence.json").read_bytes(), object_pairs_hook=_unique_cargo_object,
                        parse_constant=_reject_nonfinite_cargo)
    # Refuse anything but this launcher's prepared run without writing to it.
    if (not isinstance(record, dict) or record.get("status") != "running"
            or record.get("dispatch_started") is not True or not isinstance(record.get("attempt"), dict)
            or os.environ.get(RUNNER_ENV) != record["attempt"].get("id")
            or os.path.lexists(output / "outcome.json") or gate_process.GROUP_LEDGER_ENV in os.environ):
        parser.error("functional run was not prepared for dispatch by a journaled launcher")
    try:
        with terminal_record(record, output):
            if (Path(__file__).resolve() != (source / "scripts/release_gate.py").resolve()
                    or verify_runner_inputs(source) != record["runner_inputs"]):
                raise ValueError("prepared dispatch must execute the frozen runner inputs")
            if sha256(output / "source-files.json") != record["source_files_sha256"]:
                raise ValueError("frozen source inventory changed before dispatch")
            original = json.loads((output / "source-files.json").read_bytes())
            if inventory(source) != original:
                raise ValueError("frozen source changed before dispatch")
            environment = {key: value for key, value in os.environ.items() if key != RUNNER_ENV}
            dispatch_gates(functional_gates(record["jobs"], record["python_executable"]["path"]), source,
                           output, environment, record["gate_timeout_seconds"], record, original)
    except KeyboardInterrupt as error:
        print("Functional gate result: interrupted (" + str(error) + ")", flush=True)
        return 130
    except Exception as error:
        print("Functional gate result: failed (" + repr(error) + ")", flush=True)
        return 1
    print("Functional gate result: " + record["status"], flush=True)
    return 0 if record["status"] == "passed" else 1


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv[:1] == [PREPARED_COMMAND]:
        return run_prepared(argv[1:])
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--output", type=Path, required=True, help="new absolute evidence directory outside the checkout")
    parser.add_argument("--execution-description", required=True, help="actual host/VM and native or translated execution")
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--gate-timeout-seconds", type=int, default=14400,
                        help="original timeout for each functional gate, in 1..86400 seconds")
    parser.add_argument("--attempt-root", type=Path,
                        help="native attempt journal custody root; the output must be a new directory inside it")
    parser.add_argument("--attempt-id", help="new attempt id admitted to that journal before dispatch")
    args = parser.parse_args(argv)
    if sys.version_info < (3, 11):
        parser.error("release tooling requires Python 3.11 or newer")
    repository = args.repository.resolve()
    output = args.output
    if not output.is_absolute() or output.resolve().is_relative_to(repository):
        parser.error("output must be absolute and outside the repository")
    # Cargo's emitted executable paths and the owned process working directory
    # must have the same spelling even after evidence moves to another host.
    output = output.resolve()
    if not 1 <= args.jobs <= 64:
        parser.error("jobs must be in 1..64")
    if not 1 <= args.gate_timeout_seconds <= 86400:
        parser.error("gate timeout must be in 1..86400 seconds")
    if (args.attempt_root is None) != (args.attempt_id is None):
        parser.error("--attempt-root and --attempt-id must be given together")
    journal = None
    if args.attempt_root is not None:
        journal = admission_preflight(parser, args.attempt_root, args.attempt_id, output)
    def git(*arguments):
        return subprocess.check_output(["git", "-C", str(repository), *arguments], text=True).strip()
    if git("status", "--porcelain", "--untracked-files=no"):
        parser.error("commit tracked input changes before running release gates")
    commit = git("rev-parse", "HEAD")
    record = {
        "schema": 1, "source_commit": commit, "source_tree": git("rev-parse", commit + "^{tree}"),
        "scope": "functional gates only; not final production release acceptance",
        "execution_description": args.execution_description, "toolchain": TOOLCHAIN,
        "jobs": args.jobs,
        "gate_timeout_seconds": args.gate_timeout_seconds,
        "python_version": sys.version,
        "python_executable": {"path": os.path.abspath(sys.executable),
                              "sha256": sha256(sys.executable), "artifact": "tools/python"},
        "started_at": now(),
        "status": "running", "gates": [],
    }
    if journal is not None:
        root, head = journal
        return run_journaled(root, args.attempt_id, head, record, repository, commit, output)
    output.mkdir(parents=False, exist_ok=False)
    write_json(output / "evidence.json", record)
    with terminal_record(record, output):
        source, original, environment = prepare_source(record, repository, commit, output)
        dispatch_gates(functional_gates(args.jobs, record["python_executable"]["path"]), source, output,
                       environment, args.gate_timeout_seconds, record, original)
    print("Functional gate result: " + record["status"], flush=True)
    return 0 if record["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
