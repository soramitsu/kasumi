#!/usr/bin/env python3
"""Run functional release gates against a frozen source with retained evidence.

This does not certify capacity, recovery drills, external services or endurance.
The output directory is exclusive and keeps failed/partial runs for inspection.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile

import gate_process

TOOLCHAIN = "1.97.1"
FORBIDDEN_FIXTURE_FEATURES = frozenset({"test-utils", "embedded-fixture", "loopback-fixture"})

_SERDE_JSON = ("--manifest-path", "vendor/serde_json-1.0.151/Cargo.toml")
_RMCP = ("--manifest-path", "vendor/rmcp-3.2.0/Cargo.toml")
_OPENRAFT = ("--manifest-path", "vendor/openraft-0.9.25/Cargo.toml")
_OPENRAFT_FEATURES = "serde,storage-v2,single-term-leader,generic-snapshot-data"

# Upstream suites of every reviewed vendor fork, as (gate, Cargo subcommand,
# selection, trailing arguments). The pinned toolchain, --locked, jobs and
# JSON encoding (except for Clippy) are added by functional_gates. The OpenRaft
# rows repeat the custody commands retained by
# docs/evidence/openraft-canonical-20260920 attempts 46-49.
VENDOR_SUITES = (
    ("bitmaps", "test", ("--manifest-path", "vendor/bitmaps-3.2.1/Cargo.toml"), ()),
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


def compiler_artifact_messages(log):
    """Parse every bounded gate-log line; malformed JSON-looking lines fail."""
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


def memory_observation(membership=Path("/proc/self/cgroup"), root=Path("/sys/fs/cgroup")):
    """Retain raw visible cgroup counters, including child OOM events.

    These reads are not atomic. Ancestor counters can include other workloads;
    a cumulative peak is not a per-gate peak. Missing counters are explicit and
    cannot be interpreted as zero pressure or absence of an OOM kill.
    """
    record = {"observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "scope": "raw visible cgroup counters; non-atomic and possibly shared",
              "membership": None, "cgroups": {}, "errors": []}
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


def run_gate(name, command, source, output, environment, timeout_seconds=14400):
    """Hash actual executable outputs only after the original process group drains."""
    log = Path(output) / (name + ".log")
    process_path = Path(output) / (name + "-process.json")
    artifacts = {}
    compiled_packages = {}
    target = (Path(output) / "target").resolve()
    memory_before = memory_observation()
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
        for message in compiler_artifact_messages(log):
            record_compiled_package(compiled_packages, message)
            raw = message.get("executable")
            if raw is not None:
                if (not isinstance(raw, str) or not Path(raw).is_absolute()
                        or os.path.normpath(raw) != raw):
                    raise ValueError("compiler-artifact executable path is malformed")
                identity = compiler_executable_identity(message)
            if raw is not None:
                executable = Path(raw).resolve()
                relative = str(executable.relative_to(target))
                if relative in artifacts:
                    raise ValueError("duplicate compiler-artifact executable identity")
                artifacts[relative] = identity
        for relative, artifact in artifacts.items():
            path = target / relative
            artifact.update(sha256=sha256(path), bytes=path.stat().st_size)
    except BaseException as error:
        if process is not None:
            for cleanup_error in process["cleanup"]["errors"]:
                error.add_note(cleanup_error)
            if not process["cleanup"]["drained"]:
                error.add_note("original gate process group has not drained")
        raise
    finally:
        write_json(Path(output) / (name + "-resources.json"),
                   {"before": memory_before, "after": memory_observation()})
    return {
        "name": name, "command": command, "exit_code": process["exit_code"],
        "duration_seconds": process["duration_seconds"],
        "log": log.name, "log_sha256": sha256(log), "executables": artifacts,
        "compiled_packages": compiled_packages,
        "process": process_path.name, "process_sha256": sha256(process_path),
        "process_cleanup": process["cleanup"], "timed_out": process["timed_out"],
        "received_signals": process["received_signals"], "process_error": process["error"],
        "timeout_seconds": timeout_seconds,
        "resources": name + "-resources.json",
        "resources_sha256": sha256(Path(output) / (name + "-resources.json")),
    }


def functional_gates(jobs, python_executable):
    cargo = ["cargo", "+" + TOOLCHAIN]
    locked = ["--locked", "-j", str(jobs)]
    encoded = ["--message-format=json-render-diagnostics"]
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
         "--features", "network", "--edges", "normal,build", "--prefix", "none", "--format", "{p} {f}"]),
        ("network-driver", cargo + ["build", "--release", "-p", "kasumi-bench", "--no-default-features",
         "--features", "network", "--bins"] + locked + encoded),
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
        result["exit_code"] = 1
    if not result["compiled_packages"] or any(
            set(package["features"]) & FORBIDDEN_FIXTURE_FEATURES
            for package in result["compiled_packages"].values()):
        result["fixture_feature_violation"] = True
        result["exit_code"] = 1


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
        result = run_gate(name, command, source, output, environment, timeout_seconds)
        if name in ("production-features", "network-features") and re.search(r"kasumi-[^\n]*\btest-utils\b", (Path(output) / result["log"]).read_text()):
            result["fixture_feature_violation"] = True
            result["exit_code"] = 1
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


@contextlib.contextmanager
def terminal_record(record, output):
    """Persist a failed or interrupted status for any error, then re-raise it."""
    try:
        yield record
    except BaseException as error:
        record["status"] = "interrupted" if isinstance(error, KeyboardInterrupt) else "failed"
        record["runner_error"] = str(error)
        record["runner_error_notes"] = getattr(error, "__notes__", [])
        raise
    finally:
        record["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--output", type=Path, required=True, help="new absolute evidence directory outside the checkout")
    parser.add_argument("--execution-description", required=True, help="actual host/VM and native or translated execution")
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--gate-timeout-seconds", type=int, default=14400,
                        help="original timeout for each functional gate, in 1..86400 seconds")
    args = parser.parse_args()
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
    def git(*arguments):
        return subprocess.check_output(["git", "-C", str(repository), *arguments], text=True).strip()
    if git("status", "--porcelain", "--untracked-files=no"):
        parser.error("commit tracked input changes before running release gates")
    commit = git("rev-parse", "HEAD")
    output.mkdir(parents=False, exist_ok=False)
    record = {
        "schema": 1, "source_commit": commit, "source_tree": git("rev-parse", commit + "^{tree}"),
        "scope": "functional gates only; not final production release acceptance",
        "execution_description": args.execution_description, "toolchain": TOOLCHAIN,
        "jobs": args.jobs,
        "gate_timeout_seconds": args.gate_timeout_seconds,
        "python_version": sys.version,
        "python_executable": {"path": os.path.abspath(sys.executable),
                              "sha256": sha256(sys.executable), "artifact": "tools/python"},
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "running", "gates": [],
    }
    write_json(output / "evidence.json", record)
    with terminal_record(record, output):
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
        write_json(output / "source-files.json", original)
        record["source_files_sha256"] = sha256(output / "source-files.json")
        record["lockfile_sha256"] = sha256(source / "Cargo.lock")
        environment = os.environ.copy()
        environment.update(CARGO_TARGET_DIR=str(output / "target"), RUSTUP_TOOLCHAIN=TOOLCHAIN,
                           PYTHONDONTWRITEBYTECODE="1", SOURCE_DATE_EPOCH=git("show", "-s", "--format=%ct", commit))
        record["build_environment"] = {name: environment.get(name) for name in
                                       ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CC", "CXX", "AR", "SOURCE_DATE_EPOCH"]}
        dispatch_gates(functional_gates(args.jobs, record["python_executable"]["path"]), source, output,
                       environment, args.gate_timeout_seconds, record, original)
    print("Functional gate result: " + record["status"], flush=True)
    return 0 if record["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
