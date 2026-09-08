#!/usr/bin/env python3
"""Run functional release gates against a frozen source with retained evidence.

This does not certify capacity, recovery drills, external services or endurance.
The output directory is exclusive and keeps failed/partial runs for inspection.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import subprocess
import sys
import tarfile
import time

TOOLCHAIN = "1.97.1"


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


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


def run_gate(name, command, source, output, environment):
    """Hash actual Cargo-reported executable outputs when this gate closes."""
    started = time.monotonic()
    log = Path(output) / (name + ".log")
    artifacts = {}
    compiled_packages = {}
    target = (Path(output) / "target").resolve()
    with log.open("wb") as stream:
        process = subprocess.Popen(command, cwd=source, env=environment,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            for line in process.stdout:
                stream.write(line)
                stream.flush()
                try:
                    message = json.loads(line)
                except (ValueError, UnicodeDecodeError):
                    continue
                if not isinstance(message, dict) or message.get("reason") != "compiler-artifact":
                    continue
                package_id = message.get("package_id")
                if package_id:
                    package = compiled_packages.setdefault(package_id, {"features": [], "targets": []})
                    package["features"] = sorted(set(package["features"]) | set(message.get("features", [])))
                    target_record = {field: message.get("target", {}).get(field) for field in
                                     ("name", "kind", "crate_types")}
                    if target_record not in package["targets"]:
                        package["targets"].append(target_record)
                if message.get("executable"):
                    executable = Path(message["executable"]).resolve()
                    relative = executable.relative_to(target)
                    artifacts[str(relative)] = {
                        "target": message.get("target", {}).get("name"),
                        "test": message.get("profile", {}).get("test"),
                        "package_id": message.get("package_id"),
                    }
            code = process.wait()
        except BaseException as error:
            # Cargo can leave compiler/test children alive after its own exit.
            # Stop this gate's entire process group before closing its evidence.
            cleanup_errors = []
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except OSError as cleanup_error:
                cleanup_errors.append("SIGTERM process-group cleanup failed: " + str(cleanup_error))
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError as cleanup_error:
                cleanup_errors.append("SIGKILL process-group cleanup failed: " + str(cleanup_error))
            process.wait()
            for cleanup_error in cleanup_errors:
                error.add_note(cleanup_error)
            raise
        finally:
            process.stdout.close()
            stream.flush()
            os.fsync(stream.fileno())
    for relative, artifact in artifacts.items():
        path = target / relative
        artifact.update(sha256=sha256(path), bytes=path.stat().st_size)
    return {
        "name": name, "command": command, "exit_code": code,
        "duration_seconds": round(time.monotonic() - started, 3),
        "log": log.name, "log_sha256": sha256(log), "executables": artifacts,
        "compiled_packages": compiled_packages,
    }


def functional_gates(jobs):
    cargo = ["cargo", "+" + TOOLCHAIN]
    locked = ["--locked", "-j", str(jobs)]
    encoded = ["--message-format=json-render-diagnostics"]
    return [
        ("toolchain", ["rustc", "+" + TOOLCHAIN, "-Vv"]),
        ("format", cargo + ["fmt", "--all", "--", "--check"]),
        ("python", [sys.executable, "-m", "unittest", "discover", "-s", "scripts", "-p", "test_*.py", "-v"]),
        ("dependency-patches", [sys.executable, "scripts/check_dependency_patches.py"]),
        ("bitmaps", cargo + ["test", "--manifest-path", "vendor/bitmaps-3.2.1/Cargo.toml"] + locked + encoded),
        ("lru", cargo + ["test", "--manifest-path", "vendor/lru-0.16.4/Cargo.toml"] + locked + encoded),
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
            set(package["features"]) & {"test-utils", "embedded-fixture", "loopback-fixture"}
            for package in result["compiled_packages"].values()):
        result["fixture_feature_violation"] = True
        result["exit_code"] = 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--output", type=Path, required=True, help="new absolute evidence directory outside the checkout")
    parser.add_argument("--execution-description", required=True, help="actual host/VM and native or translated execution")
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args()
    if sys.version_info < (3, 11):
        parser.error("release tooling requires Python 3.11 or newer")
    repository = args.repository.resolve()
    output = args.output
    if not output.is_absolute() or output.resolve().is_relative_to(repository):
        parser.error("output must be absolute and outside the repository")
    if not 1 <= args.jobs <= 64:
        parser.error("jobs must be in 1..64")
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
        "python_version": sys.version,
        "python_executable_sha256": sha256(sys.executable),
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "running", "gates": [],
    }
    write_json(output / "evidence.json", record)
    try:
        archive = output / "source.tar"
        subprocess.run(["git", "-C", str(repository), "archive", "--format=tar", "--output=" + str(archive), commit], check=True)
        record["source_archive_sha256"] = sha256(archive)
        source = output / "source"
        extract_source(archive, source)
        original = inventory(source)
        write_json(output / "source-files.json", original)
        record["source_files_sha256"] = sha256(output / "source-files.json")
        record["lockfile_sha256"] = sha256(source / "Cargo.lock")
        environment = os.environ.copy()
        environment.update(CARGO_TARGET_DIR=str(output / "target"), RUSTUP_TOOLCHAIN=TOOLCHAIN,
                           PYTHONDONTWRITEBYTECODE="1", SOURCE_DATE_EPOCH=git("show", "-s", "--format=%ct", commit))
        record["build_environment"] = {name: environment.get(name) for name in
                                       ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CC", "CXX", "AR", "SOURCE_DATE_EPOCH"]}
        for name, command in functional_gates(args.jobs):
            print("Running " + name + " (" + str(output / (name + ".log")) + ")", flush=True)
            result = run_gate(name, command, source, output, environment)
            if name in ("production-features", "network-features") and re.search(r"kasumi-[^\n]*\btest-utils\b", (output / result["log"]).read_text()):
                result["fixture_feature_violation"] = True
                result["exit_code"] = 1
            validate_production_artifacts(name, result)
            record["gates"].append(result)
            if inventory(source) != original:
                raise RuntimeError("a gate changed frozen source inputs; results are invalid")
            write_json(output / "evidence.json", record)
        record["status"] = "passed" if all(g["exit_code"] == 0 for g in record["gates"]) else "failed"
    except BaseException as error:
        record["status"] = "interrupted" if isinstance(error, KeyboardInterrupt) else "failed"
        record["runner_error"] = str(error)
        record["runner_error_notes"] = getattr(error, "__notes__", [])
        raise
    finally:
        record["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        write_json(output / "evidence.json", record)
    print("Functional gate result: " + record["status"], flush=True)
    return 0 if record["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
