#!/usr/bin/env python3
"""Record and check a dedicated native functional acceptance host."""
import argparse
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

from release_gate import sha256, write_json


def host_target(system, machine):
    return {("Linux", "x86_64"): "x86_64-unknown-linux-gnu",
            ("Linux", "aarch64"): "aarch64-unknown-linux-gnu",
            ("Darwin", "arm64"): "aarch64-apple-darwin"}.get((system, machine))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    if not args.output.is_absolute() or args.output.exists():
        parser.error("an exclusive absolute output file is required")
    system, machine = platform.system(), platform.machine()
    errors = []
    if host_target(system, machine) != args.target:
        errors.append("host architecture does not match the requested native target")
    if sys.version_info < (3, 11):
        errors.append("Python 3.11 or newer is required")
    free = shutil.disk_usage(args.output.parent).free
    if free < 64 << 30:
        errors.append("functional acceptance requires at least 64 GiB free disk")
    translated = None
    memory = None
    if system == "Linux":
        memory = os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")
    if system == "Darwin":
        memory = int(subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True))
        result = subprocess.run(["sysctl", "-n", "sysctl.proc_translated"],
                                capture_output=True, text=True, check=False)
        translated = result.stdout.strip() == "1"
        if translated:
            errors.append("translated execution cannot satisfy the native host gate")
    if memory is None or memory < 8 << 30:
        errors.append("functional acceptance requires at least 8 GiB memory")
    versions = {}
    for name in ("git", "cc", "cmake", "rustup", "docker"):
        executable = shutil.which(name)
        if executable:
            result = subprocess.run([executable, "--version"], capture_output=True,
                                    text=True, timeout=10, check=False)
            versions[name] = {"executable": executable, "exit_code": result.returncode,
                              "stdout": result.stdout, "stderr": result.stderr}
    record = {"schema": 1, "system": platform.platform(), "machine": machine,
              "requested_target": args.target, "cpu_count": os.cpu_count(),
              "free_disk_bytes": free, "memory_bytes": memory, "python": sys.version,
              "python_executable_sha256": sha256(sys.executable),
              "tools": versions,
              "ci": {name: os.environ.get(name) for name in
                     ("GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "RUNNER_NAME", "RUNNER_ARCH")},
              "translated": translated, "errors": errors,
              "scope": "functional host preflight; capacity and endurance require separate resource admission"}
    write_json(args.output, record)
    if errors:
        raise SystemExit("; ".join(errors))
    print("Native functional acceptance host recorded")


if __name__ == "__main__":
    main()
