#!/usr/bin/env python3
"""Validate the immutable vendored leaf with original process-group custody."""
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys

ROOT = Path(__file__).resolve().parents[3]
VENDOR = ROOT / "vendor/redb-4.2.0"
TOOLS = Path("/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin")
TARGET = Path("/Users/mtakemiya/dev/kasumi-redb-admission-target")
OUTPUT = Path(sys.argv[1]).resolve()
OUTPUT.mkdir(mode=0o700)
PRESERVED = OUTPUT / "preserved-executables"
PRESERVED.mkdir(mode=0o700)

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

helper = module("frozen_leaf_process", ROOT / "scripts/gate_process.py")
common = module("frozen_leaf_artifacts", ROOT / "docs/evidence/first-release-be2667d-check-20260919/runner.py")

def inventory():
    return {str(p.relative_to(ROOT)): common.digest(p) for p in sorted(VENDOR.rglob("*")) if p.is_file()}

before = inventory()
common.atomic(OUTPUT / "source-before.json", before)
shutil.copy2(__file__, OUTPUT / "validate_leaf.py")
shutil.copy2(ROOT / "scripts/gate_process.py", OUTPUT / "gate_process.py")
shutil.copy2(ROOT / "docs/evidence/first-release-be2667d-check-20260919/runner.py", OUTPUT / "artifact_helper.py")
manifest = str(VENDOR / "Cargo.toml")
derive = str(VENDOR / "crates/redb-derive/Cargo.toml")
previous = ROOT / "docs/evidence/redb-canonical-20260920/06-canonical-all-features-tests.log"
required = re.findall(r"^test (.+) \.\.\. ok$", previous.read_text(), re.M)
gates = [
    {"name":"16-owned-all-features-tests", "args":["test","--manifest-path",manifest,"--locked","--offline","--all-features","--no-fail-fast","--message-format=json","--","--test-threads=2"], "timeout_seconds":900, "required_tests":required},
    {"name":"17-owned-all-features-strict-clippy", "args":["clippy","--manifest-path",manifest,"--locked","--offline","--all-features","--all-targets","--message-format=json","--","-D","warnings"], "timeout_seconds":300},
    {"name":"18-owned-default-strict-clippy", "args":["clippy","--manifest-path",manifest,"--locked","--offline","--all-targets","--message-format=json","--","-D","warnings"], "timeout_seconds":300},
    {"name":"19-owned-no-std-check", "args":["check","--manifest-path",manifest,"--locked","--offline","--no-default-features","--features","experimental-api-5","--message-format=json"], "env":{"RUSTFLAGS":"-C panic=abort"}, "timeout_seconds":300},
    {"name":"20-owned-fmt", "args":["fmt","--manifest-path",manifest,"--check"], "timeout_seconds":60},
    {"name":"21-owned-derive-tests", "args":["test","--manifest-path",derive,"--locked","--offline","--message-format=json"], "timeout_seconds":300},
    {"name":"22-owned-derive-strict-clippy", "args":["clippy","--manifest-path",derive,"--locked","--offline","--all-targets","--message-format=json","--","-D","warnings"], "timeout_seconds":300},
]
record = {"status":"running", "scope":"redb 4.2.0 canonical-only leaf; not installed Kasumi acceptance", "started_at":datetime.datetime.now(datetime.timezone.utc).isoformat(), "tools":{str(TOOLS/n):common.digest(TOOLS/n) for n in ("cargo","rustc","rustdoc","clippy-driver","rustfmt")}, "python":{"path":sys.executable,"sha256":common.digest(sys.executable)}, "source_before_sha256":common.digest(OUTPUT/"source-before.json"), "required_case_count":len(required), "gates":[dict(g,status="not_run") for g in gates]}
assert len(required) == 430, len(required)
common.atomic(OUTPUT / "evidence.json", record)
env = dict(os.environ, RUSTUP_TOOLCHAIN="1.97.1", RUSTC=str(TOOLS/"rustc"), RUSTDOC=str(TOOLS/"rustdoc"), CARGO_TARGET_DIR=str(TARGET), CARGO_BUILD_JOBS="1", CARGO_TERM_COLOR="never", RUST_BACKTRACE="1", PYTHONDONTWRITEBYTECODE="1", PATH=str(TOOLS)+os.pathsep+os.environ["PATH"])
try:
    for gate in record["gates"]:
        assert inventory() == before, "source changed before dispatch"
        log = OUTPUT / (gate["name"] + ".log")
        command = [str(TOOLS/"cargo"),*gate["args"]]
        gate.update(status="running",command=command)
        def observe(value):
            gate["process"] = value
            common.atomic(OUTPUT/"evidence.json",record)
        print("START",gate["name"],flush=True)
        with log.open("wb") as stream:
            outcome = helper.run(command,ROOT,dict(env,**gate.get("env",{})),stream,gate["timeout_seconds"],observe)
        gate["log_sha256"] = common.digest(log)
        gate["executables"],gate["compiled_packages"] = common.collect(log,TARGET,PRESERVED)
        content = log.read_text(errors="replace")
        gate["test_summaries"] = re.findall(r"test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored;",content)
        gate["missing_required_cases"] = [name for name in gate.get("required_tests",[]) if "test "+name+" ... ok" not in content]
        gate["source_unchanged"] = inventory() == before
        passed = outcome["status"] == "passed" and gate["source_unchanged"] and not gate["missing_required_cases"]
        if command[1] == "test":
            passed &= bool(gate["test_summaries"]) and all(row[0]=="ok" and row[2]=="0" and row[3]=="0" for row in gate["test_summaries"]) and any(v.get("profile",{}).get("test") for v in gate["executables"].values())
        gate["status"] = "passed" if passed else "failed"
        common.atomic(OUTPUT/"evidence.json",record)
        print("TERMINAL",gate["name"],gate["status"],"drained",outcome["cleanup"]["drained"],flush=True)
        if not passed:
            raise RuntimeError("gate failed: "+gate["name"])
    record["status"] = "passed"
except BaseException as error:
    record["status"] = "failed"
    record["error"] = repr(error)
finally:
    after = inventory()
    common.atomic(OUTPUT/"source-after.json",after)
    record["source_unchanged"] = before == after
    if not record["source_unchanged"]:
        record["status"] = "failed"
    record["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    common.atomic(OUTPUT/"evidence.json",record)
raise SystemExit(0 if record["status"] == "passed" else 1)
