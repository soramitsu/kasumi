#!/usr/bin/env python3
"""Private, single-attempt VM dispatch; default invocation prints a plan only.

Execute as root inside kasumi-production-arm64 only after the native lane grant.
The output contains installation keys. Never publish it wholesale. This invokes
an existing failed-source diagnostic; it cannot confer release acceptance.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import sys
import time
import uuid

IMAGE = "sha256:abf802c3daf7460f7498869910288b63bf5e138efc28e3c0704bf931b99e1ed4"
BASE = Path("/opt/kasumi-acceptance")
OUTPUT = BASE / "3a8d512-small-standalone-001"
BUILD = BASE / "3a8d512-functional-arm64/run"
SOURCE = BASE / "3a8d512-git"
COMMIT = "3a8d5121e1ddee14ae8a6d938d12152eaa04e417"
RUNNER = BASE / "small-native-tools-84379a4/small_native_smoke.py"
RUNNER_SHA = "d3d87af9491932a86faae1b8855c6a6c46a30caaad404fe6244f729b15488966"
BUILD_SHA = "41c9a17334c861ad20c560d6dd3cdd802b67bd307a1806fa1d83f9e6e5980545"
DEADLINE_SECONDS = 1500
CLI_SECONDS = 30
STOP_SECONDS = 90
LABEL = "org.kasumi.acceptance.dispatch-owner"
MAX_INSPECT_BYTES = 4 << 20
CONTAINER_ENV = {
    "GIT_CONFIG_COUNT": "1",
    "GIT_CONFIG_KEY_0": "safe.directory",
    "GIT_CONFIG_VALUE_0": "/source",
    "PYTHONDONTWRITEBYTECODE": "1",
}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def read_bounded(path, limit=MAX_INSPECT_BYTES):
    with Path(path).open("rb") as source:
        content = source.read(limit + 1)
    require(len(content) <= limit, "bounded evidence input exceeded")
    return content


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def private_json(path, value):
    temporary = path.with_name(path.name + ".pending-" + uuid.uuid4().hex)
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as target:
        target.write((json.dumps(value, indent=2, sort_keys=True) + "\n").encode())
        target.flush()
        os.fsync(target.fileno())
    require(not path.is_symlink(), "evidence destination changed to symlink")
    os.replace(temporary, path)
    sync_directory(path.parent)


def regular(path):
    require(stat.S_ISREG(path.lstat().st_mode), "required input is not a regular file")


def plan():
    return {"vm": "kasumi-production-arm64", "execution": "root inside VM; no host Docker",
            "image": IMAGE, "source": str(SOURCE), "commit": COMMIT,
            "build": str(BUILD), "build_evidence_sha256": BUILD_SHA,
            "runner": str(RUNNER), "runner_sha256": RUNNER_SHA,
            "output": str(OUTPUT), "output_mode": "0700; contains keys",
            "diagnostic_output": "/results/run", "network": "none", "init": True,
            "read_only_root": True, "tmpfs_tmp_bytes": 256 << 20,
            "cpus": 2, "memory_bytes": 4 << 30, "memory_swap_bytes": 4 << 30,
            "deadline_seconds": DEADLINE_SECONDS, "cli_timeout_seconds": CLI_SECONDS,
            "graceful_container_stop_seconds": STOP_SECONDS,
            "retries": 0, "remove_container_or_evidence": False,
            "claim": "129-document offline diagnostic of failed 3a8d512; not release acceptance"}


class Interrupted(RuntimeError):
    pass


class Dispatch:
    def __init__(self, expected_script_sha):
        require(sys.version_info >= (3, 11), "Python 3.11 or newer required")
        require(os.getuid() == 0 and platform.system() == "Linux"
                and platform.machine() in ("aarch64", "arm64"), "Linux ARM64 VM root required")
        require(sha(__file__) == expected_script_sha, "executing dispatch source hash differs")
        require(BASE.resolve(strict=True) == BASE, "acceptance parent must not use aliases")
        # mkdir is intentionally exclusive. Existing or uncertain prior work is
        # never resumed, removed, or silently redirected to a fresh installation.
        os.umask(0o077)
        OUTPUT.mkdir(mode=0o700)
        sync_directory(BASE)
        self.owner = uuid.uuid4().hex
        self.name = "kasumi-small-native-001-" + self.owner
        self.cid = None
        self.ownership_verified = False
        self.create_attempted = False
        self.create_certain = False
        self.started = time.monotonic()
        self.deadline = self.started + DEADLINE_SECONDS
        self.received = []
        self.old_handlers = {}
        self.record = {"schema": 1, "status": "running", "started_at": now(),
                       "plan": plan(), "dispatch_sha256": expected_script_sha,
                       "container_name": self.name, "owner_label": self.owner,
                       "commands": [], "cleanup": {"verified": False, "forced": False},
                       "signals": self.received}
        for number in (signal.SIGINT, signal.SIGTERM):
            self.old_handlers[number] = signal.signal(number, self.signal)
        self.persist()

    def signal(self, number, _frame):
        # Record intent only: all Docker operations and evidence writes happen
        # outside the handler. Further signals cannot interrupt owned cleanup.
        if number not in self.received:
            self.received.append(number)

    def persist(self):
        private_json(OUTPUT / "dispatch.json", self.record)

    def check(self):
        if self.received:
            raise Interrupted("dispatch interrupted by recorded signal")
        if time.monotonic() >= self.deadline:
            raise TimeoutError("original diagnostic deadline elapsed")

    def command(self, label, arguments, timeout=CLI_SECONDS, cleanup=False, allow_failure=False):
        if not cleanup:
            self.check()
        if arguments[0] == "docker":
            arguments = ["docker", "--host", "unix:///var/run/docker.sock", *arguments[1:]]
        ordinal = len(self.record["commands"])
        stem = f"{ordinal:04}-{label}"
        stdout, stderr = OUTPUT / (stem + ".stdout"), OUTPUT / (stem + ".stderr")
        entry = {"label": label, "argv": arguments, "started_at": now(),
                 "stdout": stdout.name, "stderr": stderr.name, "process_group_drained": False,
                 "forced_process_stop": False}
        self.record["commands"].append(entry)
        self.persist()
        process = None
        primary = None
        with stdout.open("xb") as out, stderr.open("xb") as err:
            try:
                process = subprocess.Popen(arguments, stdout=out, stderr=err, stdin=subprocess.DEVNULL,
                                           start_new_session=True, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                                           "LANG": "C.UTF-8"})
                entry.update(pid=process.pid, pgid=process.pid)
                self.persist()
                stop = time.monotonic() + timeout
                if not cleanup:
                    stop = min(stop, self.deadline)
                while True:
                    if not cleanup:
                        self.check()
                    # A late observed completion cannot turn an expired original
                    # timeout into successful command evidence.
                    if time.monotonic() >= stop:
                        raise TimeoutError("owned command deadline elapsed")
                    code = process.poll()
                    if code is not None:
                        entry["exit_code"] = code
                        break
                    time.sleep(0.05)
            except BaseException as error:
                primary = error
                entry["error_type"] = type(error).__name__
            finally:
                if process is not None:
                    # These are simple Docker/Git clients. Signal only our fresh
                    # process session, including a surviving child after exit.
                    errors = []
                    for sig, wait in ((signal.SIGTERM, 5), (signal.SIGKILL, 5)):
                        try:
                            os.killpg(process.pid, sig)
                            entry["forced_process_stop"] = True
                        except ProcessLookupError:
                            break
                        except OSError as error:
                            errors.append(type(error).__name__)
                        end = time.monotonic() + wait
                        while time.monotonic() < end:
                            process.poll()  # reap a terminated direct child
                            try:
                                os.killpg(process.pid, 0)
                            except ProcessLookupError:
                                break
                            except OSError as error:
                                errors.append(type(error).__name__)
                                break
                            time.sleep(0.05)
                        else:
                            continue
                        try:
                            os.killpg(process.pid, 0)
                        except ProcessLookupError:
                            break
                        except OSError as error:
                            errors.append(type(error).__name__)
                    process.poll()
                    try:
                        os.killpg(process.pid, 0)
                    except ProcessLookupError:
                        entry["process_group_drained"] = not errors and process.returncode is not None
                    except OSError as error:
                        errors.append(type(error).__name__)
                    entry["drain_errors"] = errors
                    entry["exit_code"] = process.returncode
                    if entry["forced_process_stop"] and primary is None:
                        primary = RuntimeError("completed command retained unexpected owned descendants")
                else:
                    entry["process_group_drained"] = True
                out.flush()
                err.flush()
                os.fsync(out.fileno())
                os.fsync(err.fileno())
        entry["finished_at"] = now()
        # No log traversal is allowed when any owned writer might remain.
        if entry["process_group_drained"]:
            entry.update(stdout_sha256=sha(stdout), stderr_sha256=sha(stderr))
        self.persist()
        require(entry["process_group_drained"], "owned command process group did not drain")
        if primary is not None:
            raise primary
        require(allow_failure or entry["exit_code"] == 0, "owned command returned nonzero")
        return entry, stdout

    def inspect(self, label, identity, cleanup=False, allow_missing=False):
        entry, output = self.command(label, ["docker", "inspect", identity], cleanup=cleanup,
                                     allow_failure=allow_missing)
        if entry["exit_code"] != 0:
            # Docker's textual error is not used as proof of nonexistence.
            return None
        values = json.loads(read_bounded(output))
        require(isinstance(values, list) and len(values) == 1, "Docker inspection is ambiguous")
        return values[0]

    def own(self, value):
        require(isinstance(value, dict) and value.get("Name") == "/" + self.name
                and value.get("Config", {}).get("Labels", {}).get(LABEL) == self.owner
                and value.get("Image") == IMAGE, "container ownership or image differs")
        cid = value.get("Id", "")
        require(re.fullmatch(r"[0-9a-f]{64}", cid) is not None, "invalid container ID")
        require(self.cid is None or cid == self.cid, "container identity changed")
        self.cid = cid
        self.ownership_verified = True
        self.record["container_id"] = cid

    def preflight(self):
        for path in (RUNNER, BUILD / "evidence.json"):
            regular(path)
        require(RUNNER.resolve(strict=True) == RUNNER and BUILD.resolve(strict=True) == BUILD
                and SOURCE.resolve(strict=True) == SOURCE, "input path alias rejected")
        require(sha(RUNNER) == RUNNER_SHA and sha(BUILD / "evidence.json") == BUILD_SHA,
                "reviewed input hash differs")
        _, head = self.command("source-head", ["git", "-C", str(SOURCE), "rev-parse", "HEAD"])
        require(read_bounded(head).decode().strip() == COMMIT, "source checkout HEAD differs")
        _, tree = self.command("source-tree", ["git", "-C", str(SOURCE), "rev-parse", COMMIT + "^{tree}"])
        self.record["source_tree"] = read_bounded(tree).decode().strip()
        _, containers = self.command("preflight-all-containers", ["docker", "ps", "-aq"])
        self.record["preserved_container_ids"] = read_bounded(containers).decode().split()
        _, active = self.command("preflight-active-containers", ["docker", "ps", "-q"])
        require(not read_bounded(active).strip(), "VM has active containers; native lane is not exclusive")
        image = self.inspect("image-inspect", IMAGE)
        require(image.get("Id") == IMAGE and image.get("Architecture") == "arm64"
                and image.get("Os") == "linux", "installed image architecture or identity differs")
        self.record["input_binaries"] = {}
        for name in ("kasumid", "kasumictl", "kasumi-bench-capacity"):
            path = BUILD / "target/release" / name
            regular(path)
            self.record["input_binaries"][name] = sha(path)
        self.persist()

    def create(self):
        mounts = [(OUTPUT, "/results", False), (SOURCE, "/source", True),
                  (BUILD, "/build", True), (RUNNER, "/tools/small_native_smoke.py", True)]
        arguments = ["docker", "create", "--pull", "never", "--name", self.name, "--label", LABEL + "=" + self.owner,
                     "--cidfile", str(OUTPUT / "container.cid"), "--init", "--network", "none",
                     "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=268435456,mode=1777",
                     "--cpus", "2", "--memory", "4g", "--memory-swap", "4g",
                     "--pids-limit", "512", "--user", "0:0", "--entrypoint", "/usr/bin/python3"]
        for key, value in CONTAINER_ENV.items():
            arguments += ["--env", key + "=" + value]
        for host, guest, readonly in mounts:
            arguments += ["--mount", f"type=bind,src={host},dst={guest}" + (",readonly" if readonly else "")]
        arguments += [IMAGE, "/tools/small_native_smoke.py", "--binaries", "/build/target/release",
                      "--build-evidence", "/build/evidence.json", "--source", COMMIT,
                      "--repository", "/source", "--output", "/results/run",
                      "--execution-description", "Native Linux ARM64 in kasumi-production-arm64; "
                      "pinned image; Docker init; network none; 2 CPUs; 4 GiB RAM; read-only inputs"]
        self.create_attempted = True
        self.record["create_attempted"] = True
        self.persist()
        _, output = self.command("container-create", arguments)
        cid = read_bounded(output).decode().strip()
        require(re.fullmatch(r"[0-9a-f]{64}", cid) is not None, "create returned invalid container ID")
        require(read_bounded(OUTPUT / "container.cid").decode().strip() == cid, "create ID file differs")
        self.cid = cid
        value = self.inspect("container-create-inspect", cid)
        self.own(value)
        configured = value.get("Config", {}).get("Env", [])
        require(isinstance(configured, list)
                and all(isinstance(item, str) and "=" in item for item in configured),
                "created container environment is malformed")
        for key, expected in CONTAINER_ENV.items():
            require([item.split("=", 1)[1] for item in configured if item.split("=", 1)[0] == key]
                    == [expected], "created container environment differs")
        host = value.get("HostConfig", {})
        require(host.get("Init") is True and host.get("ReadonlyRootfs") is True
                and host.get("NetworkMode") == "none" and host.get("NanoCpus") == 2_000_000_000
                and host.get("Memory") == 4 << 30 and host.get("MemorySwap") == 4 << 30
                and host.get("PidsLimit") == 512
                and host.get("Tmpfs") == {"/tmp": "rw,nosuid,nodev,size=268435456,mode=1777"},
                "created container isolation differs")
        actual = {(item.get("Source"), item.get("Destination"), item.get("RW"))
                  for item in value.get("Mounts", []) if item.get("Type") == "bind"}
        additional = [item for item in value.get("Mounts", []) if item.get("Type") != "bind"]
        require(actual == {(str(src), dst, not ro) for src, dst, ro in mounts}
                and len([item for item in value.get("Mounts", []) if item.get("Type") == "bind"]) == len(mounts)
                and all(item.get("Type") == "tmpfs" and item.get("Destination") == "/tmp"
                        and item.get("RW") is True for item in additional)
                and len(additional) <= 1, "created container mounts differ")
        require(value.get("State", {}).get("Status") == "created", "container started before inspection")
        self.create_certain = True
        self.record["create_certain"] = True
        self.persist()

    @staticmethod
    def drained(value):
        state = value.get("State", {})
        return (state.get("Status") in ("created", "exited", "dead")
                and state.get("Running") is False and state.get("Paused") is False
                and state.get("Restarting") is False and state.get("Pid") == 0)

    def execute(self):
        self.preflight()
        self.create()
        self.command("container-start", ["docker", "start", self.cid])
        while True:
            self.check()
            value = self.inspect("container-poll", self.cid)
            self.own(value)
            self.check()
            if self.drained(value):
                self.record["native_exit_code"] = value["State"].get("ExitCode")
                self.record["native_oom_killed"] = value["State"].get("OOMKilled")
                require(value["State"].get("Status") == "exited"
                        and value["State"].get("ExitCode") == 0
                        and value["State"].get("OOMKilled") is False,
                        "native diagnostic container did not finish successfully")
                return
            time.sleep(min(2, max(0, self.deadline - time.monotonic())))

    def cleanup(self):
        if not self.create_attempted:
            self.record["cleanup"]["verified"] = True
            self.persist()
            return
        # No create/start retry. If create acknowledgement was lost, inspect the
        # exact recorded unique name and label before touching anything.
        value = None
        try:
            value = self.inspect("cleanup-owned-inspect", self.cid or self.name,
                                 cleanup=True, allow_missing=True)
        except BaseException as error:
            self.record["cleanup"]["initial_inspect_error_type"] = type(error).__name__
        if value is not None:
            self.own(value)
        require(self.ownership_verified,
                "container creation or ownership remains uncertain; preserve exact name")
        if value is None or not self.drained(value):
            self.record["cleanup"]["forced"] = True
            self.persist()
            try:
                self.command("container-stop", ["docker", "stop", "--time", str(STOP_SECONDS), self.cid],
                             timeout=STOP_SECONDS + CLI_SECONDS, cleanup=True, allow_failure=True)
            except BaseException as error:
                self.record["cleanup"]["stop_error_type"] = type(error).__name__
            value = None
            try:
                value = self.inspect("after-stop-inspect", self.cid, cleanup=True, allow_missing=True)
            except BaseException as error:
                self.record["cleanup"]["after_stop_inspect_error_type"] = type(error).__name__
            if value is not None:
                self.own(value)
            if value is None or not self.drained(value):
                try:
                    self.command("container-kill", ["docker", "kill", "--signal", "KILL", self.cid],
                                 cleanup=True, allow_failure=True)
                except BaseException as error:
                    self.record["cleanup"]["kill_error_type"] = type(error).__name__
                value = self.inspect("after-kill-inspect", self.cid, cleanup=True, allow_missing=True)
            require(value is not None, "owned terminal container inspection unavailable")
            self.own(value)
        terminal = self.inspect("container-terminal-inspect", self.cid, cleanup=True)
        self.own(terminal)
        require(self.drained(terminal), "owned container did not drain")
        self.record["cleanup"]["verified"] = True
        self.record["terminal_state"] = terminal["State"]
        self.persist()
        self.command("container-terminal-logs", ["docker", "logs", "--timestamps", self.cid], cleanup=True)

    def finish(self, primary):
        try:
            self.cleanup()
        except BaseException as error:
            self.record["cleanup"]["error_type"] = type(error).__name__
            primary = primary or error
        if self.record["cleanup"]["verified"]:
            try:
                # The native files are inspected only after all container
                # writers have drained. They remain private on success/failure.
                evidence = OUTPUT / "run/evidence.json"
                regular(evidence)
                self.record["native_evidence_sha256"] = sha(evidence)
                native = json.loads(read_bounded(evidence, 16 << 20))
                self.record["native_status"] = native.get("status")
                require(native.get("status") == "passed" and native.get("runner_sha256") == RUNNER_SHA
                        and native.get("source_commit") == COMMIT
                        and native.get("build_evidence_sha256") == BUILD_SHA,
                        "native diagnostic evidence does not match its inputs or passing outcome")
                require(sha(RUNNER) == RUNNER_SHA and sha(BUILD / "evidence.json") == BUILD_SHA,
                        "read-only input changed during diagnostic")
            except BaseException as error:
                self.record["evidence_error_type"] = type(error).__name__
                primary = primary or error
        if self.received or self.record["cleanup"]["forced"] or not self.create_certain:
            primary = primary or RuntimeError("interrupted, forced, or uncertain diagnostic")
        if not all(entry.get("process_group_drained") for entry in self.record["commands"]):
            primary = primary or RuntimeError("owned command cleanup remained uncertain")
        self.record.update(status="failed" if primary else "passed", finished_at=now(),
                           elapsed_seconds=time.monotonic() - self.started)
        if primary:
            self.record["error_type"] = type(primary).__name__
        self.persist()
        for number, old in self.old_handlers.items():
            signal.signal(number, old)
        # Static summary only: no container logs, credentials, native response
        # payloads, or exception text reach the controlling host's stdout.
        print(json.dumps({"status": self.record["status"], "private_evidence": str(OUTPUT / "dispatch.json"),
                          "cleanup_verified": self.record["cleanup"]["verified"]}), flush=True)
        return 1 if primary else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", help="requires the separately granted native lane")
    parser.add_argument("--expected-script-sha", help="reviewed SHA-256 of this exact dispatch script")
    args = parser.parse_args()
    if not args.execute:
        print(json.dumps(plan(), indent=2, sort_keys=True))
        return 0
    require(re.fullmatch(r"[0-9a-f]{64}", args.expected_script_sha or "") is not None,
            "execution requires the reviewed dispatch hash")
    dispatch = Dispatch(args.expected_script_sha)
    primary = None
    try:
        dispatch.execute()
    except BaseException as error:
        primary = error
    return dispatch.finish(primary)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(json.dumps({"status": "failed", "error_type": type(error).__name__,
                          "message": "dispatch failed; preserve private output and recorded container"}), flush=True)
        sys.exit(1)
