"""Run the three-member native issuer crash component with a pinned server libtest.

Build kasumi-server's library tests with cargo test --locked -p kasumi-server
--all-features --lib --no-run. Pass the actual native libtest to --executable,
its source tree to --source and a new private evidence directory to --output.
The harness provisions disposable local issuer and verifier stores. It uses
fixture external OAuth, mutually authenticated SDK calls and three actual
local Raft member processes. The candidate's physical placement runs use
the separate recovery release adapter.
"""

import argparse
import datetime
import hashlib
import http.server
import json
import os
from pathlib import Path
import platform
import queue
import resource
import signal
import ssl
import subprocess
import threading
import time
import traceback

PREFIX = b"KASUMI_NATIVE_ISSUER "


def sha(path):
    with path.open("rb") as reader:
        return hashlib.file_digest(reader, "sha256").hexdigest()


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def durable(path, value):
    temporary = path.with_suffix(".tmp")
    with temporary.open("w") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


class Member:
    def __init__(self, run, member, generation, provision=False):
        self.run = run
        self.member = member
        self.name = f"member-{member}-generation-{generation}"
        self.events = queue.Queue()
        self.out = run.output / self.name
        self.out.mkdir(mode=0o700)
        self.stdout = (self.out / "stdout.log").open("wb")
        self.stderr = (self.out / "stderr.log").open("wb")
        env = {**run.env, "KASUMI_ISSUER_CRASH_MEMBER": str(member)}
        if provision:
            env["KASUMI_ISSUER_CRASH_PROVISION"] = "1"
        argv = [
            str(run.executable),
            "--exact",
            run.member_case,
            "--ignored",
            "--test-threads=1",
            "--nocapture",
        ]
        self.started = time.monotonic()
        self.process = subprocess.Popen(
            argv,
            env=env,
            cwd=run.source,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.stderr,
            start_new_session=True,
        )
        self.meta = {
            "argv": argv,
            "pid": self.process.pid,
            "member": member,
            "generation": generation,
            "started_utc": stamp(),
            "executable_sha256": run.identity,
            "input": [],
        }
        self.worker = threading.Thread(target=self._read, daemon=True)
        self.worker.start()
        self._save()

    def _save(self):
        durable(self.out / "process.json", self.meta)

    def _read(self):
        for line in self.process.stdout:
            self.stdout.write(line)
            self.stdout.flush()
            if PREFIX in line:
                self.events.put(json.loads(line.split(PREFIX, 1)[1]))
        self.events.put(None)

    def reply(self, timeout=30):
        value = self.events.get(timeout=timeout)
        if value is None:
            raise RuntimeError(
                f"{self.name} exited {self.process.poll()} before its original reply"
            )
        return value

    def send(self, item):
        if self.process.poll() is not None:
            raise RuntimeError(f"{self.name} already exited {self.process.returncode}")
        self.meta["input"].append({"elapsed": time.monotonic() - self.started, "body": item})
        self._save()
        self.process.stdin.write(json.dumps(item, separators=(",", ":")).encode() + b"\n")
        self.process.stdin.flush()

    def call(self, item, timeout=30):
        self.send(item)
        return self.reply(timeout)

    def crash(self):
        if self.process.poll() is not None:
            raise RuntimeError("original issuer victim was not running")
        self.meta["kill"] = {
            "signal": signal.SIGKILL,
            "elapsed": time.monotonic() - self.started,
            "utc": stamp(),
            "target_pid": self.process.pid,
        }
        self._save()
        os.killpg(self.process.pid, signal.SIGKILL)
        assert self.process.wait(timeout=15) == -signal.SIGKILL
        self.finish()

    def finish(self):
        if self.meta.get("finished_utc"):
            return
        self.worker.join(timeout=10)
        self.stdout.close()
        self.stderr.close()
        self.meta.update(
            exit_code=self.process.poll(),
            finished_utc=stamp(),
            seconds=time.monotonic() - self.started,
            stdout_sha256=sha(self.out / "stdout.log"),
            stderr_sha256=sha(self.out / "stderr.log"),
        )
        self._save()

    def close(self):
        if self.process.poll() is None:
            self.send({"op": "shutdown"})
            event = self.reply(timeout=90)
            assert event == {"drained": True, "pid": self.process.pid, "member": self.member}, event
        self.process.wait(timeout=15)
        self.finish()


class Run:
    def __init__(self, args):
        self.source, self.output, self.executable = (
            args.source.resolve(),
            args.output.resolve(),
            args.executable.resolve(),
        )
        self.output.mkdir(mode=0o700)
        self.installed = self.output / "installation"
        self.installed.mkdir(mode=0o700)
        temporary = self.output / "tmp"
        temporary.mkdir(mode=0o700)
        self.env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(temporary),
            "TMPDIR": str(temporary),
            "RUST_BACKTRACE": "1",
            "LC_ALL": "C",
            "TZ": "UTC",
            "KASUMI_ISSUER_CRASH_DIRECTORY": str(self.installed),
        }
        self.identity = sha(self.executable)
        cases = (
            subprocess.check_output([self.executable, "--list"], env=self.env).decode().splitlines()
        )

        def select(name):
            selected = [
                case.split(": test")[0] for case in cases if case.endswith("::" + name + ": test")
            ]
            assert len(selected) == 1
            return selected[0]

        self.member_case = select("host_one_original_issuer_member")
        self.setup_case = select("provision_original_member_identities")
        self.members = []
        self.server = None
        self.facts = {
            "scope": "three physical loopback issuer PIDs, file-backed encrypted keys, fixture external JWT, mTLS SDK",
            "started_utc": stamp(),
            "host": platform.uname()._asdict(),
            "executable_sha256": self.identity,
            "source": str(self.source),
            "limits": {
                k: resource.getrlimit(getattr(resource, "RLIMIT_" + k))
                for k in ("AS", "CPU", "FSIZE", "NOFILE", "STACK")
            },
            "originals": [],
            "observations": [],
        }
        self.started = time.monotonic()
        self.save()

    def save(self):
        durable(self.output / "report.json", self.facts)

    def record(self, stage, value):
        self.facts["observations"].append(
            {
                "stage": stage,
                "utc": stamp(),
                "elapsed": time.monotonic() - self.started,
                "value": value,
            }
        )
        self.save()

    def setup(self):
        argv = [
            str(self.executable),
            "--exact",
            self.setup_case,
            "--ignored",
            "--test-threads=1",
            "--nocapture",
        ]
        with (self.output / "setup.stdout.log").open("wb") as out, (
            self.output / "setup.stderr.log"
        ).open("wb") as err:
            child = subprocess.Popen(
                argv, cwd=self.source, env=self.env, stdout=out, stderr=err, start_new_session=True
            )
            try:
                status = child.wait(timeout=180)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                status = child.wait()
            self.record(
                "provision",
                {
                    "pid": child.pid,
                    "exit_code": status,
                    "argv": argv,
                    "stdout_sha256": sha(self.output / "setup.stdout.log"),
                    "stderr_sha256": sha(self.output / "setup.stderr.log"),
                },
            )
            assert status == 0 and b"1 passed" in (self.output / "setup.stdout.log").read_bytes()
        self.plan = json.loads((self.installed / "plan.json").read_bytes())
        config_hashes = {file.name: sha(file) for file in self.installed.glob("member-*.json")}
        self.record(
            "installed",
            {"configs": config_hashes, "plan_sha256": sha(self.installed / "plan.json")},
        )
        jwks = (self.installed / "jwks.json").read_bytes()

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(inner):
                if inner.path != "/jwks":
                    inner.send_error(404)
                    return
                inner.send_response(200)
                inner.send_header("content-type", "application/json")
                inner.send_header("content-length", str(len(jwks)))
                inner.end_headers()
                inner.wfile.write(jwks)

            def log_message(inner, *_):
                pass

        self.server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", self.plan["jwks_port"]), Handler
        )
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(self.installed / "jwks.pem", self.installed / "jwks.key")
        self.server.socket = tls.wrap_socket(self.server.socket, server_side=True)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def spawn(self, id, generation, provision=False):
        member = Member(self, id, generation, provision)
        self.members.append(member)
        self.facts["originals"].append(
            {"name": member.name, "pid": member.process.pid, "generation": generation}
        )
        self.save()
        return member

    def leader(self, active):
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            for member in active.values():
                answer = member.call({"op": "metrics"})
                if (
                    answer.get("ok")
                    and answer["result"]["leader"] == member.member
                    and answer["result"]["term"] > 0
                ):
                    return member
            time.sleep(0.15)
        raise RuntimeError("original issuer quorum did not elect a leader")

    def exercise(self):
        self.setup()
        active = {i: self.spawn(i, 1, True) for i in range(1, 4)}
        for node in active.values():
            assert node.reply(120) == {
                "ready": True,
                "pid": node.process.pid,
                "member": node.member,
            }
        victim = self.leader(active)
        caller = next(v for v in active.values() if v is not victim)

        def call(op, member, input_key, body):
            return caller.call({"op": op, "member": member.member, input_key: body})

        # Cold startup can expose the Raft leader before its native RPC listener
        # has completed the installed bootstrap barrier. Reuse the exact command.
        deadline = time.monotonic() + 90
        while True:
            enrolled = call("execute", victim, "command", self.plan["enroll"])
            self.record("enrollment-attempt", enrolled)
            if enrolled.get("ok"):
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("native issuer enrollment never returned a receipt")
            time.sleep(0.25)
        assert enrolled["result"]["receipt"]["outcome"]["kind"] == "enrolled"
        stopped = call("execute", victim, "command", self.plan["stop"])
        self.record("permanent-quorum-receipt", stopped)
        assert stopped["ok"] and stopped["result"]["receipt"]["outcome"]["kind"] == "target_stopped"
        query = self.plan["query"]
        committed = call("status", victim, "query", query)
        self.record("native-committed", committed)
        assert (
            committed["ok"]
            and committed["result"]["stage"] == "committed"
            and committed["result"]["interval_id"] is None
        )
        reference = {
            "tenant": query["tenant"],
            "command_id": query["command_id"],
            "receipt_digest": committed["result"]["first_stop_sha256"],
        }
        started = time.monotonic()
        waiting_caller = next(v for v in active.values() if v is not victim and v is not caller)
        waiting_caller.send({"op": "await_stop", "member": victim.member, "reference": reference})
        pending_rpc = waiting_caller.reply()
        self.record("first-native-grace-refusal", pending_rpc)
        assert (
            pending_rpc.get("pending_verify") is True
            and pending_rpc["caller_pid"] == waiting_caller.process.pid
        )
        assert (
            pending_rpc["member"] == victim.member
            and pending_rpc["command_id"] == reference["command_id"]
        )
        waiting = call("status", victim, "query", query)
        self.record("original-grace", waiting)
        assert (
            waiting["ok"]
            and waiting["result"]["stage"] == "draining"
            and waiting["result"]["node_id"] == victim.member
        )
        old = waiting["result"]
        victim.crash()
        elapsed = (time.monotonic() - started) * 1000
        self.record(
            "original-issuer-sigkill",
            {
                "process": victim.name,
                "pid": victim.process.pid,
                "elapsed_since_first_verify_ms": elapsed,
                "required_grace_ms": self.plan["drain_ms"],
                "status": old,
            },
        )
        # The native caller can return a non-success only after its four-second
        # retry deadline. Measure from *before* submitting that caller through
        # reaping its exact peer, and require its later non-success reply.
        assert elapsed < min(
            self.plan["drain_ms"], 4000
        ), "issuer crash missed the original live caller or grace"
        original_result = waiting_caller.reply(timeout=12)
        self.record(
            "original-caller-return-with-victim-down",
            {"pid": waiting_caller.process.pid, "result": original_result},
        )
        assert original_result["ok"] is False
        del active[victim.member]
        successor = self.leader(active)
        before = call("status", successor, "query", query)
        self.record("successor-before-verify", before)
        assert before["ok"] and before["result"] is None
        second_start = time.monotonic()
        first = call("verify", successor, "reference", reference)
        self.record("successor-fresh-grace-refusal", first)
        assert first["ok"] is False
        second = call("status", successor, "query", query)
        self.record("successor-own-interval", second)
        new = second["result"]
        assert (
            second["ok"]
            and new["stage"] == "draining"
            and new["node_id"] != old["node_id"]
            and new["boot_id"] != old["boot_id"]
            and new["term"] > old["term"]
            and new["interval_id"] != old["interval_id"]
            and new["first_stop_sha256"] == old["first_stop_sha256"]
        )
        reopened = self.spawn(victim.member, 2)
        assert reopened.reply(120) == {
            "ready": True,
            "pid": reopened.process.pid,
            "member": reopened.member,
        }
        assert reopened.process.pid != victim.process.pid
        local = reopened.call({"op": "cold_slot", "query": query})
        self.record("cold-original-physical-slot", local)
        assert local.get("ok") and local["result"] == old
        time.sleep(max(0, second_start + self.plan["drain_ms"] / 1000 + 0.1 - time.monotonic()))
        proof = call("verify", successor, "reference", reference)
        self.record("verified-successor-stop", proof)
        assert (
            proof["ok"]
            and proof["result"]["observation"]["reference"] == reference
            and proof["result"]["observation"]["drain_ms"] == self.plan["drain_ms"]
        )
        final = call("status", successor, "query", query)
        self.record("completed-successor-interval", final)
        assert final["ok"] and final["result"] == {**new, "stage": "drained"}
        # Request shutdown on each original member before awaiting individual
        # joins so the first drain cannot stall waiting on an untouched peer.
        active[reopened.member] = reopened
        for member in active.values():
            member.send({"op": "shutdown"})
        for member in active.values():
            response = member.reply(120)
            self.record("member-drain", response)
            assert response == {"drained": True, "pid": member.process.pid, "member": member.member}
            assert member.process.wait(timeout=20) == 0
            member.finish()

    def cleanup(self):
        for member in self.members:
            if member.process.poll() is None:
                try:
                    member.close()
                except BaseException as cause:
                    self.record("cleanup-original", {"process": member.name, "cause": repr(cause)})
                    if member.process.poll() is None:
                        os.killpg(member.process.pid, signal.SIGKILL)
                        member.process.wait(timeout=15)
            member.finish()
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        self.facts["finished_utc"] = stamp()
        self.facts["seconds"] = time.monotonic() - self.started
        self.facts["max_rss_child"] = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        self.facts["original_process_receipts"] = {
            m.name: sha(m.out / "process.json") for m in self.members
        }
        self.facts["executable_preserved"] = sha(self.executable) == self.identity
        self.save()


if __name__ == "__main__":
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    for key in ("source", "executable", "output"):
        parser.add_argument("--" + key, type=Path, required=True)
    run = Run(parser.parse_args())
    try:
        run.exercise()
        run.facts["status"] = "passed"
    except BaseException as error:
        run.facts["status"] = "failed"
        run.facts["failure"] = traceback.format_exc()
        raise
    finally:
        run.cleanup()
