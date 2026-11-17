"""Owned local daemon groups for process HA experiments, without domain verdicts.

The caller supplies already installed product inputs and independently performs
authenticated readiness/workloads. Starting a process or observing an open port
never establishes readiness. Every original attempt and crash is retained.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time

import gate_process
from process_ha_topology import regular_bytes, require

SCHEMA = "kasumi-process-ha-owned-v2"
# A measured interval may run its full 86,400 seconds: the last workload cycle
# and heartbeat land just after that second, so one heartbeat of slack follows.
MAX_MEASURED_SECONDS = 86400 + 60
# Startup and drain are budgeted separately and never borrow measured time.
MAX_PHASE_SECONDS = 3600
PHASES = ("startup", "measured", "drain")


def durable_json(path, value):
    pending = path.with_name(path.name + ".pending")
    with pending.open("x", encoding="utf-8") as stream:
        os.chmod(pending, 0o600)
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(pending, path)
    descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class OwnedProcesses:
    """One bounded controller; use as a context manager on the main thread.

    Each spawn is an original execution. Restarting requires the previous owned
    process to have terminated and drained, and receives a new receipt. The
    measured deadline covers the whole measured interval, including restarts.
    Optional startup and drain phases have their own budgets outside it; phases
    only advance, and each budget starts when its phase is entered.
    """

    def __init__(self, output, source, environment, timeout_seconds, *,
                 startup_seconds=0, drain_seconds=0):
        require(type(timeout_seconds) in (int, float)
                and 0 < timeout_seconds <= MAX_MEASURED_SECONDS,
                "process experiment deadline must be in (0, 86460] seconds")
        require(all(type(value) in (int, float) and 0 <= value <= MAX_PHASE_SECONDS
                    for value in (startup_seconds, drain_seconds)),
                "startup and drain budgets must be in [0, 3600] seconds")
        self.output = Path(output)
        require(self.output.is_absolute(), "process output must be absolute")
        self.output.mkdir(mode=0o700)  # Refuse prior evidence rather than overwrite.
        self.source = Path(source).resolve(strict=True)
        self.environment = dict(environment)
        self.budgets = {"startup": startup_seconds, "measured": timeout_seconds,
                        "drain": drain_seconds}
        self.timeout = startup_seconds + timeout_seconds + drain_seconds
        self.started = time.monotonic()
        self.phase = "startup" if startup_seconds else "measured"
        self.phases = {self.phase: 0.0}
        self.attempts = []
        self.active = {}
        self.received = []
        self.handlers = {}
        self.closed = False

    def __enter__(self):
        for number in (signal.SIGINT, signal.SIGTERM):
            self.handlers[number] = signal.getsignal(number)
            signal.signal(number, lambda number, _frame: self.received.append(number))
        return self

    def check(self):
        require(not self.closed, "process controller is closed")
        require(len(self.handlers) == 2, "process controller must own signal handlers before spawning")
        require(not self.received, "process controller interrupted")
        require(self.elapsed() - self.phases[self.phase] < self.budgets[self.phase],
                "process experiment " + self.phase + " deadline expired")

    def elapsed(self):
        return time.monotonic() - self.started

    def enter(self, phase):
        """Advance to the next phase and return its controller-relative start.

        The finished phase is not re-checked against its budget: the caller
        ends a measured interval on its own observation, and the offsets
        retained in every later receipt show how long each phase really ran.
        """
        require(not self.closed and not self.received, "process controller is closed or interrupted")
        require(phase in PHASES and PHASES.index(phase) == PHASES.index(self.phase) + 1
                and self.budgets[phase] > 0, "process phases only advance into a budgeted phase")
        self.phase = phase
        self.phases[phase] = self.elapsed()
        return self.phases[phase]

    def _save(self, attempt):
        durable_json(attempt["receipt_path"], attempt["record"])

    def spawn(self, name, command, expected_executable, *, interactive=False):
        """Start one owned process group.

        An interactive process gets a pipe on standard input and a separate
        standard-error log, so its standard-output log is exactly its replies.
        """
        self.check()
        require(isinstance(name, str) and name and all(c in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in name),
                "invalid process name")
        require(name not in self.active and len(self.attempts) < 1024,
                "process already owned or bounded attempt inventory exhausted")
        executable = gate_process.executable_identity(command, self.source, self.environment)
        require(executable == expected_executable and command[0] == executable["path"],
                "process command does not select exact admitted executable")
        index = len(self.attempts) + 1
        identifier = f"{name}-{index:04d}"
        output = self.output / (identifier + ".log")
        stream = output.open("xb")
        os.chmod(output, 0o600)
        record = {"schema": SCHEMA, "id": identifier, "name": name,
                  "qualification": "process-custody-only", "command": command,
                  "working_directory": str(self.source), "executable": executable,
                  "status": "starting", "process_group": None, "leader_birth": None,
                  "timeout_seconds": self.timeout, "received_signals": [], "fault": None,
                  "stop": None, "error": None, "cleanup": None, "process_exit_code": None,
                  "started_elapsed_seconds": None, "outputs_stable": False}
        attempt = {"record": record, "process": None, "stream": stream, "errors": None,
                   "receipt_path": self.output / (identifier + ".json"), "log": output}
        if interactive:
            attempt["errors"] = (self.output / (identifier + ".stderr.log")).open("xb")
            os.chmod(attempt["errors"].name, 0o600)
        self.attempts.append(attempt)
        self.active[name] = attempt
        ledger = None
        try:
            self._save(attempt)
            # Preserve the enclosing release runner's existing spawn seal. The
            # same lock covers admission, Popen and fsynced custody publication.
            # Our installed handlers only append and never interrupt this block.
            # Do not block signals around Popen: that mask would be inherited by
            # the actual daemon, making its ordinary SIGTERM shutdown unusable.
            ledger_path = os.environ.get(gate_process.GROUP_LEDGER_ENV)
            if ledger_path is not None:
                require(self.environment.get(gate_process.GROUP_LEDGER_ENV) == ledger_path,
                        "child would replace the enclosing process ledger")
                ledger = gate_process._group_ledger_open(ledger_path)
                fcntl.flock(ledger, fcntl.LOCK_EX)
                _, closed = gate_process._group_ledger_rows(ledger)
                require(not closed, "nested process admission is closed")
                # Reserve an entire bounded birth-witness row and the later
                # enclosing seal before spawning. An unreadable oversized
                # ledger would defeat the outer runner's cleanup inventory.
                require(os.fstat(ledger).st_size + 512 <= gate_process.MAX_GROUP_LEDGER_BYTES,
                        "enclosing process ledger capacity exhausted")
            process = subprocess.Popen(command, executable=executable["path"], cwd=self.source,
                                       env=self.environment, stdout=stream,
                                       stderr=attempt["errors"] or subprocess.STDOUT,
                                       stdin=subprocess.PIPE if interactive else subprocess.DEVNULL,
                                       start_new_session=True)
            attempt["process"] = process
            record["process_group"] = process.pid
            record["started_elapsed_seconds"] = self.elapsed()
            identity = gate_process.leader_identity(process.pid)
            require(identity is not None and identity["group"] == process.pid,
                    "spawned process has no live birth witness")
            record["leader_birth"] = identity["birth"]
            if ledger is not None:
                gate_process._group_ledger_append(ledger, {
                    "schema": 1, "kind": "group", "group": process.pid, "owner_pid": os.getpid(),
                    "executable_sha256": executable["sha256"], "leader_birth": identity["birth"]})
            record["status"] = "running"
            self._save(attempt)
        except BaseException as error:
            record["error"] = repr(error)
            self.finish(name)
            raise
        finally:
            if ledger is not None:
                fcntl.flock(ledger, fcntl.LOCK_UN)
                os.close(ledger)
        return record["id"]

    def assert_alive(self):
        self.check()
        for attempt in self.active.values():
            require(attempt["process"] is not None and attempt["process"].poll() is None,
                    "owned service exited before the workload completed")

    def crash(self, name, observation_path):
        """Kill the owned leader after retaining an independently obtained reply.

        The supplied bytes are an observation, not a trusted phase assertion.
        Domain validation of that reply is the caller's separate responsibility.
        """
        self.check()
        require(name in self.active, "crash target is not owned")
        attempt = self.active[name]
        process, record = attempt["process"], attempt["record"]
        require(process is not None and process.poll() is None, "crash target already exited")
        identity = gate_process.leader_identity(process.pid)
        require(identity == {"group": process.pid, "birth": record["leader_birth"]},
                "crash target birth witness changed")
        observed = regular_bytes(observation_path)
        retained = self.output / (record["id"] + ".pre-crash-observation")
        with retained.open("xb") as stream:
            os.chmod(retained, 0o600)
            stream.write(observed)
            stream.flush()
            os.fsync(stream.fileno())
        record["fault"] = {"signal": "SIGKILL", "target": "owned-leader",
                           "observation": str(retained), "observation_sha256": hashlib.sha256(observed).hexdigest(),
                           "semantic_validation": "not-performed-by-process-controller",
                           "elapsed_seconds": self.elapsed(), "sent": False}
        self._save(attempt)
        # The unreaped Popen child still owns this PID. Never signal an arbitrary
        # PID copied from a topology manifest or a prior process receipt.
        process.send_signal(signal.SIGKILL)
        record["fault"]["sent"] = True
        process.wait(timeout=min(10, max(.1, self.timeout - self.elapsed())))
        return self.finish(name)

    def stop(self, name, grace_seconds=30):
        """Ask the owned leader for its ordinary SIGTERM shutdown and retain the outcome.

        The receipt distinguishes this requested stop from the forced cleanup
        an unresponsive process needs: only the latter records drain signals.
        """
        self.check()
        require(name in self.active, "stop target is not owned")
        attempt = self.active[name]
        process, record = attempt["process"], attempt["record"]
        require(process is not None and process.poll() is None, "stop target already exited")
        identity = gate_process.leader_identity(process.pid)
        require(identity == {"group": process.pid, "birth": record["leader_birth"]},
                "stop target birth witness changed")
        record["stop"] = {"signal": "SIGTERM", "target": "owned-leader",
                          "elapsed_seconds": self.elapsed(), "sent": False}
        self._save(attempt)
        process.send_signal(signal.SIGTERM)
        record["stop"]["sent"] = True
        try:
            process.wait(timeout=min(grace_seconds, max(.1, self.timeout - self.elapsed())))
        except subprocess.TimeoutExpired:
            pass  # finish() escalates and records it; the stop is then not clean.
        return self.finish(name)

    def send(self, name, data):
        """Write one request to an interactive process's standard input."""
        self.check()
        require(name in self.active, "input target is not owned")
        process = self.active[name]["process"]
        require(process is not None and process.stdin is not None and process.poll() is None,
                "interactive process is not accepting input")
        process.stdin.write(data)
        process.stdin.flush()

    def end_input(self, name, grace_seconds=30):
        """Close an interactive process's input and retain its own orderly exit."""
        self.check()
        require(name in self.active, "input target is not owned")
        attempt = self.active[name]
        process, record = attempt["process"], attempt["record"]
        require(process is not None and process.stdin is not None, "process is not interactive")
        record["stop"] = {"signal": "EOF", "target": "owned-leader",
                          "elapsed_seconds": self.elapsed(), "sent": False}
        self._save(attempt)
        process.stdin.close()
        record["stop"]["sent"] = True
        try:
            process.wait(timeout=min(grace_seconds, max(.1, self.timeout - self.elapsed())))
        except subprocess.TimeoutExpired:
            pass
        return self.finish(name)

    def finish(self, name):
        attempt = self.active[name]
        process, record = attempt["process"], attempt["record"]
        try:
            cleanup = gate_process.drain(process) if process is not None else {
                "group": None, "before": [], "after": [], "signals": [], "errors": [],
                "drained": True, "process_returncode": None}
            record["cleanup"] = cleanup
            record["process_exit_code"] = cleanup["process_returncode"]
            record["received_signals"] = list(self.received)
            record["finished_elapsed_seconds"] = self.elapsed()
            record["duration_seconds"] = (
                0.0 if record["started_elapsed_seconds"] is None
                else record["finished_elapsed_seconds"] - record["started_elapsed_seconds"])
            record["phases"] = dict(self.phases)
            try:
                require(gate_process.executable_identity([record["executable"]["path"]], self.source,
                                                        self.environment) == record["executable"],
                        "executed bytes changed during experiment")
            except Exception as error:
                record["error"] = record["error"] or repr(error)
            for stream in (attempt["stream"], attempt["errors"]):
                if stream is not None:
                    stream.flush()
                    os.fsync(stream.fileno())
            record["outputs_stable"] = cleanup["drained"]
            record["status"] = "drained" if cleanup["drained"] and not record["error"] else "failed"
            self._save(attempt)
        finally:
            attempt["stream"].close()
            if attempt["errors"] is not None:
                attempt["errors"].close()
            if process is not None and process.stdin is not None:
                process.stdin.close()
            del self.active[name]
        require(record["cleanup"] and record["cleanup"]["drained"], "owned process group did not drain")
        return record

    def close(self):
        errors = []
        for name in list(self.active):
            try:
                self.finish(name)
            except BaseException as error:
                errors.append(repr(error))
        self.closed = True
        for number, handler in self.handlers.items():
            signal.signal(number, handler)
        require(not errors, "process controller cleanup failed: " + repr(errors))

    def __exit__(self, *_):
        self.close()
