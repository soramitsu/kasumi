"""Owned fault actions for the HA-fault and recovery producers, replayed by their adapters.

A scenario script talks to Kasumi only through this interface. The producer's
``Live`` driver executes each action as an owned candidate process, an owned
daemon spawn, stop or fault, or a signal to an owned daemon, and appends one
row to the run's action ledger. The adapter runs the *same* script with a
``Replay`` driver: every call returns the original retained output, exit code
or clock reading and is checked against that original receipt. Every verdict
is therefore recomputed from raw evidence by the code that produced it.

Nothing here decides a domain outcome. A scenario script names which owned
results count as scenario rows; the adapter recounts those rows itself.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import threading
import time

import domain_run
from domain_run import require
import gate_process
import repeatable_assembly as owned

LEDGER = "actions.jsonl"
# One management or recovery command, including a 600-second product deadline.
COMMAND_SECONDS = 1800
POLL_SECONDS = 120
# Signals a scenario may send to an owned daemon without ending it. SIGKILL and
# SIGTERM are the process controller's own crash and stop.
SIGNALS = {"SIGSTOP": signal.SIGSTOP, "SIGCONT": signal.SIGCONT, "SIGHUP": signal.SIGHUP}
# A replaced installed file: TLS chains, private keys and node configurations
# that the operator staged beside the file they replace.
REPLACEMENT_KINDS = ("public", "private")


def decode(raw):
    """A command's one JSON document, or None when it printed something else."""
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None
    return value if isinstance(value, dict) else None


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def file_identity(path):
    status = os.stat(path, follow_symlinks=False)
    require(stat.S_ISREG(status.st_mode), "replaced installed input is not a regular file")
    return {"device": status.st_dev, "inode": status.st_ino, "bytes": status.st_size,
            "mode": stat.S_IMODE(status.st_mode)}


class Driver:
    """Composite steps built only from primitive, journaled actions."""

    def poll(self, label, argv, predicate, *, limit, pause=1.0):
        """Retain every refusal; return the first decoded sample that settles."""
        for index in range(limit):
            code, raw = self.attempt(f"{label}-{index:04d}", argv)
            value = decode(raw) if code == 0 else None
            if value is not None:
                try:
                    settled = predicate(value)
                except (KeyError, TypeError, ValueError, IndexError):
                    settled = False
                if settled:
                    return value
            self.pause(pause)
        raise ValueError("owned observation did not settle: " + label)

    def json(self, label, argv, scenarios=()):
        value = decode(self.call(label, argv, scenarios))
        require(value is not None, "owned command did not print one JSON document: " + label)
        return value


class Live(Driver):
    """The producer: execute and journal; never interpret a result."""

    def __init__(self, run, details):
        self.run, self.details = run, details
        self.sequence = 0
        self.steps = 0
        details.setdefault("attempts", [])
        details["ledger"] = None
        self.path = run.output / LEDGER
        self.stream = self.path.open("xb")
        os.chmod(self.path, 0o600)
        (run.output / "requests").mkdir(mode=0o700)

    def close(self):
        if not self.stream.closed:
            self.stream.flush()
            os.fsync(self.stream.fileno())
            self.stream.close()
        self.details["ledger"] = owned.ref(self.run.output, self.path)
        self.run.save()

    def _row(self, kind, **fields):
        row = {"sequence": self.sequence, "kind": kind, **fields}
        self.sequence += 1
        self.stream.write(canonical(row))
        self.stream.flush()
        os.fsync(self.stream.fileno())
        return row

    def _step(self, label):
        self.steps += 1
        require(isinstance(label, str) and label and len(label) <= 96
                and all(c in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in label),
                "invalid owned step label")
        return f"a{self.steps:04d}-{label}"

    def clock(self):
        value = round(self.run.services.elapsed(), 6)
        self._row("clock", elapsed=value)
        return value

    def pause(self, seconds):
        time.sleep(seconds)

    def custody(self, relative):
        """The path a command names: inside this run's own custody."""
        return str(self.run.output / relative)

    def request(self, name, value):
        """Write one management request for a later command; the adapter rereads it."""
        path = self.run.output / "requests" / (name + ".json")
        with path.open("xb") as stream:
            os.chmod(path, 0o600)
            stream.write(canonical(value))
            stream.flush()
            os.fsync(stream.fileno())
        self._row("request", name=name, sha256=hashlib.sha256(canonical(value)).hexdigest())
        return str(path)

    def call(self, label, argv, scenarios=()):
        """A command that must exit zero; it joins the passing process roster."""
        step = self._step(label)
        try:
            output = self.run.command(step, argv, COMMAND_SECONDS)
        finally:
            item = self.run.report["processes"][-1] if self.run.report["processes"] else None
            ran = item is not None and item["id"] == step
            exit_code = owned.read(owned.check_ref(self.run.output, item["receipt"]))["exit_code"] \
                if ran else None
            self._row("call", step=step, argv=argv, scenarios=list(scenarios), exit_code=exit_code)
        for scenario in scenarios:
            self.run.observe(scenario, step, item["receipt"], 0, 0)
        return output.read_bytes()

    def attempt(self, label, argv, timeout=POLL_SECONDS):
        """Any exit status; retained in custody outside the passing roster."""
        step = self._step(label)
        self.run.dispatch()
        item = owned.run_owned(self.run.output, step, argv, str(self.run.source),
                               self.run.environment, timeout)
        record = owned.read(owned.check_ref(self.run.output, item["receipt"]))
        self.details["attempts"].append(item)
        self.run.save()
        self._row("attempt", step=step, argv=argv, exit_code=record["exit_code"])
        return record["exit_code"], owned.check_ref(self.run.output, item["stdout"]).read_bytes()

    def phase(self, name):
        value = round(self.run.services.enter(name), 6)
        self._row("phase", name=name, elapsed=value)
        return value

    def spawn_client(self, name, argv):
        """An interactive candidate client; its standard output is exactly its replies."""
        executable = gate_process.executable_identity(argv, self.run.source, self.run.environment)
        identifier = self.run.service(name, argv, executable, interactive=True)
        self._row("client", name=name, process=identifier, argv=argv)
        return identifier

    def send(self, name, data):
        self.run.services.send(name, data)

    def end_client(self, name):
        record = self.run.services.end_input(name)
        self._bind(record)
        self._row("end-client", name=name, process=record["id"])
        return record

    def spawn(self, name, executable, config):
        identifier = self.run.service(name, [executable["path"], "serve", config], executable)
        self._row("spawn", name=name, process=identifier, config=config)
        return identifier

    def _bind(self, record):
        item = next(item for item in self.run.report["processes"] if item["id"] == record["id"])
        item["receipt"] = owned.ref(self.run.output, self.run.output / item["receipt"]["path"])
        item["log"] = owned.ref(self.run.output, self.run.output / item["log"]["path"])
        self.run.save()
        return item

    def crash(self, name, observation, scenarios=()):
        """SIGKILL an owned daemon after retaining the reply that selected it."""
        path = self.run.output / "home" / f"observation-{self.sequence:05d}"
        path.write_bytes(observation)
        try:
            record = self.run.services.crash(name, path)
        finally:
            path.unlink()
        item = self._bind(record)
        for scenario in scenarios:
            self.run.observe(scenario, record["id"], item["receipt"], -9, record["process_exit_code"])
        self._row("crash", name=name, process=record["id"], scenarios=list(scenarios),
                  observation_sha256=hashlib.sha256(observation).hexdigest())
        return record

    def stop(self, name, scenarios=()):
        record = self.run.services.stop(name)
        item = self._bind(record)
        for scenario in scenarios:
            self.run.observe(scenario, record["id"], item["receipt"], 0, record["process_exit_code"])
        self._row("stop", name=name, process=record["id"], scenarios=list(scenarios))
        return record

    def signal(self, name, signame):
        """Freeze, thaw or reload one owned daemon without ending it."""
        require(signame in SIGNALS, "unsupported owned daemon signal")
        self.run.services.check()
        attempt = self.run.services.active.get(name)
        require(attempt is not None and attempt["process"] is not None
                and attempt["process"].poll() is None, "signal target is not a live owned daemon")
        process, record = attempt["process"], attempt["record"]
        require(gate_process.leader_identity(process.pid)
                == {"group": process.pid, "birth": record["leader_birth"]},
                "signal target birth witness changed")
        elapsed = round(self.run.services.elapsed(), 6)
        # The unreaped Popen child still owns this PID and its group.
        os.killpg(process.pid, SIGNALS[signame])
        self._row("signal", name=name, process=record["id"], signal=signame, elapsed=elapsed,
                  group=process.pid, birth=record["leader_birth"])

    def replace(self, source, destination, kind):
        """Rename an operator-staged file over the installed file it replaces.

        Private bytes are never read: only their filesystem identity is kept.
        """
        require(kind in REPLACEMENT_KINDS, "unknown replacement kind")
        source, destination = Path(source), Path(destination)
        require(source.is_absolute() and destination.is_absolute()
                and source.parent == destination.parent and source != destination,
                "a staged replacement must sit beside the installed file it replaces")
        before = file_identity(source)
        require(before["mode"] & 0o077 == 0 or kind == "public",
                "a staged private replacement is not owner-only")
        digest = owned.sha256(source) if kind == "public" else None
        os.replace(source, destination)
        descriptor = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        after = file_identity(destination)
        require(after == before, "staged replacement changed while it was installed")
        self._row("replace", source=str(source), destination=str(destination), replacement=kind,
                  identity=after, sha256=digest, elapsed=round(self.run.services.elapsed(), 6))

    def faulted(self, label, argv, name, observation, delay, scenarios=()):
        """Run one command and SIGKILL an owned daemon ``delay`` seconds after its spawn.

        The command runs on the main thread (its owner installs signal
        handlers); a timer sends the controller's own fault. The fault is
        always sent, even after a command that already returned, so each call
        ends exactly one daemon. Whether it landed is the scenario's question.
        """
        require(type(delay) in (int, float) and 0 < delay <= 600, "fault delay out of range")
        step = self._step(label)
        self.run.dispatch()
        started = self.clock()
        fired, outcome = threading.Event(), {}

        def fault():
            path = self.run.output / "home" / f"observation-{step}"
            try:
                path.write_bytes(observation)
                outcome["record"] = self.run.services.crash(name, path)
            except BaseException as error:  # retained; the main thread raises it
                outcome["error"] = error
            finally:
                if path.exists():
                    path.unlink()
                fired.set()

        timer = threading.Timer(delay, fault)
        armed = []

        def observe(record):
            if record.get("process_group") and not armed:
                armed.append(True)
                timer.start()

        try:
            item = owned.run_owned(self.run.output, step, argv, str(self.run.source),
                                   self.run.environment, COMMAND_SECONDS, observe_process=observe)
        finally:
            if not armed:
                armed.append(True)
                timer.start()
            timer.join(delay + 120)
        require(fired.is_set(), "in-flight fault was never sent")
        require("error" not in outcome, "in-flight fault failed: " + repr(outcome.get("error")))
        finished = self.clock()
        record = outcome["record"]
        bound = self._bind(record)
        for scenario in scenarios:
            self.run.observe(scenario, record["id"], bound["receipt"], -9,
                             record["process_exit_code"])
        self.details["attempts"].append(item)
        self.run.save()
        receipt = owned.read(owned.check_ref(self.run.output, item["receipt"]))
        self._row("faulted", step=step, argv=argv, name=name, process=record["id"], delay=delay,
                  exit_code=receipt["exit_code"], scenarios=list(scenarios),
                  observation_sha256=hashlib.sha256(observation).hexdigest())
        return {"exit_code": receipt["exit_code"], "started": started, "finished": finished,
                "process": record["id"], "fault_elapsed": record["fault"]["elapsed_seconds"],
                "output": owned.check_ref(self.run.output, item["stdout"]).read_bytes()}

    def race(self, label, argvs):
        """Start several candidate clients back to back and let each exit by itself.

        They are owned groups outside the passing roster: a losing racer may
        refuse. Each receipt records its own exit and drained cleanup.
        """
        self.run.dispatch()
        names = []
        for index, argv in enumerate(argvs):
            step = self._step(f"{label}-{index}")
            executable = gate_process.executable_identity(argv, self.run.source,
                                                          self.run.environment)
            owned.retain(self.run.output, Path(executable["path"]))
            names.append((step, self.run.services.spawn(step, argv, executable)))
        deadline = time.monotonic() + COMMAND_SECONDS
        while any(self.run.services.active[step]["process"].poll() is None for step, _ in names):
            require(time.monotonic() < deadline, "racing clients did not finish")
            time.sleep(.02)
        results = []
        for step, identifier in names:
            record = self.run.services.finish(step)
            results.append({"step": step, "process": identifier,
                            "exit_code": record["process_exit_code"]})
        self.details.setdefault("races", []).append(
            [{"process": item["process"], "receipt": owned.ref(
                self.run.output, self.run.output / "services" / (item["process"] + ".json")),
              "log": owned.ref(self.run.output,
                               self.run.output / "services" / (item["process"] + ".log"))}
             for item in results])
        self.run.save()
        self._row("race", argvs=argvs, results=results)
        return [(item["exit_code"], (self.run.output / "services" / (item["process"] + ".log"))
                 .read_bytes()) for item in results]

    def mark(self, scenario, process, expected_exit):
        """Count an already terminal owned daemon as one scenario row."""
        item = next(item for item in self.run.report["processes"] if item["id"] == process)
        require("sha256" in item["receipt"], "a scenario row needs a terminal daemon receipt")
        record = owned.read(owned.check_ref(self.run.output, item["receipt"]))
        self.run.observe(scenario, process, item["receipt"], expected_exit,
                         record["process_exit_code"])
        self._row("mark", scenario=scenario, process=process, expected_exit=expected_exit)

    def listing(self, root):
        """Physical identities under one installed storage root (bounded walk)."""
        entries = walk(root)
        self._row("listing", root=root, entries=entries)
        return entries

    def plant(self, path, data):
        """Create an unrelated private file the product must never touch."""
        path = Path(path)
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.write(descriptor, data)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        identity = file_identity(path)
        self._row("plant", path=str(path), sha256=hashlib.sha256(data).hexdigest(),
                  identity=identity)
        return identity

    def inspect(self, path):
        """The identity and digest of one file now, or None when it is absent."""
        try:
            value = {**file_identity(path), "sha256": owned.sha256(Path(path))}
        except FileNotFoundError:
            value = None
        self._row("inspect", path=str(path), result=value)
        return value


class Replay(Driver):
    """The adapter: the same calls, answered only from original evidence."""

    def __init__(self, facts, paths):
        import verify_release_acceptance as acceptance

        self.acceptance = acceptance
        self.facts = facts
        report, custody = facts["report"], facts["custody"]
        self.local = custody
        self.original = Path(report["custody_root"])
        self.source = Path(report["evidence_root"]) / "source"
        self.binaries = report["binaries"]
        self.paths = paths
        details = report["details"]
        self.rows = list(acceptance.rows(custody, details["ledger"]))
        self.attempts = {}
        for item in details["attempts"]:
            owned.exact(item, {"id", "receipt", "stdout", "stderr", "executable"}, "owned attempt")
            require(item["id"] not in self.attempts, "duplicate owned attempt")
            self.attempts[item["id"]] = item
        self.processes = {item["id"]: item for item in report["processes"]}
        self.index = 0
        self.steps = 0
        self.used = set()
        self.expected = {}
        self.signals = []
        self.replacements = []
        self.faults = []
        self.phases = {}
        self.clients = []
        self.spawns = []
        self.races = list(details.get("races", []))

    def _next(self, kind, **expected):
        require(self.index < len(self.rows), "action ledger ended before the scenario script")
        row = self.rows[self.index]
        require(isinstance(row, dict) and row.get("sequence") == self.index
                and row.get("kind") == kind, "action ledger differs from the scenario script")
        for key, value in expected.items():
            require(row.get(key) == value, "action ledger differs from the scenario script: " + key)
        self.index += 1
        return row

    def _step(self, label):
        self.steps += 1
        return f"a{self.steps:04d}-{label}"

    def _executable(self, argv):
        name = Path(argv[0]).name
        require(name in self.binaries and argv[0] == self.paths[name],
                "owned command selects an unqualified executable")
        return name

    def finish(self):
        """Every ledger row, attempt, command and daemon belongs to the script."""
        require(self.index == len(self.rows), "action ledger has rows the scenario never took")
        require(set(self.attempts) <= self.used and set(self.processes) <= self.used,
                "an owned process is not part of the scenario script")

    def clock(self):
        row = self._next("clock")
        return self.acceptance.number(row["elapsed"], "ledger clock")

    def pause(self, seconds):
        return None

    def custody(self, relative):
        """The path the original command named, under the producer's custody root."""
        return str(self.original / relative)

    def request(self, name, value):
        self._next("request", name=name, sha256=hashlib.sha256(canonical(value)).hexdigest())
        path = self.local / "requests" / (name + ".json")
        require(path.is_file() and not path.is_symlink() and path.read_bytes() == canonical(value),
                "retained management request differs from the scenario script")
        self.acceptance.reference(self.local, owned.ref(self.local, path))
        return self.custody("requests/" + name + ".json")

    def call(self, label, argv, scenarios=()):
        step = self._step(label)
        self._next("call", step=step, argv=argv, scenarios=list(scenarios), exit_code=0)
        original = self.facts["receipts"].get(step)
        require(original is not None and not original["service"] and step not in self.used
                and original["exit_code"] == 0
                and original["record"]["command"] == argv
                and original["record"]["working_directory"] == str(self.source)
                and original["record"]["executable"]["sha256"] == self.binaries[self._executable(argv)],
                "owned command differs from its original receipt: " + step)
        self.used.add(step)
        for scenario in scenarios:
            self.expected.setdefault(scenario, []).append((step, 0))
        return self.acceptance.reference(self.local, self.processes[step]["log"]).read_bytes()

    def _attempt(self, step, argv, timeout):
        item = self.attempts.get(step)
        require(item is not None and step not in self.used, "owned attempt is absent: " + step)
        receipt_path = owned.check_ref(self.local, item["receipt"])
        record = owned.read(receipt_path)
        stdout = owned.check_ref(self.local, item["stdout"])
        stderr = owned.check_ref(self.local, item["stderr"])
        owned.check_ref(self.local, item["executable"])
        cleanup = record.get("cleanup") or {}
        require(receipt_path == self.local / step / "process.json"
                and stdout == self.local / step / "stdout.log"
                and stderr == self.local / step / "stderr.log"
                and record.get("stdout") == item["stdout"] and record.get("stderr") == item["stderr"]
                and record.get("command") == argv
                and record.get("working_directory") == str(self.source)
                and record.get("executable") == {"path": argv[0],
                                                 "sha256": self.binaries[self._executable(argv)]}
                and item["executable"]["sha256"] == record["executable"]["sha256"]
                and record.get("timeout_seconds") == timeout and record.get("timed_out") is False
                and record.get("error") is None and record.get("received_signals") == []
                and record.get("outputs_stable") is True and type(record.get("exit_code")) is int
                and record["exit_code"] == record.get("process_exit_code")
                == cleanup.get("process_returncode")
                and cleanup.get("drained") is True and cleanup.get("after") == []
                and cleanup.get("errors") == [],
                "owned attempt differs from its original receipt: " + step)
        self.used.add(step)
        return record, stdout.read_bytes()

    def attempt(self, label, argv, timeout=POLL_SECONDS):
        step = self._step(label)
        row = self._next("attempt", step=step, argv=argv)
        record, raw = self._attempt(step, argv, timeout)
        require(row["exit_code"] == record["exit_code"], "attempt exit differs from its receipt")
        return record["exit_code"], raw

    def _service(self, identifier, name):
        original = self.facts["receipts"].get(identifier)
        require(original is not None and original["service"] and identifier not in self.used
                and original["record"]["name"] == name,
                "owned daemon differs from its original receipt: " + identifier)
        return original

    def phase(self, name):
        row = self._next("phase", name=name)
        value = self.acceptance.number(row["elapsed"], "phase start")
        self.phases[name] = value
        return value

    def spawn_client(self, name, argv):
        row = self._next("client", name=name, argv=argv)
        original = self.facts["receipts"].get(row["process"])
        require(original is not None and original["service"]
                and original["record"]["name"] == name and original["record"]["command"] == argv
                and original["record"]["executable"]["sha256"]
                == self.binaries[self._executable(argv)],
                "interactive client differs from its original receipt: " + name)
        self.clients.append(row["process"])
        return row["process"]

    def send(self, name, data):
        raise ValueError("an adapter never writes to a client")

    def end_client(self, name):
        row = self._next("end-client", name=name)
        original = self._service(row["process"], name)
        require(original["disposition"] == "input-closed",
                "interactive client did not end on closed input: " + name)
        self.used.add(row["process"])
        return original["record"]

    def spawn(self, name, executable, config):
        row = self._next("spawn", name=name, config=config)
        original = self.facts["receipts"].get(row["process"])
        require(original is not None and original["service"]
                and original["record"]["name"] == name
                and original["record"]["command"] == [executable["path"], "serve", config]
                and original["record"]["executable"] == executable
                and executable["sha256"] in self.binaries.values(),
                "owned daemon spawn differs from its original receipt: " + name)
        self.spawns.append(row["process"])
        return row["process"]

    def crash(self, name, observation, scenarios=()):
        row = self._next("crash", name=name, scenarios=list(scenarios),
                         observation_sha256=hashlib.sha256(observation).hexdigest())
        original = self._service(row["process"], name)
        fault = original["record"]["fault"]
        require(original["disposition"] == "fault"
                and fault["observation_sha256"] == row["observation_sha256"],
                "owned daemon fault differs from its original receipt: " + name)
        self.used.add(row["process"])
        self.faults.append(original["record"])
        for scenario in scenarios:
            self.expected.setdefault(scenario, []).append((row["process"], -9))
        return original["record"]

    def stop(self, name, scenarios=()):
        row = self._next("stop", name=name, scenarios=list(scenarios))
        original = self._service(row["process"], name)
        require(original["disposition"] == "clean-stop",
                "owned daemon stop differs from its original receipt: " + name)
        self.used.add(row["process"])
        for scenario in scenarios:
            self.expected.setdefault(scenario, []).append((row["process"], 0))
        return original["record"]

    def signal(self, name, signame):
        row = self._next("signal", name=name, signal=signame)
        original = self.facts["receipts"].get(row["process"])
        require(original is not None and original["service"] and original["record"]["name"] == name
                and row["group"] == original["record"]["process_group"]
                and row["birth"] == original["record"]["leader_birth"]
                and original["record"]["started_elapsed_seconds"] <= row["elapsed"]
                <= original["record"]["finished_elapsed_seconds"],
                "owned daemon signal is outside its original process lifetime: " + name)
        self.signals.append(row)

    def replace(self, source, destination, kind):
        row = self._next("replace", source=str(source), destination=str(destination),
                         replacement=kind)
        require(Path(source).parent == Path(destination).parent
                and isinstance(row["identity"], dict)
                and (row["sha256"] is None) == (kind == "private"),
                "installed replacement differs from the scenario script")
        self.replacements.append(row)
        return row

    def faulted(self, label, argv, name, observation, delay, scenarios=()):
        step = self._step(label)
        started = self.clock()
        finished = self.clock()
        row = self._next("faulted", step=step, argv=argv, name=name, delay=delay,
                         scenarios=list(scenarios),
                         observation_sha256=hashlib.sha256(observation).hexdigest())
        record, raw = self._attempt(step, argv, COMMAND_SECONDS)
        original = self._service(row["process"], name)
        fault = original["record"]["fault"]
        require(original["disposition"] == "fault"
                and fault["observation_sha256"] == row["observation_sha256"]
                and row["exit_code"] == record["exit_code"]
                and started <= fault["elapsed_seconds"] <= finished,
                "in-flight fault differs from its original receipts: " + step)
        self.used.add(row["process"])
        self.faults.append(original["record"])
        for scenario in scenarios:
            self.expected.setdefault(scenario, []).append((row["process"], -9))
        return {"exit_code": record["exit_code"], "started": started, "finished": finished,
                "process": row["process"], "fault_elapsed": fault["elapsed_seconds"],
                "output": raw}

    def race(self, label, argvs):
        steps = [self._step(f"{label}-{index}") for index in range(len(argvs))]
        row = self._next("race", argvs=argvs)
        results = row["results"]
        require(isinstance(results, list) and len(results) == len(argvs),
                "race differs from the scenario script")
        recorded = self.races.pop(0) if self.races else None
        require(recorded is not None and len(recorded) == len(argvs),
                "race receipts are absent")
        outputs = []
        for step, argv, result, item in zip(steps, argvs, results, recorded):
            receipt = owned.check_ref(self.local, item["receipt"])
            record = owned.read(receipt)
            cleanup = record.get("cleanup") or {}
            require(result["step"] == step and item["process"] == result["process"]
                    and receipt == self.local / "services" / (result["process"] + ".json")
                    and owned.check_ref(self.local, item["log"])
                    == self.local / "services" / (result["process"] + ".log")
                    and record.get("name") == step and record.get("command") == argv
                    and record.get("executable", {}).get("sha256")
                    == self.binaries[self._executable(argv)]
                    and record.get("status") == "drained" and record.get("error") is None
                    and record.get("fault") is None and record.get("stop") is None
                    and record.get("received_signals") == []
                    and cleanup.get("drained") is True and cleanup.get("signals") == []
                    and cleanup.get("before") == [] and cleanup.get("after") == []
                    and type(record.get("process_exit_code")) is int
                    and record["process_exit_code"] == result["exit_code"]
                    == cleanup.get("process_returncode"),
                    "racing client differs from its original receipt: " + step)
            outputs.append((result["exit_code"],
                            owned.check_ref(self.local, item["log"]).read_bytes()))
        return outputs

    def mark(self, scenario, process, expected_exit):
        self._next("mark", scenario=scenario, process=process, expected_exit=expected_exit)
        original = self.facts["receipts"].get(process)
        require(original is not None and original["service"] and process in self.used,
                "scenario row names a daemon the script never ended: " + process)
        self.expected.setdefault(scenario, []).append((process, expected_exit))

    def listing(self, root):
        row = self._next("listing", root=root)
        require(isinstance(row["entries"], dict), "storage listing is malformed")
        return row["entries"]

    def plant(self, path, data):
        row = self._next("plant", path=str(path), sha256=hashlib.sha256(data).hexdigest())
        return row["identity"]

    def inspect(self, path):
        return self._next("inspect", path=str(path))["result"]


def interrupted(result):
    """The fault was sent while its command ran, and the command did not succeed.

    This alone does not place the fault inside a product phase: the scenario
    also requires the product's own durable state to show that phase begun
    and not completed after the faulted daemon returns.
    """
    return (result["exit_code"] != 0
            and result["started"] <= result["fault_elapsed"] <= result["finished"])


def scenario_rows(facts):
    """(step, expected exit) per scenario, exactly as the runner recorded them."""
    return {name: [(row["step"], row["expected_exit"]) for row in rows]
            for name, rows in facts["scenarios"].items()}


def durable(path, value):
    domain_run.durable_json(path, value)


WALK_ENTRIES = 4096
WALK_DEPTH = 4


def walk(root):
    """Relative path -> physical identity under ``root``, never following links."""
    root = Path(root)
    require(root.is_absolute() and root.is_dir() and not root.is_symlink(),
            "storage listing root is not a real directory")
    entries, pending = {}, [(root, 0)]
    while pending:
        directory, depth = pending.pop()
        with os.scandir(directory) as scan:
            for entry in sorted(scan, key=lambda item: item.name):
                status = entry.stat(follow_symlinks=False)
                kind = ("dir" if stat.S_ISDIR(status.st_mode) else
                        "file" if stat.S_ISREG(status.st_mode) else "other")
                relative = Path(entry.path).relative_to(root).as_posix()
                entries[relative] = {"type": kind, "device": status.st_dev,
                                     "inode": status.st_ino}
                require(len(entries) <= WALK_ENTRIES, "storage listing exceeds its bound")
                if kind == "dir" and depth + 1 < WALK_DEPTH:
                    pending.append((Path(entry.path), depth + 1))
    return entries
