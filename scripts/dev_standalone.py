#!/usr/bin/env python3
"""Disposable loopback standalone Kasumi for development and integration tests.

  dev_standalone.py start DIRECTORY --base-port PORT [--bin-dir DIR] [--collection FILE]... [--allow-sleep]
  dev_standalone.py stop DIRECTORY [--remove]
  dev_standalone.py resume DIRECTORY [--bin-dir DIR] [--allow-sleep]

`start` creates DIRECTORY (it must not exist), checks that 127.0.0.1 ports
PORT (MCP), PORT+1 (native) and PORT+2 (admin) are free, initializes a
standalone installation listening on them and starts a detached supervisor.
The supervisor runs `kasumid serve` and one `kasumid credential watch` for
each client profile that init made: profiles/default.json, control.json,
operator.json and mcp.json. An MCP credential cannot renew itself, so the
mcp.json watcher also gets control.json, whose Control administrator renews
it. `start` waits for an authenticated
data read, creates each collection definition through the administrative
endpoint and reads the definitions back. It prints one JSON document: paths,
ports, process IDs and the profile's SHA-256 and database binding for
`kasumictl --expect-*`. If `start` fails, it stops what it started and
deletes DIRECTORY, after quoting the end of the server log in its error.
`stop` stops the supervisor, which interrupts the watchers and then
terminates the server. It then stops any recorded process that still runs
and, with --remove, deletes the directory. `resume` supervises an existing
DIRECTORY again, for example after `stop`, a reboot or a launch by an older
version of this script. It runs the kasumid that the state names, or with
--bin-dir that directory's kasumid from then on. A kasumid built before
9d686c0e never exits when its stores seal, so no restart can help it. `resume`
returns once `kasumid serve` has started. A large store can take many minutes
to reopen, so wait for an authenticated read before using it.

Restarts: kasumid exits non-zero when it cannot keep serving. For example,
if the host sleeps longer than the key-access leases (about a minute), every
store seals and kasumid logs `control_plane_closed` and exits. The supervisor
restarts a process that exits non-zero or is killed by a signal. The first
restart waits 1 s, each consecutive failure doubles the wait up to 5 min, and
a process that ran for 10 min starts again from 1 s. Each exit and restart is
one JSON line in DIRECTORY/supervisor.log, and dev-standalone.json records
the current process IDs and each process's last exit. A process that exits
with status 0 is not restarted. When `kasumid serve` exits with 0, the
supervisor stops the watchers and exits.

Keep-awake: on macOS the supervisor holds `caffeinate -i -s -w <its PID>`
while it runs. That prevents idle sleep, and system sleep on AC power.
Closing the lid on battery, or choosing Sleep, still sleeps the Mac. kasumid
then exits on wake and is restarted. Credentials expire after one hour. The
watchers recover the latest, unrevoked credential online within 24 hours of
expiry; older credentials need `kasumid recover-existing-credentials`
(docs/standalone.md). Pass --allow-sleep to
hold no assertion.

Credentials stay in owner-only files under DIRECTORY and are never printed or
passed as arguments. The processes' temporary files, including startup
diagnostics, also stay under DIRECTORY. The default profile is the read/write
application; operator.json administers the tenant. This is a development
installation, not a release deployment.
Failures go to stderr with exit status 1.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import subprocess
import sys
import time

STATE = "dev-standalone.json"
STATE_LOCK = "dev-standalone.lock"
SUPERVISOR_LOCK = "supervisor.lock"
MAX_JSON = 1 << 20
TENANT = "default"
CAFFEINATE = "/usr/bin/caffeinate"
# Restart backoff in seconds: the first restart waits RESTART_FIRST, each
# consecutive failure doubles the wait up to RESTART_CAP, and a run of
# RESTART_RESET seconds counts as healthy.
RESTART_FIRST = 1.0
RESTART_CAP = 300.0
RESTART_RESET = 600.0
# One `kasumid credential watch` per client profile: its process kind, the
# state key naming the profile, the profile's file name, the watcher's log, and
# the state key of the profile that renews it when it cannot renew itself. The
# administrative listener refuses an MCP-audience token, so the Control
# administrator renews it. The database profile always exists; the others are
# watched where init made them.
WATCHERS = (("watcher", "profile", "default.json", "credential.log", None),
            ("control_watcher", "control_profile", "control.json", "control-credential.log", None),
            ("operator_watcher", "operator_profile", "operator.json", "operator-credential.log", None),
            ("mcp_watcher", "mcp_profile", "mcp.json", "mcp-credential.log", "control_profile"))
WATCHER_KINDS = tuple(kind for kind, *_ in WATCHERS)
# The supervisor's processes, in stop order: watchers, server, keep-awake.
# `stop` signals the supervisor first, so that it restarts nothing.
CHILDREN = (*WATCHER_KINDS, "server")
RECORDED = ("supervisor", *CHILDREN)
STOP_SIGNAL = {"supervisor": signal.SIGTERM, "server": signal.SIGTERM, "keep_awake": signal.SIGTERM,
               **{kind: signal.SIGINT for kind in WATCHER_KINDS}}
# Seconds from the stop signal to SIGKILL. The supervisor's covers stopping
# its watchers, then its server, then caffeinate.
PATIENCE = {"server": 30, "keep_awake": 5, "supervisor": 60, **{kind: 10 for kind in WATCHER_KINDS}}
SCRIPT = Path(__file__).resolve()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def private_write(path, value):
    """Create a new owner-only JSON file; never replace or follow an existing one."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as output:
        json.dump(value, output, sort_keys=True)
        output.write("\n")


def read_json(path):
    with Path(path).open("rb") as source:
        data = source.read(MAX_JSON + 1)
    require(len(data) <= MAX_JSON, f"{path} exceeds its bounded input limit")
    return json.loads(data)


def ports(base):
    require(isinstance(base, int) and 1024 <= base <= 65533, "base port must be 1024 to 65533")
    return {"mcp": base, "native": base + 1, "admin": base + 2}


def require_free(selected):
    """Refuse ports that already have a loopback listener, before initializing."""
    for name, port in selected.items():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            # Like kasumid's listeners, ignore connections a stopped kasumid
            # left in TIME_WAIT; a live listener still refuses the bind.
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind(("127.0.0.1", port))
            except OSError as error:
                raise ValueError(f"{name} port {port} is not free: {error.strerror}") from None


def network(selected):
    return {
        "mcp_listen": f"127.0.0.1:{selected['mcp']}",
        "mcp_public_url": f"https://localhost:{selected['mcp']}/mcp",
        "native_listen": f"127.0.0.1:{selected['native']}",
        "admin_listen": f"127.0.0.1:{selected['admin']}",
    }


def admin_client(profile):
    """The administrative client configuration names the profile's token file."""
    require(len(profile["administrative_members"]) == 1, "expected one administrative member")
    member = next(iter(profile["administrative_members"].values()))
    return {
        "endpoint": member["endpoint"],
        "identity": profile["identity"],
        "server_ca": profile["server_ca"],
        "server_certificate_pins": sorted(member["certificate_pins"]),
        "token_file": profile["bearer_file"],
    }


def binding(profile_path):
    """The values `kasumictl --expect-*` compares; identifiers only, no secrets."""
    data = Path(profile_path).read_bytes()
    profile = json.loads(data)
    require(profile["resource"]["kind"] == "database", "profile is not a database credential")
    return {
        "profile_sha256": hashlib.sha256(data).hexdigest(),
        "tenant": profile["tenant"],
        "incarnation": profile["resource"]["incarnation"],
        "principal": profile["principal"],
        "family_id": profile["family_id"],
    }


def children(directory):
    """The environment for kasumid and kasumictl: temporary files stay inside."""
    return {**os.environ, "TMPDIR": str(directory / "tmp")}


def log_files(directory):
    return {"server": str(directory / "server.log"),
            "credential_watch": str(directory / "credential.log"),
            "control_credential_watch": str(directory / "control-credential.log"),
            "operator_credential_watch": str(directory / "operator-credential.log"),
            "mcp_credential_watch": str(directory / "mcp-credential.log"),
            "supervisor": str(directory / "supervisor.log")}


def run(command, **options):
    return subprocess.run([str(part) for part in command], stdin=subprocess.DEVNULL,
                          capture_output=True, timeout=120, **options)


def data(binaries, profile, *command, env=None):
    """One kasumictl data command; returns its exit status and JSON document."""
    result = run([binaries / "kasumictl", "--profile", profile, *command], env=env)
    try:
        return result.returncode, json.loads(result.stdout)
    except json.JSONDecodeError:
        return result.returncode, None


def command_line(pid):
    result = subprocess.run(["ps", "-ww", "-o", "command=", "-p", str(pid)], capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else None


def owned(pid, executable, argument):
    """Signal only a live process whose command line is the one this script started."""
    line = command_line(pid)
    # The executable is the first word, or follows the interpreter of a script.
    return line is not None and f" {executable} " in f" {line} " and str(argument) in line


def watched_profile(state, kind):
    """The profile a watcher of KIND renews: as recorded, else beside the database profile."""
    key, name = next((key, name) for watcher, key, name, *_ in WATCHERS if watcher == kind)
    return state.get(key) or str(Path(state["profile"]).with_name(name))


def recorded(state, kind, pid):
    """Whether PID's command line is still that of the process STATE records as KIND."""
    if kind == "supervisor":
        line = command_line(pid)
        return line is not None and line.endswith(f"{SCRIPT.name} supervise {state['directory']}")
    argument = state["configuration"] if kind == "server" else watched_profile(state, kind)
    return owned(pid, state["kasumid"], argument)


def alive(pid):
    # An exited child of this process is a zombie until reaped; reap it here
    # rather than count it as running. Other processes raise ChildProcessError.
    with contextlib.suppress(ChildProcessError):
        if os.waitpid(pid, os.WNOHANG)[0] == pid:
            return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def stop_process(entry, kind, wait):
    pid = entry.get(kind)
    if pid is None:
        return "absent"
    if not alive(pid):
        return "exited"
    if not recorded(entry, kind, pid):
        return "not_owned"
    os.kill(pid, STOP_SIGNAL[kind])
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        if not alive(pid):
            return "stopped"
        time.sleep(0.1)
    os.kill(pid, signal.SIGKILL)
    return "killed"


def stop_child(process, kind, wait):
    """Stop and reap a process this invocation started and still holds."""
    if process is None:
        return "absent"
    if process.poll() is not None:
        return "exited"
    process.send_signal(STOP_SIGNAL[kind])
    try:
        process.wait(timeout=wait)
        return "stopped"
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        return "killed"


def log_tail(path, limit=2000):
    """The end of a process log, which holds no credentials, for an error."""
    try:
        with Path(path).open("rb") as log:
            log.seek(0, os.SEEK_END)
            log.seek(max(0, log.tell() - limit))
            return log.read().decode(errors="replace").strip()
    except OSError:
        return ""


@contextlib.contextmanager
def state_lock(directory):
    """Serialize state writers: `start`, `resume` and the supervisor."""
    descriptor = os.open(directory / STATE_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def write_state(directory, state):
    """Replace the state file; the caller holds the state lock."""
    temporary = directory / (STATE + ".pending")
    with contextlib.suppress(FileNotFoundError):
        temporary.unlink()  # Left by a writer that died; the lock excludes live ones.
    private_write(temporary, state)
    os.replace(temporary, directory / STATE)


def save(directory, state):
    with state_lock(directory):
        write_state(directory, state)


def update_state(directory, changes):
    """Merge CHANGES into the state file and return the result."""
    with state_lock(directory):
        state = read_json(directory / STATE)
        state.update(changes)
        write_state(directory, state)
    return state


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def exit_status(returncode):
    if returncode < 0:
        try:
            return f"signal {signal.Signals(-returncode).name}"
        except ValueError:
            return f"signal {-returncode}"
    return f"exit status {returncode}"


def restart_delay(failures):
    """Seconds before restarting a process after FAILURES (at least 1) consecutive failed runs."""
    return min(RESTART_FIRST * 2 ** min(failures - 1, 20), RESTART_CAP)


def keep_awake_available():
    return sys.platform == "darwin" and os.access(CAFFEINATE, os.X_OK)


def announce(level, message, **fields):
    """One supervisor.log line, shaped like kasumid's JSON log lines."""
    sys.stderr.write(json.dumps({"timestamp": utc_now(), "level": level,
                                 "fields": {"message": message, **fields},
                                 "target": "dev_standalone::supervisor"}) + "\n")
    sys.stderr.flush()


class Supervised:
    """One process a supervisor keeps running, and its restart schedule."""

    def __init__(self, kind, command, log):
        self.kind = kind
        self.command = [str(part) for part in command]
        self.log = log  # Its output file, or None to discard its output.
        self.process = None
        self.started = 0.0
        self.starts = 0
        self.failures = 0  # Consecutive failed runs.
        self.due = 0.0  # time.monotonic() of its next start; None after a clean exit.


def supervised(state, directory, supervisor_pid):
    """The processes the supervisor of STATE runs, in start order."""
    kasumid = state["kasumid"]
    entries = []
    if state.get("keep_awake", True) and keep_awake_available():
        # -i prevents idle sleep; -s prevents system sleep on AC power. -w
        # releases the assertion when the supervisor exits, even if killed.
        entries.append(Supervised("keep_awake", [CAFFEINATE, "-i", "-s", "-w", supervisor_pid], None))
    entries.append(Supervised("server", [kasumid, "serve", state["configuration"]], directory / "server.log"))
    for kind, key, _, log, renewer in WATCHERS:
        if state.get(key) and (renewer is None or state.get(renewer)):
            renewing = [] if renewer is None else [state[renewer]]
            entries.append(Supervised(kind, [kasumid, "credential", "watch", state[key], *renewing],
                                      directory / log))
    return entries


class Supervisor:
    """Restart DIRECTORY's processes after failures until SIGTERM or SIGINT."""

    def __init__(self, directory, state):
        self.directory = directory
        self.processes = supervised(state, directory, os.getpid())
        self.keep_awake = ("held" if any(entry.kind == "keep_awake" for entry in self.processes)
                           else "disabled" if not state.get("keep_awake", True) else "unavailable")
        self.stopping = None

    def request_stop(self, signum, frame):
        if self.stopping is None:
            self.stopping = signal.Signals(signum).name

    def record(self, changes, exited=None):
        """Merge CHANGES into the state file; a failed write is logged, not fatal."""
        try:
            with state_lock(self.directory):
                state = read_json(self.directory / STATE)
                state.update(changes)
                if exited is not None:
                    kind, status = exited
                    state.setdefault("last_exit", {})[kind] = {"status": status, "at": utc_now()}
                write_state(self.directory, state)
        except (OSError, ValueError) as error:
            announce("WARN", "could not update the state file", error=str(error))

    def schedule(self, entry):
        """Back off before the next start after a failed run or start."""
        entry.failures += 1
        delay = restart_delay(entry.failures)
        entry.due = time.monotonic() + delay
        return delay

    def launch(self, entry):
        try:
            if entry.log is None:
                entry.process = subprocess.Popen(entry.command, stdin=subprocess.DEVNULL,
                                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                with open(entry.log, "ab") as log:
                    entry.process = subprocess.Popen(entry.command, stdin=subprocess.DEVNULL,
                                                     stdout=log, stderr=log)
        except OSError as error:
            delay = self.schedule(entry)
            announce("ERROR", "could not start supervised process; retrying", process=entry.kind,
                     error=str(error), restart_in_seconds=delay, consecutive_failures=entry.failures)
            return
        entry.started = time.monotonic()
        entry.due = None
        entry.starts += 1
        if entry.kind in CHILDREN:
            self.record({entry.kind: entry.process.pid})
        announce("INFO", "supervised process started" if entry.starts == 1 else "supervised process restarted",
                 process=entry.kind, pid=entry.process.pid, starts=entry.starts)

    def reap(self):
        for entry in self.processes:
            if entry.process is None or entry.process.poll() is None:
                continue
            pid, returncode = entry.process.pid, entry.process.returncode
            ran = round(time.monotonic() - entry.started, 1)
            entry.process = None
            if entry.kind in CHILDREN:
                self.record({entry.kind: None}, exited=(entry.kind, exit_status(returncode)))
            if self.stopping is not None:
                announce("INFO", "supervised process exited while stopping", process=entry.kind, pid=pid,
                         status=exit_status(returncode), ran_seconds=ran)
                continue
            # caffeinate -w exits by itself only once the supervisor has exited.
            if returncode == 0 and entry.kind != "keep_awake":
                entry.due = None
                announce("INFO", "supervised process exited cleanly; not restarting", process=entry.kind,
                         pid=pid, ran_seconds=ran)
                if entry.kind == "server":
                    self.stopping = "kasumid serve exited cleanly"
                continue
            if ran >= RESTART_RESET:
                entry.failures = 0
            delay = self.schedule(entry)
            announce("WARN", "supervised process exited; restarting", process=entry.kind, pid=pid,
                     status=exit_status(returncode), ran_seconds=ran, restart_in_seconds=delay,
                     consecutive_failures=entry.failures)

    def timeout(self):
        """Seconds until the next scheduled start, or None to wait for a signal."""
        due = [entry.due for entry in self.processes if entry.process is None and entry.due is not None]
        return max(0.0, min(due) - time.monotonic()) if due else None

    def run(self):
        # Every child exit (SIGCHLD) and stop request wakes the select below
        # through this pipe, without polling.
        reader, writer = os.pipe()
        os.set_blocking(reader, False)
        os.set_blocking(writer, False)
        signal.set_wakeup_fd(writer)
        signal.signal(signal.SIGCHLD, lambda signum, frame: None)
        signal.signal(signal.SIGTERM, self.request_stop)
        signal.signal(signal.SIGINT, self.request_stop)
        self.record({"supervisor": os.getpid(), "last_exit": {}, **{kind: None for kind in CHILDREN}})
        announce("INFO", "supervisor started", pid=os.getpid(), keep_awake=self.keep_awake)
        try:
            while True:
                self.reap()
                if self.stopping is not None:
                    break
                now = time.monotonic()
                for entry in self.processes:
                    if entry.process is None and entry.due is not None and entry.due <= now:
                        self.launch(entry)
                select.select([reader], [], [], self.timeout())
                with contextlib.suppress(BlockingIOError):
                    while os.read(reader, 512):
                        pass
        except Exception as error:
            # Leave the processes running, unsupervised, as before this script
            # supervised them: `stop` still finds them in the state file.
            announce("ERROR", "supervisor failed; its processes keep running unsupervised",
                     error=f"{type(error).__name__}: {error}")
            raise
        self.shutdown()

    def shutdown(self):
        announce("INFO", "supervisor stopping", reason=self.stopping)
        for group in (WATCHER_KINDS, ("server",), ("keep_awake",)):
            running = [entry for entry in self.processes if entry.kind in group and entry.process is not None]
            for entry in running:
                entry.process.send_signal(STOP_SIGNAL[entry.kind])
            deadline = time.monotonic() + max((PATIENCE[entry.kind] for entry in running), default=0)
            for entry in running:
                try:
                    entry.process.wait(timeout=max(0.0, deadline - time.monotonic()))
                    outcome = "stopped"
                except subprocess.TimeoutExpired:
                    entry.process.kill()
                    entry.process.wait()
                    outcome = "killed"
                announce("INFO", "supervised process stopped", process=entry.kind, pid=entry.process.pid,
                         outcome=outcome, status=exit_status(entry.process.returncode))
                entry.process = None
        self.record({"supervisor": None, **{kind: None for kind in CHILDREN}})
        announce("INFO", "supervisor stopped")


def supervise(arguments):
    os.umask(0o077)
    directory = Path(arguments.directory)
    state = read_json(directory / STATE)
    require(state.get("directory") == str(directory), "state file belongs to another directory")
    # Held for the supervisor's life and released by the kernel however it
    # ends; not inherited by its processes.
    lock = os.open(directory / SUPERVISOR_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise ValueError(f"another supervisor runs for {directory}") from None
    Supervisor(directory, state).run()


def launch_supervisor(directory):
    """Start DIRECTORY's supervisor in a session of its own; it outlives this command."""
    with (directory / "supervisor.log").open("ab") as log:
        # No descriptor of this command's stdout or stderr reaches the
        # supervisor, so a caller capturing them sees them close.
        return subprocess.Popen([sys.executable, str(SCRIPT), "supervise", str(directory)],
                                stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                start_new_session=True, env=children(directory))


def require_supervising(directory, supervisor):
    """Fail if the supervisor, or the kasumid serve it started, has exited."""
    if supervisor.poll() is not None:
        raise ValueError("the supervisor exited; supervisor.log ends:\n"
                         + log_tail(directory / "supervisor.log", 1000))
    exited = read_json(directory / STATE).get("last_exit", {}).get("server")
    if exited is not None:
        raise ValueError(f"kasumid serve exited with {exited['status']}; see server.log")


def abandon(directory, supervisor):
    """Stop what a failed start or resume launched."""
    if supervisor is not None:
        stop_child(supervisor, "supervisor", PATIENCE["supervisor"])
    # The supervisor stops its own processes; these remain only if it had to be killed.
    with contextlib.suppress(OSError, ValueError, KeyError):
        state = read_json(directory / STATE)
        for kind in CHILDREN:
            stop_process(state, kind, PATIENCE[kind])


def start(arguments):
    os.umask(0o077)
    directory = Path(arguments.directory)
    require(directory.is_absolute(), "directory must be absolute")
    require(directory.parent.is_dir(), "the directory's parent must exist")
    binaries = Path(arguments.bin_dir).resolve()
    for binary in ("kasumid", "kasumictl"):
        require(os.access(binaries / binary, os.X_OK), f"{binaries / binary} is not executable")
    definitions = [Path(path).resolve() for path in arguments.collection]
    names = [read_json(path)["name"] for path in definitions]
    require(len(set(names)) == len(names), "collection names must be unique")
    selected = ports(arguments.base_port)
    require_free(selected)
    directory.mkdir(mode=0o700)
    (directory / "tmp").mkdir(mode=0o700)
    environment = children(directory)
    installation = directory / "installation"
    state = {"directory": str(directory), "kasumid": str(binaries / "kasumid"),
             "configuration": str(installation / "kasumi.json"),
             "profile": str(installation / "profiles/default.json"),
             "keep_awake": not arguments.allow_sleep, "logs": log_files(directory)}
    save(directory, state)
    # This invocation's own handle on the supervisor, so a failed start reaps
    # it instead of judging an exited supervisor's zombie by its process ID.
    supervisor = None
    try:
        inputs = {
            "directory-policy": {"extent_bytes": 10485760, "max_entries": 32768},
            "file-allocation-policy": {"maximum_extra_extent_bytes": 1048576},
            "network": network(selected),
            "tenant-audit-placements": {"__kasumi_control": {"kind": "local_replica_only"},
                                        TENANT: {"kind": "local_replica_only"}},
        }
        for name, value in inputs.items():
            private_write(directory / f"{name}.json", value)
        init = run([binaries / "kasumid", "init", "--mode", "standalone", installation,
                    *[part for name in inputs for part in (f"--{name}", directory / f"{name}.json")],
                    "--tenant", TENANT], env=environment)
        require(init.returncode == 0, "kasumid init failed: " + init.stderr.decode(errors="replace")[-2000:])
        profile = Path(state["profile"])
        update_state(directory, {key: str(installation / "profiles" / name) for _, key, name, *_ in WATCHERS[1:]
                                 if (installation / "profiles" / name).exists()})
        supervisor = launch_supervisor(directory)
        update_state(directory, {"supervisor": supervisor.pid})
        deadline = time.monotonic() + arguments.ready_timeout
        while True:
            require_supervising(directory, supervisor)
            status, document = data(binaries, profile, "collections", env=environment)
            if status == 0 and document and document.get("ok"):
                break
            require(time.monotonic() < deadline, f"no authenticated data read before the deadline: {document}")
            time.sleep(0.25)
        admin = directory / "admin-client.json"
        private_write(admin, admin_client(read_json(profile.with_name("operator.json"))))
        for definition in definitions:
            created = run([binaries / "kasumictl", "--config", admin, "create-collection", definition],
                          env=environment)
            require(created.returncode == 0,
                    f"create-collection {definition} failed: " + created.stderr.decode(errors="replace")[-2000:])
        status, document = data(binaries, profile, "collections", env=environment)
        require(status == 0, f"collection readback failed: {document}")
        installed = {entry["name"]: entry for entry in document["result"]["collections"]}
        for name, definition in zip(names, definitions):
            expected = read_json(definition)
            expected.setdefault("indexes", [])
            expected.setdefault("strict_read_audit", False)
            require(installed.get(name) == expected, f"collection {name} reads back differently")
        state = update_state(directory, {
            "ports": selected,
            "endpoints": {"native": f"https://localhost:{selected['native']}",
                          "admin": f"https://localhost:{selected['admin']}",
                          "mcp": network(selected)["mcp_public_url"]},
            "admin_client": str(admin),
            "binding": binding(profile),
            "collections": names,
        })
    except BaseException as error:
        abandon(directory, supervisor)
        tail = log_tail(directory / "server.log")
        # The directory holds keys and tokens, and nothing started here still runs.
        shutil.rmtree(directory)
        if isinstance(error, ValueError) and tail:
            raise ValueError(f"{error}\nserver.log ends:\n{tail}") from error
        raise
    return state


def load_state(directory):
    require(directory.is_absolute(), "directory must be absolute")
    state = read_json(directory / STATE)
    require(state.get("directory") == str(directory), "state file belongs to another directory")
    return state


def stop(arguments):
    directory = Path(arguments.directory)
    state = load_state(directory)
    running = [kind for kind in RECORDED if state.get(kind) is not None and alive(state[kind])]
    strangers = [kind for kind in running if not recorded(state, kind, state[kind])]
    require(not strangers, f"refusing to signal processes this script did not start: {strangers}")
    result = {"directory": str(directory), "supervisor": stop_process(state, "supervisor", PATIENCE["supervisor"])}
    # A supervisor stops its own processes and clears them; any left (for
    # example after it was killed) are stopped here.
    latest = read_json(directory / STATE)
    for kind in CHILDREN:
        outcome = stop_process({**latest, kind: latest.get(kind) or state.get(kind)}, kind, PATIENCE[kind])
        result[kind] = "stopped" if outcome in ("absent", "exited") and kind in running else outcome
    require("not_owned" not in result.values(), f"refusing to signal processes this script did not start: {result}")
    if arguments.remove:
        shutil.rmtree(directory)
    result["removed"] = arguments.remove
    return result


def resume(arguments):
    os.umask(0o077)
    directory = Path(arguments.directory)
    state = load_state(directory)
    changes = {"keep_awake": not arguments.allow_sleep, "logs": {**state.get("logs", {}), **log_files(directory)},
               "last_exit": {}, **{kind: None for kind in RECORDED}}
    if arguments.bin_dir is not None:
        kasumid = Path(arguments.bin_dir).resolve() / "kasumid"
        require(os.access(kasumid, os.X_OK), f"{kasumid} is not executable")
        changes["kasumid"] = str(kasumid)
    running = [kind for kind in RECORDED
               if state.get(kind) is not None and alive(state[kind]) and recorded(state, kind, state[kind])]
    require(not running, f"{', '.join(running)} still running; stop {directory} first")
    if "ports" in state:
        require_free(state["ports"])  # Held by an unrecorded kasumid, for example.
    for kind, key, *_ in WATCHERS[1:]:
        if Path(watched_profile(state, kind)).exists():
            changes[key] = watched_profile(state, kind)
    update_state(directory, changes)
    supervisor = None
    try:
        supervisor = launch_supervisor(directory)
        update_state(directory, {"supervisor": supervisor.pid})
        deadline = time.monotonic() + 60
        while True:
            require_supervising(directory, supervisor)
            current = read_json(directory / STATE)
            if current.get("server") is not None:
                return current
            require(time.monotonic() < deadline, "the supervisor did not start kasumid serve; see supervisor.log")
            time.sleep(0.1)
    except BaseException as error:
        abandon(directory, supervisor)
        tail = log_tail(directory / "server.log")
        if isinstance(error, ValueError) and tail:
            raise ValueError(f"{error}\nserver.log ends:\n{tail}") from error
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    starting = commands.add_parser("start", help="create, initialize and start a supervised instance")
    starting.add_argument("directory")
    starting.add_argument("--base-port", type=int, required=True)
    starting.add_argument("--bin-dir", default=str(Path(__file__).resolve().parent.parent / "target/debug"))
    starting.add_argument("--collection", action="append", default=[])
    starting.add_argument("--ready-timeout", type=float, default=60)
    starting.add_argument("--allow-sleep", action="store_true", help="hold no keep-awake assertion")
    stopping = commands.add_parser("stop", help="stop the supervisor and every recorded process")
    stopping.add_argument("directory")
    stopping.add_argument("--remove", action="store_true")
    resuming = commands.add_parser("resume", help="supervise an existing, stopped instance again")
    resuming.add_argument("directory")
    resuming.add_argument("--bin-dir", help="run this directory's kasumid from now on")
    resuming.add_argument("--allow-sleep", action="store_true", help="hold no keep-awake assertion")
    supervising = commands.add_parser("supervise", help="run by start and resume; logs to supervisor.log")
    supervising.add_argument("directory")
    arguments = parser.parse_args(argv)
    handlers = {"start": start, "stop": stop, "resume": resume, "supervise": supervise}
    try:
        result = handlers[arguments.command](arguments)
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        print(f"dev_standalone: {error}", file=sys.stderr)
        return 1
    if result is not None:
        print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
