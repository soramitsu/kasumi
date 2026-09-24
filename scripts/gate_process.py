"""Bounded local gate execution with retained ownership of one process group."""
from __future__ import annotations

import os
import ctypes
import hashlib
import fcntl
import json
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import time

GROUP_LEDGER_ENV = "KASUMI_GROUP_LEDGER"
MAX_GROUP_LEDGER_BYTES = 65536


def _group_ledger_open(path):
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("process group ledger path is not absolute")
    flags = os.O_RDWR | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise ValueError("process group ledger is not a regular file")
    return descriptor


def _group_ledger_rows(descriptor):
    os.lseek(descriptor, 0, os.SEEK_SET)
    data = os.read(descriptor, MAX_GROUP_LEDGER_BYTES + 1)
    if len(data) > MAX_GROUP_LEDGER_BYTES or (data and not data.endswith(b"\n")):
        raise ValueError("process group ledger is oversized or truncated")
    rows = [json.loads(line) for line in data.splitlines()]
    groups = set()
    closed = False
    for row in rows:
        if not isinstance(row, dict) or row.get("schema") != 1:
            raise ValueError("invalid process group ledger row")
        if row.get("kind") == "group":
            if (closed or set(row) != {"schema", "kind", "group", "owner_pid", "executable_sha256", "leader_birth"}
                    or type(row["group"]) is not int or row["group"] <= 0
                    or type(row["owner_pid"]) is not int or row["owner_pid"] <= 0
                    or not isinstance(row["executable_sha256"], str)
                    or re.fullmatch(r"[0-9a-f]{64}", row["executable_sha256"]) is None
                    or (row["leader_birth"] is not None and
                        (not isinstance(row["leader_birth"], str) or
                         re.fullmatch(r"(?:linux:[0-9]+|darwin:[0-9]+:[0-9]+)", row["leader_birth"]) is None))
                    or row["group"] in groups):
                raise ValueError("duplicate, late, or malformed process group")
            groups.add(row["group"])
        elif row.get("kind") == "closed":
            if closed or set(row) != {"schema", "kind"}:
                raise ValueError("duplicate or malformed process group closure")
            closed = True
        else:
            raise ValueError("unknown process group ledger row")
    return rows, closed


def _group_ledger_append(descriptor, row):
    data = (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if os.write(descriptor, data) != len(data):
        raise OSError("short process group ledger write")
    os.fsync(descriptor)


def seal_group_ledger(path):
    """Close nested spawn admission under the same lock held across Popen."""
    descriptor = _group_ledger_open(path)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        rows, closed = _group_ledger_rows(descriptor)
        if closed:
            raise ValueError("process group ledger already closed")
        _group_ledger_append(descriptor, {"schema": 1, "kind": "closed"})
        return rows
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def read_group_ledger(path):
    descriptor = _group_ledger_open(path)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_SH)
        return _group_ledger_rows(descriptor)
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def executable_identity(command, source, environment):
    """Resolve once against the child's working directory and PATH.

    Preserve the invoked basename (Rustup uses it to select its tool). The
    observed hash follows the executable's symlink, but dispatch never performs
    a second PATH search that could select another binary.
    """
    if not command or not isinstance(command[0], str) or not command[0]:
        raise ValueError("gate executable is absent")
    source = Path(source).resolve(strict=True)
    if os.path.dirname(command[0]):
        selected = Path(command[0])
        if not selected.is_absolute():
            selected = source / selected
    else:
        search = os.pathsep.join(str(Path(entry) if Path(entry).is_absolute() else source / entry)
                                 for entry in environment.get("PATH", os.defpath).split(os.pathsep))
        found = shutil.which(command[0], path=search)
        if found is None:
            raise FileNotFoundError("gate executable was not found")
        selected = Path(found)
    selected = Path(os.path.abspath(selected))
    if not selected.is_file() or not os.access(selected, os.X_OK):
        raise ValueError("gate executable is not an executable regular file")
    with selected.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"path": str(selected), "sha256": digest}


class _DarwinBsdInfo(ctypes.Structure):
    """The SDK's proc_bsdinfo; proc_pidinfo provides microsecond start time."""
    _fields_ = [
        ("pbi_flags", ctypes.c_uint32), ("pbi_status", ctypes.c_uint32),
        ("pbi_xstatus", ctypes.c_uint32), ("pbi_pid", ctypes.c_uint32),
        ("pbi_ppid", ctypes.c_uint32), ("pbi_uid", ctypes.c_uint32),
        ("pbi_gid", ctypes.c_uint32), ("pbi_ruid", ctypes.c_uint32),
        ("pbi_rgid", ctypes.c_uint32), ("pbi_svuid", ctypes.c_uint32),
        ("pbi_svgid", ctypes.c_uint32), ("rfu_1", ctypes.c_uint32),
        ("pbi_comm", ctypes.c_char * 16), ("pbi_name", ctypes.c_char * 32),
        ("pbi_nfiles", ctypes.c_uint32), ("pbi_pgid", ctypes.c_uint32),
        ("pbi_pjobc", ctypes.c_uint32), ("e_tdev", ctypes.c_uint32),
        ("e_tpgid", ctypes.c_uint32), ("pbi_nice", ctypes.c_int32),
        ("pbi_start_tvsec", ctypes.c_uint64), ("pbi_start_tvusec", ctypes.c_uint64),
    ]


def leader_identity(pid):
    """Return a live process's group and birth witness, or None if unavailable.

    An unavailable witness must never authorize signalling a numeric PGID: it
    may already belong to another process group after the original exits.
    """
    if sys.platform.startswith("linux"):
        try:
            value = (Path("/proc") / str(pid) / "stat").read_text()
        except (FileNotFoundError, ProcessLookupError):
            return None
        fields = value.rsplit(")", 1)[1].split()
        return {"group": int(fields[2]), "birth": "linux:" + fields[19]}
    if sys.platform == "darwin":
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        library.proc_pidinfo.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                                         ctypes.c_void_p, ctypes.c_int)
        library.proc_pidinfo.restype = ctypes.c_int
        info = _DarwinBsdInfo()
        length = library.proc_pidinfo(pid, 3, 0, ctypes.byref(info), ctypes.sizeof(info))
        if length == 0:
            return None
        if length != ctypes.sizeof(info) or info.pbi_pid != pid:
            raise ValueError("incomplete process leader identity")
        return {"group": info.pbi_pgid,
                "birth": "darwin:" + str(info.pbi_start_tvsec) + ":" + str(info.pbi_start_tvusec)}
    raise RuntimeError("unsupported gate process platform")


def group_members(group):
    """A reaped leader does not imply that its process group has drained."""
    members = []
    if sys.platform.startswith("linux"):
        for directory in Path("/proc").iterdir():
            if not directory.name.isdecimal():
                continue
            try:
                value = (directory / "stat").read_text()
            except (FileNotFoundError, ProcessLookupError):
                continue
            # The command name may itself contain spaces or closing parentheses.
            fields = value.rsplit(")", 1)[1].split()
            if int(fields[2]) == group:
                members.append({"pid": int(directory.name), "ppid": int(fields[1]),
                                "group": group, "state": fields[0]})
    elif sys.platform == "darwin":
        listing = subprocess.check_output(
            ["ps", "-axo", "pid=,ppid=,pgid=,stat="], text=True, timeout=10)
        for line in listing.splitlines():
            fields = line.split()
            if len(fields) != 4:
                raise ValueError("malformed process inventory")
            if int(fields[2]) == group:
                members.append({"pid": int(fields[0]), "ppid": int(fields[1]),
                                "group": group, "state": fields[3]})
    else:
        raise RuntimeError("unsupported gate process platform")
    return sorted(members, key=lambda member: member["pid"])


def drain(process, grace_seconds=10):
    """Inspection uncertainty is retained but cannot skip owned termination."""
    record = {"group": process.pid, "before": None, "after": None,
              "signals": [], "errors": [], "drained": False}

    def inspect():
        try:
            return group_members(process.pid)
        except Exception as error:
            message = "process inspection: " + repr(error)
            if message not in record["errors"]:
                record["errors"].append(message)
            return None

    # The original deadline may expire before the first terminal poll. Reap an
    # already exited leader before deciding whether any owned process remains.
    process.poll()
    record["before"] = inspect()
    for number in (signal.SIGTERM, signal.SIGKILL):
        if inspect() == []:
            break
        # Even when inspection fails, Popen's original owned process group is
        # known. Attempt both signals; an unavailable inventory never means exit.
        try:
            os.killpg(process.pid, number)
            record["signals"].append(signal.Signals(number).name)
        except ProcessLookupError:
            pass
        except OSError as error:
            record["errors"].append(signal.Signals(number).name + ": " + repr(error))
        until = time.monotonic() + grace_seconds
        while time.monotonic() < until:
            process.poll()
            observed = inspect()
            if observed == [] or (observed is None and process.returncode is not None):
                break
            time.sleep(.05)
    process.poll()
    record["after"] = inspect()
    record["drained"] = record["after"] == [] and not record["errors"]
    record["process_returncode"] = process.returncode
    return record


def run(command, source, environment, stream, timeout_seconds, observe, *, stderr,
        before_cleanup=None, after_cleanup=None):
    """Record original command ownership before waiting; never raise in a handler.

    Commands in release_gate are local trusted builds/tests. This owns their
    process group, not independently daemonized processes or remote services.
    SIGKILL of this runner cannot execute cleanup; its running record retains
    the process group for explicit inspection by the enclosing environment.
    """
    if not 0 < timeout_seconds <= 86400:
        raise ValueError("gate timeout must be in (0, 86400] seconds")
    if stderr != subprocess.STDOUT and (not hasattr(stderr, "fileno") or not hasattr(stderr, "flush")):
        raise ValueError("gate stderr requires an explicit owned file or STDOUT")
    received = []

    def interrupted(number, _frame):
        received.append(number)

    previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
    process = None
    started = time.monotonic()
    record = {"status": "running", "command": command, "timeout_seconds": timeout_seconds,
              "working_directory": str(Path(source).resolve(strict=True)),
              "executable": None,
              "process_group": None, "leader_birth": None,
              "process_exit_code": None, "exit_code": None,
              "timed_out": False, "received_signals": received, "error": None, "cleanup": None}
    try:
        for number in previous:
            signal.signal(number, interrupted)
        observe(record)
        if not received:
            record["executable"] = executable_identity(command, source, environment)
            observe(record)
            ledger_path = os.environ.get(GROUP_LEDGER_ENV)
            ledger = None
            prior_mask = None
            try:
                if ledger_path is not None:
                    prior_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
                    ledger = _group_ledger_open(ledger_path)
                    fcntl.flock(ledger, fcntl.LOCK_EX)
                    _, closed = _group_ledger_rows(ledger)
                    if closed:
                        raise ValueError("nested process admission is closed")
                process = subprocess.Popen(command, cwd=source, env=environment,
                                           executable=record["executable"]["path"],
                                           stdout=stream, stderr=stderr,
                                           start_new_session=True)
                record["process_group"] = process.pid
                leader = leader_identity(process.pid)
                if leader is not None:
                    if leader["group"] != process.pid:
                        raise ValueError("spawned process did not own its group")
                    record["leader_birth"] = leader["birth"]
                if ledger is not None:
                    _group_ledger_append(ledger, {"schema": 1, "kind": "group", "group": process.pid,
                                                  "owner_pid": os.getpid(),
                                                  "executable_sha256": record["executable"]["sha256"],
                                                  "leader_birth": record["leader_birth"]})
            finally:
                if ledger is not None:
                    fcntl.flock(ledger, fcntl.LOCK_UN)
                    os.close(ledger)
                if prior_mask is not None:
                    signal.pthread_sigmask(signal.SIG_SETMASK, prior_mask)
            observe(record)
            while True:
                if received:
                    break
                if time.monotonic() - started >= timeout_seconds:
                    record["timed_out"] = True
                    break
                code = process.poll()
                if code is not None:
                    record["process_exit_code"] = code
                    record["exit_code"] = code
                    break
                time.sleep(.05)
    except BaseException as error:
        record["error"] = repr(error)
    finally:
        try:
            if before_cleanup is not None:
                try:
                    before_cleanup(record)
                except BaseException as error:
                    record["error"] = record["error"] or repr(error)
            if process is not None:
                record["cleanup"] = drain(process)
                record["process_exit_code"] = process.returncode
            else:
                record["cleanup"] = {"group": None, "before": [], "after": [],
                                     "signals": [], "errors": [], "drained": True}
            if after_cleanup is not None:
                try:
                    after_cleanup(record)
                except BaseException as error:
                    record["error"] = record["error"] or repr(error)
            cleanup = record["cleanup"]
            if record["executable"] is not None:
                try:
                    after = executable_identity([record["executable"]["path"]], source, environment)
                    if after != record["executable"]:
                        raise ValueError("gate executable changed during execution")
                except (OSError, ValueError) as error:
                    record["error"] = record["error"] or repr(error)
            if record["timed_out"]:
                record["exit_code"] = 124
            elif received:
                record["exit_code"] = 128 + received[0]
            elif record["error"] is not None or not cleanup["drained"] or cleanup["errors"] or cleanup["before"]:
                record["exit_code"] = 125
            record["status"] = "passed" if record["exit_code"] == 0 else "failed"
            record["duration_seconds"] = round(time.monotonic() - started, 3)
            stream.flush()
            os.fsync(stream.fileno())
            if stderr != subprocess.STDOUT:
                stderr.flush()
                os.fsync(stderr.fileno())
            observe(record)
        finally:
            for number, handler in previous.items():
                signal.signal(number, handler)
    return record
