"""Bounded local gate execution with retained ownership of one process group."""
from __future__ import annotations

import os
import hashlib
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time


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


def run(command, source, environment, stream, timeout_seconds, observe, *, stderr):
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
              "process_group": None, "process_exit_code": None, "exit_code": None,
              "timed_out": False, "received_signals": received, "error": None, "cleanup": None}
    try:
        for number in previous:
            signal.signal(number, interrupted)
        observe(record)
        if not received:
            record["executable"] = executable_identity(command, source, environment)
            observe(record)
            process = subprocess.Popen(command, cwd=source, env=environment,
                                       executable=record["executable"]["path"],
                                       stdout=stream, stderr=stderr,
                                       start_new_session=True)
            record["process_group"] = process.pid
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
            if process is not None:
                record["cleanup"] = drain(process)
                record["process_exit_code"] = process.returncode
            else:
                record["cleanup"] = {"group": None, "before": [], "after": [],
                                     "signals": [], "errors": [], "drained": True}
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
