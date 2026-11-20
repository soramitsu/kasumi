"""Measure the namespace used by the permanent backup-session witness on its actual device."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import tempfile
import time
import uuid

from verify_release_acceptance import BACKUP_SESSION_FLOOR


def write(path, value):
    staged = path.with_suffix(".tmp")
    with staged.open("w") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    staged.replace(path)


def measure(directory, count, unit):
    # The session directory holds UUID names. Its objects directory must
    # also allow a cleanup that crosses the 256-object page boundary.
    sessions = directory / "sessions"
    sessions.mkdir()
    high = sessions.stat().st_blocks * 512
    for ordinal in range(1, count + 1):
        (sessions / str(uuid.UUID(int=ordinal))).mkdir()
        high = max(high, sessions.stat().st_blocks * 512)
    one = sessions / str(uuid.UUID(int=1))
    objects = one / "objects"
    objects.mkdir()
    for ordinal in range(1, 306):
        (objects / (str(uuid.UUID(int=ordinal)) + ".kasumi")).touch()
        high = max(high, objects.stat().st_blocks * 512)
    rows = []
    for size in (0, 1, 4095, 4096, 65536, 65537, 131072, 1 << 20, 2 << 20, 32 << 20):
        part = one / "part"
        data = os.urandom(min(65536, size))
        with part.open("xb") as stream:
            remaining = size
            while remaining:
                n = min(len(data), remaining)
                stream.write(data[:n])
                remaining -= n
            stream.flush()
            os.fsync(stream.fileno())
        terminal = one / "terminal"
        part.replace(terminal)
        allocated = terminal.stat().st_blocks * 512
        high = max(high, one.stat().st_blocks * 512)
        rounded = (size + unit - 1) // unit * unit
        rows.append(dict(logical=size, allocated=allocated, excess=max(0, allocated - rounded)))
        terminal.unlink()
    return high, rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new directory on the witness filesystem")
    parser.add_argument("--complete-interval", type=int, choices=range(2, 257), metavar="2..256",
                        help="complete every nth original session and abort the others before the two reserved kills")
    args = parser.parse_args()
    output = args.output
    output.mkdir(mode=0o700)
    start = time.monotonic()
    count = BACKUP_SESSION_FLOOR + 8
    fs = os.statvfs(output)
    unit = fs.f_frsize or fs.f_bsize
    receipt = dict(started=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   host=platform.uname()._asdict(), device=output.stat().st_dev, unit=unit,
                   status="running", namespace_entries=count, free_before=shutil.disk_usage(output).free,
                   limits={k: resource.getrlimit(getattr(resource, "RLIMIT_" + k))
                           for k in ("AS", "CPU", "FSIZE", "NOFILE", "STACK")})
    probe = output / "filesystem-probe.json"
    write(probe, receipt)
    try:
        with tempfile.TemporaryDirectory(dir=output) as private:
            high, rows = measure(Path(private), count, unit)
            excess = max(row["excess"] for row in rows)
            receipt.update(files=rows, max_observed_directory=high, max_observed_file_extra=excess,
                           fixture_directory_policy=dict(extent_bytes=max(16 * unit, 2 * high), max_entries=count),
                           fixture_file_policy=dict(maximum_extra_extent_bytes=max(4 * unit, 2 * excess)))
        receipt["status"] = "passed"
    except BaseException as error:
        receipt.update(status="failed", error=repr(error))
        raise
    finally:
        receipt.update(finished=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                       seconds=time.monotonic() - start, free_after=shutil.disk_usage(output).free)
        write(probe, receipt)
    profile = dict(device=receipt["device"], probe_sha256=hashlib.sha256(probe.read_bytes()).hexdigest(),
                   directory_policy=receipt["fixture_directory_policy"], file_allocation_policy=receipt["fixture_file_policy"],
                   max_persistent_files=1_000_000, max_persistent_subdirectories=216_386,
                   complete_interval=args.complete_interval)
    write(output / "session-profile.json", profile)


if __name__ == "__main__":
    main()
