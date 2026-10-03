"""Observe append/overwrite/truncate and full-sync allocation transitions.

This touches only owned temporary files. It does not alter Kasumi accounting.
F_FULLFSYNC=51 is from the installed macOS SDK sys/fcntl.h.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time


def extent(stat):
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_blocks * 512)


print(json.dumps({"script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}), flush=True)
cases = 0
changes = 0
with tempfile.TemporaryDirectory(prefix="kasumi-close-extent-v2-") as directory:
    for length in (139264, 385024):
        for mode in ("append", "prelength", "shrink", "overwrite"):
            for full in (False, True):
                path = Path(directory) / str(cases)
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
                sync = (lambda: fcntl.fcntl(fd, 51)) if full else (lambda: os.fsync(fd))
                if mode == "prelength":
                    os.ftruncate(fd, length)
                written_length = length + (65536 if mode == "shrink" else 0)
                for offset in range(0, written_length, 4096):
                    data = os.urandom(min(4096, written_length - offset))
                    assert os.pwrite(fd, data, offset) == len(data)
                    if offset % 16384 == 0:
                        sync()
                if mode == "shrink":
                    sync()
                    os.ftruncate(fd, length)
                if mode == "overwrite":
                    for round in range(16):
                        assert os.pwrite(fd, os.urandom(512), (round % 8) * 4096) == 512
                        sync()
                pre_sync = extent(os.fstat(fd))
                sync()
                post_sync = extent(os.fstat(fd))
                time.sleep(0.02)
                pre_close = extent(os.fstat(fd))
                os.close(fd)
                post_close = extent(path.stat())
                time.sleep(0.02)
                fd = os.open(path, os.O_RDONLY)
                reopened = extent(os.fstat(fd))
                os.close(fd)
                observations = [pre_sync, post_sync, pre_close, post_close, reopened]
                changed = any(value != post_sync for value in observations[2:])
                changes += changed
                print(json.dumps({"case": cases, "length": length, "mode": mode, "full_sync": full, "observations": observations, "post_sync_transition": changed}), flush=True)
                path.unlink()
                cases += 1
print(json.dumps({"cases": cases, "post_sync_transitions": changes, "kasumi_policy_changed": False}), flush=True)
