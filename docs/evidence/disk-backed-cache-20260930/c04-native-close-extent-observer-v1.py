"""Observe raw native allocation at fsync/close without changing Kasumi policy."""
import hashlib
import json
import os
from pathlib import Path
import platform
import tempfile


def extent(stat):
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_blocks * 512)


print(json.dumps({"platform": platform.platform(), "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}), flush=True)
count = 0
changes = 0
with tempfile.TemporaryDirectory(prefix="kasumi-close-extent-observer-") as directory:
    for length in (139264, 385024, 434176):
        for chunk_size in (4096, 8192, 65536):
            for sync_each in (False, True):
                path = Path(directory) / f"case-{count}"
                descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
                data = bytes((index * 29 + 71) % 256 for index in range(chunk_size))
                offset = 0
                while offset < length:
                    part = data[: min(chunk_size, length - offset)]
                    written = os.pwrite(descriptor, part, offset)
                    assert written == len(part)
                    offset += written
                    if sync_each:
                        os.fsync(descriptor)
                before_sync = extent(os.fstat(descriptor))
                os.fsync(descriptor)
                before_close = extent(os.fstat(descriptor))
                os.close(descriptor)
                after_close = extent(path.stat())
                descriptor = os.open(path, os.O_RDONLY)
                after_reopen = extent(os.fstat(descriptor))
                digest = hashlib.sha256()
                while part := os.read(descriptor, 65536):
                    digest.update(part)
                os.close(descriptor)
                changed = before_sync != before_close or before_close != after_close or after_close != after_reopen
                changes += int(changed)
                print(json.dumps({"case": count, "length": length, "chunk": chunk_size, "sync_each": sync_each, "before_sync": before_sync, "before_close": before_close, "after_close": after_close, "after_reopen": after_reopen, "content_sha256": digest.hexdigest(), "changed": changed}), flush=True)
                count += 1
                path.unlink()
print(json.dumps({"cases": count, "allocation_transitions": changes, "kasumi_policy_changed": False}), flush=True)
