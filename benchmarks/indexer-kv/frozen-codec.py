"""Run the upstream codec controls against one sealed snapshot of a Polkaswap trace.

Compile frozen-codec.cc with a C++20 compiler and an LZ4-enabled RocksDB.
Run python3 frozen-codec.py /path/to/frozen-codec /path/to/trace.jsonl [read_rounds].
"""
import gzip
import hashlib
import json
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile


def framed(data):
    return struct.pack(">I", len(data)) + data


def footprint(directory):
    totals = {"allocated": 0, "apparent": 0, "files": 0,
              "sst_allocated": 0, "sst_apparent": 0, "sst_files": 0}
    for path in directory.rglob("*"):
        st = path.lstat()
        if stat.S_ISDIR(st.st_mode):
            continue
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"unexpected database entry {path}")
        totals["files"] += 1
        totals["apparent"] += st.st_size
        totals["allocated"] += st.st_blocks * 512
        if path.suffix == ".sst":
            totals["sst_files"] += 1
            totals["sst_apparent"] += st.st_size
            totals["sst_allocated"] += st.st_blocks * 512
    return totals


def read_trace(source):
    state = {}
    for line in source.splitlines():
        ops = json.loads(line)["ops"]
        if not ops:
            raise ValueError("empty batch")
        for op in ops:
            key = bytes.fromhex(op[1])
            if not key or key.hex() != op[1]:
                raise ValueError("expected nonempty lower-case hex key")
            if len(op) == 3 and op[0] == "put":
                value = bytes.fromhex(op[2])
                if value.hex() != op[2]:
                    raise ValueError("expected lower-case hex value")
                state[key] = value
            elif len(op) == 2 and op[0] == "del":
                state.pop(key, None)
            else:
                raise ValueError("invalid trace operation")
    if not state:
        raise ValueError("empty final state")
    return state


def main():
    if len(sys.argv) not in (3, 4):
        raise SystemExit("usage: frozen-codec.py NATIVE_BINARY TRACE_JSONL_OR_GZ [READ_ROUNDS]")
    worker = str(Path(sys.argv[1]).resolve(strict=True))
    trace = Path(sys.argv[2])
    rounds = int(sys.argv[3]) if len(sys.argv) == 4 else 3
    if not 1 <= rounds <= 100:
        raise ValueError("expected 1-100 rounds")
    data = trace.read_bytes()
    if trace.suffix == ".gz":
        data = gzip.decompress(data)
    state = read_trace(data)
    rows = sorted(state)
    block_prefix = b"x\0networkSnapshots\0y-t\0BLOCK\0"
    state_digest = hashlib.sha256()
    page_digest = hashlib.sha256()
    page_keys = [k for k in reversed(rows) if k.startswith(block_prefix)][:24]
    for key in reversed(rows):
        state_digest.update(framed(key) + framed(state[key]))
    for index in page_keys:
        key = b"d\0networkSnapshots\0" + index.rsplit(b"\0", 1)[1]
        page_digest.update(framed(key) + framed(state[key]))
    output = {"trace_sha256": hashlib.sha256(data).hexdigest(),
              "state_sha256": state_digest.hexdigest(), "page_sha256": page_digest.hexdigest(),
              "rows": len(rows), "documents_per_page": len(page_keys), "controls": {}}
    with tempfile.TemporaryDirectory(prefix="kasumi-rocks-codec-") as tmp:
        root = Path(tmp)
        reference = root / "sorted.bin"
        with reference.open("xb") as f:
            for key in rows:
                f.write(framed(key))
                f.write(framed(state[key]))

        def run(codec, phase):
            db = root / codec
            result = subprocess.run([worker, phase, str(reference), str(db), codec],
                                    check=True, stdout=subprocess.PIPE)
            metrics = json.loads(result.stdout)
            if metrics["rows"] != len(rows):
                raise ValueError("reference size differs")
            if phase == "read" and (metrics["verified_rows"] != len(rows) or
                                    metrics["documents_per_page"] != len(page_keys)):
                raise ValueError("reopened state differs")
            metrics["footprint"] = footprint(db)
            return metrics

        codecs = ("none", "lz4", "lz4_32k")
        for codec in codecs:
            output["controls"][codec] = {"sealed": run(codec, "write"), "reads": []}
        for i in range(rounds):
            start = i % len(codecs)
            for codec in codecs[start:] + codecs[:start]:
                output["controls"][codec]["reads"].append(run(codec, "read"))
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
