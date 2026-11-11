#!/usr/bin/env python3
"""Size of a sorted row stream if sorted-run blocks used Zstandard.

Reads the raw stream that `kasumi-live-transfer export-read-only DIRECTORY`
writes on stdin, checks its trailer, cuts the rows into the writer's canonical
blocks (at most 32 KiB, a larger row alone) and compresses every block on its
own, as a sorted run does. Compare the totals with the database's allocated
bytes. This measures payload blocks only: directories, level indexes, filters
and the WAL are the same under either codec. Nothing is written.

    kasumi-live-transfer export-read-only DIRECTORY \\
        | python3 benchmarks/indexer-kv/codec-probe.py --levels 7

The writer uses level 7 and also prefix-codes keys where that helps, so the
blocks of a real `kasumi-live-transfer import NEW_DIRECTORY zstd` are usually a
little smaller than this figure.

Needs Python 3.14 or newer for the standard library's `compression.zstd`.
"""

import argparse
import hashlib
import json
import struct
import sys

BLOCK_TARGET = 32 << 10
ROW_HEADER = 6


def read_exact(stream, length):
    data = stream.read(length)
    if len(data) != length:
        raise SystemExit("truncated raw stream")
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--levels", default="7", help="Zstandard levels, comma separated")
    arguments = parser.parse_args()
    levels = [int(level) for level in arguments.levels.split(",")]
    try:
        from compression import zstd
    except ImportError:
        raise SystemExit("compression.zstd requires Python 3.14 or newer")

    stream = sys.stdin.buffer
    if read_exact(stream, 8) != b"KSRKRAW1":
        raise SystemExit("not a KSRKRAW1 stream")
    digest = hashlib.sha256()
    rows = logical = canonical = blocks = 0
    packed = dict.fromkeys(levels, 0)
    block = bytearray()

    def flush():
        nonlocal blocks, canonical
        if block:
            blocks += 1
            canonical += len(block)
            for level in levels:
                packed[level] += len(zstd.compress(bytes(block), level=level))
            block.clear()

    while True:
        prefix = read_exact(stream, 4)
        (key_length,) = struct.unpack(">I", prefix)
        if key_length == 0xFFFFFFFF:
            break
        key = read_exact(stream, key_length)
        value_prefix = read_exact(stream, 4)
        (value_length,) = struct.unpack(">I", value_prefix)
        value = read_exact(stream, value_length)
        for part in (prefix, key, value_prefix, value):
            digest.update(part)
        record = ROW_HEADER + key_length + value_length
        if block and len(block) + record > BLOCK_TARGET:
            flush()
        block += struct.pack("<HI", key_length, value_length) + key + value
        rows += 1
        logical += key_length + value_length
    flush()
    count, total = struct.unpack(">QQ", read_exact(stream, 16))
    if (count, total) != (rows, logical) or read_exact(stream, 32) != digest.digest():
        raise SystemExit("raw stream trailer differs from its rows")
    if stream.read(1):
        raise SystemExit("data follows the raw stream trailer")
    json.dump(
        {
            "rows": rows,
            "blocks": blocks,
            "logical_bytes": logical,
            "canonical_block_bytes": canonical,
            "zstd_block_bytes": {str(level): packed[level] for level in levels},
        },
        sys.stdout,
        indent=2,
    )
    print()


if __name__ == "__main__":
    main()
