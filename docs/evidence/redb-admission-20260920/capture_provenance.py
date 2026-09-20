#!/usr/bin/env python3
"""Verify the two authoritative archives and inventory the standalone fork."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import tarfile


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def archive_files(path, expected, prefix):
    assert sha256(path.read_bytes()) == expected, f"archive checksum mismatch: {path}"
    with tarfile.open(path) as archive:
        return {
            member.name.removeprefix(prefix): archive.extractfile(member).read()
            for member in archive.getmembers()
            if member.isfile() and member.name.startswith(prefix)
        }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("published_crate", type=Path)
    parser.add_argument("upstream_archive", type=Path)
    args = parser.parse_args()
    evidence = Path(__file__).resolve().parent
    repository = evidence.parents[2]
    vendor = repository / "vendor/redb-4.2.0"
    crate_sha = "de6c3b63e007e90ce536ec2ae4690826136a20ec8dbbbb400daef1bb999d2e36"
    upstream_sha = "3aabc11f3779daebfc463b077e4c63779c384adb4ea3a4a947f03ac3cc6a244f"
    upstream_commit = "23b6ba05473b13e69ed4db82f4b5bc07f0c33be9"
    original = archive_files(args.published_crate, crate_sha, "redb-4.2.0/")
    companion = archive_files(
        args.upstream_archive,
        upstream_sha,
        f"redb-{upstream_commit}/crates/redb-derive/",
    )
    current = {
        str(path.relative_to(vendor)): path.read_bytes()
        for path in sorted(vendor.rglob("*"))
        if path.is_file()
    }
    records = []
    differences = []
    for name in sorted(original.keys() | current.keys()):
        before, after = original.get(name), current.get(name)
        status = "unchanged" if before == after else "modified"
        if before is None:
            status = "added"
        elif after is None:
            status = "removed"
        record = {
            "path": name,
            "status": status,
            "published_sha256": sha256(before) if before is not None else None,
            "fork_sha256": sha256(after) if after is not None else None,
        }
        companion_name = name.removeprefix("crates/redb-derive/")
        if name.startswith("crates/redb-derive/") and companion_name in companion:
            record["upstream_companion_sha256"] = sha256(companion[companion_name])
        records.append(record)
        if status != "unchanged":
            differences.extend(
                difflib.unified_diff(
                    (before or b"").decode().splitlines(keepends=True),
                    (after or b"").decode().splitlines(keepends=True),
                    fromfile=f"published/redb-4.2.0/{name}" if before is not None else "/dev/null",
                    tofile=f"fork/redb-4.2.0/{name}" if after is not None else "/dev/null",
                )
            )
    metadata = {
        "published_crate_sha256": crate_sha,
        "published_crate_url": "https://static.crates.io/crates/redb/redb-4.2.0.crate",
        "upstream_commit": upstream_commit,
        "companion_archive_sha256": upstream_sha,
        "companion_archive_url": f"https://codeload.github.com/cberner/redb/tar.gz/{upstream_commit}",
        "files": records,
    }
    (evidence / "provenance.json").write_text(json.dumps(metadata, indent=2) + "\n")
    (evidence / "published-to-fork.patch").write_text("".join(differences))
    print(f"Verified {len(original)} published files and {len(companion)} companion files")
    print(f"Inventoried {len(current)} fork files")


if __name__ == "__main__":
    main()
