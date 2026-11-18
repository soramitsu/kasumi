#!/usr/bin/env python3
"""Verify each vendored crate against its published upstream archive.

The reviewed manifest records ``published_crate_sha256`` for every vendored
crate distribution. This check hashes the operator-supplied ``.crate`` archive
against that value, then compares every archive member with the reviewed
vendored inventory. The only admitted differences are the reviewed patch
delta fixed below. Archives are streamed and hashed, never extracted or run.

OpenRaft is vendored as its complete workspace under a custody checkpoint
review record. It has no single published archive and is reported as such; it
is never counted as archive-verified.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile

import check_dependency_patches

SCHEMA = "kasumi-dependency-upstream-provenance-v1"
VERIFIER = "scripts/dependency_provenance.py"
MAX_ARCHIVE_BYTES = 64 << 20
MAX_MEMBER_BYTES = 32 << 20
MAX_MEMBERS = 4096
# Reviewed differences from each published archive. ``added`` and ``changed``
# name vendored files; ``removed`` names archive members that are not vendored.
# The rmcp entry follows vendor/rmcp-terminal-ownership.md and the vendored
# sources; the remaining entries were derived from the published archives.
UPSTREAM_DELTA = {
    "vendor/lru-0.16.4": {
        "changed": ("src/lib.rs",),
        "added": ("Cargo.lock",),
        "removed": (".github/workflows/main.yml", ".gitignore")},
    "vendor/serde_json-1.0.151": {
        "changed": ("Cargo.toml", "src/number.rs", "src/raw.rs", "src/value/de.rs"),
        "added": ("tests/literal_keys.rs",),
        "removed": ()},
    "vendor/rmcp-3.2.0": {
        "changed": ("src/transport/streamable_http_server.rs",
                    "src/transport/streamable_http_server/tower.rs"),
        "added": ("LICENSE", "src/transport/streamable_http_server/terminal_stateless_tests.rs"),
        "removed": ()},
}
# Roots admitted by a review record instead of a published archive.
REVIEW_RECORD_ROOTS = {"vendor/openraft-0.9.25": "openraft-checkpoint"}


def require(value, message):
    if not value:
        raise ValueError(message)


def archive_name(root):
    return PurePosixPath(root).name + ".crate"


def file_sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def archive_members(path, prefix):
    """Hash every regular member under the archive's single package directory."""
    members = {}
    with tarfile.open(path, "r:gz") as archive:
        for count, member in enumerate(archive, 1):
            require(count <= MAX_MEMBERS, "upstream archive has too many members")
            name = PurePosixPath(member.name)
            require(not name.is_absolute() and ".." not in name.parts and name.parts
                    and name.parts[0] == prefix and name.as_posix() == member.name.rstrip("/"),
                    "upstream archive member escapes its package directory")
            if member.isdir():
                continue
            require(member.isfile() and len(name.parts) > 1 and member.size <= MAX_MEMBER_BYTES,
                    "upstream archive member is not a bounded regular file")
            relative = PurePosixPath(*name.parts[1:]).as_posix()
            require(relative not in members, "upstream archive repeats a member")
            with archive.extractfile(member) as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            members[relative] = {"sha256": digest, "bytes": member.size}
    require(members, "upstream archive is empty")
    return members


def archive_file(directory, name):
    path = Path(directory) / name
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        raise ValueError("upstream archive is absent: " + name) from None
    require(stat.S_ISREG(mode), "upstream archive is not a regular file: " + name)
    require(path.stat().st_size <= MAX_ARCHIVE_BYTES, "upstream archive exceeds work limit")
    return path


def verify_root(inventory, archive):
    """Compare one reviewed inventory with its published archive bytes."""
    root = inventory["path"]
    expected = inventory.get("published_crate_sha256")
    require(root in UPSTREAM_DELTA and isinstance(expected, str),
            "vendored root has no reviewed published archive: " + str(root))
    require(Path(archive).name == archive_name(root), "upstream archive is misnamed for " + root)
    before = file_sha256(archive)
    require(before == expected,
            "upstream archive differs from the reviewed published checksum: " + root)
    upstream = archive_members(archive, PurePosixPath(root).name)
    vendored = inventory["files"]
    delta = {
        "changed": sorted(name for name in vendored if name in upstream
                          and (vendored[name]["sha256"], vendored[name]["bytes"])
                          != (upstream[name]["sha256"], upstream[name]["bytes"])),
        "added": sorted(name for name in vendored if name not in upstream),
        "removed": sorted(name for name in upstream if name not in vendored)}
    reviewed = {kind: sorted(names) for kind, names in UPSTREAM_DELTA[root].items()}
    require(delta == reviewed, "vendored source differs from the reviewed upstream delta: "
            + root + " " + json.dumps(delta, sort_keys=True))
    require(file_sha256(archive) == before, "upstream archive changed during verification")
    packages = inventory["packages"]
    require(len(packages) == 1 and packages[0]["path"] == root
            and archive_name(root) == packages[0]["name"] + "-" + packages[0]["version"] + ".crate",
            "published archive does not name the reviewed package: " + root)
    return {"root": root, "package": packages[0]["name"], "version": packages[0]["version"],
            "provenance": "published-archive",
            "archive": {"name": archive_name(root), "sha256": before,
                        "bytes": Path(archive).stat().st_size},
            "upstream_files": len(upstream),
            "identical_files": len(set(upstream) & set(vendored)) - len(delta["changed"]),
            **delta}


def verify(source, archives):
    """Verify every reviewed root; reject an omitted, extra or substituted archive."""
    source = Path(source).resolve(strict=True)
    archives = Path(archives)
    require(archives.is_absolute() and not archives.is_symlink() and archives.is_dir(),
            "upstream archive directory is absent or aliased")
    check_dependency_patches.verify_sources(source)
    manifest = check_dependency_patches.read_json(source / "vendor/patch-manifest.json")
    expected = set(UPSTREAM_DELTA) | set(REVIEW_RECORD_ROOTS)
    inventories = {item["path"]: item for item in manifest["inventories"]}
    require(set(inventories) == expected and len(inventories) == len(manifest["inventories"]),
            "reviewed vendor roster omits or adds an upstream provenance root")
    with os.scandir(archives) as entries:
        present = {entry.name for entry in entries}
    require(present == {archive_name(root) for root in UPSTREAM_DELTA},
            "upstream archive roster omits or adds a published crate")
    roots = []
    for root in sorted(expected):
        inventory = inventories[root]
        if root in REVIEW_RECORD_ROOTS:
            review = inventory.get("review")
            require("published_crate_sha256" not in inventory and isinstance(review, dict)
                    and review.get("kind") == REVIEW_RECORD_ROOTS[root],
                    "review-record root changed its provenance kind: " + root)
            roots.append({"root": root, "provenance": "review-record",
                          "review": {key: review[key] for key in ("kind", "path", "sha256")},
                          "packages": sorted(package["name"]
                                             for package in inventory["packages"])})
        else:
            roots.append(verify_root(inventory, archive_file(archives, archive_name(root))))
    # Recheck the vendored bytes: the comparison used the reviewed inventory.
    check_dependency_patches.verify_sources(source)
    return {"schema": SCHEMA,
            "verifier": {"source_path": VERIFIER, "sha256": file_sha256(source / VERIFIER)},
            "manifest_sha256": file_sha256(source / "vendor/patch-manifest.json"),
            "roots": roots}


def summary(receipt):
    """The exact stdout of a passing run; the owned runner compares it bytewise."""
    lines = []
    for root in receipt["roots"]:
        if root["provenance"] == "published-archive":
            lines.append("upstream {package} {version} {sha256} changed={changed} added={added} "
                         "removed={removed}\n".format(
                             sha256=root["archive"]["sha256"],
                             **{key: len(root[key]) if isinstance(root[key], list) else root[key]
                                for key in ("package", "version", "changed", "added", "removed")}))
        else:
            lines.append("review-record " + root["root"] + " " + root["review"]["sha256"] + "\n")
    return "".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--archives", type=Path, required=True,
                        help="directory holding exactly the published .crate archives")
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    try:
        require(Path(__file__).resolve(strict=True)
                == args.source.resolve(strict=True) / VERIFIER,
                "provenance verifier is not the frozen source executable")
        receipt = verify(args.source, args.archives)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, EOFError) as error:
        print("upstream provenance verification failed: " + str(error), file=sys.stderr)
        return 1
    sys.stdout.write(summary(receipt))
    return 0


if __name__ == "__main__":
    sys.exit(main())
