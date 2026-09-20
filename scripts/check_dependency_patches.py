#!/usr/bin/env python3
"""Verify exact reviewed vendor trees and Cargo selections (Python 3.11+)."""

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import tomllib


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate manifest key: {key}")
        value[key] = item
    return value


def read_json(path):
    return json.loads(path.read_text(), object_pairs_hook=unique_object)


def relative_path(value):
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("invalid reviewed path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or str(path) != value or value == ".":
        raise ValueError(f"noncanonical reviewed path: {value}")
    return path


def owned_path(root, relative):
    path = root
    parts = relative_path(relative).parts
    for index, part in enumerate(parts):
        path = path / part
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) or (index < len(parts) - 1 and not stat.S_ISDIR(mode)):
            raise ValueError(f"indirect reviewed input: {path}")
    return path


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def file_record(record):
    if not isinstance(record, dict) or set(record) != {"sha256", "bytes", "mode"}:
        raise ValueError("invalid reviewed file record")
    if (not isinstance(record["sha256"], str) or len(record["sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in record["sha256"])
            or type(record["bytes"]) is not int or record["bytes"] < 0
            or record["mode"] not in {"0o644", "0o755"}):
        raise ValueError("invalid reviewed file hash, size or mode")


def check_file(path, expected):
    file_record(expected)
    observed = path.lstat()
    if not stat.S_ISREG(observed.st_mode):
        raise ValueError(f"missing or indirect patched input: {path}")
    if (observed.st_size != expected["bytes"]
            or oct(stat.S_IMODE(observed.st_mode)) != expected["mode"]
            or digest(path) != expected["sha256"]):
        raise ValueError(f"patched input changed without review: {path}")


def scan_tree(directory):
    """Include hidden/ignored inputs; never follow any file or directory symlink."""
    files = set()
    pending = [directory]
    while pending:
        current = pending.pop()
        with os.scandir(current) as entries:
            for entry in entries:
                path = Path(entry.path)
                relative = path.relative_to(directory).as_posix()
                mode = entry.stat(follow_symlinks=False).st_mode
                if stat.S_ISDIR(mode):
                    pending.append(path)
                elif stat.S_ISREG(mode):
                    files.add(relative)
                else:
                    raise ValueError(f"indirect or special vendor input: {path}")
    return files


def checked_evidence(root, path, expected_hash):
    source = owned_path(root, path)
    if not stat.S_ISREG(source.lstat().st_mode) or digest(source) != expected_hash:
        raise ValueError(f"review evidence changed: {path}")
    return read_json(source)


def verify_review(root, inventory):
    review = inventory.get("review")
    if review is None:
        return
    common = {"kind", "path", "sha256"}
    if review["kind"] == "redb-provenance" and set(review) == common:
        source = checked_evidence(root, review["path"], review["sha256"])
        expected = {}
        for item in source["files"]:
            if item["fork_sha256"] is not None:
                if item["path"] in expected:
                    raise ValueError("duplicate redb provenance path")
                expected[item["path"]] = item["fork_sha256"]
        actual = {name: item["sha256"] for name, item in inventory["files"].items()}
        if (actual != expected or inventory["published_crate_sha256"]
                != source["published_crate_sha256"]):
            raise ValueError("redb inventory differs from reviewed provenance")
    elif review["kind"] == "openraft-checkpoint" and set(review) == common | {
            "inventory_path", "inventory_sha256"}:
        checkpoint = checked_evidence(root, review["path"], review["sha256"])
        source = checked_evidence(root, review["inventory_path"], review["inventory_sha256"])
        referenced = PurePosixPath(review["path"]).parent / checkpoint["source_inventory"]
        expected = {}
        for item in source:
            if set(item) != {"path", "sha256", "bytes", "mode"} or item["path"] in expected:
                raise ValueError("invalid OpenRaft source inventory")
            expected[item["path"]] = {key: item[key] for key in ("sha256", "bytes", "mode")}
        if (referenced.as_posix() != review["inventory_path"]
                or checkpoint["source_inventory_sha256"] != review["inventory_sha256"]
                or checkpoint["source_files"] != len(expected)
                or checkpoint["source_bytes"] != sum(item["bytes"] for item in source)
                or inventory["files"] != expected):
            raise ValueError("OpenRaft inventory differs from reviewed checkpoint")
    else:
        raise ValueError("unsupported dependency review record")


def verify_sources(root):
    root = root.resolve(strict=True)
    manifest_path = owned_path(root, "vendor/patch-manifest.json")
    if (not stat.S_ISREG(manifest_path.lstat().st_mode)
            or stat.S_IMODE(manifest_path.lstat().st_mode) != 0o644):
        raise ValueError("patch manifest is not a regular file")
    manifest = read_json(manifest_path)
    if (set(manifest) != {"format", "inventories", "support_files"}
            or type(manifest["format"]) is not int or manifest["format"] != 2):
        raise ValueError("unsupported dependency patch manifest")
    expected_files = {"patch-manifest.json"}
    packages, patches, roots = {}, {}, []
    for inventory in manifest["inventories"]:
        if (not {"path", "packages", "files"}.issubset(inventory)
                or set(inventory) - {"path", "packages", "files", "published_crate_sha256", "review"}):
            raise ValueError("invalid reviewed inventory")
        path = relative_path(inventory["path"])
        if len(path.parts) != 2 or path.parts[0] != "vendor" or path in roots:
            raise ValueError("vendor inventory roots must be distinct direct children")
        roots.append(path)
        directory = owned_path(root, str(path))
        if not directory.is_dir() or not inventory["files"] or not inventory["packages"]:
            raise ValueError("empty reviewed inventory")
        for name, expected in inventory["files"].items():
            relative = relative_path(name)
            check_file(owned_path(directory, str(relative)), expected)
            expected_files.add((PurePosixPath(path.name) / relative).as_posix())
        verify_review(root, inventory)
        for package in inventory["packages"]:
            if set(package) != {"name", "version", "path", "patch"}:
                raise ValueError("invalid reviewed Cargo package")
            package_path = relative_path(package["path"])
            if (package["name"] in packages or not isinstance(package["name"], str)
                    or not isinstance(package["version"], str) or type(package["patch"]) is not bool
                    or not package_path.is_relative_to(path)):
                raise ValueError("duplicate or misplaced reviewed Cargo package")
            local_manifest = package_path.relative_to(path) / "Cargo.toml"
            if str(local_manifest) not in inventory["files"]:
                raise ValueError("Cargo package manifest is outside reviewed inventory")
            packages[package["name"]] = package
            if package["patch"]:
                patches[package["name"]] = {"path": package["path"]}
    for name, record in manifest["support_files"].items():
        if len(relative_path(name).parts) != 1 or name in expected_files:
            raise ValueError("invalid vendor support file")
        check_file(owned_path(root, "vendor/" + name), record)
        expected_files.add(name)
    actual_files = scan_tree(root / "vendor")
    if actual_files != expected_files:
        raise ValueError("unexpected or missing files in reviewed vendor tree")
    cargo = tomllib.loads(owned_path(root, "Cargo.toml").read_text())
    if cargo.get("patch") != {"crates-io": patches} or cargo.get("replace"):
        raise ValueError("Cargo patch roster differs from reviewed manifest")
    return packages


def verify_selection(root, packages, metadata):
    root = root.resolve(strict=True)
    resolved = {node["id"] for node in metadata["resolve"]["nodes"]}
    for name, expected in packages.items():
        selected = [package for package in metadata["packages"] if package["name"] == name]
        if len(selected) != 1:
            raise ValueError(f"unexpected dependency copies: {name}")
        package = selected[0]
        wanted = owned_path(root, expected["path"] + "/Cargo.toml")
        if (package["source"] is not None or package["version"] != expected["version"]
                or Path(package["manifest_path"]) != wanted or package["id"] not in resolved):
            raise ValueError(f"reviewed source not selected: {name}")
    for package in metadata["packages"]:
        path = Path(package["manifest_path"])
        if path.is_relative_to(root / "vendor") and package["name"] not in packages:
            raise ValueError(f"unrecorded selected vendor package: {package['name']}")


def verify(root):
    root = root.resolve(strict=True)
    packages = verify_sources(root)
    manifest_hash = digest(root / "vendor/patch-manifest.json")
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--format-version", "1"], cwd=root
    ))
    verify_selection(root, packages, metadata)
    # Recheck after metadata: qualification requires unchanged reviewed inputs.
    if (verify_sources(root) != packages
            or digest(root / "vendor/patch-manifest.json") != manifest_hash):
        raise ValueError("reviewed manifest changed during Cargo metadata")
    for name, package in packages.items():
        print(f"verified {name} {package['version']} ({package['path']})")


if __name__ == "__main__":
    try:
        verify(Path(__file__).resolve().parents[1])
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(f"dependency patch verification failed: {error}", file=sys.stderr)
        sys.exit(1)
