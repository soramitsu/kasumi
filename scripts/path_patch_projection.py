#!/usr/bin/env python3
"""Target-only prototype: turn six reviewed local packages into audit-only rows.

The projected lock is NEVER a Cargo build input. It gives cargo-audit the
registry source marker it requires to enumerate advisories for path packages.
The binding receipt and the original frozen lock are the source of truth.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib

REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
SCHEMA = "kasumi-path-patch-advisory-projection-v1"
EXPECTED_VENDOR = frozenset({
    "bitmaps", "lru", "serde_json", "rmcp", "openraft", "openraft-macros",
})
PACKAGE_HEADER = re.compile(r"(?m)^\[\[package\]\]\s*$")


def require(condition: object, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha256(path: Path) -> str:
    return sha256(path.read_bytes())


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON key")
        value[key] = item
    return value


def read_json(path: Path) -> dict:
    value = json.loads(path.read_text(), object_pairs_hook=unique_object)
    require(isinstance(value, dict), "JSON root differs")
    return value


def version(package: dict, workspace_version: str) -> str:
    value = package.get("version")
    if value == {"workspace": True}:
        value = workspace_version
    require(isinstance(value, str) and value, "package version is absent")
    return value


def vendor_packages(source: Path, manifest: dict) -> dict[tuple[str, str], dict]:
    result: dict[tuple[str, str], dict] = {}
    for inventory in manifest["inventories"]:
        root = inventory["path"]
        workspace_path = source / root / "Cargo.toml"
        workspace = tomllib.loads(workspace_path.read_text())
        workspace_version = workspace.get("workspace", {}).get("package", {}).get("version", "")
        for selected in inventory["packages"]:
            require(set(selected) == {"name", "version", "path", "patch"},
                    "reviewed vendor package fields differ")
            name, selected_version, path = (selected[key] for key in ("name", "version", "path"))
            require(isinstance(name, str) and isinstance(selected_version, str)
                    and isinstance(path, str) and
                    (path.startswith(root + "/") or path == root)
                    and not Path(path).is_absolute() and ".." not in Path(path).parts,
                    "reviewed vendor path differs")
            require(type(selected["patch"]) is bool and
                    selected["patch"] is (name != "openraft-macros"),
                    "reviewed vendor patch role differs")
            local = source / path / "Cargo.toml"
            relative = local.relative_to(source / root).as_posix()
            require(relative in inventory["files"] and
                    file_sha256(local) == inventory["files"][relative]["sha256"],
                    "reviewed vendor manifest bytes differ")
            cargo = tomllib.loads(local.read_text())
            require(cargo["package"]["name"] == name and
                    version(cargo["package"], workspace_version) == selected_version,
                    "reviewed vendor package identity differs")
            key = name, selected_version
            require(key not in result, "duplicate reviewed vendor package")
            result[key] = {"name": name, "version": selected_version, "path": path,
                           "patch": selected["patch"], "manifest_sha256": file_sha256(local),
                           "inventory_sha256": sha256(json.dumps(inventory["files"], sort_keys=True,
                                                            separators=(",", ":")).encode())}
    require({name for name, _ in result} == EXPECTED_VENDOR and len(result) == 6,
            "exact reviewed vendor package roster differs")
    return result


def workspace_packages(source: Path) -> set[tuple[str, str]]:
    cargo = tomllib.loads((source / "Cargo.toml").read_text())
    base_version = cargo["workspace"]["package"]["version"]
    result: set[tuple[str, str]] = set()
    for member in cargo["workspace"]["members"]:
        require(isinstance(member, str) and member.startswith("crates/") and
                ".." not in Path(member).parts, "workspace member path differs")
        package = tomllib.loads((source / member / "Cargo.toml").read_text())["package"]
        key = package["name"], version(package, base_version)
        require(key not in result, "duplicate workspace package")
        result.add(key)
    return result


def synthetic_checksum(original_sha: str, manifest_sha: str, selected: dict) -> str:
    payload = "\0".join((SCHEMA, original_sha, manifest_sha, selected["name"],
                         selected["version"], selected["path"],
                         selected["manifest_sha256"], selected["inventory_sha256"]))
    return sha256(payload.encode())


def project(source: Path) -> tuple[str, dict]:
    """Pure projection after the caller verifies the frozen vendor source inventory."""
    source = source.resolve(strict=True)
    original_path = source / "Cargo.lock"
    original = original_path.read_text()
    manifest_path = source / "vendor/patch-manifest.json"
    manifest = read_json(manifest_path)
    require(manifest.get("format") == 2, "unsupported reviewed manifest")
    vendor = vendor_packages(source, manifest)
    workspace = workspace_packages(source)
    original_sha, manifest_sha = file_sha256(original_path), file_sha256(manifest_path)
    parsed = tomllib.loads(original)
    require(parsed.get("version") == 4 and isinstance(parsed.get("package"), list),
            "unsupported frozen lock")
    rows = parsed["package"]
    keys = [(row["name"], row["version"]) for row in rows]
    require(len(keys) == len(set(keys)), "ambiguous frozen lock name/version")
    unourced = {(row["name"], row["version"]) for row in rows if "source" not in row}
    require(unourced == set(vendor) | workspace and not (set(vendor) & workspace),
            "unreviewed source-less package in frozen lock")
    require(all(row.get("source") == REGISTRY for row in rows if "source" in row),
            "unreviewed non-registry third-party source in frozen lock")
    require(all("checksum" not in row for row in rows if
                (row["name"], row["version"]) in vendor),
            "reviewed vendor package acquired a checksum")
    matches = list(PACKAGE_HEADER.finditer(original))
    require(len(matches) == len(rows), "lock text/package roster differs")
    pieces = [original[:matches[0].start()]]
    bindings = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(original)
        block = original[match.start():end]
        row = tomllib.loads(block)["package"][0]
        require(row == rows[index], "lock text/package order differs")
        key = row["name"], row["version"]
        if key in vendor:
            selected = vendor[key]
            checksum = synthetic_checksum(original_sha, manifest_sha, selected)
            needle = f'version = "{row["version"]}"\n'
            require(block.count(needle) == 1, "noncanonical local lock package version")
            block = block.replace(needle, needle + f'source = "{REGISTRY}"\n'
                                  + f'checksum = "{checksum}"\n', 1)
            bindings.append({**selected, "original_source": None,
                             "projected_source": REGISTRY, "synthetic_checksum": checksum})
        pieces.append(block)
    projected = "".join(pieces)
    reparsed = tomllib.loads(projected)
    require(len(reparsed["package"]) == len(rows), "projection changed package count")
    for before, after in zip(rows, reparsed["package"]):
        expected = dict(before)
        key = before["name"], before["version"]
        if key in vendor:
            binding = next(item for item in bindings if
                           (item["name"], item["version"]) == key)
            expected.update(source=REGISTRY, checksum=binding["synthetic_checksum"])
        require(after == expected, "projection changed an unrelated lock field")
    require(len(bindings) == 6, "incomplete projected vendor roster")
    receipt = {"schema": SCHEMA, "original_lock_sha256": original_sha,
               "vendor_manifest_sha256": manifest_sha, "projected_lock_sha256": sha256(projected.encode()),
               "original_package_count": len(rows), "projected_package_count": len(reparsed["package"]),
               "workspace_package_count": len(workspace), "bindings": bindings}
    return projected, receipt


def verify_projection(source: Path, projected_path: Path, receipt_path: Path) -> dict:
    """Re-derive exact projected bytes and receipt from frozen source inputs."""
    expected_lock, expected_receipt = project(source)
    require(projected_path.read_bytes() == expected_lock.encode(),
            "retained advisory projection bytes differ")
    observed_receipt = read_json(receipt_path)
    require(observed_receipt == expected_receipt,
            "retained advisory binding receipt differs")
    return observed_receipt


def main() -> None:
    require(len(sys.argv) == 3, "usage: path_patch_projection.py SOURCE OUTPUT_DIRECTORY")
    source, output = Path(sys.argv[1]), Path(sys.argv[2])
    sys.path.insert(0, str(source / "scripts"))
    import check_dependency_patches
    check_dependency_patches.verify_sources(source)
    projected, receipt = project(source)
    output.mkdir(parents=True, exist_ok=False)
    (output / "Cargo.lock").write_text(projected)
    (output / "binding.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    verify_projection(source, output / "Cargo.lock", output / "binding.json")


if __name__ == "__main__":
    main()
