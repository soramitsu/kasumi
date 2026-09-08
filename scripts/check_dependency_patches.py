#!/usr/bin/env python3
"""Fail closed if Cargo stops using any exact reviewed dependency patch."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys


def verify(root: Path) -> None:
    manifest = json.loads((root / "vendor/patch-manifest.json").read_text())
    if manifest["format"] != 1:
        raise ValueError("unsupported dependency patch manifest")
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--format-version", "1"], cwd=root
    ))
    for expected in manifest["packages"]:
        directory = root / expected["path"]
        packages = [p for p in metadata["packages"] if p["name"] == expected["name"]]
        if len(packages) != 1:
            raise ValueError(f"unexpected dependency copies: {expected['name']}")
        package = packages[0]
        if (package["source"] is not None or package["version"] != expected["version"]
                or Path(package["manifest_path"]).resolve() != (directory / "Cargo.toml").resolve()):
            raise ValueError(f"reviewed source not selected: {expected['name']}")
        for relative, digest in expected["files"].items():
            path = directory / relative
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"missing or indirect patched input: {path}")
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise ValueError(f"patched input changed without review: {path}")
        actual = {str(p.relative_to(directory)) for p in directory.rglob("*") if p.is_file()}
        if actual != expected["files"].keys():
            raise ValueError(f"unexpected files in reviewed package: {directory}")
        print(f"verified {expected['name']} {expected['version']} ({len(actual)} inputs)")


if __name__ == "__main__":
    try:
        verify(Path(__file__).resolve().parents[1])
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"dependency patch verification failed: {error}", file=sys.stderr)
        sys.exit(1)
