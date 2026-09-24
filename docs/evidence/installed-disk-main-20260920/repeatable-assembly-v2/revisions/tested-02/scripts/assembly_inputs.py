"""Declared assembly dependencies and actual consumed-input binding.

Host dependency completeness is an operator assertion backed by retained host
inventory evidence. This is the same producer trust boundary as release host
attestations, not a claim to have traced every kernel read or authenticated the
producer. Missing declarations and actual inputs outside them are rejected.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import sys

from release_gate import inventory, sha256

SCHEMA = "kasumi-assembly-inputs-v1"
ROLES = {"python-runtime", "rust-sysroot", "cargo-registry"}
TOOLS = {"python", "cargo", "rustc"}


def require(value, message):
    if not value:
        raise ValueError(message)


def exact(value, fields, name):
    require(isinstance(value, dict) and set(value) == set(fields), name + " fields differ")


def absolute(value):
    require(isinstance(value, str) and Path(value).is_absolute(), "input path is not absolute")
    path = Path(value)
    require(str(path) == value and path.resolve(strict=True) == path,
            "input path is not canonical or contains a symlink")
    return path


def digest(value):
    require(isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value), "invalid input SHA256")
    return value


def file_identity(path):
    path = absolute(str(path))
    require(path.is_file(), "declared input is not a regular file")
    return {"sha256": sha256(path), "bytes": path.stat().st_size,
            "executable": bool(path.stat().st_mode & 0o111)}


def validate_declaration(value):
    exact(value, {"schema", "target", "tools", "roots", "host_files", "host_inventory", "cargo_home"},
          "assembly inputs")
    require(value["schema"] == SCHEMA, "unsupported assembly input schema")
    exact(value["tools"], TOOLS, "native tools")
    for tool, item in value["tools"].items():
        exact(item, {"path", "sha256"}, tool)
        require(file_identity(item["path"])["sha256"] == digest(item["sha256"]), tool + " changed")
        require(os.access(item["path"], os.X_OK), tool + " is not executable")
    exact(value["roots"], ROLES, "dependency roots")
    for role, root in value["roots"].items():
        require(absolute(root).is_dir(), role + " root is absent")
    rust = Path(value["roots"]["rust-sysroot"])
    for tool in ("cargo", "rustc"):
        require(Path(value["tools"][tool]["path"]) == rust / "bin" / tool,
                "use direct native toolchain executable, not a Rustup wrapper")
    require(Path(value["roots"]["cargo-registry"]) == absolute(value["cargo_home"]) / "registry",
            "Cargo registry does not belong to declared Cargo home")
    # Cargo reads configuration from Cargo home even for offline metadata.
    require(not any((Path(value["cargo_home"]) / name).exists() for name in ("config", "config.toml")),
            "undeclared Cargo home configuration")
    require(isinstance(value["host_files"], list) and value["host_files"], "host library declaration is empty")
    seen = set()
    for item in value["host_files"]:
        exact(item, {"path", "sha256"}, "host dependency")
        require(item["path"] not in seen, "duplicate host dependency")
        seen.add(item["path"])
        require(file_identity(item["path"])["sha256"] == digest(item["sha256"]), "host dependency changed")
    exact(value["host_inventory"], {"path", "sha256"}, "host dependency inventory evidence")
    require(file_identity(value["host_inventory"]["path"])["sha256"] == digest(value["host_inventory"]["sha256"]),
            "host dependency inventory evidence changed")
    return value


def observe(value):
    """Inventory all declared runtime bytes; preserve paths in the signed-off declaration."""
    validate_declaration(value)
    files = {}
    for root in value["roots"].values():
        for relative, identity in inventory(root).items():
            files[str(Path(root) / relative)] = identity
    for item in [*value["tools"].values(), *value["host_files"], value["host_inventory"]]:
        identity = file_identity(item["path"])
        require(item["path"] not in files or files[item["path"]] == identity, "conflicting input identity")
        files[item["path"]] = identity
    require(files, "empty declared input inventory")
    return dict(sorted(files.items()))


def environment(value, home):
    """An explicit environment excludes ambient Python and Cargo overrides."""
    return {"PATH": str(Path(value["tools"]["cargo"]["path"]).parent) + os.pathsep + "/usr/bin:/bin",
            "HOME": str(home), "CARGO_HOME": value["cargo_home"],
            "RUSTC": value["tools"]["rustc"]["path"], "CARGO_NET_OFFLINE": "true",
            "PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0", "LC_ALL": "C", "TZ": "UTC",
            "TMPDIR": str(home)}


def consumed(value, source, metadata, observed):
    """Bind every package root and every imported Python module to frozen bytes."""
    source = Path(source).resolve(strict=True)
    paths = set()
    for item in metadata["packages"]:
        root = absolute(str(Path(item["manifest_path"]).parent))
        if root.is_relative_to(source):
            continue
        require(root.is_relative_to(Path(value["roots"]["cargo-registry"]) / "src"),
                "metadata consumed an undeclared package root")
        for relative, identity in inventory(root).items():
            path = str(root / relative)
            require(observed.get(path) == identity, "metadata package bytes are not bound")
            paths.add(path)
    for module in tuple(sys.modules.values()):
        filename = getattr(module, "__file__", None)
        if filename is None or filename.startswith("<"):
            continue
        path = Path(filename).resolve(strict=True)
        if path.is_relative_to(source):
            continue
        require(observed.get(str(path)) == file_identity(path), "Python imported unbound module: " + str(path))
        paths.add(str(path))
    return sorted(paths)
