#!/usr/bin/env python3
"""Assemble a candidate from successful frozen functional evidence.

Never builds a replacement executable or treats functional evidence as complete
production acceptance. Missing provenance, notices or changed inputs fail closed.
"""
from __future__ import annotations

import argparse
import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tomllib

from release_gate import TOOLCHAIN, functional_gates, inventory, sha256, write_json

TARGETS = {"aarch64-unknown-linux-gnu": ("elf", 183),
           "x86_64-unknown-linux-gnu": ("elf", 62),
           "aarch64-apple-darwin": ("macho", 0x100000C)}
BINARIES = {"kasumid", "kasumictl", "kasumi-authority"}
NOTICE_NAME = re.compile(r"^(licen[cs]e|copying|copyright|notice)([-_.]|$)", re.I)


def owned_file(root, relative):
    root = Path(root).resolve(strict=True)
    relative = Path(relative)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("artifact path escapes its owned directory")
    path = root / relative
    for parent in (path, *path.parents):
        if parent == root:
            break
        if parent.is_symlink():
            raise ValueError("artifact path contains a symbolic link")
    if not path.is_file() or not path.resolve(strict=True).is_relative_to(root):
        raise ValueError("artifact is not an owned regular file")
    return path


def verify_file(root, relative, digest):
    path = owned_file(root, relative)
    if sha256(path) != digest:
        raise ValueError("artifact changed: " + str(relative))
    return path


def verify_evidence(directory):
    directory = Path(directory).resolve(strict=True)
    record = json.loads(owned_file(directory, "evidence.json").read_text())
    if record.get("schema") != 1 or record.get("status") != "passed" or record.get("toolchain") != TOOLCHAIN:
        raise ValueError("successful pinned functional evidence is required")
    gates = record["gates"]
    required = {name for name, _ in functional_gates(2)}
    if {g["name"] for g in gates} != required or len(gates) != len(required):
        raise ValueError("functional gate set differs from this packaging contract")
    for gate in gates:
        if gate["exit_code"] != 0 or gate.get("fixture_feature_violation") or gate.get("missing_production_executables"):
            raise ValueError("a functional gate failed")
        verify_file(directory, gate["log"], gate["log_sha256"])
    source = directory / "source"
    source_files = verify_file(directory, "source-files.json", record["source_files_sha256"])
    if inventory(source) != json.loads(source_files.read_text()):
        raise ValueError("frozen source differs from its recorded inventory")
    verify_file(directory, "source.tar", record["source_archive_sha256"])
    verify_file(source, "Cargo.lock", record["lockfile_sha256"])
    toolchain = next(g for g in gates if g["name"] == "toolchain")
    hosts = re.findall(r"^host: (\S+)$", (directory / toolchain["log"]).read_text(), re.M)
    if len(hosts) != 1 or hosts[0] not in TARGETS:
        raise ValueError("unsupported or ambiguous native build host")
    production = next(g for g in gates if g["name"] == "production")
    if not production.get("compiled_packages"):
        raise ValueError("production dependency inventory is missing; rerun frozen gates")
    binaries = {}
    for relative, artifact in production["executables"].items():
        name = artifact["target"]
        if name not in BINARIES or artifact["test"] or name in binaries:
            raise ValueError("unexpected production executable")
        path = verify_file(directory / "target", relative, artifact["sha256"])
        verify_architecture(path, hosts[0])
        binaries[name] = (path, artifact["sha256"])
    if set(binaries) != BINARIES:
        raise ValueError("production executable set is incomplete")
    return record, production, hosts[0], binaries


def verify_architecture(path, target):
    with Path(path).open("rb") as source:
        header = source.read(20)
    kind, expected = TARGETS[target]
    if kind == "elf":
        valid = (len(header) == 20 and header[:6] == b"\x7fELF\x02\x01"
                 and struct.unpack_from("<H", header, 18)[0] == expected)
    else:
        valid = (len(header) == 20 and header[:4] == b"\xcf\xfa\xed\xfe"
                 and struct.unpack_from("<I", header, 4)[0] == expected)
    if not valid:
        raise ValueError("executable architecture differs from recorded native host")


def normalized_archive(directory, output, prefix, epoch):
    """Normalize names, modes, owner, ordering and gzip/tar timestamps."""
    files = inventory(directory)
    with Path(output).open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for relative, metadata in files.items():
                    item = tarfile.TarInfo(prefix + "/" + relative)
                    item.size = metadata["bytes"]
                    item.mode = 0o755 if metadata["executable"] else 0o644
                    item.mtime = epoch
                    with owned_file(directory, relative).open("rb") as data:
                        archive.addfile(item, data)
        raw.flush()
        os.fsync(raw.fileno())


def license_files(package, source, supplements):
    package_root = Path(package["manifest_path"]).parent.resolve(strict=True)
    if package["id"] in supplements["workspace_members"]:
        return [(owned_file(source, name), name, None) for name in ("LICENSE", "NOTICE")]
    files = {}
    for path in sorted(package_root.rglob("*")):
        if path.is_file() and NOTICE_NAME.match(path.name):
            relative = path.relative_to(package_root).as_posix()
            files[relative] = (owned_file(package_root, relative), relative, None)
    if package.get("license_file"):
        declared = Path(package["license_file"])
        relative = declared.relative_to(package_root) if declared.is_absolute() else declared
        path = owned_file(package_root, relative)
        files[str(relative)] = (path, str(relative), None)
    extra = supplements["packages"].get((package["name"], package["version"]))
    if extra:
        vcs = package_root / ".cargo_vcs_info.json"
        if extra.get("upstream_commit"):
            if not vcs.is_file() or json.loads(vcs.read_text())["git"]["sha1"] != extra["upstream_commit"]:
                raise ValueError("supplement does not match published crate source")
        for item in extra["files"]:
            path = verify_file(source / "release/licenses", item["path"], item["sha256"])
            files["supplement/" + item["path"]] = (path, item["path"], item["source_url"])
    if not files:
        raise ValueError("missing upstream license text: " + package["name"] + " " + package["version"])
    return list(files.values())


def verify_registry_notices(package, files, checksum):
    """Tie cached source notices and VCS identity to the locked published crate."""
    if not package["source"]:
        return
    if not package["source"].startswith("registry+") or not checksum:
        raise ValueError("unsupported dependency origin or missing registry checksum")
    root = Path(package["manifest_path"]).parent.resolve(strict=True)
    cache = root.parent.parent.parent / "cache" / root.parent.name
    crate_name = package["name"] + "-" + package["version"]
    archive = verify_file(cache, crate_name + ".crate", checksum)
    expected = []
    for path, _, url in files:
        if url is None:
            # macOS /var and /tmp may alias their physical parent directories;
            # normalize the parent while still rejecting a substituted leaf.
            relative = path.parent.resolve(strict=True).relative_to(root) / path.name
            expected.append((owned_file(root, relative), str(relative)))
    expected.append((root / "Cargo.toml", "Cargo.toml"))
    if (root / ".cargo_vcs_info.json").exists():
        expected.append((root / ".cargo_vcs_info.json", ".cargo_vcs_info.json"))
    with tarfile.open(archive, "r:gz") as tar:
        for path, relative in expected:
            member = tar.getmember(crate_name + "/" + relative)
            if not member.isfile():
                raise ValueError("registry notice is not a regular archive member")
            with tar.extractfile(member) as original:
                digest = hashlib.file_digest(original, "sha256").hexdigest()
            if digest != sha256(path):
                raise ValueError("cached dependency notice differs from locked crate")


def build_inventory(source, output, record, production, target, epoch):
    """Map Cargo-reported compiled packages to exact locked crate sources."""
    command = ["cargo", "+" + TOOLCHAIN, "metadata", "--locked", "--format-version", "1",
               "--no-default-features", "--filter-platform", target]
    metadata = json.loads(subprocess.check_output(command, cwd=source))
    packages = {p["id"]: p for p in metadata["packages"]}
    compiled = production["compiled_packages"]
    if not set(compiled).issubset(packages):
        raise ValueError("compiled package identities differ from the frozen metadata")
    for identity, built in compiled.items():
        if packages[identity]["name"].startswith("kasumi-") and "test-utils" in built["features"]:
            raise ValueError("fixture capability in a production package")
    manifest = json.loads(owned_file(source, "release/licenses/sources.json").read_text())
    supplements = {"workspace_members": metadata["workspace_members"],
                   "packages": {(p["name"], p["version"]): p for p in manifest["packages"]}}
    lock = tomllib.loads((source / "Cargo.lock").read_text())
    checksums = {(p["name"], p["version"], p.get("source")): p.get("checksum") for p in lock["package"]}
    entries, notices, identities = [], [], {}
    license_root = output / "licenses"
    license_root.mkdir()
    for identity in sorted(compiled, key=lambda i: (packages[i]["name"], packages[i]["version"], i)):
        package = packages[identity]
        name, version = package["name"], package["version"]
        origin = package["source"]
        if origin is None:
            relative = Path(package["manifest_path"]).resolve().relative_to(source.resolve())
            origin = "source:" + record["source_commit"] + ":" + str(relative)
        stable = name + "@" + version + ":" + origin
        spdx_id = "SPDXRef-" + name + "-" + hashlib.sha256(stable.encode()).hexdigest()[:20]
        identities[identity] = spdx_id
        copied = []
        files = license_files(package, source, supplements)
        checksum = checksums.get((name, version, package["source"]))
        supplemental = supplements["packages"].get((name, version), {})
        if supplemental.get("locked_crate_sha256") and supplemental["locked_crate_sha256"] != checksum:
            raise ValueError("supplement differs from the locked crate checksum")
        verify_registry_notices(package, files, checksum)
        for path, original, url in files:
            digest = sha256(path)
            dest = license_root / (digest + ".txt")
            if not dest.exists():
                shutil.copyfile(path, dest)
            verify_file(license_root, dest.name, digest)
            copied.append({"path": "licenses/" + dest.name, "sha256": digest,
                           "original_path": original, "source_url": url})
        entry = {"SPDXID": spdx_id, "name": name, "versionInfo": version,
                 "downloadLocation": "https://crates.io/api/v1/crates/" + name + "/" + version + "/download"
                 if package["source"] and package["source"].startswith("registry+") else "NOASSERTION",
                 "filesAnalyzed": False, "licenseConcluded": supplemental.get("license_selection", "NOASSERTION"),
                 "licenseDeclared": re.sub(r"\s*/\s*", " OR ", package["license"]) if package["license"] else "NOASSERTION",
                 "copyrightText": "NOASSERTION",
                 "sourceInfo": origin,
                 "comment": "Cargo compiled package; includes host build tools. Original license/notice text is retained in THIRD-PARTY-NOTICES.json."}
        if checksum:
            entry["checksums"] = [{"algorithm": "SHA256", "checksumValue": checksum}]
        if package.get("repository"):
            entry["homepage"] = package["repository"]
        entries.append(entry)
        notices.append({"name": name, "version": version, "source": origin,
                        "license_declared": package["license"], "files": copied,
                        "compiled_features": compiled[identity]["features"]})
    relations = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                  "relatedSpdxElement": identities[i]} for i in sorted(identities)]
    created = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    sbom = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
            "name": "kasumi-" + record["source_commit"] + "-" + target,
            "creationInfo": {"creators": ["Tool: kasumi-package-release-1"], "created": created},
            "packages": entries, "relationships": relations,
            "comment": "Exact Cargo production compilation inventory, including host build dependencies. Embedded native sources retain their discovered notices; OS shared libraries and OCI base packages require a separate platform SBOM."}
    sbom["documentNamespace"] = "https://spdx.org/spdxdocs/kasumi-" + hashlib.sha256(json.dumps(sbom, sort_keys=True).encode()).hexdigest()
    write_json(output / "sbom.spdx.json", sbom)
    write_json(output / "THIRD-PARTY-NOTICES.json", notices)
    with (output / "THIRD-PARTY-NOTICES.txt").open("w") as text:
        for item in notices:
            text.write(item["name"] + " " + item["version"] + "\n" + item["source"] + "\n")
            text.write("Declared license: " + str(item["license_declared"]) + "\n")
            for file in item["files"]:
                text.write("  " + file["path"] + " (" + file["original_path"] + ")\n")
            text.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path, help="exclusive new directory outside evidence/source")
    args = parser.parse_args()
    evidence = args.evidence.resolve(strict=True)
    if not args.output.is_absolute() or args.output.resolve().is_relative_to(evidence):
        parser.error("output must be absolute and outside frozen evidence")
    record, production, target, binaries = verify_evidence(evidence)
    source = evidence / "source"
    for tool in ("package_release.py", "release_gate.py"):
        verify_file(source, "scripts/" + tool, sha256(Path(__file__).resolve().parent / tool))
    epoch = int(record["build_environment"]["SOURCE_DATE_EPOCH"])
    if not 0 <= epoch <= 0xFFFFFFFF:
        raise ValueError("invalid source date epoch")
    version = tomllib.loads((source / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    if not re.fullmatch(r"[0-9A-Za-z.+-]+", version):
        raise ValueError("invalid package version")
    args.output.mkdir(exist_ok=False)
    package = args.output / "package"
    package.mkdir()
    (package / "bin").mkdir()
    for name, (path, digest) in binaries.items():
        shutil.copyfile(path, package / "bin" / name)
        (package / "bin" / name).chmod(0o755)
        verify_file(package, "bin/" + name, digest)
    for name in ("LICENSE", "NOTICE", "SECURITY.md", "CONTRIBUTING.md"):
        shutil.copyfile(owned_file(source, name), package / name)
    shutil.copytree(source / "release/systemd", package / "systemd")
    build_inventory(source, package, record, production, target, epoch)
    if inventory(source) != json.loads((evidence / "source-files.json").read_text()):
        raise ValueError("packaging changed frozen source inputs")
    write_json(package / "provenance.json", {"schema": 1, "source_commit": record["source_commit"],
               "source_tree": record["source_tree"], "lockfile_sha256": record["lockfile_sha256"],
               "functional_evidence_sha256": sha256(evidence / "evidence.json"), "target": target,
               "packager_sha256": sha256(Path(__file__)),
               "source_date_epoch": epoch, "executables": {n: h for n, (_, h) in binaries.items()},
               "scope": "candidate artifact; functional evidence only; final production acceptance remains separate"})
    archive = args.output / ("kasumi-" + version + "-" + target + ".tar.gz")
    normalized_archive(package, archive, "kasumi-" + version, epoch)
    source_archive = args.output / ("kasumi-" + version + "-source.tar.gz")
    normalized_archive(source, source_archive, "kasumi-" + version, epoch)
    paths = [archive, source_archive]
    with (args.output / "SHA256SUMS").open("x") as checksums:
        for path in paths:
            checksums.write(sha256(path) + "  " + path.name + "\n")
    print("Candidate artifacts: " + str(args.output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
