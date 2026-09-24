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
import sys
import tarfile
import tomllib

import gate_process

from release_gate import TOOLCHAIN, functional_gates, inventory, sha256, write_json

TARGETS = {"aarch64-unknown-linux-gnu": ("elf", 183),
           "x86_64-unknown-linux-gnu": ("elf", 62),
           "aarch64-apple-darwin": ("macho", 0x100000C)}
BINARIES = {"kasumid", "kasumictl", "kasumi-authority"}
NOTICE_NAME = re.compile(r"^(licen[cs]e|copying|copyright|notice)([-_.]|$)", re.I)
ATTRIBUTION_NAME = re.compile(r"^(authors|contributors)([-_.]|$)", re.I)


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
    jobs = record.get("jobs")
    if type(jobs) is not int or not 1 <= jobs <= 64:
        raise ValueError("recorded functional concurrency is missing or invalid")
    timeout = record.get("gate_timeout_seconds")
    if type(timeout) is not int or not 1 <= timeout <= 86400:
        raise ValueError("recorded functional timeout is missing or invalid")
    interpreter = record.get("python_executable")
    if (not isinstance(interpreter, dict) or set(interpreter) != {"path", "sha256", "artifact"}
            or not isinstance(interpreter["path"], str) or not Path(interpreter["path"]).is_absolute()
            or not isinstance(interpreter["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", interpreter["sha256"]) is None):
        raise ValueError("recorded Python interpreter identity is missing or invalid")
    verify_file(directory, interpreter["artifact"], interpreter["sha256"])
    expected = dict(functional_gates(jobs, interpreter["path"]))
    required = set(expected)
    if {g["name"] for g in gates} != required or len(gates) != len(required):
        raise ValueError("functional gate set differs from this packaging contract")
    for gate in gates:
        if gate["command"] != expected[gate["name"]]:
            raise ValueError("recorded gate command differs from the pinned contract")
        if gate["exit_code"] != 0 or gate.get("fixture_feature_violation") or gate.get("missing_production_executables"):
            raise ValueError("a functional gate failed")
        verify_file(directory, gate["log"], gate["log_sha256"])
        if not gate.get("resources") or not gate.get("resources_sha256"):
            raise ValueError("gate resource evidence is missing; rerun frozen gates")
        verify_file(directory, gate["resources"], gate["resources_sha256"])
        process = verify_process_receipt(directory, gate, timeout)
        if gate["name"] in {"python", "dependency-patches"} and process["executable"] != {
                "path": interpreter["path"], "sha256": interpreter["sha256"]}:
            raise ValueError("Python gate did not execute the recorded interpreter")
    source = directory / "source"
    inputs = record.get("runner_inputs")
    if not isinstance(inputs, dict) or set(inputs) != {"scripts/release_gate.py", "scripts/gate_process.py"}:
        raise ValueError("executing release tool provenance is missing")
    for relative, checksum in inputs.items():
        verify_file(source, relative, checksum)
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


def verify_process_receipt(directory, gate, timeout):
    if not gate.get("process") or not gate.get("process_sha256"):
        raise ValueError("gate process evidence is missing; rerun frozen gates")
    path = verify_file(directory, gate["process"], gate["process_sha256"])
    process = json.loads(path.read_text())
    executable = process.get("executable")
    if (not isinstance(executable, dict) or set(executable) != {"path", "sha256"}
            or not isinstance(executable["path"], str) or not Path(executable["path"]).is_absolute()
            or not isinstance(executable["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", executable["sha256"]) is None
            or not isinstance(gate.get("command"), list) or not gate["command"]
            or (Path(gate["command"][0]).is_absolute() and gate["command"][0] != executable["path"])
            or Path(gate["command"][0]).name != Path(executable["path"]).name):
        raise ValueError("gate executable identity is missing or differs from the command")
    cleanup = process.get("cleanup")
    group = process.get("process_group")
    if (process.get("status") != "passed" or process.get("outputs_stable") is not True
            or process.get("command") != gate["command"]
            or process.get("exit_code") != 0 or process.get("process_exit_code") != 0
            or process.get("timeout_seconds") != timeout or gate.get("timeout_seconds") != timeout
            or process.get("timed_out") is not False or gate.get("timed_out") is not False
            or process.get("received_signals") != [] or gate.get("received_signals") != []
            or "error" not in process or process["error"] is not None
            or "process_error" not in gate or gate["process_error"] is not None
            or type(group) is not int or group <= 0 or not isinstance(cleanup, dict)
            or cleanup.get("group") != group or cleanup.get("drained") is not True
            or cleanup.get("before") != [] or cleanup.get("after") != []
            or cleanup.get("signals") != [] or cleanup.get("errors") != []
            or cleanup.get("process_returncode") != 0 or gate.get("process_cleanup") != cleanup):
        raise ValueError("gate process did not finish with exact drained ownership")
    return process


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
    # Notices may identify copyright holders through a separate author list.
    # Retain such lists, but never treat an author list alone as a license grant.
    for path in sorted(package_root.rglob("*")):
        if path.is_file() and ATTRIBUTION_NAME.match(path.name):
            relative = path.relative_to(package_root).as_posix()
            files[relative] = (owned_file(package_root, relative), relative, None)
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


METADATA_SCHEMA = "kasumi-package-metadata-v1"
METADATA_TIMEOUT_SECONDS = 600
MAX_METADATA_BYTES = 64 << 20


def metadata_command(executable, target):
    if target not in TARGETS or not Path(executable).is_absolute():
        raise ValueError("metadata requires a native target and absolute executable")
    return [str(executable), "+" + TOOLCHAIN, "metadata", "--locked", "--offline",
            "--format-version", "1", "--no-default-features", "--filter-platform", target]


def _metadata_bytes(path):
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_METADATA_BYTES + 1)
    if len(data) > MAX_METADATA_BYTES:
        raise ValueError("metadata JSON exceeds work limit")
    return data


def _metadata_json(data):
    if len(data) > MAX_METADATA_BYTES:
        raise ValueError("metadata JSON exceeds work limit")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate metadata JSON key")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite metadata JSON")))


def _metadata_ref(directory, name):
    path = owned_file(directory, name)
    return {"path": name, "sha256": sha256(path), "bytes": path.stat().st_size}


def _metadata_reference(directory, value):
    if (not isinstance(value, dict) or set(value) != {"path", "sha256", "bytes"}
            or not isinstance(value["path"], str) or not isinstance(value["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is None
            or type(value["bytes"]) is not int or value["bytes"] < 0):
        raise ValueError("invalid metadata file reference")
    path = verify_file(directory, value["path"], value["sha256"])
    if path.stat().st_size != value["bytes"]:
        raise ValueError("metadata file length changed")
    return path


def verify_metadata_capture(directory, target, expected_source_files):
    """Consume only the exact successfully drained metadata invocation.

    This verifies the runner's observed transcript, not an authenticated remote
    producer or a complete repeatable-assembly domain. It never executes Cargo.
    """
    directory = Path(directory).resolve(strict=True)
    attempt_path = owned_file(directory, "attempt.json")
    attempt_bytes = _metadata_bytes(attempt_path)
    record = _metadata_json(attempt_bytes)
    fields = {"schema", "status", "target", "source_root", "source_before", "source_after",
              "command", "timeout_seconds", "executable", "process", "stdout", "stderr", "error"}
    if not isinstance(record, dict) or set(record) != fields:
        raise ValueError("metadata attempt fields differ")
    if (record["schema"] != METADATA_SCHEMA or record["status"] != "passed"
            or record["target"] != target or record["error"] is not None
            or record["timeout_seconds"] != METADATA_TIMEOUT_SECONDS
            or not isinstance(record["source_root"], str)
            or not Path(record["source_root"]).is_absolute()):
        raise ValueError("metadata attempt did not pass exact contract")
    refs = {name: record[name] for name in
            ("source_before", "source_after", "executable", "process", "stdout", "stderr")}
    paths = {name: _metadata_reference(directory, ref) for name, ref in refs.items()}
    expected_paths = {"source_before": "source-before.json", "source_after": "source-after.json",
                      "executable": "executable", "process": "process.json",
                      "stdout": "stdout.json", "stderr": "stderr.log"}
    if any(refs[name]["path"] != path for name, path in expected_paths.items()):
        raise ValueError("metadata custody paths differ")
    for name in ("source_before", "source_after"):
        if _metadata_json(_metadata_bytes(paths[name])) != expected_source_files:
            raise ValueError("metadata source differs from frozen input")
    process = _metadata_json(_metadata_bytes(paths["process"]))
    executed = process.get("executable")
    if (not isinstance(executed, dict) or set(executed) != {"path", "sha256"}
            or executed["sha256"] != refs["executable"]["sha256"]):
        raise ValueError("metadata process executable differs from retained bytes")
    command = metadata_command(executed["path"], target)
    if record["command"] != command or process.get("command") != command:
        raise ValueError("metadata command differs from frozen contract")
    if process.get("working_directory") != record["source_root"]:
        raise ValueError("metadata process working directory differs from frozen source")
    gate = {"command": command, "process": refs["process"]["path"],
            "process_sha256": refs["process"]["sha256"],
            "process_cleanup": process.get("cleanup"), "timeout_seconds": METADATA_TIMEOUT_SECONDS,
            "timed_out": process.get("timed_out"), "received_signals": process.get("received_signals"),
            "process_error": process.get("error")}
    verify_process_receipt(directory, gate, METADATA_TIMEOUT_SECONDS)
    if process.get("stdout") != refs["stdout"] or process.get("stderr") != refs["stderr"]:
        raise ValueError("metadata outputs do not belong to the drained process")
    raw = _metadata_bytes(paths["stdout"])
    if hashlib.sha256(raw).hexdigest() != refs["stdout"]["sha256"]:
        raise ValueError("metadata changed before parsing")
    metadata = _metadata_json(raw)
    if (not isinstance(metadata, dict) or metadata.get("version") != 1
            or type(metadata.get("version")) is not int
            or not isinstance(metadata.get("packages"), list)
            or not isinstance(metadata.get("workspace_members"), list)
            or not isinstance(metadata.get("resolve"), dict)):
        raise ValueError("Cargo metadata document is incomplete")
    for ref in refs.values():
        _metadata_reference(directory, ref)
    if _metadata_bytes(attempt_path) != attempt_bytes:
        raise ValueError("metadata attempt changed during verification")
    return metadata


def capture_metadata(source, directory, target, expected_source_files):
    """Own the original input-producing process and preserve every failed attempt.

    The directory is exclusive and never reused. SIGKILL cannot run cleanup;
    the persisted running receipt retains the actual process group for explicit
    recovery and can never pass verify_metadata_capture.
    """
    source = Path(source).resolve(strict=True)
    directory = Path(directory)
    if not directory.is_absolute() or directory.resolve().is_relative_to(source):
        raise ValueError("metadata custody requires an absolute directory outside source")
    directory.mkdir(exist_ok=False)
    record = {"schema": METADATA_SCHEMA, "status": "running", "target": target,
              "source_root": str(source), "source_before": None, "source_after": None,
              "command": None, "timeout_seconds": METADATA_TIMEOUT_SECONDS,
              "executable": None, "process": None, "stdout": None, "stderr": None, "error": None}
    attempt_path = directory / "attempt.json"
    write_json(attempt_path, record)
    try:
        before = inventory(source)
        write_json(directory / "source-before.json", before)
        record["source_before"] = _metadata_ref(directory, "source-before.json")
        if before != expected_source_files:
            raise ValueError("metadata source differs before dispatch")
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        executable = gate_process.executable_identity(["cargo"], source, environment)
        command = metadata_command(executable["path"], target)
        record["command"] = command
        with Path(executable["path"]).open("rb") as original, (directory / "executable").open("xb") as retained:
            shutil.copyfileobj(original, retained)
            retained.flush()
            os.fsync(retained.fileno())
        record["executable"] = _metadata_ref(directory, "executable")
        if record["executable"]["sha256"] != executable["sha256"]:
            raise ValueError("metadata executable changed before dispatch")
        write_json(attempt_path, record)
        with (directory / "stdout.json").open("xb") as stdout, (directory / "stderr.log").open("xb") as stderr:
            process = gate_process.run(command, source, environment, stdout, METADATA_TIMEOUT_SECONDS,
                                       lambda value: write_json(directory / "process.json", value),
                                       stderr=stderr)
        stable = process["cleanup"]["drained"] and not process["cleanup"]["errors"]
        process["outputs_stable"] = stable
        # Bind exact drained files into the original process receipt. An
        # unresolved process keeps its raw files but gets no terminal hashes.
        if stable:
            record["stdout"] = _metadata_ref(directory, "stdout.json")
            record["stderr"] = _metadata_ref(directory, "stderr.log")
            process["stdout"] = record["stdout"]
            process["stderr"] = record["stderr"]
        write_json(directory / "process.json", process)
        record["process"] = _metadata_ref(directory, "process.json")
        if not stable or process["status"] != "passed":
            raise ValueError("metadata process failed or retained uncertain ownership")
        if process["executable"] != executable:
            raise ValueError("metadata dispatched executable identity changed")
        after = inventory(source)
        write_json(directory / "source-after.json", after)
        record["source_after"] = _metadata_ref(directory, "source-after.json")
        if after != before:
            raise ValueError("metadata changed frozen source inputs")
        record["status"] = "passed"
        write_json(attempt_path, record)
        return verify_metadata_capture(directory, target, expected_source_files)
    except BaseException as error:
        record["status"] = "failed"
        record["error"] = repr(error)
        write_json(attempt_path, record)
        raise


def build_inventory(source, output, record, production, target, epoch):
    """Map Cargo-reported compiled packages to exact locked crate sources."""
    metadata = capture_metadata(source, output.parent / "metadata-custody", target,
                                json.loads((source.parent / "source-files.json").read_text()))
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
    for tool in ("package_release.py", "release_gate.py", "gate_process.py"):
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
    with (args.output / "binary-sha256").open("x") as checksums:
        for name, (_, digest) in sorted(binaries.items()):
            checksums.write(digest + "  bin/" + name + "\n")
    (args.output / ".dockerignore").write_text("*\n!package\n!package/**\n!binary-sha256\n")
    with (args.output / "SHA256SUMS").open("x") as checksums:
        for path in paths:
            checksums.write(sha256(path) + "  " + path.name + "\n")
    print("Candidate artifacts: " + str(args.output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
