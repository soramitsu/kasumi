"""Frozen cargo-audit input, finding, and explicit disposition contract.

The operator supplies a review declaration before the owned native run. The
runner binds its bytes and independently derives findings from retained scanner
stdout over the audited registry-source projection. Three known decisions stay
mandatory even if the scanner's advisory database changes.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import shutil
import tomllib

import assembly_inputs
import dependency_git
from release_gate import inventory, sha256, write_json

SCHEMA = "kasumi-dependency-advisory-inputs-v2"
KNOWN = {
    ("RUSTSEC-2025-0167", "bitmaps", "3.2.1"): ("source-patched", "vendor/bitmaps-3.2.1",
                                                   {"bitmaps-invalid-bool", "bitmaps-no-mutable-bytes"}),
    ("RUSTSEC-2026-0253", "lru", "0.16.4"): ("source-patched", "vendor/lru-0.16.4",
                                               {"lru-panicking-drop", "lru-mut-iterator"}),
    ("RUSTSEC-2026-0247", "bitmaps", "3.2.1"): ("accepted-residual-risk", "vendor/bitmaps-3.2.1", set()),
}
MAX_AGE_HOURS = 72


def require(value, message):
    if not value:
        raise ValueError(message)


def exact(value, fields, name):
    require(isinstance(value, dict) and set(value) == set(fields), name + " fields differ")


def digest(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "invalid SHA256")
    return value


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode()).hexdigest()


def timestamp(value):
    require(isinstance(value, str), "advisory timestamp missing")
    result = dt.datetime.fromisoformat(value)
    require(result.tzinfo is not None, "advisory timestamp needs timezone")
    return result.astimezone(dt.timezone.utc)


def locked_packages(projected_lock):
    lock = tomllib.loads(Path(projected_lock).read_text())
    packages = lock.get("package")
    require(isinstance(packages, list) and packages, "projected dependency lock is empty")
    identities = {(item["name"], item["version"]): item for item in packages}
    require(len(identities) == len(packages), "ambiguous projected lock package identity")
    return identities


def inspect_declaration(value, source, projected_lock, now, regressions,
                        attested_git, *, require_executable=True):
    exact(value, {"schema", "scanner", "git", "database", "dispositions"}, "advisory declaration")
    require(value["schema"] == SCHEMA, "unsupported advisory input schema")
    scanner = value["scanner"]
    exact(scanner, {"path", "sha256"}, "advisory scanner")
    require(assembly_inputs.file_identity(scanner["path"])["sha256"] == digest(scanner["sha256"])
            and (not require_executable or Path(scanner["path"]).stat().st_mode & 0o111),
            "advisory scanner executable changed")
    git_tool = value["git"]
    exact(git_tool, {"path", "sha256"}, "advisory Git verifier")
    require(assembly_inputs.file_identity(git_tool["path"])["sha256"] == digest(git_tool["sha256"])
            and (not require_executable or Path(git_tool["path"]).stat().st_mode & 0o111),
            "advisory Git verifier executable changed")
    database = value["database"]
    exact(database, {"path", "files_sha256", "commit", "fetched_at"}, "advisory database")
    root = assembly_inputs.absolute(database["path"])
    require(root.is_dir() and root != Path(source), "advisory database root differs")
    require(re.fullmatch(r"[0-9a-f]{40}", database["commit"]) and
            attested_git == database["commit"], "advisory Git commit differs")
    dependency_git.prepare(root)
    observed = inventory(root)
    require(observed and canonical_hash(observed) == digest(database["files_sha256"]),
            "advisory database bytes differ from declaration")
    fetched = timestamp(database["fetched_at"])
    observed_at = timestamp(now)
    require(dt.timedelta(0) <= observed_at - fetched <= dt.timedelta(hours=MAX_AGE_HOURS),
            "advisory database freshness assertion expired")
    packages = locked_packages(projected_lock)
    decisions = {}
    require(isinstance(value["dispositions"], list), "advisory dispositions are absent")
    for entry in value["dispositions"]:
        exact(entry, {"id", "package", "version", "decision", "vendor_root", "vendor_manifest_sha256",
                      "regressions", "owner", "reviewed_at", "rationale"}, "advisory disposition")
        key = (entry["id"], entry["package"], entry["version"])
        require(re.fullmatch(r"RUSTSEC-\d{4}-\d{4,}", entry["id"]) and key not in decisions,
                "duplicate or invalid advisory disposition")
        require((entry["package"], entry["version"]) in packages,
                "disposition package is not resolved by frozen lock")
        require(isinstance(entry["owner"], str) and entry["owner"].strip()
                and isinstance(entry["rationale"], str) and len(entry["rationale"].strip()) >= 30,
                "advisory review owner or rationale is missing")
        reviewed = timestamp(entry["reviewed_at"])
        require(reviewed <= observed_at and reviewed >= fetched - dt.timedelta(days=30),
                "advisory review timestamp differs")
        require(entry["decision"] in {"source-patched", "accepted-residual-risk"},
                "unknown advisory decision")
        require(isinstance(entry["regressions"], list) and
                len(entry["regressions"]) == len(set(entry["regressions"])),
                "duplicate advisory regression")
        known = KNOWN.get(key)
        if known is not None:
            require((entry["decision"], entry["vendor_root"], set(entry["regressions"])) == known,
                    "known source advisory disposition differs")
        if entry["decision"] == "source-patched":
            require(known is not None and set(entry["regressions"]) <= set(regressions),
                    "unmapped source patch cannot be accepted")
        else:
            require(not entry["regressions"], "residual risk cannot claim a patch regression")
        vendor = entry["vendor_root"]
        require(known is not None and vendor == known[1],
                "unreviewed package has no fixed disposition mapping")
        require(sha256(Path(source) / vendor / "Cargo.toml") == digest(entry["vendor_manifest_sha256"]),
                "advisory disposition vendor source differs")
        advisory_path = root / "crates" / entry["package"] / (entry["id"] + ".md")
        require(advisory_path.is_file() and advisory_path.relative_to(root).as_posix() in observed,
                "known advisory is absent from declared database")
        decisions[key] = entry
    require(set(KNOWN) <= set(decisions), "required source advisory dispositions are absent")
    require({"atomic-polyfill", "rustls-pemfile"}.isdisjoint({name for name, _ in packages}),
            "removed legacy dependencies returned to frozen lock")
    return observed, decisions, packages


def retain_database(root, database, observed):
    destination = Path(root) / "advisory-db"
    shutil.copytree(database, destination, symlinks=False)
    require(inventory(destination) == observed, "retained advisory database differs")
    write_json(Path(root) / "advisory-db-files.json", observed)
    return destination


def command(value, projected_lock, retained_database):
    return [value["scanner"]["path"], "audit", "--no-fetch", "--db", str(retained_database),
            "--file", str(projected_lock), "--format", "json"]


def parse_report(data, packages):
    require(isinstance(data, dict) and set(data) ==
            {"database", "lockfile", "settings", "vulnerabilities", "warnings"},
            "cargo-audit report schema differs")
    require(type(data["database"].get("advisory-count")) is int
            and data["database"]["advisory-count"] > 0,
            "scanner database had no advisories")
    require(type(data["lockfile"].get("dependency-count")) is int
            and data["lockfile"].get("dependency-count") == len(packages),
            "scanner did not inspect the complete frozen lock")
    settings = data["settings"]
    require(settings.get("target_arch") == [] and settings.get("target_os") == []
            and settings.get("ignore") == [] and settings.get("severity") is None,
            "scanner report applied filters or ignores")
    informational = settings.get("informational_warnings")
    require(isinstance(informational, list) and len(informational) == 3
            and set(informational) == {"unmaintained", "unsound", "notice"},
            "scanner omitted an informational advisory class")
    vulnerabilities = data["vulnerabilities"]
    require(isinstance(vulnerabilities.get("list"), list)
            and type(vulnerabilities.get("count")) is int
            and vulnerabilities.get("count") == len(vulnerabilities["list"])
            and vulnerabilities.get("found") is bool(vulnerabilities["list"]),
            "scanner vulnerability summary differs")
    warnings = data["warnings"]
    require(isinstance(warnings, dict), "scanner warning map differs")
    findings = {}
    for category, entries in [("vulnerability", vulnerabilities["list"]), *warnings.items()]:
        require(isinstance(category, str) and isinstance(entries, list), "scanner warning category differs")
        for item in entries:
            require(isinstance(item, dict) and isinstance(item.get("advisory"), dict)
                    and isinstance(item.get("package"), dict), "scanner finding differs")
            advisory, package = item["advisory"], item["package"]
            key = (advisory.get("id"), package.get("name"), package.get("version"))
            require(all(isinstance(part, str) for part in key) and
                    re.fullmatch(r"RUSTSEC-\d{4}-\d{4,}", key[0]) and
                    (key[1], key[2]) in packages and key not in findings,
                    "scanner finding is duplicate or not in the frozen lock")
            require(advisory.get("package") == key[1] and
                    package.get("source") == packages[(key[1], key[2])].get("source") and
                    package.get("checksum") == packages[(key[1], key[2])].get("checksum"),
                    "scanner advisory package source or checksum differs")
            findings[key] = {"id": key[0], "package": key[1], "version": key[2],
                             "category": category, "kind": item.get("kind")}
    return findings


def reconcile(findings, decisions, verdicts):
    require(set(findings) <= set(decisions), "scanner produced an undisposed advisory")
    for key, decision in decisions.items():
        known = KNOWN.get(key)
        require(known is not None, "disposition has no reviewed source mapping")
        if decision["decision"] == "source-patched":
            require(all(verdicts.get(case) == "passed" for case in decision["regressions"]),
                    "source patch lacks named passing regressions")
        else:
            require(key == ("RUSTSEC-2026-0247", "bitmaps", "3.2.1"),
                    "unreviewed residual risk cannot be accepted")
    return [{**finding, "decision": decisions[key]} for key, finding in sorted(findings.items())]
