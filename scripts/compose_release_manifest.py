#!/usr/bin/env python3
"""Compose a Kasumi release manifest from retained files in a collected evidence directory."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

import attempt_index
import operating_limits
import verify_release_acceptance as acceptance


def publish(path, data):
    """Make complete bytes visible once. An identical retry is safe."""
    with tempfile.NamedTemporaryFile(dir=path.parent) as temporary:
        temporary.write(data)
        temporary.flush()
        os.fsync(temporary.fileno())
        try:
            os.link(temporary.name, path)
        except FileExistsError:
            existing = attempt_index.owned_file(path.parent, path.name)
            if existing.read_bytes() != data:
                raise ValueError(f"existing output differs: {path.name}") from None
        attempt_index.fsync_directory(path.parent)


def compose(root, inputs, repository):
    acceptance.exact(inputs, {"source", "configurations", "artifacts", "gates", "candidates", "journals"},
                     "release selections")

    def ref(name):
        relative = acceptance.relative_path(name)
        acceptance.require("\n" not in relative and "\r" not in relative, "newline in release file path")
        return attempt_index.file_ref(root, root / relative)

    def records(key, allowed=None, field="file"):
        entries = inputs[key]
        acceptance.require(isinstance(entries, dict) and all(isinstance(name, str) and name for name in entries),
                           f"invalid {key} selections")
        if allowed is not None:
            acceptance.require(entries.keys() <= allowed, f"unknown {key} selection")
        return [{"id": name, field: ref(path)} for name, path in sorted(entries.items())]

    source = inputs["source"]
    acceptance.exact(source, {"commit", "archive", "files"}, "selected source")
    commit = subprocess.check_output(["git", "-C", repository, "rev-parse", "HEAD"], text=True).strip()
    acceptance.require(source["commit"] == commit, "repository is not at the selected commit")
    tree = subprocess.check_output(["git", "-C", repository, "rev-parse", "HEAD^{tree}"], text=True).strip()
    archive, inventory = ref(source["archive"]), ref(source["files"])
    files = acceptance.json_reference(root, inventory)
    acceptance.require(files == acceptance.archive_inventory(root / archive["path"], strip_root=False),
                       "source archive and inventory differ")
    with tempfile.TemporaryDirectory() as temporary:
        original = Path(temporary) / "source.tar"
        subprocess.run(["git", "-C", repository, "archive", "--format=tar", "-o", original, commit], check=True)
        acceptance.require(acceptance.sha256(original) == archive["sha256"], "source differs from frozen Git archive")
    vendor = {name: value for name, value in files.items() if name.startswith("vendor/")}
    acceptance.require(vendor and "Cargo.lock" in files, "source lacks vendor inventory or Cargo.lock")
    artifacts = records("artifacts", acceptance.required_artifacts() - {"checksums"})
    acceptance.require(len({row["file"]["path"] for row in artifacts}) == len(artifacts),
                       "two deliverables selected the same file")
    gates = records("gates", acceptance.required_gates(), "evidence")
    for row in gates:
        observation = acceptance.json_reference(root, row["evidence"])
        acceptance.require(observation.get("id") == row["id"] and observation.get("status") == "passed",
                           "selected gate has a different identity or did not pass")
    candidates = []
    for row in records("candidates", set(acceptance.PLATFORMS)):
        candidate = acceptance.json_reference(root, row["file"])
        acceptance.exact(candidate, {"platform", "primary", "independent"}, "candidate selection")
        acceptance.require(candidate["platform"] == row["id"], "native candidate target differs")
        acceptance.reference(root, candidate["primary"]["functional"])
        acceptance.reference(root, candidate["independent"])
        candidates.append(candidate)
    journals = records("journals", field="journal")
    for row in journals:
        expected = f"native-attempts/{row['id']}/attempts/index.jsonl"
        acceptance.require(attempt_index.ID.fullmatch(row["id"]) and row["journal"]["path"] == expected,
                           "native journal is outside its permanent namespace")
    return {"schema": acceptance.SCHEMA,
            "source": {"commit": commit, "tree": tree, "archive": archive, "files": inventory,
                       "lockfile_sha256": files["Cargo.lock"]["sha256"],
                       "patches_sha256": acceptance.canonical_hash(vendor), "configurations": records("configurations")},
            "artifacts": artifacts, "gates": gates, "candidates": candidates, "attempts": journals}


def write_checksums(root, artifacts):
    checksums = root / "SHA256SUMS"
    publish(checksums, "".join(f"{a['file']['sha256']}  {a['file']['path']}\n" for a in artifacts).encode())
    artifacts.append({"id": "checksums", "file": attempt_index.file_ref(root, checksums)})


def write_bundle(selection, output, repository, *, draft=False, journal_heads=None):
    root = selection.parent.resolve(strict=True)
    acceptance.require(output.parent.resolve(strict=True) == root and output.name not in (selection.name, "SHA256SUMS"),
                       "manifest must have its own name in the selections directory")
    manifest = compose(root, acceptance.read_json(attempt_index.owned_file(root, selection.name)), repository)
    artifacts = manifest["artifacts"]
    gates = {g["id"]: g for g in manifest["gates"]}
    reported = next((a for a in artifacts if a["id"] == "operating-limits"), None)
    if operating_limits.GATES <= gates.keys():
        path = root / (reported["file"]["path"] if reported else "operating-limits.md")
        publish(path, operating_limits.render(root, gates, manifest["source"], report_dir=path.parent))
        if reported is None:
            artifacts.append({"id": "operating-limits", "file": attempt_index.file_ref(root, path)})
            artifacts.sort(key=lambda row: row["id"])
    elif reported is not None:
        raise ValueError("selected operating limits lack original reference measurements")
    remaining = {"artifacts": sorted(acceptance.required_artifacts() - {"checksums"} - {a['id'] for a in artifacts}),
                 "gates": sorted(acceptance.required_gates() - {g['id'] for g in manifest['gates']}),
                 "platforms": sorted(set(acceptance.PLATFORMS) - {c['platform'] for c in manifest['candidates']})}
    if not draft:
        acceptance.require(not any(remaining.values()), "release selections incomplete: " + json.dumps(remaining))
        acceptance.require(journal_heads is not None, "final verification requires the operator's journal heads")
    if not remaining["artifacts"]:
        write_checksums(root, artifacts)
    data = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    if not draft:
        verifier_name = "scripts/verify_release_acceptance.py"
        verifier = attempt_index.owned_file(repository, verifier_name)
        files = acceptance.json_reference(root, manifest["source"]["files"])
        acceptance.require(acceptance.sha256(verifier) == files[verifier_name]["sha256"],
                           "final verifier differs from the frozen source")
        with tempfile.NamedTemporaryFile(dir=root, suffix=".json") as staged:
            staged.write(data)
            staged.flush()
            result = subprocess.check_output([sys.executable, "-I", "-B", "-S", verifier, staged.name,
                                              "--repository", repository, "--journal-heads", journal_heads])
            receipt = acceptance.decode(result)
            acceptance.require(receipt.get("status") == "passed" and receipt.get("schema") == acceptance.SCHEMA
                               and receipt.get("domain_gates") == len(acceptance.required_gates())
                               and receipt.get("manifest_sha256") == hashlib.sha256(data).hexdigest(),
                               "verifier did not certify the composed manifest")
    publish(root / output.name, data)
    return {"status": "draft" if draft else "passed", "manifest": attempt_index.file_ref(root, root / output.name),
            "remaining": remaining}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("selection", type=Path)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--draft", action="store_true", help="write incomplete selections and report missing results")
    parser.add_argument("--journal-heads", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(write_bundle(args.selection, args.output, args.repository, draft=args.draft,
                                      journal_heads=args.journal_heads), sort_keys=True))
    except (KeyError, OSError, TypeError, ValueError, subprocess.CalledProcessError, tarfile.TarError) as exc:
        print(f"Release manifest composition failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
