#!/usr/bin/env python3
"""Read saved Cargo metadata/lock; never invoke Cargo or accept a patched decoder."""
import argparse
import hashlib
import json
from pathlib import Path
import tomllib

KASUMI = {"kasumi-client", "kasumi-types", "kasumi-clock", "kasumi-serving", "kasumi-transport"}
FIXTURE = "kasumi-stock-json-sdk-consumer"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
SERDE_JSON_SHA = "c841b55ecdae098c80dcae9cf767f6f8a0c2cdb3416bbef72181df4d0fe73f14"


def verify(metadata, lock, fixture, mode):
    fixture = fixture.resolve()
    sdk = fixture.parents[1]
    manifest = tomllib.loads((fixture / "Cargo.toml").read_text())
    if "patch" in manifest or "replace" in manifest or "workspace" not in manifest:
        raise ValueError("fixture must own its workspace without dependency overrides")
    if Path(metadata["workspace_root"]).resolve() != fixture:
        raise ValueError("Cargo used the Kasumi workspace root")
    packages = metadata["packages"]
    by_name = {}
    for package in packages:
        by_name.setdefault(package["name"], []).append(package)
    local = {p["name"] for p in packages if p["source"] is None}
    if local != KASUMI | {FIXTURE}:
        raise ValueError(f"unexpected local package graph: {sorted(local)}")
    for name in KASUMI:
        if len(by_name[name]) != 1:
            raise ValueError("duplicate SDK package")
        if Path(by_name[name][0]["manifest_path"]).resolve() != sdk / "crates" / name / "Cargo.toml":
            raise ValueError("SDK package path differs from the frozen checkout")
    if len(by_name[FIXTURE]) != 1:
        raise ValueError("duplicate consumer package")
    root_id = by_name[FIXTURE][0]["id"]
    if metadata["workspace_members"] != [root_id] or metadata["resolve"]["root"] != root_id:
        raise ValueError("fixture is not the sole workspace root")
    for package in packages:
        if package["source"] is not None and package["source"] != REGISTRY:
            raise ValueError("unexpected non-registry dependency")
        if package["name"].startswith("kasumi-") and package["name"] not in local:
            raise ValueError("unexpected registry Kasumi package")
    if len(by_name.get("serde_json", [])) != 1:
        raise ValueError("expected one stock serde_json package")
    decoder = by_name["serde_json"][0]
    if decoder["version"] != "1.0.151" or decoder["source"] != REGISTRY:
        raise ValueError("stock serde_json 1.0.151 was not selected")
    locked = [p for p in lock["package"] if p["name"] == "serde_json"]
    if len(locked) != 1 or locked[0].get("checksum") != SERDE_JSON_SHA or locked[0].get("source") != REGISTRY:
        raise ValueError("published serde_json archive checksum differs")
    for name in ("serde", "serde_core"):
        if len(by_name.get(name, [])) != 1 or by_name[name][0]["version"] != "1.0.229":
            raise ValueError("locked Serde buffering version differs")
    node = next(n for n in metadata["resolve"]["nodes"] if n["id"] == decoder["id"])
    consumer_node = next(n for n in metadata["resolve"]["nodes"] if n["id"] == root_id)
    consumer_features = set(consumer_node["features"])
    expected_consumer_features = {"default"}
    if mode in ("numbers-and-raw", "ordered"):
        expected_consumer_features.add("numbers-and-raw")
    if mode == "ordered":
        expected_consumer_features.add("ordered")
    if consumer_features != expected_consumer_features:
        raise ValueError("consumer feature selection differs from the requested mode")
    for candidate in metadata["resolve"]["nodes"]:
        if {"test-utils", "embedded-fixture", "loopback-fixture"} & set(candidate["features"]):
            raise ValueError("fixture capabilities entered the consumer graph")
    features = set(node["features"])
    if not {"arbitrary_precision", "raw_value", "std"} <= features:
        raise ValueError("effective SDK decoder features differ")
    if ("preserve_order" in features) != (mode == "ordered"):
        raise ValueError("preserve_order mode differs")
    return {"fixture_root": str(fixture), "local_packages": sorted(local),
            "consumer_features": sorted(consumer_features),
            "serde_json": {"id": decoder["id"], "version": decoder["version"],
                           "source": decoder["source"], "features": sorted(features),
                           "checksum": SERDE_JSON_SHA},
            "root_patch_absent": True,
            "scope": "Resolver graph only; no compiled binary or network acceptance claim"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("metadata", type=Path)
    parser.add_argument("--mode", choices=("default", "numbers-and-raw", "ordered"), required=True)
    args = parser.parse_args()
    fixture = Path(__file__).resolve().parent
    data = args.metadata.read_bytes()
    lock_bytes = (fixture / "Cargo.lock").read_bytes()
    report = verify(json.loads(data), tomllib.loads(lock_bytes.decode()), fixture, args.mode)
    report.update(metadata_sha256=hashlib.sha256(data).hexdigest(),
                  lock_sha256=hashlib.sha256(lock_bytes).hexdigest())
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
