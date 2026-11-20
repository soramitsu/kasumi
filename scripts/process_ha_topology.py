"""Admission for a local, separately installed nine-process HA rehearsal.

This is not a release-domain adapter. A successful inspection only establishes
the stated local topology and immutable input bytes. Native check-config,
provisioning, authenticated readiness and workload observations remain required.
No credentials, keys, certificates or installation authority are generated here.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import re
import stat
import uuid

import gate_process

SCHEMA = "kasumi-process-ha-plan-v1"
MAX_INPUT_BYTES = 2 << 20


def require(condition, message):
    if not condition:
        raise ValueError(message)


def exact(value, fields, name):
    require(isinstance(value, dict) and set(value) == set(fields), name + " fields differ")


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON member")
        result[key] = value
    return result


def regular_bytes(path, limit=MAX_INPUT_BYTES):
    path = Path(path)
    require(path.is_absolute() and path == path.resolve(strict=True), "input path is not canonical")
    before = path.stat()
    require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, "input is not a bounded regular file")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    after = path.stat()
    require(len(data) <= limit and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), "input changed while reading")
    return data


def read_json(path):
    data = regular_bytes(path)
    value = json.loads(data.decode("utf-8"), object_pairs_hook=unique_pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON number")))
    require(isinstance(value, dict), "JSON input is not an object")
    return value, hashlib.sha256(data).hexdigest()


def certificate(path):
    data = regular_bytes(path, 1 << 20)
    # Chain files are valid product inputs. Only the actual first leaf identifies
    # this process; changing chain whitespace cannot create a distinct identity.
    blocks = re.findall(rb"-----BEGIN CERTIFICATE-----\s+([A-Za-z0-9+/=\s]+?)\s+-----END CERTIFICATE-----", data)
    residue = re.sub(rb"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+?\s+-----END CERTIFICATE-----", b"", data)
    require(blocks and not residue.strip(), "certificate file is not a PEM certificate chain")
    der = [base64.b64decode(re.sub(rb"\s", b"", block), validate=True) for block in blocks]
    require(all(der), "empty certificate")
    return {"path": str(path), "file_sha256": hashlib.sha256(data).hexdigest(),
            "leaf_sha256": hashlib.sha256(der[0]).hexdigest()}


def directory(path):
    selected = Path(path)
    require(selected.is_absolute() and selected == selected.resolve(strict=True)
            and selected.is_dir(), "storage root is not an existing canonical directory")
    require(selected.stat().st_mode & 0o077 == 0, "storage root is not private")
    return selected


def beneath(path, roots):
    selected = Path(path)
    require(selected.is_absolute() and selected == selected.resolve(), "storage file is not canonical")
    require(any(root in selected.parents for root in roots), "storage file lies outside its own persistent roots")
    return selected


def transport_roster(role, peers, voters):
    """Three genesis voters may share a Data transport pool with future learners."""
    require(isinstance(voters, list) and len(voters) == 3
            and all(type(node) is int and node > 0 for node in voters)
            and len(set(voters)) == 3, "each HA group requires three original voters")
    require(isinstance(peers, list) and 3 <= len(peers) <= (64 if role == "data" else 3)
            and all(isinstance(peer, dict) and type(peer.get("node_id")) is int
                    and peer["node_id"] > 0 for peer in peers), "invalid HA peer roster")
    by_id = {peer["node_id"]: peer for peer in peers}
    require(len(by_id) == len(peers) and set(voters) <= by_id.keys(),
            "transport peer IDs repeat or omit an original voter")
    return by_id


def verify_control_placement(nodes, configs):
    """Bind the three data voters to the signing root of the three hosted Control voters."""
    controls = [n for n in nodes if n["role"] == "control"]
    data = [n for n in nodes if n["role"] == "data"]
    require(len(controls) == len(data) == 3, "dedicated placements require three data and three Control voters")
    control_ids = {str(node["node_id"]) for node in controls}
    data_ids = {str(node["node_id"]) for node in data}
    root = None
    for node in controls:
        config = configs[node["id"]]
        hosted = config.get("control")
        require(isinstance(hosted, dict) and config.get("remote_control") is None
                and config.get("tenants") == [] and config.get("target_recovery") is None,
                "Control-only process must not host data or target recovery and must host Control")
        catalog = hosted.get("remote_data")
        require(isinstance(catalog, dict) and isinstance(catalog.get("nodes"), dict)
                and data_ids <= set(catalog["nodes"]), "hosted Control does not enroll the data voters")
        lifecycle = hosted.get("lifecycle")
        require(isinstance(lifecycle, dict) and isinstance(lifecycle.get("installation"), dict),
                "dedicated Control lacks its signing installation")
        signing = lifecycle["installation"].get("root")
        exact(signing, {"control_incarnation", "public_key"}, "hosted Control signing root")
        incarnation = signing["control_incarnation"]
        require(isinstance(incarnation, str) and len(incarnation) == 36 and uuid.UUID(incarnation).int
                and str(uuid.UUID(incarnation)) == incarnation and incarnation == hosted.get("incarnation")
                and isinstance(signing["public_key"], str) and re.fullmatch(r"[0-9a-f]{64}", signing["public_key"])
                and (root is None or root == signing), "dedicated Control signing roots differ")
        root = signing
    for node in data:
        config = configs[node["id"]]
        remote = config.get("remote_control")
        require(config.get("control") is None and config.get("tenants") and isinstance(remote, dict),
                "data voter must host tenants and use remote Control")
        require(remote.get("root") == root and isinstance(remote.get("endpoints"), dict)
                and set(remote["endpoints"]) == control_ids, "data voter selects another Control root or roster")


def verify_retained_control(nodes, retained):
    configs = {n["id"]: read_json(retained["node-" + n["id"]])[0] for n in nodes if n["role"] != "authority"}
    verify_control_placement(nodes, configs)


def inspect(plan_path, environment):
    """Read exact installed inputs without opening any private key or token."""
    plan, plan_sha = read_json(plan_path)
    exact(plan, {"schema", "binaries", "nodes"}, "HA plan")
    require(plan["schema"] == SCHEMA, "unsupported HA plan")
    exact(plan["binaries"], {"kasumid", "kasumi-authority"}, "candidate binaries")
    binaries = {}
    for name, path in plan["binaries"].items():
        selected = Path(path)
        require(selected.is_absolute() and selected == selected.resolve(strict=True), "candidate path is not canonical")
        binaries[name] = gate_process.executable_identity([str(selected)], selected.parent, environment)
    require(isinstance(plan["nodes"], list) and len(plan["nodes"]) == 9, "HA requires nine installed processes")
    ids, physical_ids, certificates, roots, databases, roles = set(), set(), set(), [], set(), {}
    nodes = []
    configs = {}
    for value in plan["nodes"]:
        exact(value, {"id", "role", "group", "config"}, "HA node")
        name, role, group = value["id"], value["role"], value["group"]
        require(isinstance(name, str) and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", name)
                and name not in ids, "invalid or duplicate process identity")
        ids.add(name)
        require(role in {"data", "control", "authority"} and isinstance(group, str)
                and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", group), "invalid HA role or group")
        roles.setdefault(role, []).append(group)
        config, config_sha = read_json(value["config"])
        if role != "authority":
            configs[name] = config
            require(config.get("mode") == "replicated", "data and Control require replicated mode")
            tenants = config.get("tenants")
            require(isinstance(tenants, list), "tenant roster missing")
            if role == "control":
                require(not tenants and config.get("target_recovery") is None,
                        "Control-only process must not host tenants or recovery targets")
            else:
                require(tenants, "data process has no installed tenants")
        replication = config.get("replication")
        require(isinstance(replication, dict), "replication configuration missing")
        node_id = replication.get("node_id")
        require(type(node_id) is int and node_id > 0 and node_id not in physical_ids,
                "HA physical node identities must be distinct")
        physical_ids.add(node_id)
        peers, voters = replication.get("peers"), replication.get("initial_voters")
        transports = transport_roster(role, peers, voters)
        require(node_id in voters, "each HA process must host an original voter")
        tls = replication["listener"]["tls"]
        cert = certificate(tls["certificate"])
        require(cert["leaf_sha256"] not in certificates, "HA leaf TLS identities are not distinct")
        certificates.add(cert["leaf_sha256"])
        own = transports[node_id]
        require(own.get("certificate_pins") == [cert["leaf_sha256"]], "installed leaf differs from exact current peer pin")
        persistent = config.get("persistent_disk", {}).get("roots")
        require(isinstance(persistent, dict) and persistent, "persistent roots missing")
        owned_roots = [directory(path) for path in persistent.values()]
        owned_roots.append(directory(config["scratch_disk"]["directory"]))
        for root in owned_roots:
            require(all(root != previous and root not in previous.parents and previous not in root.parents
                        and (root.stat().st_dev, root.stat().st_ino)
                        != (previous.stat().st_dev, previous.stat().st_ino) for previous in roots),
                    "HA persistent and scratch roots overlap or alias")
            roots.append(root)
        selected_databases = [beneath(config["database_path"], owned_roots[:-1])]
        verifier = config.get("signer_verifier")
        require(isinstance(verifier, dict) and verifier.get("identity", {}).get("node_id") == node_id,
                "installed physical signer verifier missing or belongs to another node")
        selected_databases.append(beneath(verifier["database_path"], owned_roots[:-1]))
        for selected in selected_databases:
            require(selected not in databases, "database or verifier storage is shared")
            databases.add(selected)
        nodes.append({**value, "config_sha256": config_sha, "node_id": node_id,
                      "voters": sorted(voters), "peers": peers, "certificate": cert,
                      "persistent_roots": [str(p) for p in owned_roots[:-1]],
                      "scratch_root": str(owned_roots[-1]),
                      "executable": binaries["kasumi-authority" if role == "authority" else "kasumid"]})
    require(set(roles) == {"data", "control", "authority"}, "HA role coverage differs")
    groups = set()
    for role, values in roles.items():
        require(len(values) == 3 and len(set(values)) == 1 and values[0] not in groups,
                "HA requires three separate groups of three processes")
        groups.add(values[0])
        selected = [node for node in nodes if node["role"] == role]
        roster = sorted(node["node_id"] for node in selected)
        require(all(node["voters"] == roster and node["peers"] == selected[0]["peers"] for node in selected),
                "installed peer sets differ or cross role boundaries")
        require(all(peer["node_id"] in roster or peer["node_id"] not in physical_ids
                    for peer in selected[0]["peers"]), "transport learner reuses another group's member")
    verify_control_placement(nodes, configs)
    return {"schema": SCHEMA, "plan": str(plan_path), "plan_sha256": plan_sha,
            "qualification": "local-input-inspection-only", "binaries": binaries, "nodes": nodes}


def verify_unchanged(admitted, environment):
    require(inspect(admitted["plan"], environment) == admitted, "installed HA inputs changed")
