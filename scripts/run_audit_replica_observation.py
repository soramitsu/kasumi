"""Retain a newly pruned audit chain from all three live installed data voters."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid

if __name__ == "__main__":
    scripts = Path(__file__).resolve(strict=True).parent
    if not (
        sys.flags.isolated
        and sys.flags.no_site
        and sys.flags.dont_write_bytecode
        and sys.pycache_prefix is None
        and "PYTHONPYCACHEPREFIX" not in os.environ
    ):
        raise SystemExit("audit replica observation requires -I -B -S")
    if any(
        p.name == "__pycache__"
        or p.suffix in {".pyc", ".pyo"}
        or (p.suffix == ".py" and p.is_symlink())
        for p in scripts.rglob("*")
    ):
        raise SystemExit("only frozen Python sources can be executed")
    sys.path.insert(0, str(scripts))

import concurrency_workloads as work
import domain_run
from domain_run import require
import process_ha_topology as topology
import repeatable_assembly as owned
import run_concurrency as ha
import run_installed_observability as observation
import verify_release_acceptance as acceptance

RUNNER = "scripts/run_audit_replica_observation.py"
MODULES = (
    "scripts/concurrency_workloads.py",
    "scripts/run_concurrency.py",
    "scripts/run_installed_observability.py",
    "scripts/installed_observation.py",
    "scripts/run_correctness.py",
    "scripts/run_observability_probes.py",
)


def cache_root(config):
    """The installed ordinary tenant shares its node's durable database root."""
    data = Path(config["database_path"])
    directory = Path(
        config.get("tenant_audit_cache") or data.parent / "tenant-audit-archives"
    )
    require(
        directory.is_absolute() and data.is_absolute(),
        "installed paths are not absolute",
    )
    return directory


def copy_segment(config, reference, output):
    link = reference["object"]
    name = str(uuid.UUID(link["object_id"])) + ".audit"
    require(
        name == link["object_id"] + ".audit"
        and 0 < reference["ciphertext_bytes"] <= 8 << 20
        and re.fullmatch("[0-9a-f]{64}", link["ciphertext_sha256"]),
        "invalid archive identity",
    )
    directory = cache_root(config)
    require(
        directory == directory.resolve(strict=True),
        "archive directory traverses a link",
    )
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    dirname = os.open(directory, flags)
    try:
        data = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=dirname,
        )
        with os.fdopen(data, "rb") as stream:
            before = os.fstat(stream.fileno())
            require(
                stat.S_ISREG(before.st_mode)
                and before.st_size == reference["ciphertext_bytes"],
                "archive is missing, not regular, or has another length",
            )
            with output.open("xb") as copy:
                os.fchmod(copy.fileno(), 0o600)
                digest = hashlib.sha256()
                while chunk := stream.read(65536):
                    require(
                        copy.tell() + len(chunk) <= reference["ciphertext_bytes"],
                        "archive grew while retained",
                    )
                    digest.update(chunk)
                    copy.write(chunk)
                copy.flush()
                os.fsync(copy.fileno())
            now = os.stat(name, dir_fd=dirname, follow_symlinks=False)
            require(
                os.path.samestat(before, now)
                and (before.st_mtime_ns, before.st_size)
                == (now.st_mtime_ns, now.st_size)
                and digest.hexdigest() == link["ciphertext_sha256"],
                "replica returned a different or changing archive",
            )
            return {
                "object_id": link["object_id"],
                "path": str(directory / name),
                "device": before.st_dev,
                "inode": before.st_ino,
                "sha256": digest.hexdigest(),
                "bytes": before.st_size,
            }
    finally:
        os.close(dirname)


def identity(status, tenant, incarnation):
    require(
        status["tenant"] == tenant
        and status["incarnation"] == incarnation
        and str(uuid.UUID(status["position"]["stream_id"]))
        == status["position"]["stream_id"],
        "audit observation differs from enrolled tenant generation",
    )
    return status["position"]


def check_page(page, tenant, incarnation, start, through, index, cursor, links):
    require(
        page["tenant"] == tenant
        and page["incarnation"] == incarnation
        and page["stream_id"] == start["stream_id"]
        and page["through_index"] == through
        and 1 <= len(page["results"]) <= 32,
        "audit verification page changed stream or bounds",
    )
    for row in page["results"]:
        if index == start["archive_segments"]:
            break
        ref = row["reference"]
        require(
            row["index"] == index - 1
            and row["object"] == cursor
            and ref
            and ref["object"] == cursor
            and ref["stream_id"] == start["stream_id"]
            and row["cache"] == "verified"
            and 0 < ref["ciphertext_bytes"] <= 8 << 20
            and ref["record_count"]
            == cursor["next_sequence"] - cursor["first_sequence"]
            > 0,
            "stored dependency, ordinal or checked ciphertext differs",
        )
        previous = ref["previous"]
        require(
            (previous is None and cursor["first_sequence"] == 0)
            or (
                previous is not None
                and previous["next_sequence"] == cursor["first_sequence"]
            ),
            "audit predecessor sequence gap",
        )
        links.append(ref)
        index -= 1
        cursor = previous
    return index, cursor


def check_copies(ref, configs, rows, retained):
    require(
        len(configs) == 3 and set(rows) == set(retained) == set(configs),
        "all three original data voters must retain the dependency",
    )
    identities = set()
    for name, config in configs.items():
        item = rows[name]
        require(
            item["path"]
            == str(cache_root(config) / (ref["object"]["object_id"] + ".audit"))
            and item["object_id"] == ref["object"]["object_id"]
            and item["sha256"]
            == retained[name]["sha256"]
            == ref["object"]["ciphertext_sha256"]
            and item["bytes"] == retained[name]["bytes"] == ref["ciphertext_bytes"]
            and item["inode"] > 0,
            "original voter ciphertext or durable location differs",
        )
        identities.add((item["device"], item["inode"]))
    require(
        len(identities) == 3, "three archive copies refer to the same physical inode"
    )


def observe(run, plan_path, topology_path):
    require(
        run.bind() == acceptance.REFERENCE,
        "the nine-process installed audit observation requires native Linux ARM64",
    )
    functional = owned.read(run.evidence / "evidence.json")
    python = functional["python_executable"]["path"]
    require(
        owned.sha256(python) == functional["python_executable"]["sha256"],
        "original functional interpreter differs",
    )
    plan = owned.read(run.configuration("audit-plan", plan_path))
    owned.exact(
        plan, {"schema", "data_profile", "operator_profile"}, "installed audit plan"
    )
    require(plan["schema"] == "kasumi-audit-replica-v1", "wrong installed audit plan")
    profiles = {
        role: owned.read(run.configuration(role + "-profile", plan[role + "_profile"]))
        for role in ("data", "operator")
    }
    run.configuration("ha-topology", topology_path)
    admitted = topology.inspect(topology_path.resolve(strict=True), run.environment)
    nodes = admitted["nodes"]
    configs = {}
    certs = {}
    pins = {}
    inputs = {}
    for n in nodes:
        name = n["id"]
        cfg = configs[name] = owned.read(run.configuration("node-" + name, n["config"]))
        files = {
            "replication": cfg["replication"]["listener"]["tls"]["certificate"],
            "native": cfg["native"]["tls"]["certificate"],
        }
        if n["role"] != "authority":
            files["admin"] = cfg["admin"]["tls"]["certificate"]
        certs[name] = {k: owned.retain(run.output, Path(p)) for k, p in files.items()}
        if n["role"] == "data":
            pins[n["node_id"]] = {
                k: topology.certificate(owned.check_ref(run.output, certs[name][k]))[
                    "leaf_sha256"
                ]
                for k in ("admin", "native")
            }
        inputs.update({p: certs[name][k]["sha256"] for k, p in files.items()})
    collection = "audit_" + uuid.uuid5(uuid.NAMESPACE_URL, run.attempt_id).hex
    aliases = {
        **plan,
        "schema": "kasumi-concurrency-plan-v1",
        "collection": collection,
        "destination": "local",
    }
    voters, tenant, incarnation = ha.plan_data(
        aliases, profiles, list(configs.values()), pins
    )
    ha.role_bindings(configs, nodes, certs, run.output, tenant, incarnation, voters)
    data_nodes = {n["id"]: configs[n["id"]] for n in nodes if n["role"] == "data"}
    parameter_paths = {role: plan[role + "_profile"] for role in profiles}
    inputs.update({path: owned.sha256(path) for path in parameter_paths.values()})
    for n in nodes:
        require(
            n["executable"]["sha256"]
            == run.report["binaries"][
                "kasumi-authority" if n["role"] == "authority" else "kasumid"
            ],
            "topology selected another product",
        )
    details = {
        "functional_sha256": owned.sha256(run.evidence / "evidence.json"),
        "certificates": certs,
        "polls": {},
        "objects": [],
    }
    run.report["details"] = details
    run.save()
    services = ha.start_cluster(run, run.binary_paths, nodes)
    server = run.binary_paths["kasumid"]
    client = run.binary_paths["kasumictl"]
    operator = plan["operator_profile"]
    data = plan["data_profile"]

    def request(name, value):
        path = run.output / (name + ".json")
        domain_run.durable_json(path, value)
        return str(path)

    def q(name, command):
        raw = run.command(name, list(map(str, command)), 180)
        require(
            run.report["processes"][-1]["executable"]["sha256"]
            == (
                functional["python_executable"]["sha256"]
                if command[0] == python
                else run.report["binaries"][Path(command[0]).name]
            ),
            "audit operation did not use the original native process",
        )
        return owned.read(raw)

    status = [server, "tenant-audit", "status", operator]
    observation.poll(
        run,
        details,
        "startup",
        status,
        lambda v: identity(v, tenant, incarnation) is not None,
    )
    services.enter("measured")
    membership = request("membership", {"operation": "status"})
    actual = q(
        "membership-before", [client, "--profile", operator, "manage", membership]
    )
    work.raft_observation(actual, incarnation, voters)
    before = identity(q("audit-before", status), tenant, incarnation)
    spec = ha.collection({"collection": collection})
    spec["strict_read_audit"] = True
    made = q(
        "collection",
        [
            client,
            "--profile",
            operator,
            "create-collection",
            request("collection-input", spec),
        ],
    )
    require(made["revision"] > 0, "strict audit collection was not installed")
    body = {"step": 1, "sha256": hashlib.sha256(run.attempt_id.encode()).hexdigest()}
    put = q(
        "put",
        [
            client,
            "--profile",
            data,
            "put",
            collection,
            "record",
            json.dumps(body, separators=(",", ":")),
            "--if",
            "absent",
        ],
    )
    require(
        put["ok"] and put["result"]["receipt"]["revision"] >= made["revision"],
        "original native write failed",
    )
    # One command has its own receipt, duration and clean drain. The owner can
    # interrupt a long run without losing which strict reads actually completed.
    for i in range(50000):
        got = q(
            f"read-{i:05d}", [client, "--profile", data, "get", collection, "record"]
        )
        require(
            got["ok"] and got["result"]["document"]["body"] == body,
            "strict read lost the written body",
        )
        if (i + 1) % 32 == 0:
            last = identity(q(f"position-{i:05d}", status), tenant, incarnation)
            require(
                last["stream_id"] == before["stream_id"],
                "audit stream changed during workload",
            )
            if (
                last["archive_segments"] > before["archive_segments"]
                and last["pruned_before"] > before["pruned_before"]
            ):
                break
    else:
        raise ValueError(
            "fifty thousand original strict reads did not produce a new pruned archive"
        )
    cap = q("capacity", [server, "tenant-audit", "capacity", operator])
    require(
        cap["tenant"] == tenant
        and cap["incarnation"] == incarnation
        and cap["stream_id"] == before["stream_id"],
        "capacity came from another application",
    )
    c = cap["capacity"]
    budget = c["hot_budget_bytes"]
    require(
        c["starts_at_bytes"] == budget - budget // 4
        and c["drains_to_bytes"] == budget // 2
        and c["max_segment_bytes"] == 8 << 20,
        "installed audit thresholds differ",
    )
    links = []
    continuation = None
    seen = set()
    index = None
    head = None
    for page_no in range(128):
        query = request(f"verify-{page_no:03d}", {"cursor": continuation, "limit": 32})
        page = q(
            f"page-{page_no:03d}", [server, "tenant-audit", "verify", operator, query]
        )
        if index is None:
            through = index = page["through_index"]
            head = page["snapshot_head"]
            cursor = head
            require(
                through > before["archive_segments"],
                "verified chain omits the new durable prefix",
            )
        require(page["snapshot_head"] == head, "continuation switched captured head")
        index, cursor = check_page(
            page, tenant, incarnation, before, through, index, cursor, links
        )
        if index == before["archive_segments"]:
            break
        continuation = page["cursor"]
        require(
            continuation and continuation not in seen,
            "archive cursor missing or repeated",
        )
        seen.add(continuation)
    else:
        raise ValueError("archive chain exceeds one observation")
    require(
        cursor == (before["archive_head"] or {}).get("object")
        and len(links) == through - before["archive_segments"],
        "new durable prefix did not link to the original head",
    )
    for i, ref in enumerate(links):
        file = request(f"object-{i:04d}", ref)
        facts = {}
        objects = {}
        for name, cfg in data_nodes.items():
            services.assert_alive()
            n = next(n for n in nodes if n["id"] == name)
            dst = run.output / f"data-{name}-{i:04d}.audit"
            facts[name] = q(
                f"copy-{name}-{i:04d}",
                [
                    python,
                    "-I",
                    "-B",
                    "-S",
                    str(run.source / RUNNER),
                    "copy",
                    n["config"],
                    file,
                    str(dst),
                ],
            )
            objects[name] = owned.ref(run.output, dst)
        check_copies(ref, data_nodes, facts, objects)
        details["objects"].append(
            {"reference": ref, "voters": facts, "ciphertexts": objects}
        )
        run.save()
    after = q("membership-after", [client, "--profile", operator, "manage", membership])
    work.raft_observation(after, incarnation, voters)
    require(
        after["raft_applied_index"] >= actual["raft_applied_index"]
        and after["raft_membership_index"] == actual["raft_membership_index"],
        "audit observation spans an unrelated voting configuration",
    )
    details.update(
        reads=sum(item["id"].startswith("read-") for item in run.report["processes"]),
        tenant=tenant,
        incarnation=incarnation,
        capacity=cap,
        before=before,
        through=through,
    )
    services.enter("drain")
    topology.verify_unchanged(admitted, run.environment)
    require(
        all(owned.sha256(p) == h for p, h in inputs.items()),
        "installed audit identity changed",
    )
    for n in reversed(nodes):
        require(
            domain_run.service_disposition(services.stop(n["id"])) == "clean-stop",
            "audit voter did not drain",
        )
    run.passed(details)


def main():
    if sys.argv[1:2] == ["copy"] and len(sys.argv) == 5:
        print(
            json.dumps(
                copy_segment(
                    owned.read(Path(sys.argv[2])),
                    owned.read(Path(sys.argv[3])),
                    Path(sys.argv[4]),
                ),
                sort_keys=True,
            )
        )
        return
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("evidence", "journal", "output", "topology", "plan"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--attempt-id", required=True)
    a = parser.parse_args()
    with domain_run.Run(
        "audit-retention",
        RUNNER,
        MODULES,
        a.evidence,
        a.output,
        a.journal,
        a.attempt_id,
        {},
        domain_run.REHEARSAL,
    ) as run:
        observe(run, a.plan, a.topology)


if __name__ == "__main__":
    main()
