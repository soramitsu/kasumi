"""Retain a newly pruned audit chain from all three live installed data voters."""

import argparse
import datetime as dt
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
import package_release as package
import process_ha_topology as topology
import repeatable_assembly as owned
import run_concurrency as ha
import run_installed_observability as observation
import verify_release_acceptance as acceptance

VERIFY_LIMIT = 8
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
        and 1 <= len(page["results"]) <= VERIFY_LIMIT,
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


def application(attempt, plan, profiles, nodes, configs, certs, custody):
    pins = {
        n["node_id"]: {
            k: topology.certificate(owned.check_ref(custody, certs[n["id"]][k]))[
                "leaf_sha256"
            ]
            for k in ("native", "admin")
        }
        for n in nodes
        if n["role"] == "data"
    }
    collection = "audit_" + uuid.uuid5(uuid.NAMESPACE_URL, attempt).hex
    aliases = {
        **plan,
        "schema": "kasumi-concurrency-plan-v1",
        "collection": collection,
        "destination": "local",
    }
    voters, tenant, incarnation = ha.plan_data(
        aliases, profiles, list(configs.values()), pins
    )
    ha.role_bindings(configs, nodes, certs, custody, tenant, incarnation, voters)
    data_nodes = {n["id"]: configs[n["id"]] for n in nodes if n["role"] == "data"}
    return voters, tenant, incarnation, collection, data_nodes


def measure(
    attempt,
    original,
    custody,
    source,
    binaries,
    python,
    plan,
    nodes,
    application_inputs,
    request,
    q,
    alive,
):
    voters, tenant, incarnation, collection, data_nodes = application_inputs
    server, client = binaries["kasumid"], binaries["kasumictl"]
    operator, data = plan["operator_profile"], plan["data_profile"]
    status = [server, "tenant-audit", "status", operator]
    membership = request("membership", {"operation": "status"})
    actual = q(
        "membership-before", [client, "--profile", operator, "manage", membership]
    )
    work.raft_observation(actual, incarnation, voters)
    require(
        type(actual["raft_membership_index"]) is int,
        "initial management view has no applied membership position",
    )
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
    body = {"step": 1, "sha256": hashlib.sha256(attempt.encode()).hexdigest()}
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
        reads = i + 1
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
        query = request(
            f"verify-{page_no:03d}", {"cursor": continuation, "limit": VERIFY_LIMIT}
        )
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
    captured = []
    for i, ref in enumerate(links):
        file = request(f"object-{i:04d}", ref)
        facts = {}
        objects = {}
        for name, cfg in data_nodes.items():
            alive()
            n = next(n for n in nodes if n["id"] == name)
            dst = original / f"data-{name}-{i:04d}.audit"
            facts[name] = q(
                f"copy-{name}-{i:04d}",
                [
                    python,
                    "-I",
                    "-B",
                    "-S",
                    str(source / RUNNER),
                    "copy",
                    n["config"],
                    file,
                    str(dst),
                ],
            )
            objects[name] = owned.ref(custody, custody / dst.name)
        check_copies(ref, data_nodes, facts, objects)
        captured.append({"reference": ref, "voters": facts, "ciphertexts": objects})

    after = q("membership-after", [client, "--profile", operator, "manage", membership])
    work.raft_observation(after, incarnation, voters)
    require(
        after["raft_applied_index"] >= actual["raft_applied_index"]
        and after["raft_membership_index"] == actual["raft_membership_index"],
        "audit observation spans an unrelated voting configuration",
    )
    return dict(
        objects=captured,
        reads=reads,
        tenant=tenant,
        incarnation=incarnation,
        capacity=cap,
        before=before,
        through=through,
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
        inputs.update({p: certs[name][k]["sha256"] for k, p in files.items()})
    inputs_for_measurement = application(
        run.attempt_id, plan, profiles, nodes, configs, certs, run.output
    )
    _, tenant, incarnation, _, _ = inputs_for_measurement
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
    admission_file = run.output / "topology-admission.json"
    domain_run.durable_json(admission_file, admitted)
    details = {
        "functional_sha256": owned.sha256(run.evidence / "evidence.json"),
        "certificates": certs,
        "polls": {},
        "admission": owned.ref(run.output, admission_file),
        "phases": {},
    }
    run.report["details"] = details
    run.save()
    services = ha.start_cluster(run, run.binary_paths, nodes)
    server = run.binary_paths["kasumid"]
    operator = plan["operator_profile"]

    def request(name, value):
        path = run.output / (name + ".json")
        domain_run.durable_json(path, value)
        return str(path)

    def q(name, command):
        services.assert_alive()
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
    details["phases"]["measured"] = services.enter("measured")
    details["result"] = measure(
        run.attempt_id,
        run.output,
        run.output,
        run.source,
        run.binary_paths,
        python,
        plan,
        nodes,
        inputs_for_measurement,
        request,
        q,
        services.assert_alive,
    )
    details["phases"]["drain"] = services.enter("drain")
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


def replay_members(custody, report, admission, topology_plan, configs, paths, phases):
    nodes = admission["nodes"]
    roster = report["topology"]
    processes = report["processes"]
    acceptance.check_topology(roster, processes, report["binaries"], "required")
    require(
        len(nodes) == len(roster) == 9
        and len({n["node_id"] for n in nodes}) == 9
        and topology_plan["nodes"]
        == [{k: n[k] for k in ("id", "role", "group", "config")} for n in nodes]
        and 0
        <= phases["measured"]
        < phases["drain"]
        <= phases["measured"] + ha.PARAMETERS["measured_seconds_limit"],
        "original topology or measured service lifetime differs",
    )
    details = report["details"]
    original_source = Path(report["evidence_root"]) / "source"
    groups = set()
    roots = []
    for n, member, proc in zip(nodes, roster, processes[:9], strict=True):
        name = n["id"]
        cfg = configs[name]
        certs = details["certificates"][name]
        replication = cfg["replication"]
        members = sorted(v["node_id"] for v in nodes if v["role"] == n["role"])
        expected_pins = {
            v["node_id"]: v["certificate"]["leaf_sha256"]
            for v in nodes
            if v["role"] == n["role"]
        }
        peers = replication["peers"]
        tls = replication["listener"]["tls"]["certificate"]
        cert = topology.certificate(owned.check_ref(custody, certs["replication"]))
        exe = "kasumi-authority" if n["role"] == "authority" else "kasumid"
        pid = member["process_id"]
        record_path = owned.check_ref(custody, proc["receipt"])
        record = owned.read(record_path)
        require(
            proc["id"] == pid == record["id"]
            and record_path == custody / "services" / (pid + ".json")
            and owned.check_ref(custody, proc["log"])
            == custody / "services" / (pid + ".log")
            and owned.check_ref(custody, proc["executable"]).is_file()
            and member
            == {
                "id": name,
                "role": n["role"],
                "group": n["group"],
                "process_id": pid,
                "certificate_sha256": cert["leaf_sha256"],
            }
            and n["certificate"] == {**cert, "path": tls}
            and n["node_id"] == replication["node_id"]
            and n["voters"] == sorted(replication["initial_voters"]) == members
            and n["peers"] == peers
            and len(peers) == 3
            and {p["node_id"] for p in peers} == set(members)
            and all(
                p["certificate_pins"] == [expected_pins[p["node_id"]]] for p in peers
            )
            and (n["role"] == "authority" or cfg["mode"] == "replicated")
            and (
                n["role"] != "control"
                or (cfg["tenants"] == [] and cfg.get("target_recovery") is None)
            )
            and record["command"] == [paths[exe], "serve", n["config"]]
            and record["name"] == name
            and record["working_directory"] == str(original_source)
            and n["executable"]
            == record["executable"]
            == {"path": paths[exe], "sha256": report["binaries"][exe]}
            and record["phases"]["measured"] == phases["measured"]
            and record["phases"]["drain"] == phases["drain"]
            and record["started_elapsed_seconds"]
            <= phases["measured"]
            < phases["drain"]
            <= record["stop"]["elapsed_seconds"]
            and domain_run.service_disposition(record) == "clean-stop"
            and record["process_group"] not in groups,
            "enrolled daemon, physical identity, voter set or clean drain differs: "
            + name,
        )
        groups.add(record["process_group"])
        storage = list(map(Path, cfg["persistent_disk"]["roots"].values()))
        scratch = Path(cfg["scratch_disk"]["directory"])
        require(
            n["persistent_roots"] == list(map(str, storage))
            and n["scratch_root"] == str(scratch)
            and all(
                p.is_absolute() and ".." not in p.parts for p in [*storage, scratch]
            )
            and all(
                any(root in Path(key).parents for root in storage)
                for key in (
                    cfg["database_path"],
                    cfg["signer_verifier"]["database_path"],
                )
            ),
            "substituted installed storage",
        )
        for root in [*storage, scratch]:
            require(
                all(
                    root != old and old not in root.parents and root not in old.parents
                    for old in roots
                ),
                "shared physical root",
            )
            roots.append(root)


def replay_operations(custody, report, plan, nodes, inputs, paths, python, python_sha):
    details = report["details"]
    source = Path(report["evidence_root"]) / "source"
    original = Path(report["custody_root"])
    _, tenant, incarnation, _, _ = inputs
    queue = iter(report["processes"][9:])
    require(set(details["polls"]) == {"startup"}, "unexpected audit readiness group")
    polls = details["polls"]["startup"]
    require(1 <= len(polls) <= 601, "missing or unbounded readiness history")
    status = [paths["kasumid"], "tenant-audit", "status", plan["operator_profile"]]
    for i, item in enumerate(polls):
        code, raw = observation.original_command(
            custody,
            item,
            f"startup-{i:04d}",
            status,
            source,
            report["binaries"]["kasumid"],
            60,
        )
        if code == 0:
            identity(package._metadata_json(raw), tenant, incarnation)
            require(
                i + 1 == len(polls), "successful native audit readiness was ignored"
            )
            break
    else:
        raise ValueError("no original successful audit readiness observation")

    def request(name, value):
        retained = package.owned_file(custody, name + ".json")
        require(owned.read(retained) == value, "substituted audit request: " + name)
        return str(original / retained.name)

    def query(name, command):
        item = next(queue, None)
        require(
            item and item["id"] == name,
            "original audit operation missing, repeated or reordered: " + name,
        )
        digest = (
            python_sha
            if command[0] == python
            else report["binaries"][Path(command[0]).name]
        )
        code, raw = observation.original_command(
            custody, item, name, command, source, digest, 180
        )
        require(code == 0, "original audit operation failed: " + name)
        return package._metadata_json(raw)

    result = measure(
        report["attempt_id"],
        original,
        custody,
        source,
        paths,
        python,
        plan,
        nodes,
        inputs,
        request,
        query,
        lambda: None,
    )
    require(
        next(queue, None) is None and result == details["result"],
        "audit workload verdict or remaining operation roster differs",
    )
    return result


def replay(evidence, custody):
    """Check a transported component against the independently supplied frozen functional directory."""
    evidence = Path(evidence).resolve(strict=True)
    custody = Path(custody).resolve(strict=True)
    functional, _, target, binaries = package.verify_evidence(evidence)
    report = owned.read(package.owned_file(custody, "report.json"))
    owned.exact(report, domain_run.REPORT_FIELDS, "audit replica observation report")
    details = report["details"]
    owned.exact(
        details,
        {"functional_sha256", "admission", "certificates", "phases", "polls", "result"},
        "audit replica evidence",
    )
    files = owned.read(evidence / "source-files.json")
    scripts = domain_run.frozen_scripts(evidence / "source", files, {RUNNER, *MODULES})
    dates = [
        dt.datetime.fromisoformat(report[k]) for k in ("started_at", "finished_at")
    ]
    require(
        report["schema"] == domain_run.SCHEMA
        and report["kind"] == "audit-retention"
        and report["qualification"] == domain_run.REHEARSAL
        and report["status"] == "passed"
        and report["target"] == target == acceptance.REFERENCE
        and report["error"] is None
        and report["dispatch_started"] is True
        and report["scenarios"] == []
        and dates[0] <= dates[1]
        and Path(report["custody_root"]).is_absolute()
        and Path(report["evidence_root"]).is_absolute()
        and details["functional_sha256"] == owned.sha256(evidence / "evidence.json")
        and report["binaries"]
        == {name: digest for name, (_, digest) in binaries.items()}
        and report["source_scripts"] == scripts
        and report["invocation"]
        == {
            "parameters": {},
            "runner": {"source_path": RUNNER, "sha256": scripts[RUNNER]},
        }
        and report["source"]
        == {
            k: functional[v]
            for k, v in {
                "commit": "source_commit",
                "tree": "source_tree",
                "archive_sha256": "source_archive_sha256",
                "source_files_sha256": "source_files_sha256",
                "lockfile_sha256": "lockfile_sha256",
            }.items()
        },
        "audit component differs from its frozen functional candidate and source",
    )
    retained = {
        r["id"]: owned.check_ref(custody, r["file"]) for r in report["configurations"]
    }
    admitted = owned.read(owned.check_ref(custody, details["admission"]))
    nodes = admitted["nodes"]
    plan = owned.read(retained["audit-plan"])
    owned.exact(
        plan, {"schema", "data_profile", "operator_profile"}, "installed audit plan"
    )
    require(
        plan["schema"] == "kasumi-audit-replica-v1"
        and admitted["schema"] == topology.SCHEMA
        and admitted["qualification"] == "local-input-inspection-only"
        and admitted["plan_sha256"] == owned.sha256(retained["ha-topology"])
        and len(retained) == len(report["configurations"])
        and set(retained)
        == {
            "audit-plan",
            "ha-topology",
            "data-profile",
            "operator-profile",
            *("node-" + n["id"] for n in nodes),
        },
        "original installation admission or input inventory differs",
    )
    configs = {n["id"]: owned.read(retained["node-" + n["id"]]) for n in nodes}
    for n in nodes:
        require(
            owned.sha256(retained["node-" + n["id"]]) == n["config_sha256"],
            "substituted voter configuration",
        )
    profiles = {
        role: owned.read(retained[role + "-profile"]) for role in ("operator", "data")
    }
    paths = {
        name: str(Path(report["evidence_root"]) / path.relative_to(evidence))
        for name, (path, _) in binaries.items()
    }
    topo = owned.read(retained["ha-topology"])
    require(
        topo["binaries"]
        == {name: paths[name] for name in ("kasumid", "kasumi-authority")},
        "topology selected other executables",
    )
    require(
        set(details["certificates"]) == set(configs), "unexpected certificate roster"
    )
    for n in nodes:
        certs = details["certificates"][n["id"]]
        require(
            set(certs)
            == (
                {"native", "replication"}
                if n["role"] == "authority"
                else {"native", "replication", "admin"}
            ),
            "substituted TLS certificate roster",
        )
        for cert in certs.values():
            owned.check_ref(custody, cert)
    replay_members(custody, report, admitted, topo, configs, paths, details["phases"])
    inputs = application(
        report["attempt_id"],
        plan,
        profiles,
        nodes,
        configs,
        details["certificates"],
        custody,
    )
    python = functional["python_executable"]
    result = replay_operations(
        custody, report, plan, nodes, inputs, paths, python["path"], python["sha256"]
    )
    return {
        "qualification": domain_run.REHEARSAL,
        "target": target,
        "tenant": result["tenant"],
        "incarnation": result["incarnation"],
        "reads": result["reads"],
        "new_archives": len(result["objects"]),
        "voters": 3,
        "clean_processes": 9,
    }


def main():
    if sys.argv[1:2] == ["replay"]:
        cli = argparse.ArgumentParser(
            description="Verify a transported audit component"
        )
        cli.add_argument("--evidence", type=Path, required=True)
        cli.add_argument("--custody", type=Path, required=True)
        args = cli.parse_args(sys.argv[2:])
        print(json.dumps(replay(args.evidence, args.custody), sort_keys=True))
        return
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
