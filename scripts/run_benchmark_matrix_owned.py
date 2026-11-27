#!/usr/bin/env python3
"""Run the fifteen native benchmark cases against enrolled, dedicated installations."""
import argparse
import json
import os
from pathlib import Path
import resource
import sys

if __name__ == "__main__":
    scripts = Path(__file__).resolve().parent
    if not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode
            and sys.pycache_prefix is None and "PYTHONPYCACHEPREFIX" not in os.environ):
        raise SystemExit("benchmark matrix requires Python -I -B -S")
    if any(p.name == "__pycache__" or p.suffix in {".pyc", ".pyo"}
           or (p.suffix == ".py" and p.is_symlink()) for p in scripts.rglob("*")):
        raise SystemExit("benchmark matrix requires source-only Python imports")
    sys.path.insert(0, str(scripts))

import domain_run
import repeatable_assembly as owned
import run_benchmark_probes as probes
import verify_release_acceptance as acceptance
from domain_run import require
from release_gate import sha256

KIND = "benchmark-matrix"
RUNNER = "scripts/run_benchmark_matrix_owned.py"
MODULES = ("scripts/run_benchmark_probes.py",)
TIMEOUT = 86_400
CASES = [(mode, tenants) for tenants in acceptance.TENANTS for mode in acceptance.MODES]


def plan_inputs(plan, mode, tenants, config, prefix):
    owned.exact(plan, {"mode", "documents", "operations", "nodes", "tenants", "load"} | ({"network"} if mode == "network" else set()), "installed matrix plan")
    # Uncertain-batch resolution bounds are fixed here, before the driver runs.
    acceptance.load_bounds(plan["load"])
    require(plan["mode"] == mode and type(plan["documents"]) is int and plan["documents"] == probes.DOCUMENTS
            and type(plan["operations"]) is int and plan["operations"] == probes.OPERATIONS
            and len(plan["nodes"]) == (3 if mode == "replicated" else 1)
            and type(plan["tenants"]) is dict and len(plan["tenants"]) == tenants, "shortened installed case")
    for names in plan["tenants"].values():
        owned.exact(names, {"administrator", "application"}, "trusted embedded principals")
        require(all(isinstance(v, str) and v for v in names.values()), "missing enrolled principal")

    def select(suffix, entry):
        owned.exact(entry, {"path", "sha256"}, "enrolled benchmark input")
        p = Path(entry["path"])
        require(p.is_absolute(), "enrollment input path must be absolute")
        path = config(prefix + suffix, p)
        require(sha256(path) == entry["sha256"], "enrollment input differs from exact plan")
        return owned.read(path)

    nodes = [select("-node-" + str(i), entry) for i, entry in enumerate(plan["nodes"])]
    network = probes.network_inputs(select("-network", plan["network"]), tenants) if mode == "network" else None
    return nodes, network


def original_outputs(root, directory, native, expected):
    seal = json.loads(native, object_pairs_hook=acceptance.object_pairs)
    owned.exact(seal, {"schema", "files"}, "native benchmark output receipt")
    require(seal["schema"] == "kasumi-benchmark-outputs-v1" and set(seal["files"]) == expected, "incomplete native output receipt")
    for name in expected:
        output = directory / name
        reference = owned.ref(root, output)
        require(reference["sha256"] == seal["files"][name], "native output differs from original stdout hash")
        owned.check_ref(root, reference)
    return seal["files"]


def installed_case(root, directory, name, digest, raw, plan, node_inputs, network, replay):
    mode, count = name.rsplit("-", 1)
    count = int(count)
    expected = {"case.json", "load-batches.jsonl"} | ({"network.json"} if network is not None else set())
    original_outputs(root, directory, raw, expected)
    case = owned.read(directory / "case.json")
    owned.exact(case, {"schema", "executable_sha256", "plan_sha256", "mode", "attempt", "nodes", "tenants", "voters",
                       "documents", "canonical_bytes", "load", "measurements", "complete"}, "native installed benchmark")
    names = sorted(plan["tenants"])
    require(case["schema"] == "kasumi-installed-embedded-v2" and case["executable_sha256"] == digest
            and case["mode"] == mode and case["complete"] is True and case["tenants"] == names
            and set(case["voters"]) == set(names) and len(case["nodes"]) == len(node_inputs)
            and type(case["documents"]) is int and case["documents"] == probes.DOCUMENTS
            and type(case["canonical_bytes"]) is int and case["canonical_bytes"] == probes.DOCUMENTS * 1024,
            "native mode, tenants, corpus or driver differs")
    voters = set()
    incarnations = {}
    for i, (facts, config) in enumerate(zip(case["nodes"], node_inputs)):
        owned.exact(facts, {"configuration_sha256", "database_id", "voter", "providers"}, "installed node facts")
        require(facts["configuration_sha256"] == plan["nodes"][i]["sha256"] and facts["database_id"] == config["database_id"]
                and config["mode"] == ("replicated" if mode == "replicated" else "standalone"), "installed identity differs")
        stores = {t["tenant"]: [t["keys"]["kind"], t["custody_keys"]["kind"]] for t in config["tenants"]}
        require(sorted(stores) == names and facts["providers"] == stores
                and all(k in ("file", "transit") for ks in stores.values() for k in ks), "fixture or substitute storage provider")
        for tenant in config["tenants"]:
            require(incarnations.setdefault(tenant["tenant"], tenant.get("incarnation")) == tenant.get("incarnation"),
                    "installed tenant incarnation differs between nodes")
        if mode == "replicated":
            voter = config["replication"]["node_id"]
            require(type(voter) is int and facts["voter"] == voter and voter not in voters, "duplicate or invalid committed voter")
            voters.add(voter)
        else:
            require(facts["voter"] is None and not config.get("replication"), "local case used replicated enrollment")
    for observed in case["voters"].values():
        require(isinstance(observed, list) and all(type(v) is int for v in observed)
                and (set(observed) == voters and len(observed) == 3 if mode == "replicated" else len(observed) == 1),
                "effective tenant membership differs")
    # Recompute the corpus and its recovery cost from the ordered, hash-bound
    # batch records, then bind every receipt scope and key to this plan and run.
    records = owned.ref(root, directory / "load-batches.jsonl")
    summary, order, scopes, prefix = acceptance.check_load(root, records, plan["load"], count, probes.DOCUMENTS)
    require(order == names and prefix == case["attempt"]
            and all(scopes[t] == {"tenant": t, "incarnation": incarnations[t], "principal": plan["tenants"][t]["application"]}
                    for t in names),
            "corpus load tenants, receipt scopes or idempotency keys differ from this plan and attempt")
    require(acceptance.strict_equal(case["load"], summary) and summary["documents"] == case["documents"]
            and summary["canonical_bytes"] == case["canonical_bytes"],
            "native corpus load summary differs from its ordered records")
    if network is not None:
        require(case["measurements"] == [], "network case substituted embedded workload")
        workloads = probes.network_samples(root, owned.read(directory / "network.json"), network, digest, count, replay)
    else:
        by_name = acceptance.unique(case["measurements"], "name", "native installed workloads")
        expected_names = acceptance.BASE_WORKLOADS | ({"text_english_Phrase_complete_pages", "text_english_Prefix_complete_pages",
            "text_english_Fuzzy_complete_pages", "text_japanese_Terms_complete_pages"} if mode == "text" else set())
        require(set(by_name) == expected_names, "missing installed benchmark workload")
        workloads = [probes.project(root, target, by_name[target], probes.OPERATIONS,
                                    root / (name + "-" + target + ".jsonl"), replay) for target in sorted(by_name)]
    return {"id": name, "mode": mode, "tenants": count, "documents": summary["documents"], "provider": "production",
            "load": {**summary, "records": records}, "workloads": workloads}


def matrix(custody, original_output, plans_path, binary, digest, config, command, replay=False):
    cases = []
    for mode, tenants in CASES:
        name = f"{mode}-{tenants}"
        directory = custody / (name + ".native")
        original = original_output / directory.name
        if mode == "raw":
            if not replay:
                directory.mkdir()
            raw = command(name, [binary, "--raw-baseline", str(tenants), str(probes.DOCUMENTS), str(probes.OPERATIONS), str(original / "case.json")])
            original_outputs(custody, directory, raw, {"case.json"})
            case = probes.raw_case(custody, owned.read(directory / "case.json"), digest, tenants, replay=replay)
        else:
            retained = config(name + "-plan", plans_path / (name + ".json"))
            plan = owned.read(retained)
            node_inputs, network = plan_inputs(plan, mode, tenants, config, name)
            raw = command(name, [binary, "--installed-matrix", str(original_output / retained.relative_to(custody)), str(original), "--allow-writes"])
            case = installed_case(custody, directory, name, digest, raw, plan, node_inputs, network, replay)
            require(owned.read(directory / "case.json")["plan_sha256"] == sha256(retained), "different plan ran")
        cases.append(case)
    return cases


def execute(run, plans):
    target = run.bind()
    require(target == acceptance.REFERENCE, "the full matrix requires the reference native platform")
    source = run.evidence / "evidence.json"
    driver, digest = probes.driver(run.evidence, owned.read(source))

    def perform(step, args):
        log = run.command(step, args, TIMEOUT, scenario=step)
        require(run.report["processes"][-1]["executable"]["sha256"] == digest, "another executable ran")
        return log.read_bytes()

    limits = {name: list(resource.getrlimit(getattr(resource, "RLIMIT_" + name))) for name in ("AS", "CPU", "FSIZE", "NOFILE")}
    run.report["details"] = {"functional_sha256": sha256(source), "resource_limits": limits}
    run.save()
    cases = matrix(run.output, run.output, plans, str(driver), digest, run.configuration, perform)
    run.passed({**run.report["details"], "cases": cases})


def gate_details(root, report_path):
    root = Path(root).resolve(strict=True)
    report_path = Path(report_path).resolve(strict=True)
    custody = report_path.parent
    cases = owned.read(report_path)["details"]["cases"]
    for c in cases:
        for m in c["workloads"]:
            m["samples"] = owned.ref(root, owned.check_ref(custody, m["samples"]))
        if "load" in c:
            c["load"]["records"] = owned.ref(root, owned.check_ref(custody, c["load"]["records"]))
    return {"report": owned.ref(root, report_path), "cases": cases}


def verify_domain(root, domain, files, configs, _, candidates):
    facts = domain_run.verify_run(root, domain, files, configs, KIND, RUNNER, MODULES)
    report, custody = facts["report"], facts["custody"]
    primary = candidates[acceptance.REFERENCE]["primary"]["functional"]
    functional_path = acceptance.reference(root, primary)
    functional = owned.read(functional_path)
    built, digest = probes.driver(functional_path.parent, functional)
    original = Path(report["evidence_root"])
    executable = str(original / "target" / built.relative_to(functional_path.parent / "target"))
    parameters = report["invocation"]["parameters"]
    owned.exact(parameters, {"plans"}, "matrix parameters")
    plans = Path(parameters["plans"])
    require(plans.is_absolute() and report["details"]["functional_sha256"] == primary["sha256"]
            and domain["topology"] == [] and domain["artifacts"] == {}, "different functional run or platform")
    inputs = iter(report["configurations"])
    steps = iter(report["processes"])

    def config(identifier, path):
        item = next(inputs)
        require(item["id"] == identifier, "matrix input was substituted")
        return owned.check_ref(custody, item["file"])

    def command(step, command):
        item = next(steps)
        require(item["id"] == step and item["receipt"]["path"] == step + "/process.json"
                and item["log"]["path"] == step + "/stdout.log" and item["executable"]["sha256"] == digest, "matrix child was substituted")
        original_command = facts["receipts"][step]["record"]
        owned.check_owned(custody, {"id": step, "receipt": item["receipt"], "stdout": item["log"], "stderr": original_command["stderr"],
                                    "executable": item["executable"]}, command, str(original / "source"), TIMEOUT)
        return acceptance.reference(custody, item["log"]).read_bytes()

    verified = matrix(custody, Path(report["custody_root"]), plans, executable, digest, config, command, True)
    require(next(inputs, None) is None and next(steps, None) is None and report["details"]["cases"] == verified,
            "matrix report omitted or changed a case")
    require(domain["details"] == gate_details(root, custody / "report.json"), "matrix gate samples were substituted")
    by_scenario = acceptance.unique(report["scenarios"], "id", "matrix scenarios")
    require(set(by_scenario) == acceptance.SCENARIOS[KIND], "matrix scenario missing")
    for name in by_scenario:
        rows = domain_run.scenario_rows(acceptance, custody, by_scenario[name], facts["receipts"])
        require(len(rows) == 1 and rows[0]["step"] == name and rows[0]["exit_code"] == rows[0]["expected_exit"] == 0,
                "matrix scenario did not run its distinct original command")
    return facts["evidence"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("evidence", "output", "journal", "plans"):
        parser.add_argument("--" + key, type=Path, required=True)
    parser.add_argument("--attempt-id", required=True)
    args = parser.parse_args()
    plans = args.plans.resolve(strict=True)
    with domain_run.Run(KIND, RUNNER, MODULES, args.evidence, args.output, args.journal, args.attempt_id,
                        {"plans": str(plans)}, domain_run.QUALIFYING) as run:
        execute(run, plans)
