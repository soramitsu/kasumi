#!/usr/bin/env python3
"""Execute and independently verify two retained candidate assembly invocations.

No build, acceptance waiver, compatibility path, retry, or output-directory
reuse is supported. The supplied native dependency declaration belongs to the
same trusted-producer boundary as the release host inventory and attestation.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import sys

import assembly_inputs
import gate_process
import package_release as package
from release_gate import TOOLCHAIN, inventory, sha256, write_json

SCHEMA = "kasumi-repeatable-assembly-v1"
TIMEOUT_SECONDS = 1800
PROBE_TIMEOUT_SECONDS = 60
RUNNER = "scripts/repeatable_assembly.py"
SCRIPTS = {RUNNER, "scripts/package_release.py", "scripts/assembly_inputs.py",
           "scripts/release_gate.py", "scripts/gate_process.py", "scripts/verify_release_acceptance.py",
           "scripts/run_repeatable_assembly_owned.py"}


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def require(value, message):
    if not value:
        raise ValueError(message)


def exact(value, fields, name):
    require(isinstance(value, dict) and set(value) == set(fields), name + " fields differ")


def read(path):
    return package._metadata_json(package._metadata_bytes(path))


def ref(root, path):
    return package._metadata_ref(root, str(Path(path).relative_to(root)))


def check_ref(root, value):
    from pathlib import PurePosixPath
    name = value.get("path") if isinstance(value, dict) else None
    require(isinstance(name, str) and "\\" not in name and PurePosixPath(name).as_posix() == name
            and name != ".", "noncanonical assembly reference")
    from verify_release_acceptance import reference
    return reference(root, value)


def retain(root, path):
    """Deduplicate exact immutable bytes; never execute a retained copy implicitly."""
    path = Path(path)
    checksum = sha256(path)
    destination = root / "blobs" / checksum
    destination.parent.mkdir(exist_ok=True)
    if not destination.exists():
        with path.open("rb") as source, destination.open("xb") as output:
            shutil.copyfileobj(source, output)
            output.flush()
            os.fsync(output.fileno())
    require(sha256(destination) == checksum, "input changed while retaining bytes")
    return ref(root, destination)


def run_owned(root, name, command, source, environment, timeout, *, before_cleanup=None, after_cleanup=None):
    """Always retain the original child outcome, including an interrupted attempt."""
    directory = root / name
    directory.mkdir(exist_ok=False)
    executable = gate_process.executable_identity(command, source, environment)
    require(command[0] == executable["path"], "assembly command must select an absolute executable")
    retained = retain(root, Path(executable["path"]))
    require(retained["sha256"] == executable["sha256"], "executable changed before dispatch")
    with (directory / "stdout.log").open("xb") as stdout, (directory / "stderr.log").open("xb") as stderr:
        process = gate_process.run(command, source, environment, stdout, timeout,
                                  lambda value: write_json(directory / "process.json", value), stderr=stderr,
                                  before_cleanup=before_cleanup, after_cleanup=after_cleanup)
    process["outputs_stable"] = bool(process["cleanup"]["drained"] and not process["cleanup"]["errors"])
    process["stdout"] = ref(root, directory / "stdout.log")
    process["stderr"] = ref(root, directory / "stderr.log")
    write_json(directory / "process.json", process)
    return {"id": name, "receipt": ref(root, directory / "process.json"),
            "stdout": process["stdout"], "stderr": process["stderr"], "executable": retained}


def check_owned(root, item, command, cwd, timeout):
    exact(item, {"id", "receipt", "stdout", "stderr", "executable"}, "assembly process")
    paths = {key: check_ref(root, item[key]) for key in ("receipt", "stdout", "stderr", "executable")}
    process = read(paths["receipt"])
    require(process.get("command") == command and process.get("working_directory") == cwd,
            "assembly process command or working directory differs")
    require(process.get("executable") == {"path": command[0], "sha256": item["executable"]["sha256"]},
            "assembly process executable is unbound")
    require(process.get("stdout") == item["stdout"] and process.get("stderr") == item["stderr"],
            "assembly output is not the original process output")
    gate = {"command": command, "process": item["receipt"]["path"],
            "process_sha256": item["receipt"]["sha256"], "process_cleanup": process.get("cleanup"),
            "timeout_seconds": timeout, "timed_out": process.get("timed_out"),
            "received_signals": process.get("received_signals"), "process_error": process.get("error")}
    package.verify_process_receipt(root, gate, timeout)
    return process


def command(inputs, source, evidence, output, declaration):
    return [inputs["tools"]["python"]["path"], "-B", "-S", str(Path(source) / "scripts/package_release.py"),
            "--evidence", evidence, "--output", output, "--native-inputs", declaration]


def probe_commands(inputs):
    return {"cargo-version": [inputs["tools"]["cargo"]["path"], "-Vv"],
            "rustc-version": [inputs["tools"]["rustc"]["path"], "-vV"],
            "python-version": [inputs["tools"]["python"]["path"], "-B", "-S", "--version"]}


def check_probe_outputs(root, probes, inputs):
    values = {item["id"]: check_ref(root, item["stdout"]).read_text() for item in probes}
    require(set(values) == set(probe_commands(inputs)), "native tool probe roster differs")
    for tool in ("cargo", "rustc"):
        text = values[tool + "-version"]
        require(text.splitlines()[0].startswith(tool + " " + TOOLCHAIN + " "),
                "native " + tool + " version differs")
        require([line for line in text.splitlines() if line.startswith("host: ")] ==
                ["host: " + inputs["target"]], "native " + tool + " host differs")
    parts = values["python-version"].strip().split()
    require(len(parts) == 2 and parts[0] == "Python", "Python version probe is malformed")
    version = tuple(int(n) for n in parts[1].split("."))
    require(version >= (3, 11, 0), "Python is older than 3.11")


def check_config_ancestry(source, cargo_home):
    """Cargo may read ancestor config and wrapper commands even while offline."""
    source = Path(source)
    for parent in source.parents:
        require(not any((parent / ".cargo" / name).exists() for name in ("config", "config.toml")),
                "Cargo configuration outside frozen source is unsupported")
    import tomllib
    for config in (source / ".cargo/config", source / ".cargo/config.toml"):
        if config.exists():
            value = tomllib.loads(config.read_text())
            require("env" not in value, "Cargo environment configuration is unsupported for assembly")
            build = value.get("build", {})
            require(not any(key in build for key in ("rustc-wrapper", "rustc-workspace-wrapper")),
                    "Cargo compiler wrappers are unsupported for assembly")
    require(not any((Path(cargo_home) / name).exists() for name in ("config", "config.toml")),
            "Cargo home configuration is outside frozen source")


def execute_pair(root, inputs, source, evidence, declaration, environment, observe):
    """The internal custody primitive; callers must validate inputs before dispatch.

    Tests may execute synthetic packagers here. This function alone does not
    produce or validate a native repeatable-assembly gate.
    """
    invocations = []
    for name in ("assembly-a", "assembly-b"):
        output = root / (name + "-output")
        require(not output.exists(), "assembly output is not independently fresh")
        selected = command(inputs, source, evidence, str(output), declaration)
        item = run_owned(root, name, selected, source, environment, TIMEOUT_SECONDS)
        invocation = {"id": name, "output_root": str(output), "process": item, "outputs": None}
        invocations.append(invocation)
        observe(invocations)
        check_owned(root, item, selected, source, TIMEOUT_SECONDS)
        invocation["outputs"] = inventory(output)
        observe(invocations)
    return invocations


def frozen_input_names(functional, production, source_files):
    """Name the complete original inputs retained for repeatable assembly."""
    selected = {"evidence.json", "source-files.json", "source.tar", functional["python_executable"]["artifact"]}
    for gate in functional["gates"]:
        selected.update(gate[key] for key in ("log", "resources", "process"))
    selected.update("target/" + relative for relative in production["executables"])
    selected.update("source/" + relative for relative in source_files)
    return selected


def check_frozen_input_roster(frozen, functional, production, source_files):
    require(set(frozen) == frozen_input_names(functional, production, source_files),
            "assembly frozen input roster differs from original functional evidence")


def evidence_inputs(evidence, functional, production):
    """Exactly the frozen source, provenance, gate transcripts and binaries read by packaging."""
    selected = frozen_input_names(functional, production, inventory(evidence / "source"))
    return {name: assembly_inputs.file_identity(package.owned_file(evidence, name)) for name in sorted(selected)}


def run(evidence, declaration, destination):
    evidence = Path(evidence).resolve(strict=True)
    declaration = Path(declaration).resolve(strict=True)
    destination = Path(destination)
    require(destination.is_absolute() and not destination.resolve().is_relative_to(evidence),
            "assembly custody must be outside frozen evidence")
    destination.mkdir(exist_ok=False)
    record = {"schema": SCHEMA, "status": "running", "started_at": now(), "finished_at": None,
              "evidence_root": str(evidence), "source_root": str(evidence / "source"),
              "custody_root": str(destination), "declaration_path": str(declaration),
              "declaration": None, "frozen_inputs": None, "dependencies": None,
              "probes": [], "assemblies": [], "frozen_after": None, "dependencies_after": None, "error": None}
    attempt = destination / "attempt.json"
    write_json(attempt, record)
    try:
        inputs = assembly_inputs.validate_declaration(read(declaration))
        require(str(Path(sys.executable).resolve(strict=True)) == inputs["tools"]["python"]["path"],
                "assembly runner interpreter differs from declared Python")
        require(inputs["target"] in package.TARGETS, "unsupported native assembly target")
        functional, production, target, binaries = package.verify_evidence(evidence)
        require(target == inputs["target"], "assembly native target differs from qualified binaries")
        source = evidence / "source"
        check_config_ancestry(source, inputs["cargo_home"])
        for relative in SCRIPTS:
            package.verify_file(source, relative, sha256(Path(__file__).parent / Path(relative).name))
        for name, identity in inputs["tools"].items():
            package.verify_architecture(identity["path"], target)
        before = evidence_inputs(evidence, functional, production)
        dependencies = assembly_inputs.observe(inputs)
        assembly_inputs.consumed(inputs, source, {"packages": []}, dependencies)
        record["declaration"] = retain(destination, declaration)
        # Bytes of dependencies and the complete frozen evidence are retained,
        # allowing read-only verification away from this build host.
        frozen = {relative: {"identity": identity, "file": retain(destination, evidence / relative)}
                  for relative, identity in before.items()}
        declared = {path: {"identity": identity, "file": retain(destination, Path(path))}
                    for path, identity in dependencies.items()}
        write_json(destination / "frozen-inputs.json", frozen)
        write_json(destination / "dependencies.json", declared)
        record["frozen_inputs"] = ref(destination, destination / "frozen-inputs.json")
        record["dependencies"] = ref(destination, destination / "dependencies.json")
        home = destination / "home"
        home.mkdir()
        environment = assembly_inputs.environment(inputs, home)
        group_ledger = os.environ.get(gate_process.GROUP_LEDGER_ENV)
        if group_ledger is not None:
            require(group_ledger == str(destination.parent / "descendant-groups.jsonl")
                    and Path(group_ledger).is_file() and not Path(group_ledger).is_symlink(),
                    "owned process group ledger is missing")
            environment[gate_process.GROUP_LEDGER_ENV] = group_ledger
        if sys.platform == "darwin":
            inspector = gate_process.executable_identity(["ps"], source, environment)
            require(dependencies.get(inspector["path"], {}).get("sha256") == inspector["sha256"],
                    "native process census executable is not a declared host dependency")
        for name, selected in probe_commands(inputs).items():
            item = run_owned(destination, name, selected, str(source), environment, PROBE_TIMEOUT_SECONDS)
            record["probes"].append(item)
            write_json(attempt, record)
            check_owned(destination, item, selected, str(source), PROBE_TIMEOUT_SECONDS)
        check_probe_outputs(destination, record["probes"], inputs)
        def observed(assemblies):
            record["assemblies"] = assemblies
            write_json(attempt, record)
        execute_pair(destination, inputs, str(source), str(evidence), str(declaration), environment, observed)
        after = evidence_inputs(evidence, functional, production)
        dependencies_after = assembly_inputs.observe(inputs)
        write_json(destination / "frozen-after.json", after)
        write_json(destination / "dependencies-after.json", dependencies_after)
        record["frozen_after"] = ref(destination, destination / "frozen-after.json")
        record["dependencies_after"] = ref(destination, destination / "dependencies-after.json")
        require(after == before, "assembly changed frozen evidence")
        require(dependencies_after == dependencies, "assembly changed declared dependencies")
        require(sha256(declaration) == record["declaration"]["sha256"], "assembly declaration changed")
        record["status"] = "passed"
        record["finished_at"] = now()
        write_json(attempt, record)
        verify(destination, ref(destination, attempt))
        assembly_inputs.consumed(inputs, source, {"packages": []}, dependencies)
        return record
    except BaseException as error:
        record["status"] = "failed"
        record["error"] = repr(error)
        record["finished_at"] = now()
        write_json(attempt, record)
        raise


def verify(root, receipt):
    """Read-only semantic check of the two original process-produced assemblies."""
    root = Path(root).resolve(strict=True)
    original = check_ref(root, receipt).read_bytes()
    record = package._metadata_json(original)
    exact(record, {"schema", "status", "started_at", "finished_at", "evidence_root", "source_root",
                   "custody_root", "declaration_path", "declaration", "frozen_inputs", "dependencies",
                   "probes", "assemblies", "frozen_after", "dependencies_after", "error"}, "repeatable assembly")
    require(record["schema"] == SCHEMA and record["status"] == "passed" and record["error"] is None,
            "repeatable assembly did not pass")
    require(dt.datetime.fromisoformat(record["finished_at"]) > dt.datetime.fromisoformat(record["started_at"]),
            "assembly has no elapsed interval")
    for name in ("evidence_root", "source_root", "custody_root", "declaration_path"):
        require(isinstance(record[name], str) and Path(record[name]).is_absolute(), "assembly root is not absolute")
    require(record["source_root"] == str(Path(record["evidence_root"]) / "source"), "source root differs")
    inputs = read(check_ref(root, record["declaration"]))
    exact(inputs, {"schema", "target", "tools", "roots", "host_files", "host_inventory", "cargo_home"}, "input declaration")
    require(inputs["schema"] == assembly_inputs.SCHEMA and inputs["target"] in package.TARGETS,
            "unsupported input declaration")
    exact(inputs["tools"], assembly_inputs.TOOLS, "native tools")
    exact(inputs["roots"], assembly_inputs.ROLES, "declared roots")
    frozen = read(check_ref(root, record["frozen_inputs"]))
    dependencies = read(check_ref(root, record["dependencies"]))
    require(isinstance(frozen, dict) and frozen and isinstance(dependencies, dict) and dependencies,
            "frozen inputs or dependencies are absent")
    for inventory_ in (frozen, dependencies):
        for entry in inventory_.values():
            exact(entry, {"identity", "file"}, "retained input")
            exact(entry["identity"], {"sha256", "bytes", "executable"}, "input identity")
            path = check_ref(root, entry["file"])
            require(entry["identity"]["sha256"] == entry["file"]["sha256"] and
                    entry["identity"]["bytes"] == path.stat().st_size and
                    type(entry["identity"]["executable"]) is bool, "retained input identity differs")
    for after_name, before in (("frozen_after", frozen), ("dependencies_after", dependencies)):
        require(read(check_ref(root, record[after_name])) == {name: entry["identity"] for name, entry in before.items()},
                "assembly inputs changed between original observations")
    source_files = read(check_ref(root, frozen["source-files.json"]["file"]))
    require({name.removeprefix("source/"): entry["identity"] for name, entry in frozen.items() if name.startswith("source/")} == source_files,
            "retained source bytes differ from frozen source inventory")
    functional = read(check_ref(root, frozen["evidence.json"]["file"]))
    production = [gate for gate in functional["gates"] if gate["name"] == "production"]
    require(len(production) == 1, "functional production evidence is ambiguous")
    check_frozen_input_roster(frozen, functional, production[0], source_files)
    for relative in SCRIPTS:
        require(source_files.get(relative, {}).get("sha256") == sha256(Path(__file__).parent / Path(relative).name),
                "assembly runner/parser differs from retained frozen source")
    from verify_release_acceptance import archive_inventory
    require(archive_inventory(check_ref(root, frozen["source.tar"]["file"]), strip_root=False) == source_files,
            "retained source archive differs from source inventory")
    for tool, value in inputs["tools"].items():
        exact(value, {"path", "sha256"}, "native tool")
        require(value["path"] in dependencies and dependencies[value["path"]]["identity"]["sha256"] == value["sha256"],
                "native tool is not a declared retained dependency")
        package.verify_architecture(check_ref(root, dependencies[value["path"]]["file"]), inputs["target"])
    for tool in ("cargo", "rustc"):
        require(inputs["tools"][tool]["path"] == str(Path(inputs["roots"]["rust-sysroot"]) / "bin" / tool),
                "tool is a wrapper outside direct native sysroot")
    require(isinstance(inputs["host_files"], list) and inputs["host_files"], "host dependency declaration is empty")
    for item in [*inputs["host_files"], inputs["host_inventory"]]:
        exact(item, {"path", "sha256"}, "host declaration")
        require(dependencies.get(item["path"], {}).get("identity", {}).get("sha256") == item["sha256"],
                "host dependency evidence is unbound")
    probes = {item["id"]: item for item in record["probes"]}
    require(len(probes) == len(record["probes"]) == 3 and set(probes) == set(probe_commands(inputs)),
            "duplicate or missing native probe")
    for name, selected in probe_commands(inputs).items():
        check_owned(root, probes[name], selected, record["source_root"], PROBE_TIMEOUT_SECONDS)
        tool = name.removesuffix("-version")
        require(probes[name]["executable"]["sha256"] == inputs["tools"][tool]["sha256"], "probe tool changed")
    check_probe_outputs(root, record["probes"], inputs)
    require([item.get("id") for item in record["assemblies"]] == ["assembly-a", "assembly-b"],
            "both original independent assembly invocations are required")
    output_inventories = []
    target = inputs["target"]
    for item in record["assemblies"]:
        exact(item, {"id", "output_root", "process", "outputs"}, "assembly invocation")
        expected_output = str(Path(record["custody_root"]) / (item["id"] + "-output"))
        require(item["output_root"] == expected_output and item["process"]["id"] == item["id"],
                "assembly output directory is reused or misbound")
        selected = command(inputs, record["source_root"], record["evidence_root"], expected_output, record["declaration_path"])
        process = check_owned(root, item["process"], selected, record["source_root"], TIMEOUT_SECONDS)
        require(item["process"]["executable"]["sha256"] == inputs["tools"]["python"]["sha256"],
                "assembly interpreter differs")
        output = root / (item["id"] + "-output")
        require(inventory(output) == item["outputs"], "assembly output differs from original drained inventory")
        for name, identity in item["outputs"].items():
            check_ref(root, {"path": (item["id"] + "-output/" + name), "sha256": identity["sha256"], "bytes": identity["bytes"]})
        declared = read(output / "declared-inputs.json")
        require(declared == {path: value["identity"] for path, value in dependencies.items()},
                "packager did not bind the declared dependency inventory")
        consumed = read(output / "consumed-inputs.json")
        require(isinstance(consumed, list) and consumed and len(consumed) == len(set(consumed)) and
                set(consumed) <= set(declared), "packager actual input consumption is unbound")
        source_files = read(check_ref(root, frozen["source-files.json"]["file"]))
        metadata = package.verify_metadata_capture(output / "metadata-custody", target, source_files)
        metadata_receipt = read(output / "metadata-custody/process.json")
        require(metadata_receipt["executable"] == inputs["tools"]["cargo"], "metadata used a different Cargo")
        require(metadata_receipt["working_directory"] == record["source_root"], "metadata used another source")
        # Cached manifests/notices used by every reported package must be bound
        # before metadata dispatch, not retrofitted from output after success.
        for dependency in metadata["packages"]:
            manifest = dependency["manifest_path"]
            if not Path(manifest).is_relative_to(record["source_root"]):
                require(manifest in declared and manifest in consumed, "metadata package manifest is unbound")
        output_inventories.append(item["outputs"])
    first, second = output_inventories
    archives = {name for name in first if name.endswith(".tar.gz") and "/" not in name}
    require(len(archives) == 2 and archives == {name for name in second if name.endswith(".tar.gz") and "/" not in name},
            "package/source archive roster differs")
    require(sum(name.endswith("-source.tar.gz") for name in archives) == 1 and
            sum(name.endswith("-" + target + ".tar.gz") for name in archives) == 1,
            "assembly produced the wrong native package")
    for name in archives:
        require(first[name] == second[name], "independent assembly archives differ byte-for-byte")
    source_archive = next(name for name in archives if name.endswith("-source.tar.gz"))
    package_archive = next(name for name in archives if name != source_archive)
    require(archive_inventory(root / "assembly-a-output" / source_archive) == source_files,
            "assembled source archive differs from consumed frozen source")
    packaged = archive_inventory(root / "assembly-a-output" / package_archive)
    binaries = {}
    for relative, binary in production[0]["executables"].items():
        name = binary["target"]
        require(name in package.BINARIES and name not in binaries and binary["test"] is False,
                "production executable roster differs")
        require(frozen["target/" + relative]["identity"]["sha256"] == binary["sha256"],
                "consumed production binary differs from functional evidence")
        require(packaged.get("bin/" + name, {}).get("sha256") == binary["sha256"],
                "assembled binary differs from consumed qualified binary")
        binaries[name] = binary["sha256"]
    require(set(binaries) == package.BINARIES, "assembled native binary set is incomplete")
    for name in ("LICENSE", "NOTICE", "SECURITY.md", "CONTRIBUTING.md"):
        require(packaged.get(name) == source_files.get(name), "assembled legal/documentation input differs")
    for name, entry in source_files.items():
        if name.startswith("release/systemd/"):
            require(packaged.get(name.removeprefix("release/")) == entry, "assembled systemd input differs")
    require(check_ref(root, receipt).read_bytes() == original, "assembly receipt changed during verification")
    return {"record": record, "inputs": inputs, "frozen": frozen, "archives": sorted(archives)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--native-inputs", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    run(args.evidence, args.native_inputs, args.output)
    print("Two candidate assemblies verified: " + str(args.output))
    return 0



def domain_adapter(root, domain, files, configs, artifacts):
    """Acceptance bridge, still unregistered pending native runner validation."""
    import verify_release_acceptance as acceptance
    import run_repeatable_assembly_owned as owned
    exact(domain["details"], {"launcher", "report", "second_package", "second_source"},
          "assembly domain details")
    launcher_path = acceptance.reference(root, domain["details"]["launcher"])
    report_path = acceptance.reference(root, domain["details"]["report"])
    attempt_root = report_path.parent
    launch_root = launcher_path.parent
    require(launcher_path.name == "launcher.json" and report_path.name == "attempt.json"
            and attempt_root == launch_root / "assembly", "assembly launcher/report layout differs")
    launched = owned.verify(launch_root, ref(launch_root, launcher_path))
    parsed = launched["inner"]
    record, inputs, frozen = parsed["record"], parsed["inputs"], parsed["frozen"]
    target = domain["id"].split(":", 1)[1]
    require(inputs["target"] == target, "assembly domain target differs")
    require(domain["runner"] == {"source_path": owned.LAUNCHER, "sha256": files[owned.LAUNCHER]["sha256"]},
            "assembly domain runner differs from fixed contract")
    require(domain["started_at"] == launched["record"]["started_at"]
            and domain["finished_at"] == launched["record"]["finished_at"],
            "assembly domain did not retain the actual invocation interval")
    source_files = read(check_ref(attempt_root, frozen["source-files.json"]["file"]))
    require(source_files == files, "assembly domain consumed another frozen source")
    require(frozen["source.tar"]["file"]["sha256"] == domain["identity"]["source_archive_sha256"] and
            frozen["source-files.json"]["file"]["sha256"] == domain["identity"]["source_files_sha256"],
            "assembly domain source provenance differs")
    functional = read(check_ref(attempt_root, frozen["evidence.json"]["file"]))
    for name in ("source_commit", "source_tree", "lockfile_sha256"):
        require(functional[name] == domain["identity"][name], "assembly functional identity differs")
    declared_configs = [key for key, value in configs.items() if value["file"]["sha256"] == record["declaration"]["sha256"]]
    require(len(declared_configs) == 1 and domain["configuration_ids"] == declared_configs,
            "assembly native input configuration is unbound or ambiguous")
    actual = {}
    def global_ref(relative):
        path = check_ref(attempt_root, relative)
        result = ref(Path(root), path)
        acceptance.reference(root, result)
        return result
    runner = launched["record"]["runner_process"]
    def launcher_ref(relative):
        path = check_ref(launch_root, relative)
        result = ref(Path(root), path)
        acceptance.reference(root, result)
        return result
    actual["runner"] = {"id": "runner", "receipt": launcher_ref(runner["receipt"]),
                        "log": launcher_ref(runner["stdout"]),
                        "executable": launcher_ref(runner["executable"])}
    for item in [*record["probes"], *(entry["process"] for entry in record["assemblies"])]:
        actual[item["id"]] = {"id": item["id"], "receipt": global_ref(item["receipt"]),
                              "log": global_ref(item["stdout"]), "executable": global_ref(item["executable"])}
    for name in ("assembly-a", "assembly-b"):
        directory = attempt_root / (name + "-output") / "metadata-custody"
        actual[name + "-metadata"] = {"id": name + "-metadata", "receipt": ref(Path(root), directory / "process.json"),
                                     "log": ref(Path(root), directory / "stdout.json"),
                                     "executable": ref(Path(root), directory / "executable")}
    require(acceptance.unique(domain["processes"], "id", "assembly domain processes") == actual,
            "assembly domain omitted or substituted an actual owned child")
    scenarios = acceptance.unique(domain["scenarios"], "id", "assembly scenarios")
    require(set(scenarios) == {"assembly-a", "assembly-b"}, "assembly scenario roster differs")
    for name in scenarios:
        require(scenarios[name] == {"id": name, "status": "passed", "iterations": 1,
                                  "failures": 0, "unattempted": 0, "log": actual[name]["log"]},
                "assembly scenario does not describe its actual completed invocation")
    for name in parsed["archives"]:
        source = name.endswith("-source.tar.gz")
        artifact_id = "source" if source else "package:" + target
        first = attempt_root / "assembly-a-output" / name
        second = attempt_root / "assembly-b-output" / name
        require(sha256(first) == artifacts[artifact_id]["file"]["sha256"],
                "delivered artifact differs from actual assembly output")
        field = "second_source" if source else "second_package"
        require(domain["details"][field] == ref(Path(root), second),
                "repeat output is not the second original assembly artifact")
    # Join every transitive byte to the enclosing acceptance verifier's final
    # observation seal, including raw metadata transcripts and dependency blobs.
    for path in launch_root.rglob("*"):
        if path.is_file():
            acceptance.reference(root, ref(Path(root), path))


if __name__ == "__main__":
    raise SystemExit(main())
