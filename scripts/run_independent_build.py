#!/usr/bin/env python3
"""Produce one native independent production compilation for release acceptance.

The attempt is admitted to this host's native journal before any output,
input copy or validation exists, so every outcome, including a rejected input,
is an original terminal row. Every operator input is retained by exact bytes
inside the admitted output and parsed from the retained copy.

A fresh source tree is extracted from the frozen Git archive named by the
release identity, and Cargo builds it into a fresh target directory with the
verifier's exact fixture-free production command:

    cargo +1.97.1 build --release -p kasumi-server --bins --no-default-features
        --locked -j <jobs> --message-format=json-render-diagnostics

A direct sysroot Cargo rejects ``+toolchain``, so the command runs Rustup's
``cargo`` proxy from the declared Cargo home. The ``assembly_inputs``
declaration is mandatory: the proxy's resolved Rustup executable must be one
of its ``host_files``, the selector must name its Rust sysroot and the child
receives the declaration's explicit offline environment. No ambient Cargo,
Rustup or Python setting reaches the compiler.

The one Cargo process is owned by ``gate_process``; its receipt, combined log
and executable bytes are retained, and the actual binaries are hashed only
after its process group drains. The terminal outcome names those binaries as
products and selects ``independent-build.json`` as its ``build_evidence``. That
record uses final bundle paths, ``native-attempts/<journal-id>/<output>/...``,
because the release verifier reads it from the transported bundle. A failed
or interrupted attempt keeps its partial products and the same record.

Run it with the declared native Python from the frozen source::

    python3 -I -S -B /frozen/source/scripts/run_independent_build.py \\
      --journal /native/custody --attempt-id independent-1 \\
      --output /native/custody/independent-1 \\
      --identity /operator/release-identity.json \\
      --source-archive /operator/source.tar \\
      --native-inputs /operator/assembly-inputs/inputs.json \\
      --host-preflight /operator/host-preflight.json \\
      --host-attestation /operator/host-attestation.txt \\
      --host-reservation /operator/host-reservation.json --jobs 2

The identity file holds the verifier's seven source identity fields. The
preflight is ``release_host.py`` output for this target, and the reservation
holds ``id``, ``starts_at``, ``ends_at``, ``cpu_count``, ``memory_bytes`` and
``disk_bytes``. This is a trusted-producer record, like the host attestation:
it does not authenticate an adversarial host.
"""
from __future__ import annotations

import sys
if __name__ == "__main__" and not (sys.flags.isolated and sys.flags.no_site
                                  and sys.flags.dont_write_bytecode):
    raise SystemExit("independent build producer requires native Python -I -S -B")

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import signal
import subprocess
import tarfile

if __name__ == "__main__":
    _scripts = Path(__file__).resolve(strict=True).parent
    if sys.pycache_prefix is not None or "PYTHONPYCACHEPREFIX" in os.environ:
        raise SystemExit("independent build producer forbids a redirected Python bytecode cache")
    if ((_scripts / "__pycache__").exists() or (_scripts / "__pycache__").is_symlink()
            or any(path.suffix in {".pyc", ".pyo"} for path in _scripts.rglob("*"))):
        raise SystemExit("independent build producer requires source-only Python imports")
    sys.path.insert(0, str(_scripts))

import assembly_inputs
import attempt_index
import gate_process
import package_release as package
import release_gate
import release_host

KIND = "independent-build"
SCHEMA = attempt_index.ACCEPTANCE_SCHEMA
ENVIRONMENT_SCHEMA = "kasumi-independent-build-environment-v1"
RECORD = "independent-build.json"
PROCESS = "production"
TOOLCHAIN = release_gate.TOOLCHAIN
DEFAULT_TIMEOUT_SECONDS = 14400
MAX_INPUT_BYTES = 16 << 20
MIN_RESERVED_DISK_BYTES = 64 << 30
IPADIC_ARCHIVE = "mecab-ipadic-2.7.0-20250920.tar.gz"
IPADIC_SHA256 = "a7ba9f645ffe7094e56ae1c4a81d100df8fbb1e28bbe1792622e9728e162db3d"
SIGNALS = {signal.SIGINT, signal.SIGTERM}
MACHINES = {"x86_64-unknown-linux-gnu": "x86_64", "aarch64-unknown-linux-gnu": "aarch64",
            "aarch64-apple-darwin": "aarch64"}
IDENTITY_FIELDS = ("source_commit", "source_tree", "source_archive_sha256", "source_files_sha256",
                   "lockfile_sha256", "patches_sha256", "configurations_sha256")
RESERVATION_FIELDS = {"id", "starts_at", "ends_at", "cpu_count", "memory_bytes", "disk_bytes"}
# Exactly the fields check_independent_build accepts.
RECORD_FIELDS = ("schema", "status", "identity", "toolchain", "platform", "jobs", "started_at",
                 "finished_at", "build_id", "build_root", "environment_id", "environment",
                 "fresh_build_root", "host", "processes", "compiled_packages", "binaries",
                 "source_archive", "source_files")
# Local modules this producer executes; each must be the frozen source's bytes.
RUNNER_INPUTS = ("scripts/run_independent_build.py", "scripts/assembly_inputs.py",
                 "scripts/attempt_index.py", "scripts/gate_process.py",
                 "scripts/package_release.py", "scripts/release_gate.py", "scripts/release_host.py")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
OBJECT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


def require(value, message):
    if not value:
        raise ValueError(message)


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode()).hexdigest()


def production_command(cargo, jobs):
    """The verifier reconstructs exactly this fixture-free production gate."""
    production = dict(release_gate.functional_gates(jobs, sys.executable))["production"]
    require(production[0] == "cargo" and production[1] == "+" + TOOLCHAIN,
            "functional production gate no longer selects the pinned toolchain")
    return [str(cargo), *production[1:]]


def retain(source, destination):
    """Copy an operator input once; later reads use only the retained bytes."""
    source = Path(source)
    require(source.is_absolute() and source.is_file(), "operator input is not an absolute regular file")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    with source.open("rb") as stream, open(destination, "xb",
                                            opener=lambda name, _: os.open(name, flags, 0o600)) as output:
        shutil.copyfileobj(stream, output)
        output.flush()
        os.fsync(output.fileno())
    attempt_index.fsync_directory(Path(destination).parent)
    return Path(destination)


def load(path):
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_INPUT_BYTES + 1)
    require(len(data) <= MAX_INPUT_BYTES, "operator input exceeds work limit: " + Path(path).name)
    return json.loads(data, object_pairs_hook=attempt_index.unique_pairs,
                      parse_constant=attempt_index.reject_constant)


def check_identity(value):
    require(isinstance(value, dict) and set(value) == set(IDENTITY_FIELDS),
            "release identity fields differ from the verifier's source identity")
    require(all(isinstance(value[field], str) for field in IDENTITY_FIELDS)
            and OBJECT.fullmatch(value["source_commit"]) and OBJECT.fullmatch(value["source_tree"])
            and all(DIGEST.fullmatch(value[field]) for field in IDENTITY_FIELDS[2:]),
            "release identity is not a set of Git object IDs and SHA256 values")
    return value


def check_preflight(value, target):
    """The same native platform facts the verifier's host check requires."""
    require(isinstance(value, dict), "native host preflight is not an object")
    native = (value.get("os"), value.get("machine"))
    require(all(isinstance(item, str) for item in native) and release_host.host_target(*native) == target,
            "native host preflight platform differs from the journal target")
    require(value.get("schema") == release_host.SCHEMA and value.get("requested_target") == target
            and value.get("errors") == [] and value.get("translated") is False,
            "native host preflight failed")
    memory = value.get("effective_memory_bytes")
    require(type(memory) is int and memory >= release_host.MIN_MEMORY_BYTES,
            "native host preflight has insufficient effective memory")


def check_reservation(value, started_at):
    require(isinstance(value, dict) and set(value) == RESERVATION_FIELDS, "host reservation fields differ")
    require(isinstance(value["id"], str) and value["id"], "host reservation has no identifier")
    for field, minimum in (("cpu_count", 1), ("memory_bytes", release_host.MIN_MEMORY_BYTES),
                           ("disk_bytes", MIN_RESERVED_DISK_BYTES)):
        require(type(value[field]) is int and minimum <= value[field] <= (1 << 64) - 1,
                "host reservation " + field + " is below contract")
    starts = attempt_index.timestamp(value["starts_at"], "host reservation start")
    ends = attempt_index.timestamp(value["ends_at"], "host reservation end")
    require(starts <= attempt_index.timestamp(started_at, "native attempt start") < ends,
            "host reservation does not cover the admitted attempt")
    return value


def runner_inputs(source, files):
    """Bind every executing local module to the fresh frozen source bytes."""
    scripts = Path(__file__).resolve(strict=True).parent
    result = {}
    for relative in RUNNER_INPUTS:
        executing = scripts / PurePosixPath(relative).name
        if relative != RUNNER_INPUTS[0]:
            loaded = sys.modules.get(PurePosixPath(relative).stem)
            require(loaded is not None and Path(loaded.__file__).resolve(strict=True) == executing,
                    "independent build imported another module copy: " + relative)
        entry = files.get(relative)
        digest = release_gate.sha256(executing)
        require(isinstance(entry, dict) and entry.get("sha256") == digest
                and release_gate.sha256(Path(source) / relative) == digest,
                "independent build producer differs from frozen source: " + relative)
        result[relative] = digest
    return result


def cargo_proxy(declared, target):
    """Rustup's cargo from the declared Cargo home, resolving to the declared sysroot."""
    sysroot = Path(declared["roots"]["rust-sysroot"])
    require(sysroot.parent.name == "toolchains" and sysroot.name == TOOLCHAIN + "-" + target,
            "declared Rust sysroot is not Rustup's pinned native " + TOOLCHAIN + " toolchain")
    proxy = Path(declared["cargo_home"]) / "bin" / "cargo"
    require(proxy.is_file() and os.access(proxy, os.X_OK), "declared Cargo home has no Rustup cargo proxy")
    resolved = proxy.resolve(strict=True)
    require(resolved != Path(declared["tools"]["cargo"]["path"]),
            "direct sysroot Cargo cannot handle the pinned +toolchain selector")
    digest = release_gate.sha256(resolved)
    require({"path": str(resolved), "sha256": digest} in declared["host_files"],
            "Rustup cargo proxy is not a declared native host file")
    return proxy, sysroot.parent.parent


class Attempt:
    """One admitted independent build; every exit finishes its journal row."""

    def __init__(self, root, head, row, jobs, timeout_seconds):
        self.root = root
        self.head = head
        self.attempt_id = row["id"]
        self.relative = row["output"]
        self.output = root / row["output"]
        self.build_root = self.output / "build"
        self.jobs = jobs
        self.timeout_seconds = timeout_seconds
        self.dispatch_started = False
        self.products = {}
        self.process_paths = None
        self.record = dict.fromkeys(RECORD_FIELDS)
        self.record.update(
            schema=SCHEMA, status="running", toolchain=TOOLCHAIN, platform=head["target"], jobs=jobs,
            started_at=row["started_at"], build_id=head["journal_id"] + ":" + row["id"],
            build_root=str(self.build_root), fresh_build_root=False, processes=[],
            compiled_packages={}, binaries=[])

    def bundle(self, path):
        """A custody file's reference at its final transported bundle path."""
        ref = attempt_index.file_ref(self.root, path)
        return {**ref, "path": "native-attempts/" + self.head["journal_id"] + "/" + ref["path"]}

    def save(self):
        release_gate.write_json(self.output / RECORD, self.record)

    def prepare(self, inputs):
        """Validate retained inputs and the native environment; nothing is dispatched."""
        output, target = self.output, self.head["target"]
        require(gate_process.GROUP_LEDGER_ENV not in os.environ,
                "independent build cannot inherit a nested process group ledger")
        (output / "inputs").mkdir()
        (output / "host").mkdir()
        declaration = retain(inputs["native_inputs"], output / "inputs" / "native-inputs.json")
        declared = assembly_inputs.validate_declaration(load(declaration))
        require(declared["target"] == target, "native input declaration names another target")
        require(release_host.host_target(platform.system(), platform.machine()) == target,
                "producer is not executing natively on the journal target")
        python = Path(sys.executable).resolve(strict=True)
        require(str(python) == declared["tools"]["python"]["path"],
                "producer interpreter differs from the declared native Python")
        identity = check_identity(load(retain(inputs["identity"], output / "inputs" / "identity.json")))
        self.record["identity"] = identity
        self.record["host"] = self.host_facts(inputs)
        self.save()

        archive = retain(inputs["source_archive"], output / "source.tar")
        self.record["source_archive"] = self.bundle(archive)
        require(self.record["source_archive"]["sha256"] == identity["source_archive_sha256"],
                "source archive differs from the release identity")
        self.build_root.mkdir()
        self.record["fresh_build_root"] = True
        source = self.build_root / "source"
        release_gate.extract_source(archive, source)
        files = release_gate.inventory(source)
        release_gate.write_json(output / "source-files.json", files)
        self.record["source_files"] = self.bundle(output / "source-files.json")
        self.save()
        require(self.record["source_files"]["sha256"] == identity["source_files_sha256"],
                "fresh source inventory differs from the release identity")
        require(files.get("Cargo.lock", {}).get("sha256") == identity["lockfile_sha256"],
                "fresh source lockfile differs from the release identity")
        vendor = {name: entry for name, entry in files.items() if name.startswith("vendor/")}
        require(vendor and canonical_hash(vendor) == identity["patches_sha256"],
                "fresh source vendor inventory differs from the release identity")
        runner = runner_inputs(source, files)

        proxy, rustup_home = cargo_proxy(declared, target)
        home = output / "home"
        home.mkdir(mode=0o700)
        target_directory = self.build_root / "target"
        environment = assembly_inputs.environment(declared, home)
        # Cargo's offline mode does not cover a dictionary build script's HTTP
        # client. Seed its fresh, versioned cache with the declared upstream
        # archive. Its compiled dictionary must be generated by this build.
        for item in declared["host_files"]:
            if Path(item["path"]).name == IPADIC_ARCHIVE:
                require(item["sha256"] == IPADIC_SHA256, "declared IPADIC archive digest differs")
                cache = home / "dictionary"
                version = cache / "5.3.0-fmt2"
                version.mkdir(parents=True)
                retained = retain(item["path"], version / IPADIC_ARCHIVE)
                require(release_gate.sha256(retained) == IPADIC_SHA256, "retained IPADIC archive changed")
                environment["LINDERA_BUILD_DICTIONARY_CACHE_DIR"] = str(cache)
                break
        with tarfile.open(archive, "r:") as frozen:
            # git archive records the source commit's timestamp on each entry.
            epoch = str(int(frozen.getmember("Cargo.lock").mtime))
        environment.update(CARGO_TARGET_DIR=str(target_directory), RUSTUP_HOME=str(rustup_home),
                           RUSTUP_AUTO_INSTALL="0", SOURCE_DATE_EPOCH=epoch)
        environment = release_gate.production_environment(environment, source, target_directory)
        command = production_command(proxy, self.jobs)
        executable = gate_process.executable_identity(command, source, environment)
        require(executable["path"] == command[0], "Cargo command must select an absolute executable")
        resolved = Path(executable["path"]).resolve(strict=True)
        (output / "tools").mkdir()
        retained = retain(resolved, output / "tools" / "cargo")
        require(release_gate.sha256(retained) == executable["sha256"],
                "Cargo executable changed before dispatch")
        require(not os.path.lexists(target_directory), "Cargo target directory is not fresh")
        release_gate.write_json(output / "environment.json", {
            "schema": ENVIRONMENT_SCHEMA, "build_id": self.record["build_id"], "target": target,
            "toolchain": TOOLCHAIN, "jobs": self.jobs, "timeout_seconds": self.timeout_seconds,
            "build_root": str(self.build_root), "working_directory": str(source.resolve(strict=True)),
            "target_directory": str(target_directory), "command": command, "variables": environment,
            "cargo": executable, "cargo_resolved": str(resolved), "rustup_home": str(rustup_home),
            "declaration": attempt_index.file_ref(output, declaration), "tools": declared["tools"],
            "python": {"path": str(python), "sha256": declared["tools"]["python"]["sha256"],
                       "version": sys.version},
            "runner_inputs": runner,
            "platform": {"system": platform.system(), "machine": platform.machine(),
                         "release": platform.release()}})
        self.record["environment"] = self.bundle(output / "environment.json")
        self.record["environment_id"] = "sha256:" + self.record["environment"]["sha256"]
        self.save()
        return command, source, environment, executable, files

    def host_facts(self, inputs):
        output, target = self.output, self.head["target"]
        preflight = retain(inputs["host_preflight"], output / "host" / "preflight.json")
        check_preflight(load(preflight), target)
        suffix = Path(inputs["host_attestation"]).suffix
        name = "attestation" + (suffix if re.fullmatch(r"\.[A-Za-z0-9]{1,16}", suffix) else "")
        attestation = retain(inputs["host_attestation"], output / "host" / name)
        reservation = check_reservation(
            load(retain(inputs["host_reservation"], output / "host" / "reservation.json")),
            self.record["started_at"])
        machine = MACHINES[target]
        return {"id": self.head["host"], "physical_machine": machine, "execution_machine": machine,
                "emulated": False, "reservation": reservation, "preflight": self.bundle(preflight),
                "attestation": self.bundle(attestation)}

    def compile(self, command, source, environment, executable):
        """Run the one owned Cargo process; its receipt exists once dispatch begins."""
        output = self.output
        self.process_paths = {"receipt": output / (PROCESS + "-process.json"),
                              "log": output / (PROCESS + ".log"),
                              "executable": output / "tools" / "cargo"}
        self.dispatch_started = True
        before = release_gate.memory_observation()
        resources = output / (PROCESS + "-resources.json")
        release_gate.write_json(resources, {"before": before, "after": None})
        try:
            with self.process_paths["log"].open("xb") as stream:
                process = gate_process.run(
                    command, source, environment, stream, self.timeout_seconds,
                    lambda value: release_gate.write_json(self.process_paths["receipt"], value),
                    stderr=subprocess.STDOUT)
            process["outputs_stable"] = process["cleanup"]["drained"] and not process["cleanup"]["errors"]
            release_gate.write_json(self.process_paths["receipt"], process)
        finally:
            release_gate.write_json(resources, {"before": before, "after": release_gate.memory_observation()})
        require(process["executable"] in (None, executable),
                "owned Cargo dispatch differs from the retained preflight executable")
        return process

    def conclude(self, process, source, original):
        """Bind actual compiler outputs, read only after the owned group drained."""
        target_release = self.build_root / "target" / "release"
        packages, executables, problems = {}, {}, []
        if process["outputs_stable"]:
            for message in release_gate.compiler_artifact_messages(self.process_paths["log"]):
                release_gate.record_compiled_package(packages, message)
                raw = message.get("executable")
                if raw is None:
                    continue
                emitted = release_gate.compiler_executable_identity(message)
                name = emitted["target"]
                if (name in package.BINARIES and not emitted["test"] and name not in executables
                        and message["target"]["kind"] == ["bin"]
                        and message["target"]["crate_types"] == ["bin"]
                        and raw == str(target_release / name)):
                    executables[name] = emitted
                else:
                    problems.append("Cargo emitted an unexpected executable: " + repr(raw))
            self.record["compiled_packages"] = packages
            for name in sorted(executables):
                path = target_release / name
                if path.is_symlink() or not path.is_file():
                    problems.append("Cargo executable is absent: " + name)
                    continue
                self.products[name] = path.relative_to(self.output).as_posix()
                self.record["binaries"].append({"name": name, "file": self.bundle(path)})
                try:
                    package.verify_architecture(path, self.head["target"])
                except ValueError as error:
                    problems.append(name + ": " + str(error))
        if process["received_signals"]:
            raise KeyboardInterrupt("independent build cancelled after owned Cargo cleanup")
        require(process["outputs_stable"], "Cargo process custody is uncertain; outputs remain unverified")
        require(process["status"] == "passed" and process["exit_code"] == 0,
                "Cargo production compilation failed with exit code " + str(process["exit_code"]))
        require(not problems, "; ".join(problems))
        require(set(executables) == package.BINARIES, "Cargo production executable set is incomplete")
        require(packages and not any(set(item["features"]) & release_gate.FORBIDDEN_FIXTURE_FEATURES
                                     for item in packages.values()),
                "production compilation contains fixture capabilities")
        require(release_gate.inventory(source) == original, "Cargo changed the frozen source")

    def finish(self, status, error):
        finished_at = now()
        if status == "passed":
            ends = self.record["host"]["reservation"]["ends_at"]
            if attempt_index.timestamp(ends, "host reservation end") < \
                    attempt_index.timestamp(finished_at, "native attempt finish"):
                status, error = "failed", "host reservation does not cover the finished compilation"
        processes = []
        if (self.process_paths is not None and self.process_paths["receipt"].is_file()
                and self.process_paths["log"].is_file()):
            processes.append({"id": PROCESS, **{key: attempt_index.file_ref(self.root, path)
                                               for key, path in self.process_paths.items()}})
            self.record["processes"] = [{"id": PROCESS, **{key: self.bundle(path)
                                                           for key, path in self.process_paths.items()}}]
        self.record.update(status=status, finished_at=finished_at)
        self.save()
        attempt_index.finish_outcome(
            self.root, self.attempt_id, status, finished_at, products=self.products,
            processes=processes, dispatch_started=self.dispatch_started,
            facts={"build_id": self.record["build_id"], "error": error}, build_evidence=RECORD)
        return status, error


def interrupt(number, _frame):
    raise KeyboardInterrupt("independent build received " + signal.Signals(number).name)


def produce(journal, attempt_id, output, inputs, *, jobs=2, timeout_seconds=DEFAULT_TIMEOUT_SECONDS):
    """Admit, prepare, compile and finish one attempt; return its terminal summary."""
    require(type(jobs) is int and 1 <= jobs <= 64, "jobs must be in 1..64")
    require(type(timeout_seconds) is int and 1 <= timeout_seconds <= 86400,
            "Cargo timeout must be in 1..86400 seconds")
    output = Path(output)
    require(output.is_absolute(), "independent build output must be absolute")
    previous = signal.signal(signal.SIGTERM, interrupt)
    try:
        root = attempt_index.custody(journal)
        head = attempt_index.head(root)
        # Admit before any output exists, with cancellation held until the
        # terminal path owns the admission. An interruption is then an
        # original "interrupted" row, never an absent or unfinished attempt.
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
        try:
            row = attempt_index.begin(root, attempt_id, KIND, output, now())
            attempt = Attempt(root, head, row, jobs, timeout_seconds)
        except BaseException:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)
            raise
        status, error = "failed", None
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)
            attempt.output.mkdir(mode=0o700)
            attempt.save()
            command, source, environment, executable, files = attempt.prepare(inputs)
            process = attempt.compile(command, source, environment, executable)
            attempt.conclude(process, source, files)
            status = "passed"
        except BaseException as failure:
            status = "interrupted" if isinstance(failure, KeyboardInterrupt) else "failed"
            error = repr(failure)
        signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
        try:
            status, error = attempt.finish(status, error)
            summary = {
                "status": status, "error": error, "attempt_id": attempt_id,
                "custody_root": str(attempt.output),
                "build_evidence": attempt.relative + "/" + RECORD,
                "bundle_record": "native-attempts/" + head["journal_id"] + "/" + attempt.relative + "/" + RECORD,
                "binaries": {item["name"]: item["file"]["sha256"] for item in attempt.record["binaries"]},
                "head": attempt_index.head(root)}
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        return summary
    finally:
        signal.signal(signal.SIGTERM, previous)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--journal", type=Path, required=True, help="this host's native attempt custody root")
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--output", type=Path, required=True, help="fresh absolute path inside the custody root")
    parser.add_argument("--identity", type=Path, required=True, help="the verifier's source identity JSON")
    parser.add_argument("--source-archive", type=Path, required=True, help="the frozen Git archive")
    parser.add_argument("--native-inputs", type=Path, required=True, help="assembly_inputs declaration")
    parser.add_argument("--host-preflight", type=Path, required=True)
    parser.add_argument("--host-attestation", type=Path, required=True)
    parser.add_argument("--host-reservation", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--timeout-seconds", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    args = parser.parse_args(argv)
    if not 1 <= args.jobs <= 64:
        parser.error("jobs must be in 1..64")
    if not 1 <= args.timeout_seconds <= 86400:
        parser.error("timeout must be in 1..86400 seconds")
    inputs = {key: str(getattr(args, key).absolute()) for key in
              ("identity", "source_archive", "native_inputs", "host_preflight", "host_attestation",
               "host_reservation")}
    try:
        summary = produce(args.journal, args.attempt_id, args.output, inputs, jobs=args.jobs,
                          timeout_seconds=args.timeout_seconds)
    except (OSError, ValueError) as error:
        print("Independent build was not admitted or finished: " + str(error), file=sys.stderr)
        return 2
    sys.stdout.buffer.write(attempt_index.canonical(summary))
    if summary["status"] != "passed":
        print("Independent build " + summary["status"] + ": " + str(summary["error"]), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
