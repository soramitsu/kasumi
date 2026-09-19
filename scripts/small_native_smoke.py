#!/usr/bin/env python3
"""Private small standalone diagnostic using existing fixture-free binaries.

Never compiles software. The exclusive output includes installation keys and
credentials and must remain private. This is not capacity, HA, endurance or
production release acceptance. See scripts/validation/small-native-smoke.md.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import re
import signal
import socket
import ssl
import stat
import subprocess
import sys
import time
import uuid

DOCUMENTS = 129
DOCUMENT_BYTES = 1024
BATCH_DOCUMENTS = 32
MAX_JSON = 2 << 20
PROTOCOL = "2026-07-28"
SCOPE = ("Small private offline standalone diagnostic: 129 documents of 1024 canonical bytes. "
         "No 3 GiB, HA, performance, soak or release-acceptance claim.")
BINARIES = {"kasumid": "production", "kasumictl": "production",
            "kasumi-bench-capacity": "network-driver"}
FIXTURE_FEATURES = {"test-utils", "embedded-fixture", "loopback-fixture"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def private_write(path, data):
    """Publish a new or replacement private file without following a target link."""
    path = Path(path)
    temporary = path.with_name(path.name + ".pending-" + uuid.uuid4().hex)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        require(not path.is_symlink(), "refusing a symbolic-link output")
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def write_json(path, value):
    private_write(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())


def read_json(path, limit=MAX_JSON):
    with Path(path).open("rb") as source:
        data = source.read(limit + 1)
    require(len(data) <= limit, "JSON exceeds its bounded input limit")
    return json.loads(data)


def private_inventory(root):
    """Record permissions and hashes, never file contents, for the owned output."""
    root = Path(root)
    result = {}
    for path in [root, *sorted(root.rglob("*"))]:
        info = path.lstat()
        require(not stat.S_ISLNK(info.st_mode), "private installation contains a symbolic link")
        require(info.st_uid == os.getuid() and info.st_mode & 0o077 == 0,
                "private installation has wrong ownership or permissions: " + str(path))
        require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode),
                "private installation contains a special file")
        entry = {"mode": oct(stat.S_IMODE(info.st_mode)), "uid": info.st_uid,
                 "kind": "file" if path.is_file() else "directory"}
        if path.is_file():
            entry.update(bytes=info.st_size, sha256=sha256(path))
        result[str(path.relative_to(root))] = entry
    return result


def validate_build_evidence(evidence, commit, tree, lock_sha256):
    """Bind actual artifacts to their passed build graph, not the overall suite."""
    require(evidence.get("status") in ("passed", "failed") and evidence.get("finished_at"),
            "build evidence is not a finished functional run")
    require(evidence.get("source_commit") == commit and evidence.get("source_tree") == tree,
            "build evidence does not name the exact requested source")
    require(evidence.get("lockfile_sha256") == lock_sha256 and evidence.get("toolchain") == "1.97.1",
            "build lockfile or pinned toolchain differs")
    result = {}
    for binary, gate_name in BINARIES.items():
        gates = [gate for gate in evidence.get("gates", []) if gate.get("name") == gate_name]
        require(len(gates) == 1 and gates[0].get("exit_code") == 0,
                "required production build gate did not pass: " + gate_name)
        gate = gates[0]
        packages = gate.get("compiled_packages", {})
        require(bool(packages) and all(isinstance(p.get("features"), list) for p in packages.values()),
                "actual compiled feature inventory is absent")
        require(not any(FIXTURE_FEATURES.intersection(p["features"]) for p in packages.values()),
                "fixture feature present in production compilation")
        artifacts = [(path, artifact) for path, artifact in gate.get("executables", {}).items()
                     if artifact.get("target") == binary]
        require(len(artifacts) == 1 and artifacts[0][1].get("test") is False,
                "required artifact is absent, ambiguous or a test binary: " + binary)
        path, artifact = artifacts[0]
        require(re.fullmatch(r"[0-9a-f]{64}", artifact.get("sha256", "")) is not None,
                "build artifact has no exact executable hash")
        result[binary] = {"build_gate": gate_name, "reported_path": path, **artifact}
    return result


def capacity_config(profile, run_id):
    return {"endpoint": profile["native_endpoint"], "ca_pem": profile["server_ca"],
            "client_certificate_pem": profile["identity"]["certificate"],
            "client_private_key_pem": profile["identity"]["private_key"],
            "server_certificate_sha256": profile["native_certificate_pin"],
            "token_file": profile["bearer_file"], "timeout_ms": 30_000,
            "corpus": {"run_id": run_id, "seed_sha256": "12" * 32, "collection": "capacity",
                       "documents": DOCUMENTS, "document_bytes": DOCUMENT_BYTES,
                       "batch_documents": BATCH_DOCUMENTS}}


def corpus_document(ordinal):
    """Independent Python implementation of the driver's published corpus vector."""
    value = {"ordinal": ordinal, "payload": "", "version": 0}
    size = DOCUMENT_BYTES - len(json.dumps(value, separators=(",", ":")))
    alphabet = [chr(c) for c in range(33, 127) if c not in (34, 92)]
    payload = []
    counter = 0
    while len(payload) < size:
        block = hashlib.sha256(b"kasumi-capacity-corpus-v1\0" + bytes.fromhex("12" * 32)
                               + ordinal.to_bytes(8, "big") + counter.to_bytes(8, "big")).digest()
        counter += 1
        payload.extend(alphabet[byte % 92] for byte in block if byte < 184)
    value["payload"] = "".join(payload[:size])
    return value


def driver_result(directory, config, expected_executable, denied=False):
    with (Path(directory) / "events.jsonl").open() as source:
        events = []
        for line in source:
            require(len(line) <= MAX_JSON, "oversized driver event")
            events.append(json.loads(line))
            require(len(events) < 4096, "unexpected small-run driver event count")
    require(len(events) >= 2 and events[0].get("event") == "started", "driver did not start its journal")
    require(events[0].get("executable_sha256") == expected_executable
            and events[0].get("configuration_sha256") == sha256(config),
            "driver journal identifies another binary or configuration")
    if denied:
        require(events[-1].get("event") == "failed"
                and events[-1].get("transport_code") in ("Unauthenticated", "PermissionDenied")
                and not any(e.get("event") in ("passed", "verified_prefix") for e in events),
                "old resource failed for a reason other than native authorization rejection")
    else:
        final = events[-1]
        require(final.get("event") == "passed" and final.get("documents") == DOCUMENTS
                and final.get("canonical_bytes") == DOCUMENTS * DOCUMENT_BYTES
                and final.get("expected_sha256") == final.get("observed_sha256")
                and re.fullmatch(r"[0-9a-f]{64}", final.get("observed_sha256", "")) is not None,
                "driver did not verify the entire exact small corpus")
    return events[-1]


def bearer(path):
    with Path(path).open() as source:
        token = source.read(16385)
    require(0 < len(token) <= 16384 and not any(c.isspace() for c in token), "invalid private token file")
    return token


def public_claims(token):
    """Continuity/timing checks only; the actual native server authenticates JWTs."""
    parts = token.split(".")
    require(len(parts) == 3, "expected a signed JWT")
    return json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))


def mcp_request(method, request_id, params):
    params = {"_meta": {"io.modelcontextprotocol/protocolVersion": PROTOCOL,
                        "io.modelcontextprotocol/clientInfo": {"name": "kasumi-small-smoke", "version": "1"},
                        "io.modelcontextprotocol/clientCapabilities": {}}, **params}
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}


def validate_local_restore(status, request):
    require(status.get("request") == request and status.get("phase") == "finished"
            and status.get("fencing_scope") == "exclusive_local_installation"
            and status.get("last_failure") is None and isinstance(status.get("client_profile"), str),
            "local recovery did not finish with its exact local-only request")
    return Path(status["client_profile"])


class OwnedProcess:
    """Every child gets a private session; never signals a name or shared group."""
    def __init__(self, runner, name, command):
        self.runner, self.name = runner, name
        self.entry = {"name": name, "command": list(map(str, command)), "started_at": utc_now(),
                      "status": "starting", "forced_stop": False}
        runner.record["steps"].append(self.entry)
        runner.persist()
        self.started = time.monotonic()
        self.streams = []
        self.process = None
        self.closed = False
        try:
            for stream in ("stdout", "stderr"):
                path = runner.output / (name + "." + stream + ".log")
                self.streams.append(path.open("xb"))
                self.entry[stream] = path.name
            self.process = subprocess.Popen(self.entry["command"], cwd=runner.output,
                                            env=runner.environment, stdout=self.streams[0],
                                            stderr=self.streams[1], start_new_session=True)
            self.entry.update(pid=self.process.pid, process_group=self.process.pid, status="running")
            runner.children.append(self)
            runner.persist()
        except BaseException:
            self.finish()
            raise

    def terminate(self):
        if self.process is None:
            return
        try:
            os.killpg(self.process.pid, signal.SIGTERM)
        except ProcessLookupError:
            self.process.wait(timeout=10)
            self.entry["process_group_drained"] = True
            return
        try:
            self.process.wait(timeout=self.runner.stop_timeout)
        except subprocess.TimeoutExpired:
            self.entry["forced_stop"] = True
            os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait(timeout=10)
        # A child process must not outlive its leader's apparent success.
        try:
            os.killpg(self.process.pid, 0)
        except ProcessLookupError:
            self.entry["process_group_drained"] = True
        else:
            self.entry["forced_stop"] = True
            os.killpg(self.process.pid, signal.SIGKILL)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                try:
                    os.killpg(self.process.pid, 0)
                except ProcessLookupError:
                    self.entry["process_group_drained"] = True
                    return
                time.sleep(0.05)
            self.entry["process_group_drained"] = False
            raise RuntimeError("owned process group survived forced shutdown")

    def finish(self):
        if not self.closed:
            self.closed = True
            for stream in self.streams:
                try:
                    stream.flush()
                    os.fsync(stream.fileno())
                except OSError as error:
                    self.runner.record["cleanup_errors"].append({
                        "step": self.name, "operation": "sync-process-log",
                        "error_type": type(error).__name__, "message": str(error)})
                finally:
                    try:
                        stream.close()
                    except OSError as error:
                        self.runner.record["cleanup_errors"].append({
                            "step": self.name, "operation": "close-process-log",
                            "error_type": type(error).__name__, "message": str(error)})
        self.entry.update(seconds=time.monotonic() - self.started, finished_at=utc_now())
        if self.process is not None:
            self.entry["exit_code"] = self.process.poll()
        for kind in ("stdout", "stderr"):
            if kind in self.entry:
                path = self.runner.output / self.entry[kind]
                self.entry[kind + "_sha256"] = sha256(path)
        self.runner.persist()


class Runner:
    def __init__(self, args):
        self.args = args
        self.output = args.output
        self.children = []
        self.daemon = None
        self.stop_timeout = args.stop_timeout
        self.environment = {key: value for key, value in os.environ.items() if "proxy" not in key.lower()}
        self.environment["NO_PROXY"] = "localhost,127.0.0.1,::1"
        self.record = {"schema": 1, "scope": SCOPE, "status": "running", "started_at": utc_now(),
                       "execution_description": args.execution_description, "steps": [], "cleanup_errors": [],
                       "timeouts_seconds": {"command": args.command_timeout, "readiness": args.ready_timeout,
                                            "graceful_stop": args.stop_timeout},
                       "host": {"platform": platform.platform(), "machine": platform.machine(),
                                "python": sys.version, "openssl": ssl.OPENSSL_VERSION},
                       "runner_sha256": sha256(__file__), "proxy_policy": "removed inherited proxy variables"}

    def persist(self):
        write_json(self.output / "evidence.json", self.record)

    def command(self, name, command, denied=False):
        child = OwnedProcess(self, name, command)
        primary = None
        try:
            code = child.process.wait(timeout=self.args.command_timeout)
            child.entry["status"] = "passed" if code == 0 else "failed"
            require((code != 0 and code > 0) if denied else code == 0,
                    "command did not produce its expected exit: " + name)
            child.entry["status"] = "expected_nonzero_pending_validation" if denied else "passed"
        except BaseException as error:
            primary = error
            child.entry.update(status="interrupted" if isinstance(error, KeyboardInterrupt) else "failed",
                               error_type=type(error).__name__)
            raise
        finally:
            try:
                child.terminate()
            except BaseException as error:
                self.record["cleanup_errors"].append({"step": name, "error_type": type(error).__name__,
                                                       "message": str(error)})
                if primary is None:
                    raise
            finally:
                try:
                    child.finish()
                except BaseException as error:
                    self.record["cleanup_errors"].append({"step": name, "error_type": type(error).__name__,
                                                           "message": str(error)})
                    if primary is None:
                        raise
        return self.output / child.entry["stdout"]

    def prepare(self):
        def git(*arguments):
            log = self.command("source-git-" + str(len(self.record["steps"])),
                               ["git", "-C", self.args.repository, *arguments])
            with log.open("rb") as source:
                data = source.read(MAX_JSON + 1)
            require(len(data) <= MAX_JSON, "source evidence object exceeded input bound")
            return data
        commit = git("rev-parse", "--verify", "--end-of-options", self.args.source + "^{commit}").decode().strip()
        require(re.fullmatch(r"[0-9a-f]{40}", commit) is not None, "unexpected source commit identity")
        tree = git("rev-parse", commit + "^{tree}").decode().strip()
        lock = git("show", commit + ":Cargo.lock")
        with self.args.build_evidence.open("rb") as source:
            evidence_bytes = source.read((128 << 20) + 1)
        require(len(evidence_bytes) <= 128 << 20, "build evidence exceeds input bound")
        evidence = json.loads(evidence_bytes)
        artifacts = validate_build_evidence(evidence, commit, tree, hashlib.sha256(lock).hexdigest())
        provenance = self.output / "provenance"
        provenance.mkdir(mode=0o700)
        private_write(provenance / "build-evidence.json", evidence_bytes)
        private_write(provenance / "Cargo.lock", lock)
        collection = git("show", commit + ":benchmarks/capacity-collection.json")
        require(json.loads(collection)["name"] == "capacity", "unexpected source collection schema")
        private_write(self.output / "collection.json", collection)
        self.record.update(source_commit=commit, source_tree=tree, lockfile_sha256=hashlib.sha256(lock).hexdigest(),
                           source_repository=str(self.args.repository),
                           build_evidence_sha256=sha256(provenance / "build-evidence.json"),
                           build_overall_status=evidence.get("status"),
                           source_collection_sha256=sha256(self.output / "collection.json"), binaries={})
        target = self.output / "binaries"
        target.mkdir(mode=0o700)
        for name, artifact in artifacts.items():
            source, copy = self.args.binaries / name, target / name
            info = source.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_size > 0, "binary must be a regular file")
            digest = hashlib.sha256()
            with source.open("rb") as incoming, copy.open("xb") as outgoing:
                for chunk in iter(lambda: incoming.read(1 << 20), b""):
                    outgoing.write(chunk)
                    digest.update(chunk)
                outgoing.flush()
                os.fsync(outgoing.fileno())
            require(digest.hexdigest() == artifact["sha256"], "binary differs from its build evidence: " + name)
            copy.chmod(0o700)
            self.record["binaries"][name] = {**artifact, "original_path": str(source),
                                             "executed_path": str(copy), "bytes": copy.stat().st_size}
        sync_directory(target)
        self.binaries = {name: target / name for name in BINARIES}
        self.persist()

    def http(self, profile, endpoint, path, method="GET", data=None, headers=None):
        from urllib.parse import urlsplit
        url = urlsplit(endpoint)
        require(url.scheme == "https" and url.hostname == "localhost" and url.port
                and not url.username and not url.password and not url.query and not url.fragment,
                "smoke HTTP endpoint must be installed loopback TLS")
        context = ssl.create_default_context(cafile=profile["server_ca"])
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(profile["identity"]["certificate"], profile["identity"]["private_key"])
        connection = http.client.HTTPSConnection("localhost", url.port, context=context, timeout=5)
        try:
            connection.connect()
            require(connection.sock.version() == "TLSv1.3", "unexpected TLS protocol")
            pin = hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()
            expected_pin = profile["administrative_members"]["1"]["certificate_pins"] if endpoint == profile["administrative_members"]["1"]["endpoint"] else [self.mcp_pin]
            require(pin in expected_pin, "installed TLS leaf pin differs")
            request_headers = {"Authorization": "Bearer " + bearer(profile["bearer_file"]),
                               "Accept": "application/json", **(headers or {})}
            connection.request(method, path, body=None if data is None else json.dumps(data), headers=request_headers)
            response = connection.getresponse()
            body = response.read(MAX_JSON + 1)
            require(len(body) <= MAX_JSON, "HTTP response exceeded bounded limit")
            return response.status, body, {"tls": "TLSv1.3", "certificate_sha256": pin}
        finally:
            connection.close()

    def start(self, name):
        require(self.daemon is None, "daemon is already owned")
        self.daemon = OwnedProcess(self, name, [self.binaries["kasumid"], "serve", self.config_file])
        deadline = time.monotonic() + self.args.ready_timeout
        observations = []
        try:
            while time.monotonic() < deadline:
                require(self.daemon.process.poll() is None, "daemon exited before protected readiness")
                try:
                    code, body, tls = self.http(self.control, self.control["administrative_members"]["1"]["endpoint"], "/ready")
                    observations.append({"status": code, "body_sha256": hashlib.sha256(body).hexdigest(), **tls})
                    if code == 200:
                        value = json.loads(body)
                        require(value.get("ready") is True and value.get("lifecycle") == "serving",
                                "readiness response does not report actual serving readiness")
                        private_write(self.output / (name + ".ready.json"), body)
                        self.daemon.entry["readiness"] = observations
                        self.persist()
                        return
                    require(code == 503, "protected readiness denied or unsupported")
                except (ConnectionError, socket.timeout) as error:
                    observations.append({"connection_error": type(error).__name__})
                time.sleep(0.1)
            raise TimeoutError("protected readiness deadline elapsed")
        except BaseException:
            self.daemon.entry["status"] = "failed"
            raise
        finally:
            self.daemon.entry["readiness"] = observations
            self.persist()

    def stop(self):
        child, self.daemon = self.daemon, None
        if child is None:
            return
        try:
            child.terminate()
            require(not child.entry["forced_stop"] and child.process.returncode == 0,
                    "daemon failed or required forced shutdown")
            child.entry["status"] = "passed"
        except BaseException:
            child.entry["status"] = "failed"
            raise
        finally:
            child.finish()

    def verify(self, name, config, expected=None, denied=False):
        output = self.output / name
        self.command(name, [self.binaries["kasumi-bench-capacity"], config, "verify", output], denied=denied)
        result = driver_result(output, config, self.record["binaries"]["kasumi-bench-capacity"]["sha256"], denied)
        self.record.setdefault("corpus_checks", {})[name] = result
        if denied:
            self.record["steps"][-1]["status"] = "passed_expected_authorization_rejection"
        elif expected is not None:
            require(result["observed_sha256"] == expected, "corpus changed across a lifecycle transition")
        self.persist()
        return result

    def mcp(self, profile, name, run_id):
        metadata = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                    "MCP-Protocol-Version": PROTOCOL}
        requests = [mcp_request("tools/list", 1, {}),
                    mcp_request("tools/call", 2, {"name": "kasumi_get", "arguments": {
                        "collection": "capacity", "id": "capacity-" + uuid.UUID(run_id).hex + "-0"}})]
        for request in requests:
            headers = {**metadata, "MCP-Method": request["method"]}
            if request["method"] == "tools/call":
                headers["MCP-Name"] = "kasumi_get"
            code, body, tls = self.http(profile, profile["mcp_endpoint"], "/mcp", "POST", request, headers)
            require(code == 200, "MCP request did not succeed")
            reply = json.loads(body)
            require(reply.get("id") == request["id"] and "error" not in reply, "MCP response identity or result differs")
            result = reply.get("result", {})
            if request["method"] == "tools/list":
                require("kasumi_get" in [tool["name"] for tool in result.get("tools", [])], "MCP discovery lacks document reads")
            else:
                document = result.get("structuredContent", {})
                require(not result.get("isError", False) and document.get("id") == request["params"]["arguments"]["id"]
                        and document.get("version", 0) > 0 and document.get("body") == corpus_document(0),
                        "MCP did not read the exact native document")
            file = self.output / (name + "-" + str(request["id"]) + ".json")
            private_write(file, body)
            self.record.setdefault("mcp_checks", []).append({"file": file.name, "sha256": sha256(file), **tls})
            self.persist()

    def exercise(self):
        daemon = self.binaries["kasumid"]
        installation = self.output / "installation"
        self.command("init", [daemon, "init", "--mode", "standalone", installation, "--tenant", "capacity-smoke"])
        self.config_file = installation / "kasumi.json"
        config = read_json(self.config_file)
        require(config["mode"] == "standalone" and not config["serving_authorities"]
                and config["replication"] is None, "init did not produce explicit standalone storage")
        certificate = Path(config["mcp"]["tls"]["certificate"]).read_text()
        self.mcp_pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate)).hexdigest()
        profile_file = installation / "profiles/default.json"
        control_file = installation / "profiles/control.json"
        held = []
        try:
            ports = {}
            for name in ("native", "admin", "mcp"):
                listener = socket.socket()
                held.append(listener)
                listener.bind(("127.0.0.1", 0))
                ports[name] = listener.getsockname()[1]
                config[name]["listen"] = "127.0.0.1:" + str(ports[name])
            config["mcp"]["protocol"] = {"public_url": f"https://localhost:{ports['mcp']}/mcp",
                                         "allowed_hosts": [f"localhost:{ports['mcp']}"], "allowed_origins": []}
            write_json(self.config_file, config)
            for path in (profile_file, control_file):
                profile = read_json(path)
                profile.update(native_endpoint=f"https://localhost:{ports['native']}",
                               mcp_endpoint=config["mcp"]["protocol"]["public_url"])
                profile["administrative_members"]["1"]["endpoint"] = f"https://localhost:{ports['admin']}"
                write_json(path, profile)
            profile, self.control = read_json(profile_file), read_json(control_file)
            self.record["ports"] = ports
            write_json(self.output / "installation-initial.json", private_inventory(installation))
            self.command("check-config", [daemon, "check-config", self.config_file])
        finally:
            for listener in held:
                listener.close()
        # Ports cannot be inherited by these binaries; a bind race is retained
        # as a failed startup, never repaired by silently changing identities.
        self.start("daemon-initial")
        admin_file = self.output / "admin.json"
        write_json(admin_file, {"endpoint": profile["administrative_members"]["1"]["endpoint"], "identity": profile["identity"],
                               "server_ca": profile["server_ca"],
                               "server_certificate_pins": profile["administrative_members"]["1"]["certificate_pins"],
                               "token_file": profile["bearer_file"]})
        self.command("create-collection", [self.binaries["kasumictl"], "--config", admin_file,
                                           "create-collection", self.output / "collection.json"])
        run_id = str(uuid.uuid4())
        corpus = self.output / "capacity.json"
        write_json(corpus, capacity_config(profile, run_id))
        self.record["corpus"] = capacity_config(profile, run_id)["corpus"]
        load = self.output / "load"
        self.command("load", [self.binaries["kasumi-bench-capacity"], corpus, "load", load, "--allow-writes"])
        result = driver_result(load, corpus, self.record["binaries"]["kasumi-bench-capacity"]["sha256"])
        digest = result["observed_sha256"]
        before = sha256(profile["bearer_file"])
        renewal = read_json(self.command("renew", [daemon, "credential", "renew", profile_file]))
        require(renewal["family_id"] == profile["family_id"] and sha256(profile["bearer_file"]) != before,
                "credential renewal did not update its exact installed token file")
        self.record["renewal"] = {"family_id": renewal["family_id"], "expires_at_ms": renewal["expires_at_ms"],
                                   "before_file_sha256": before, "after_file_sha256": sha256(profile["bearer_file"])}
        self.verify("verify-renewed", corpus, digest)
        self.mcp(profile, "mcp-original", run_id)
        checkpoint_file = self.output / "checkpoint.json"
        self.command("backup-create", [daemon, "backup", "create", profile_file, "local", checkpoint_file])
        checkpoint = read_json(checkpoint_file)
        verified = read_json(self.command("backup-verify", [daemon, "backup", "verify", profile_file,
                                                           "local", checkpoint["backup_id"]]))
        require(verified == checkpoint, "verified backup differs from its exact completed checkpoint")
        self.stop()
        self.start("daemon-restarted")
        self.verify("verify-restarted", corpus, digest)
        self.stop()
        require(len(config["tenants"]) == 1, "smoke requires one installed application tenant")
        tenant = config["tenants"][0]
        require(tenant["serving"]["kind"] == "standalone" and tenant["incarnation"] == checkpoint["source_incarnation"],
                "restore source differs from installed standalone generation")
        request = {"operation_id": str(uuid.uuid4()), "tenant": tenant["tenant"],
                   "expected_active_incarnation": tenant["incarnation"], "target_incarnation": str(uuid.uuid4()),
                   "checkpoint": checkpoint, "source_purpose": {"kind": "Standalone",
                       "installation_id": tenant["serving"]["installation_id"],
                       "tenant": tenant["tenant"], "incarnation": tenant["incarnation"]},
                   "source_keys": tenant["keys"], "source_principal": "administrator", "destination": "local",
                   "phase_timeout_ms": 30_000}
        request_file = self.output / "restore.json"
        write_json(request_file, request)
        status = read_json(self.command("restore", [daemon, "local-recovery", "start", self.config_file, request_file]))
        recovered_file = validate_local_restore(status, request)
        require(recovered_file.is_absolute() and recovered_file.resolve().is_relative_to(installation / "profiles"),
                "recovery profile escaped the owned installation")
        observed = read_json(self.command("restore-status", [daemon, "local-recovery", "status", self.config_file,
                                                            request["operation_id"]]))
        require(validate_local_restore(observed, request) == recovered_file, "recovery status changed its published profile")
        recovered = read_json(recovered_file)
        require(recovered["resource"] == {"kind": "database", "incarnation": request["target_incarnation"]}
                and recovered["resource"] != profile["resource"], "recovered profile did not bind the new resource")
        restored_corpus = self.output / "restored-capacity.json"
        write_json(restored_corpus, capacity_config(recovered, run_id))
        self.start("daemon-restored")
        self.verify("verify-restored", restored_corpus, digest)
        self.mcp(recovered, "mcp-restored", run_id)
        claims = public_claims(bearer(profile["bearer_file"]))
        require(claims.get("kasumi_resource") == profile["resource"] and claims.get("exp", 0) > time.time() + 30,
                "old-resource negative check requires the original still-unexpired JWT")
        self.verify("old-resource-refused", corpus, denied=True)
        self.verify("verify-after-rejection", restored_corpus, digest)
        self.stop()
        self.record.update(corpus_sha256=digest, documents=DOCUMENTS, canonical_bytes=DOCUMENTS * DOCUMENT_BYTES,
                           recovery={"operation_id": request["operation_id"], "phase": observed["phase"],
                                     "fencing_scope": observed["fencing_scope"], "target_incarnation": request["target_incarnation"]})

    def cleanup(self):
        for child in reversed(self.children):
            if child.entry.get("process_group_drained") is True:
                continue
            try:
                child.terminate()
            except BaseException as error:
                self.record["cleanup_errors"].append({"step": child.name, "error_type": type(error).__name__, "message": str(error)})
            finally:
                try:
                    child.finish()
                except BaseException as error:
                    self.record["cleanup_errors"].append({"step": child.name, "error_type": type(error).__name__, "message": str(error)})
        self.daemon = None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binaries", type=Path, required=True)
    parser.add_argument("--build-evidence", type=Path, required=True,
                        help="scripts/release_gate.py evidence.json for the actual binary builds")
    parser.add_argument("--source", required=True)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--execution-description", required=True)
    parser.add_argument("--command-timeout", type=int, default=180)
    parser.add_argument("--ready-timeout", type=int, default=90)
    parser.add_argument("--stop-timeout", type=int, default=90)
    args = parser.parse_args(argv)
    require(sys.version_info >= (3, 11) and os.name == "posix", "Python 3.11+ on a Unix host is required")
    require(all(1 <= value <= 600 for value in (args.command_timeout, args.ready_timeout, args.stop_timeout)),
            "timeouts must be in 1..600 seconds")
    args.repository = args.repository.resolve(strict=True)
    args.binaries = args.binaries.resolve(strict=True)
    args.build_evidence = args.build_evidence.resolve(strict=True)
    require(args.output.is_absolute() and not args.output.exists() and not args.output.is_symlink()
            and not args.output.resolve().is_relative_to(args.repository),
            "output must be a new absolute directory outside the repository")
    os.umask(0o077)
    args.output.mkdir(mode=0o700)
    sync_directory(args.output.parent)
    runner = Runner(args)
    runner.persist()
    previous = {}
    def interrupted(number, _frame):
        raise KeyboardInterrupt("runner received signal " + str(number))
    for number in (signal.SIGINT, signal.SIGTERM):
        previous[number] = signal.signal(number, interrupted)
    try:
        runner.prepare()
        runner.exercise()
        runner.record["status"] = "passed"
    except BaseException as error:
        runner.record.update(status="interrupted" if isinstance(error, KeyboardInterrupt) else "failed",
                             error_type=type(error).__name__, error=str(error))
    finally:
        try:
            runner.cleanup()
        except BaseException as error:
            runner.record["cleanup_errors"].append({"step": "runner-cleanup", "error_type": type(error).__name__, "message": str(error)})
        if runner.record["cleanup_errors"] or any(s.get("forced_stop") for s in runner.record["steps"]):
            runner.record["status"] = "failed"
        try:
            installation = runner.output / "installation"
            if installation.exists():
                inventory = runner.output / "installation-final.json"
                write_json(inventory, private_inventory(installation))
                runner.record["installation_inventory_sha256"] = sha256(inventory)
            for binary in runner.record.get("binaries", {}).values():
                require(sha256(binary["executed_path"]) == binary["sha256"], "executed binary changed during the diagnostic")
            runner.record["artifact_inventory"] = {
                str(path.relative_to(runner.output)): {"sha256": sha256(path), "bytes": path.stat().st_size}
                for path in sorted(runner.output.rglob("*")) if path.is_file()
                and not path.is_relative_to(installation) and path.name != "evidence.json"}
        except BaseException as error:
            runner.record.update(status="failed", final_inventory_error=str(error))
        runner.record["finished_at"] = utc_now()
        runner.persist()
        for number, handler in previous.items():
            signal.signal(number, handler)
    print(json.dumps({"status": runner.record["status"], "build_overall_status": runner.record.get("build_overall_status"),
                      "source_commit": runner.record.get("source_commit"),
                      "release_acceptance": False, "evidence": str(runner.output / "evidence.json"), "scope": SCOPE}))
    return 0 if runner.record["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
