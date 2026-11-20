"""Exercise and replay the complete lifecycle of a fresh installed standalone node."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import uuid

if __name__ == "__main__":
    scripts = Path(__file__).resolve(strict=True).parent
    if (
        sys.pycache_prefix is not None
        or "PYTHONPYCACHEPREFIX" in os.environ
        or (scripts / "__pycache__").exists()
        or (scripts / "__pycache__").is_symlink()
        or any(
            p.suffix in {".pyc", ".pyo"} or (p.suffix == ".py" and p.is_symlink())
            for p in scripts.rglob("*")
        )
    ):
        raise SystemExit("installed lifecycle needs source-only Python imports")
    sys.path.insert(0, str(scripts))

import domain_run
from domain_run import require
import installed_lifecycle as probe
import repeatable_assembly as owned
import run_package_smoke as package
import verify_release_acceptance as acceptance

KIND = "installed"
RUNNER = "scripts/run_installed.py"
MODULES = (
    "scripts/installed_lifecycle.py",
    "scripts/run_package_smoke.py",
    "scripts/run_oci_smoke.py",
    "scripts/mcp_probe.py",
)
INTENT = "release/installed-default-intent.json"
COLLECTION = "installed_docs"
EXPECTED_REFUSALS = {
    "family-denied": 4,
    "old-generation-denied": 4,
    "live-admin-refused": 1,
}


class Live:
    def __init__(self, run, params, inputs, intent):
        self.run = run
        self.params = params
        self.source = run.source
        self.output = run.output
        self.original = run.output
        self.binary = run.binary_paths
        self.inputs = inputs
        self.intent = intent
        self.attempt = run.attempt_id
        self.daemon = None
        self.count = 0
        self.times = {}
        self.witness = {}
        self.checked = []

    def input(self, name, obj):
        path = self.output / (name + ".json")
        domain_run.durable_json(path, obj)
        return str(path)

    def command(self, name, command, scenario=None, expected=0):
        data = self.run.command(
            name,
            list(map(str, command)),
            600,
            scenario=scenario,
            expected_exit=expected,
        )
        self.checked.append(name)
        return data.read_bytes()

    def stderr(self, name):
        return (self.output / name / "stderr.log").read_text()

    def serve(self):
        self.count += 1
        cmd = [self.binary["kasumid"], "serve", str(self.config)]
        self.daemon = self.run.service(
            "daemon",
            cmd,
            {"path": cmd[0], "sha256": self.run.report["binaries"]["kasumid"]},
        )
        require(
            self.daemon == f"daemon-{self.count:04d}",
            "unexpected installed process ordinal",
        )
        self.checked.append(self.daemon)

    def stop(self, scenario=None):
        record = self.run.services.stop("daemon", 180)
        require(
            domain_run.service_disposition(record) == "clean-stop",
            "original installed daemon did not drain",
        )
        if scenario:
            self.run.observe(
                scenario,
                self.daemon,
                owned.ref(
                    self.output, self.output / "services" / (self.daemon + ".json")
                ),
                0,
                record["process_exit_code"],
            )

    def captured_rejection(self, payload):
        return verify_rejection(self.output, self.daemon, payload)

    def check_readback(self, witness, expected):
        self.witness = {"files": witness, "expected": expected}
        # Original process references for still-running services have no content
        # hash until stop. The semantic component consumes only the three CLI steps.
        steps = [
            v
            for v in self.run.report["processes"]
            if v["id"] in ("policy-before", "schema", "policy-after")
        ]
        acceptance.check_native_admin_readback(
            self.output, witness, steps, self.run.report["binaries"], expected
        )


def verify_rejection(root, daemon, payload):
    route = root / "services"
    record = owned.read(route / (daemon + ".json"))
    log = route / (daemon + ".log")
    require(
        record["process_group"] == payload["pid"]
        and record["leader_birth"] == payload["birth"]
        and type(payload["log_offset"]) is int
        and 0 <= payload["log_offset"] < log.stat().st_size,
        "TLS rejection belongs to a different process",
    )
    with log.open("rb") as stream:
        stream.seek(payload["log_offset"])
        return any(
            row.get("fields", {}).get("event") == "tls_reload_failed"
            for line in stream.read(1 << 20).splitlines()
            if line.startswith(b"{")
            for row in [json.loads(line)]
        )


def evidence_path(run, name):
    return owned.ref(run.output, run.output / (name + ".json"))


def lifecycle(run):
    p = run.params
    private = Path(p["private_root"])
    require(
        private.is_absolute() and 1024 <= p["base_port"] <= 65532,
        "invalid fresh installation or loopback ports",
    )
    root = private / "installation"
    profiles = root / "profiles"
    config = root / "kasumi.json"
    run.config = config
    prog = run.binary
    node, ctl = prog["kasumid"], prog["kasumictl"]
    python = [p["python"], "-I", "-B", "-S"]
    helper = [*python, str(run.source / RUNNER), "helper"]

    def command(name, args, scenario=None, expected=0):
        return run.command(name, list(map(str, args)), scenario, expected)

    def obj(name, args, scenario=None, expected=0):
        return json.loads(command(name, args, scenario, expected))

    def observation(name, op, *values, scenario=None):
        return obj(name, [*helper, op, *values], scenario)

    def data(name, profile, *args, scenario=None, expected=0):
        return obj(name, [ctl, "--profile", profile, *args], scenario, expected)

    def mcp(name, scenario, profile_name=None):
        result = command(
            name,
            [
                *python,
                str(run.source / "scripts/mcp_probe.py"),
                "--installation",
                root,
                "--mapped",
                root,
                *(["--profile-name", profile_name] if profile_name else []),
            ],
            scenario,
        )
        package.check_output("mcp-1", result, p, prog)
        return json.loads(result)

    def listeners(n):
        output = command(
            "listeners-" + str(n),
            [
                *python,
                str(run.source / "scripts/run_package_smoke.py"),
                "listeners",
                str(p["base_port"]),
            ],
        )
        package.check_output("listeners-" + str(n), output, p, prog)

    def ready(n, profile=None):
        result = data("ready-" + str(n), profile or profiles / "control.json", "ready")
        require(
            result["ready"] is True and result["lifecycle"] == "serving",
            "candidate is not ready",
        )

    def claims(c, expected_profile, inc):
        require(
            c["resource"] == {"kind": "database", "incarnation": inc}
            and c["family_id"] == expected_profile["family_id"]
            and c["sub"] == c["principal"] == expected_profile["principal"]
            and isinstance(c["iat"], int)
            and type(c["exp"]) is int
            and c["exp"] - c["iat"] == 3600
            and c["kid"]
            and c["cnf"] == {"x5t#S256": c["client_thumbprint"]}
            and c["tenant"] == package.TENANT
            and len(c["sha256"]) == 64,
            "credential is not an hour-long certificate-bound grant",
        )

    def key_report(value):
        require(
            value["files"] > 0
            and value["wrapping_keyrings"] >= 5
            and value["retained_wrapping_generations"] >= value["wrapping_keyrings"]
            and len(value["manifest_sha256"]) == 64,
            "operator backup verification omitted key dependencies",
        )

    def record(x):
        require(
            x.get("ok") is True and isinstance(x.get("result"), dict),
            "native application request failed",
        )
        return x["result"]

    def denial(x):
        require(
            x.get("ok") is False and x["error"]["class"] == "unauthorized",
            "credential was not refused for lack of authority",
        )

    fixed = package.init_inputs(p["base_port"])
    command(
        "init",
        [
            node,
            "init",
            "--mode",
            "standalone",
            root,
            *[a for k in sorted(fixed) for a in ("--" + k, run.inputs[k])],
            "--tenant",
            package.TENANT,
        ],
        "offline-initialize",
    )
    initial = observation(
        "installation", "installation", root, scenario="offline-initialize"
    )
    require(
        initial["tenant"] == run.intent["tenant"] == package.TENANT
        and initial["policy"] == run.intent["policy"]
        and initial["limits"] == run.intent["limits"]
        and initial["serving"]["kind"] == "standalone"
        and initial["auth_kind"] == "local",
        "new installation differs from the frozen standalone intent",
    )
    incarnation = initial["initial_incarnation"]
    admin = initial["profiles"]["operator"]
    native = initial["profiles"]["default"]
    require(
        admin["resource"]
        == native["resource"]
        == {"kind": "database", "incarnation": incarnation}
        and len(admin["administrative_members"]) == 1,
        "profiles did not enroll this generation",
    )
    member = next(iter(admin["administrative_members"].values()))
    require(
        member["certificate_pins"] == [initial["tls"]["admin"]]
        and native["native_certificate_pin"] == initial["tls"]["native"],
        "installed operator and data clients do not pin the fresh live identity",
    )
    admin_path = run.input(
        "operator-client",
        {
            "endpoint": member["endpoint"],
            "identity": admin["identity"],
            "server_ca": admin["server_ca"],
            "server_certificate_pins": member["certificate_pins"],
            "token_file": admin["bearer_file"],
        },
    )
    spec = run.input("collection", run.intent["collections"][COLLECTION])
    policy = run.input(
        "policy-request",
        {"tenant": package.TENANT, "expected_incarnation": incarnation},
    )
    schema = run.input("schema-request", {"selection": "all"})
    default, operator, control = [
        profiles / (name + ".json") for name in ("default", "operator", "control")
    ]
    before = observation("jwt-before", "token", default, scenario="one-hour-jwt")
    claims(before, native, incarnation)
    run.serve()
    listeners(1)
    ready(1)
    grant = record(
        data("original-authorized", default, "collections", scenario="one-hour-jwt")
    )
    require(grant["collections"] == [], "initial namespace is not empty")
    result = obj(
        "create-schema",
        [ctl, "--config", admin_path, "create-collection", spec],
        "native-mtls",
    )
    require(
        type(result["revision"]) is int and result["revision"] > 0,
        "collection genesis missing",
    )
    for name, op, file in (
        ("policy-before", "read-policy-limits", policy),
        ("schema", "read-schema", schema),
        ("policy-after", "read-policy-limits", policy),
    ):
        obj(name, [ctl, "--config", admin_path, op, file], "native-mtls")
    witness = {
        **{
            k: evidence_path(run, n)
            for k, n in (
                ("admin_config", "operator-client"),
                ("policy_request", "policy-request"),
                ("schema_request", "schema-request"),
            )
        },
        "policy_before": "policy-before",
        "schema": "schema",
        "policy_after": "policy-after",
    }
    run.check_readback(
        witness,
        {
            "admin_config_sha256": witness["admin_config"]["sha256"],
            "incarnation": incarnation,
            **run.intent,
        },
    )
    seen = mcp("mcp-first", "mcp")
    require(
        seen["certificate_sha256"] == initial["tls"]["mcp"],
        "MCP exited the new installation",
    )
    discover = observation("oauth", "discovery", root, scenario="oauth-discovery")
    require(
        all(
            discover[path]["status"] == 404
            for path in (
                "/.well-known/oauth-protected-resource",
                "/.well-known/oauth-protected-resource/mcp",
            )
        )
        and discover["/mcp"]["status"] == 401
        and discover["/mcp"]["challenge"] == "Bearer"
        and all(x["leaf_sha256"] == initial["tls"]["mcp"] for x in discover.values()),
        "local OAuth discovery incorrectly advertised a provider",
    )
    renewed = obj("renew", [node, "credential", "renew", default], "renewal")
    after = observation("jwt-renewed", "token", default, scenario="renewal")
    claims(after, native, incarnation)
    require(
        after["sha256"] != before["sha256"]
        and after["exp"] >= before["exp"]
        and renewed["family_id"] == before["family_id"]
        and renewed["expires_at_ms"] // 1000 == after["exp"],
        "renewal did not produce the enrolled one-hour family",
    )
    record(data("renewed-authorized", default, "collections", scenario="renewal"))
    family = str(uuid.uuid5(uuid.NAMESPACE_URL, run.attempt + "/revocation"))
    issue = run.input(
        "credential-request",
        {
            "family_id": family,
            "tenant": package.TENANT,
            "resource": native["resource"],
            "principal": native["principal"],
            "scopes": ["read"],
        },
    )
    rev = private / "revoke.json"
    require(
        obj(
            "issue",
            [
                node,
                "credential",
                "create",
                control,
                issue,
                rev,
                native["identity"]["certificate"],
                native["identity"]["private_key"],
            ],
            "revocation",
        )["family_id"]
        == family,
        "another family was issued",
    )
    record(data("family-authorized", rev, "collections", scenario="revocation"))
    command("revoke", [node, "credential", "revoke", control, family], "revocation")
    denial(data("family-denied", rev, "collections", scenario="revocation", expected=4))
    body = json.dumps({"marker": run.attempt}, separators=(",", ":"))
    put = record(
        data(
            "put",
            default,
            "put",
            COLLECTION,
            "kept",
            body,
            "--if",
            "absent",
            scenario="native-mtls",
        )
    )
    require(
        put["receipt"]["versions"]
        == {"/" + COLLECTION + "/kept": put["receipt"]["revision"]},
        "original write receipt differs",
    )
    checkpoint_path = private / "checkpoint.json"
    created = obj(
        "backup-create",
        [node, "backup", "create", operator, "local", checkpoint_path],
        "backup",
    )
    checkpoint = obj(
        "backup-verify",
        [node, "backup", "verify", operator, "local", created["session_id"]],
        "backup",
    )
    require(
        created["checkpoint"] == str(checkpoint_path)
        and checkpoint["tenant"] == package.TENANT
        and checkpoint["source_incarnation"] == incarnation
        and checkpoint["backup_id"] == created["session_id"]
        and checkpoint["revision"] >= put["receipt"]["revision"]
        and all(
            len(checkpoint[k]) == 64
            for k in (
                "resident_sha256",
                "manifest_ciphertext_sha256",
                "key_lineage_digest",
            )
        ),
        "checkpoint did not authenticate original data",
    )
    record(
        data(
            "post-checkpoint",
            default,
            "put",
            COLLECTION,
            "later",
            body,
            "--if",
            "absent",
            scenario="backup",
        )
    )
    command(
        "live-admin-refused",
        [node, "recover-administrator", config, private / "refused"],
        "exclusive-stopped-admin-recovery",
        1,
    )
    require(
        "persistent storage ownership unavailable" in run.stderr("live-admin-refused"),
        "live recovery failed for another reason",
    )
    payload = observation(
        "invalid-tls",
        "invalid-tls",
        root,
        run.original / "services" / (run.daemon + ".json"),
        run.original / "services" / (run.daemon + ".log"),
        scenario="invalid-tls-replacement",
    )
    require(
        run.captured_rejection(payload),
        "TLS replacement rejection was not produced by the original running daemon",
    )
    require(
        payload["old_leaf"]
        == payload["served"]
        == payload["restored"]
        == initial["tls"]["mcp"],
        "failed TLS reload lost enrolled identity",
    )
    run.stop("restart")
    backup = private / "operator-backup"
    command(
        "operator-backup",
        [node, "backup-operator-keys", config, backup],
        "operator-key-backup",
    )
    operator_backup = obj(
        "operator-verify", [node, "verify-operator-keys", backup], "operator-key-backup"
    )
    key_report(operator_backup)
    protection = observation(
        "operator-permissions",
        "operator-backup",
        backup,
        scenario="operator-key-backup",
    )
    require(
        protection["private"] and protection["files"] >= operator_backup["files"],
        "unsafe operator key backup",
    )
    command(
        "wrapping",
        [node, "maintenance", "rotate-wrapping-keys", config],
        "wrapping-rotation",
    )
    signer = obj(
        "signer", [node, "maintenance", "rotate-signer", config], "signer-rotation"
    )
    rotated = observation("rotated", "installation", root, scenario="wrapping-rotation")
    for name, ring in initial["rings"].items():
        new = rotated["rings"][name]
        require(
            new["id"] == ring["id"]
            and new["active"] == ring["active"] + 1
            and new["generations"] == [*ring["generations"], new["active"]],
            "wrapping rotation failed to retain an original generation",
        )
    require(signer["generation"] >= 2, "signer generation did not advance")
    run.serve()
    listeners(2)
    ready(2)
    obj("renew-rotated", [node, "credential", "renew", default], "signer-rotation")
    current = observation("jwt-rotated", "token", default, scenario="signer-rotation")
    claims(current, native, incarnation)
    require(current["kid"] != after["kid"], "renewal reused the retired signer")
    retained = record(
        data("retained", default, "get", COLLECTION, "kept", scenario="restart")
    )
    require(
        retained["document"]["body"] == json.loads(body),
        "original document failed restart",
    )
    run.stop("restore")
    operation = str(uuid.uuid5(uuid.NAMESPACE_URL, run.attempt + "/restore"))
    restored = str(uuid.uuid5(uuid.NAMESPACE_URL, run.attempt + "/new-incarnation"))
    request = {
        "operation_id": operation,
        "tenant": package.TENANT,
        "expected_active_incarnation": incarnation,
        "target_incarnation": restored,
        "checkpoint": checkpoint,
        "source_purpose": {
            "kind": "Standalone",
            "installation_id": initial["serving"]["installation_id"],
            "tenant": package.TENANT,
            "incarnation": incarnation,
        },
        "source_keys": initial["source_keys"],
        "source_principal": admin["principal"],
        "destination": "local",
        "phase_timeout_ms": 600000,
    }
    restore = run.input("restore-request", request)
    obj("restore", [node, "local-recovery", "start", config, restore], "restore")
    status = obj(
        "restore-status",
        [node, "local-recovery", "status", config, operation],
        "restore",
    )
    require(
        status["phase"] == "finished"
        and status["request"]["operation_id"] == operation
        and status["request"]["target_incarnation"] == restored
        and status["request"]["checkpoint"] == checkpoint
        and status["last_failure"] is None
        and status["client_profile"]
        == str(profiles / ("recovery-" + operation + ".json")),
        "stopped restore did not activate the original checkpoint",
    )
    restored_profile = status["client_profile"]
    run.serve()
    listeners(3)
    ready(3)
    recovered_doc = record(
        data(
            "restored-read",
            restored_profile,
            "get",
            COLLECTION,
            "kept",
            scenario="restore",
        )
    )
    require(
        recovered_doc["document"]["body"] == json.loads(body),
        "restored data differs from checkpoint",
    )
    missing = record(
        data(
            "restored-absence",
            restored_profile,
            "get",
            COLLECTION,
            "later",
            scenario="restore",
        )
    )
    require(missing["document"] is None, "restore included a post-checkpoint write")
    denial(
        data(
            "old-generation-denied",
            default,
            "collections",
            scenario="restore",
            expected=4,
        )
    )
    run.stop("restore")
    recovery = private / "recovered"
    admin_paths = obj(
        "recover-admin",
        [node, "recover-administrator", config, recovery],
        "exclusive-stopped-admin-recovery",
    )
    recovered = recovery / ("database-" + restored + ".json")
    require(
        set(admin_paths) == {str(recovery / "control.json"), str(recovered)},
        "administrator recovery did not replace the installed authorities",
    )
    run.serve()
    listeners(4)
    ready(4, recovery / "control.json")
    require(
        data(
            "control-before-rotation", control, "ready", scenario="certificate-rotation"
        )["ready"]
        is True,
        "enrolled Control family lost admission before rotation",
    )
    result = record(
        data(
            "recovered-admin-read",
            recovered,
            "get",
            COLLECTION,
            "kept",
            scenario="exclusive-stopped-admin-recovery",
        )
    )
    require(
        result["document"]["body"] == json.loads(body),
        "newly recovered administrator cannot read the activated checkpoint",
    )
    # Restore fences the original database incarnation. Exercise certificate
    # rotation with an MCP family issued for the activated checkpoint.
    mcp_family = str(uuid.uuid5(uuid.NAMESPACE_URL, run.attempt + "/restored-mcp"))
    mcp_request = run.input(
        "restored-mcp-request",
        {
            "family_id": mcp_family,
            "tenant": package.TENANT,
            "resource": {"kind": "database", "incarnation": restored},
            "principal": "application",
            "scopes": ["read"],
            "audience": "mcp",
        },
    )
    issued = obj(
        "restored-mcp-issue",
        [
            node,
            "credential",
            "create",
            recovery / "control.json",
            mcp_request,
            profiles / "restored-mcp.json",
        ],
        "certificate-rotation",
    )
    require(
        issued["family_id"] == mcp_family, "new MCP profile belongs to another family"
    )
    mcp("restored-mcp-before", "certificate-rotation", "restored-mcp.json")
    run.stop("exclusive-stopped-admin-recovery")
    issuer_port = p["base_port"] + 3
    issuer = f"https://localhost:{issuer_port}"
    external = observation(
        "oauth-config",
        "external-config",
        root,
        str(issuer_port),
        scenario="oauth-discovery",
    )
    require(
        external["config"] == str(root / "oauth-qualification.json")
        and external["issuer"] == issuer
        and external["jwks_uri"] == issuer + "/keys"
        and len(external["sha256"]) == 64,
        "wrong isolated external OAuth installation",
    )
    run.config = Path(external["config"])
    run.serve()
    listeners(5)
    observed = observation(
        "oauth-external",
        "external-discovery",
        root,
        str(issuer_port),
        scenario="oauth-discovery",
    )
    require(
        observed["issuer"] == issuer
        and observed["jwks_uri"] == external["jwks_uri"]
        and observed["issuer_requests"] == ["/keys"],
        "external discovery lacks a live configured issuer",
    )
    expected_metadata = {
        "resource": initial["profiles"]["mcp"]["mcp_endpoint"],
        "authorization_servers": [issuer],
        "scopes_supported": ["kasumi:read", "kasumi:write"],
        "bearer_methods_supported": ["header"],
    }
    observed_metadata = observed["metadata"]
    for path in (
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
    ):
        require(
            observed_metadata[path]["status"] == 200
            and observed_metadata[path]["metadata"] == expected_metadata
            and observed_metadata[path]["leaf_sha256"] == initial["tls"]["mcp"],
            "external protected-resource metadata differs from configured provider",
        )
    challenge = observed_metadata["/mcp"]
    require(
        challenge["status"] == 401
        and "resource_metadata" in challenge["challenge"]
        and challenge["leaf_sha256"] == initial["tls"]["mcp"],
        "external MCP challenge omitted OAuth discovery",
    )
    run.stop("oauth-discovery")
    run.config = config
    certificate = obj(
        "certificates",
        [node, "maintenance", "rotate-certificates", config],
        "certificate-rotation",
    )
    renewed_tls = observation(
        "rotated-tls", "installation", root, scenario="certificate-rotation"
    )
    require(
        all(
            renewed_tls["tls"][f] != initial["tls"][f]
            for f in ("admin", "native", "mcp")
        )
        and renewed_tls["tls"]["native"] == certificate["native_certificate_pin"]
        and renewed_tls["tls"]["admin"] == certificate["admin_certificate_pin"],
        "new listener generation missing",
    )
    run.serve()
    listeners(6)
    ready(6)
    live = mcp("mcp-rotated", "certificate-rotation", "restored-mcp.json")
    require(
        live["certificate_sha256"] == renewed_tls["tls"]["mcp"],
        "running daemon lost certificate rotation",
    )
    run.stop("certificate-rotation")


class Replay:
    """Replay every original binary, helper, input, refusal and service lifetime."""

    expected_refusals = EXPECTED_REFUSALS

    def __init__(self, facts, params, binary, hashes, inputs, intent):
        self.facts = facts
        report = facts["report"]
        self.params = params
        self.original = Path(report["custody_root"])
        self.output = facts["custody"]
        self.source = Path(report["evidence_root"]) / "source"
        self.binary = binary
        self.hashes = hashes
        self.inputs = inputs
        self.intent = intent
        self.attempt = report["attempt_id"]
        self.sequence = iter(report["processes"])
        self.count = 0
        self.daemon = None
        self.previous = None
        self.scenarios = {}
        self.witness = {}

    def input(self, name, obj):
        relative = name + ".json"
        require(
            owned.read(self.output / relative) == obj, "original input differs: " + name
        )
        return str(self.original / relative)

    def take(self, name, args, service):
        item = next(self.sequence, None)
        require(
            item is not None and item["id"] == name,
            "missing or reordered original process: " + name,
        )
        original = self.facts["receipts"][name]
        record = original["record"]
        expected = self.hashes[args[0]]
        require(
            original["service"] is service
            and record["command"] == args
            and record["working_directory"] == str(self.source)
            and item["executable"]["sha256"] == expected
            and record["executable"] == {"path": args[0], "sha256": expected},
            "original installation command or candidate substitution: " + name,
        )
        return item, record

    def command(self, name, args, scenario=None, expected=0):
        item, record = self.take(name, list(map(str, args)), False)
        require(
            expected == self.expected_refusals.get(name, 0)
            and record["exit_code"] == expected
            and item["receipt"]["path"] == name + "/process.json"
            and item["log"]["path"] == name + "/stdout.log"
            and item["log"] == record["stdout"]
            and record["stderr"]["path"] == name + "/stderr.log",
            "original command or refusal outcome differs: " + name,
        )
        gate = {
            "command": record["command"],
            "process": item["receipt"]["path"],
            "process_sha256": item["receipt"]["sha256"],
            "process_cleanup": record["cleanup"],
            "timeout_seconds": 600,
            "timed_out": record["timed_out"],
            "received_signals": record["received_signals"],
            "process_error": record["error"],
        }
        domain_run.package.verify_process_receipt(self.output, gate, 600, expected)
        if scenario:
            self.scenarios.setdefault(scenario, []).append(name)
        return owned.check_ref(self.output, item["log"]).read_bytes()

    def stderr(self, name):
        return owned.check_ref(
            self.output, self.facts["receipts"][name]["record"]["stderr"]
        ).read_text()

    def serve(self):
        self.count += 1
        self.daemon = f"daemon-{self.count:04d}"
        item, record = self.take(
            self.daemon, [self.binary["kasumid"], "serve", str(self.config)], True
        )
        require(
            record["id"] == self.daemon
            and record["name"] == "daemon"
            and item["log"]["path"] == "services/" + self.daemon + ".log"
            and item["receipt"]["path"] == "services/" + self.daemon + ".json"
            and domain_run.service_disposition(record) == "clean-stop",
            "daemon lacks original clean termination",
        )
        if self.previous is not None:
            require(
                self.previous["finished_elapsed_seconds"]
                <= record["started_elapsed_seconds"]
                and (record["leader_birth"], record["process_group"])
                != (self.previous["leader_birth"], self.previous["process_group"]),
                "installed daemon lifetimes overlap or repeat",
            )
        self.previous = record

    def stop(self, scenario=None):
        require(self.daemon is not None, "no original installed process to stop")
        if scenario:
            self.scenarios.setdefault(scenario, []).append(self.daemon)
        self.daemon = None

    def captured_rejection(self, payload):
        return verify_rejection(self.output, self.daemon, payload)

    def check_readback(self, witness, expected):
        self.witness = {"files": witness, "expected": expected}
        acceptance.check_native_admin_readback(
            self.output,
            witness,
            self.facts["report"]["processes"],
            self.facts["report"]["binaries"],
            expected,
            original_root=self.original,
        )


def execute(run, params):
    run.bind()
    functional = owned.read(run.evidence / "evidence.json")
    require(
        owned.sha256(params["python"]) == functional["python_executable"]["sha256"],
        "installed interpreter differs from functional qualification",
    )
    inputs = {}
    for name, value in sorted(package.init_inputs(params["base_port"]).items()):
        path = run.output / (name + ".json")
        domain_run.durable_json(path, value)
        inputs[name] = str(run.configuration(name, path))
    intent = run.configuration("installed-intent", run.source / INTENT)
    run.start_services(21600, 0, 0)
    live = Live(run, params, inputs, owned.read(intent))
    lifecycle(live)
    require(
        set(run.scenarios) == acceptance.SCENARIOS[KIND],
        "installed lifecycle omitted a scenario",
    )
    run.passed(
        {
            "functional_sha256": owned.sha256(run.evidence / "evidence.json"),
            "readback": live.witness,
        }
    )


def verify_domain(root, domain, files, configs, artifacts, candidates):
    facts = domain_run.verify_run(root, domain, files, configs, KIND, RUNNER, MODULES)
    report, custody = facts["report"], facts["custody"]
    params = report["invocation"]["parameters"]
    owned.exact(params, {"base_port", "private_root", "python"}, "installed parameters")
    require(
        not domain["topology"]
        and not domain["artifacts"]
        and Path(params["python"]).is_absolute(),
        "installed qualification requires private standalone configuration",
    )
    selected = candidates[report["target"]]["primary"]["functional"]
    functional = acceptance.json_reference(root, selected)
    details = report["details"]
    owned.exact(details, {"functional_sha256", "readback"}, "installed observations")
    require(
        details["functional_sha256"] == selected["sha256"],
        "installed selected another functional candidate",
    )
    production = next(g for g in functional["gates"] if g["name"] == "production")
    binaries = {
        v["target"]: str(Path(report["evidence_root"]) / "target" / p)
        for p, v in production["executables"].items()
    }
    hashes = {path: domain["binaries"][name] for name, path in binaries.items()}
    hashes[params["python"]] = functional["python_executable"]["sha256"]
    expected = package.init_inputs(params["base_port"])
    inputs = {}
    configs_by_name = {v["id"]: v["file"] for v in report["configurations"]}
    require(
        set(configs_by_name) == {*expected, "installed-intent"}
        and configs_by_name["installed-intent"]["sha256"] == files[INTENT]["sha256"],
        "installed intent or configuration roster differs",
    )
    for name, value in expected.items():
        ref = configs_by_name[name]
        require(
            owned.read(owned.check_ref(custody, ref)) == value,
            "enrollment input differs",
        )
        inputs[name] = str(Path(report["custody_root"]) / ref["path"])
    replay = Replay(
        facts,
        params,
        binaries,
        hashes,
        inputs,
        owned.read(owned.check_ref(custody, configs_by_name["installed-intent"])),
    )
    lifecycle(replay)
    require(
        next(replay.sequence, None) is None
        and replay.witness == details["readback"]
        and set(replay.scenarios) == acceptance.SCENARIOS[KIND]
        and {key: [v["step"] for v in rows] for key, rows in facts["scenarios"].items()}
        == replay.scenarios,
        "installed lifecycle lacks original complete scenario evidence",
    )
    return facts["evidence"]


def main():
    if sys.argv[1:2] == ["helper"]:
        print(json.dumps(probe.observe(sys.argv[2], sys.argv[3:]), sort_keys=True))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("evidence", "output", "journal"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--base-port", type=int, required=True)
    args = parser.parse_args()
    require(
        1024 <= args.base_port <= 65532,
        "four free unprivileged loopback ports required",
    )
    with tempfile.TemporaryDirectory(prefix="kasumi-installed-") as private:
        params = {
            "private_root": str(Path(private).resolve(strict=True)),
            "base_port": args.base_port,
            "python": str(Path(sys.executable).resolve(strict=True)),
        }
        with domain_run.Run(
            KIND,
            RUNNER,
            MODULES,
            args.evidence,
            args.output,
            args.journal,
            args.attempt_id,
            params,
            domain_run.QUALIFYING,
        ) as run:
            execute(run, params)


if __name__ == "__main__":
    main()
