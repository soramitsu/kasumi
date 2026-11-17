#!/usr/bin/env python3
"""Write the deployed-format fixtures with the binaries of the deployed commits.

  deployed_format_fixture.py generate --first-bin-dir DIR --second-bin-dir DIR
      --work DIRECTORY --out DIRECTORY --base-port PORT

`generate` initializes one standalone installation with `kasumid` from
--first-bin-dir (commit 12140939, the build that first wrote the deployed
store), drives it through `kasumictl`, and copies the installation at three
points:

  12140939-killed    the first build killed in the compaction cycle after its
                     first segment was sealed, while its root listed garbage
                     files and a writer was running
  12140939-clean     the same installation after the first build recovered
                     from that kill and stopped cleanly
  cf9959f1-clean     the same installation after --second-bin-dir (commit
                     cf9959f1, the build serving the deployed store) served
                     and stopped it

Each copy gets a `manifest.json`: what the build that wrote it answered for
every document, query, receipt, policy, limit, credential and backup. The
tests in `tests/deployed-format/` open the copies with the current code and
compare its answers with these.

The binaries are built from `git archive` exports of those commits. A store
that passed 5000 journal entries and 256 MiB of growth cannot be committed, so
the committed fixtures come from builds with
`tests/deployed-format/schedule-<commit>.patch` applied. The patch reads the
two scheduling thresholds from the environment; this script sets them so that
snapshots and compaction cycles happen within a few hundred writes. Formats
are untouched.

--work must not exist. It holds keys and credentials of a disposable
installation that protects nothing else; the copies in --out hold the same
keys, without bearer tokens. `tests/deployed-format/README.md` describes how
the copies are packed and committed.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import random
import re
import select
import shutil
import signal
import ssl
import struct
import subprocess
import sys
import time

TENANT = "default"
# Every process this run started, so a failed run leaves none behind.
CHILDREN = []
SNAPSHOT_INTERVAL = 96
COMPACTION_SLACK_BYTES = 4 << 20
# A stack this size lets the unoptimized builds of these commits initialize.
STACK_KIB = 65520
LONG_STRING = 4096
ROOT_SLOT_BYTES = 4096
ENVELOPE_BYTES = 4096
SEGMENT_BYTES = 64 << 20
# A document near the default 1 MiB limit, to fill a segment quickly.
LARGE_BYTES = 700_000
GARBAGE_COUNT_AT = 152
GARBAGE_AT = 160
GARBAGE_ENTRY_BYTES = 16
MAX_GARBAGE = 128


def require(condition, message):
    if not condition:
        raise ValueError(message)


def write_private(path, value):
    data = value if isinstance(value, bytes) else json.dumps(value, sort_keys=True).encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)
    return path


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


NUMBER = "\u0000number:"


def loads_exact(text):
    """Parse JSON keeping every number as the server spelled it: Python would
    respell `12.500` as `12.5`, and a document's number is its exact text."""
    return json.loads(text, parse_float=lambda digits: NUMBER + digits,
                      parse_int=lambda digits: NUMBER + digits)


def dumps_exact(value, **options):
    return re.sub(r'"\\u0000number:([^"]*)"', r"\1", json.dumps(value, **options))


def summarize(value):
    """Replace long strings by their digest, as the tests do before comparing."""
    if isinstance(value, dict):
        return {key: summarize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [summarize(item) for item in value]
    if isinstance(value, str) and len(value.encode()) > LONG_STRING:
        data = value.encode()
        return {"$sha256": hashlib.sha256(data).hexdigest(), "$bytes": len(data)}
    return value


class Installation:
    """One installation directory and the build currently driving it."""

    def __init__(self, work, base_port, schedule):
        self.work = Path(work)
        self.root = self.work / "installation"
        self.ports = {"mcp": base_port, "native": base_port + 1, "admin": base_port + 2}
        self.schedule = schedule
        self.binaries = None
        self.server = None
        self.sessions = {}
        self.counter = 0
        self.renewed = ["default", "control"]

    # --- processes -------------------------------------------------------
    def environment(self):
        environment = {**os.environ, "TMPDIR": str(self.work / "tmp")}
        environment["KASUMI_FIXTURE_SNAPSHOT_INTERVAL"] = str(self.schedule["snapshot_interval"])
        environment["KASUMI_FIXTURE_COMPACTION_SLACK_BYTES"] = str(
            self.schedule["compaction_slack_bytes"])
        return environment

    def run(self, program, *arguments, check=True, timeout=600, stdin=None):
        command = [str(self.binaries / program), *[str(argument) for argument in arguments]]
        result = subprocess.run(
            ["/bin/sh", "-c", f'ulimit -s {STACK_KIB} 2>/dev/null; exec "$@"', "sh", *command],
            input=stdin, capture_output=True, timeout=timeout, env=self.environment())
        if check:
            require(result.returncode == 0,
                    f"{program} {' '.join(map(str, arguments[:3]))} failed: "
                    + result.stderr.decode(errors="replace")[-2000:]
                    + result.stdout.decode(errors="replace")[-2000:])
        return result

    def profile(self, name):
        return self.root / "profiles" / f"{name}.json"

    def init(self, binaries):
        self.binaries = Path(binaries).resolve()
        self.work.mkdir(mode=0o700)
        (self.work / "tmp").mkdir(mode=0o700)
        inputs = {
            "directory-policy": {"extent_bytes": 10485760, "max_entries": 32768},
            "file-allocation-policy": {"maximum_extra_extent_bytes": 1048576},
            "network": {
                "mcp_listen": f"127.0.0.1:{self.ports['mcp']}",
                "mcp_public_url": f"https://localhost:{self.ports['mcp']}/mcp",
                "native_listen": f"127.0.0.1:{self.ports['native']}",
                "admin_listen": f"127.0.0.1:{self.ports['admin']}",
            },
            "tenant-audit-placements": {"__kasumi_control": {"kind": "local_replica_only"},
                                        TENANT: {"kind": "local_replica_only"}},
        }
        arguments = []
        for name, value in inputs.items():
            arguments += [f"--{name}", write_private(self.work / f"{name}.json", value)]
        self.run("kasumid", "init", "--mode", "standalone", self.root, *arguments,
                 "--tenant", TENANT)

    def serve(self, binaries, extra=()):
        self.binaries = Path(binaries).resolve()
        log = open(self.work / "server.log", "ab")
        self.server = subprocess.Popen(
            ["/bin/sh", "-c", f'ulimit -s {STACK_KIB} 2>/dev/null; exec "$@"', "sh",
             str(self.binaries / "kasumid"), "serve", str(self.root / "kasumi.json"), *extra],
            stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=self.environment(),
            start_new_session=True)
        CHILDREN.append(self.server)
        deadline = time.monotonic() + 600
        while True:
            require(self.server.poll() is None, "kasumid serve exited; see server.log")
            self.renew(check=False)
            result = self.run("kasumictl", "--profile", self.profile("default"), "collections",
                              check=False)
            if result.returncode == 0:
                break
            require(time.monotonic() < deadline, "the installation did not serve in time")
            time.sleep(0.5)
        self.renew()
        admin = json.loads(self.profile("default").read_bytes())
        member = next(iter(admin["administrative_members"].values()))
        write_private(self.work / "admin-client.json", {
            "endpoint": member["endpoint"], "identity": admin["identity"],
            "server_ca": admin["server_ca"],
            "server_certificate_pins": sorted(member["certificate_pins"]),
            "token_file": admin["bearer_file"]})

    def renew(self, check=True):
        """Renew every live credential: each lasts one hour."""
        for name in self.renewed:
            result = self.run("kasumid", "credential", "renew", self.profile(name), check=False)
            require(not check or result.returncode == 0,
                    f"renewing {name} failed: {result.stderr.decode(errors='replace')}")

    def close_sessions(self):
        for session in self.sessions.values():
            session.stdin.close()
            session.wait(timeout=60)
        self.sessions = {}

    def stop(self):
        self.close_sessions()
        os.killpg(self.server.pid, signal.SIGTERM)
        require(self.server.wait(timeout=900) == 0, "kasumid serve did not stop cleanly")
        self.server = None

    def kill(self):
        os.killpg(self.server.pid, signal.SIGKILL)
        self.server.wait()
        self.server = None
        for session in self.sessions.values():
            session.kill()
            session.wait()
        self.sessions = {}

    # --- clients ---------------------------------------------------------
    def session(self, profile="default"):
        if profile not in self.sessions:
            self.sessions[profile] = subprocess.Popen(
                [str(self.binaries / "kasumictl"), "--profile", str(self.profile(profile)),
                 "--timeout-ms", "600000", "session"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=self.environment())
            CHILDREN.append(self.sessions[profile])
        return self.sessions[profile]

    def data(self, *argv, input=None, profile="default", expect=0):
        """One data command through the profile's session: (status, document)."""
        session = self.session(profile)
        self.counter += 1
        request = {"id": self.counter, "argv": list(argv)}
        if input is not None:
            request["input"] = input
        session.stdin.write((json.dumps(request) + "\n").encode())
        session.stdin.flush()
        line = session.stdout.readline()
        require(line, "the kasumictl session ended")
        answer = json.loads(line)
        require(answer["id"] == self.counter, "the session answered another request")
        if expect is not None:
            require(answer["status"] == expect,
                    f"{argv[:3]} returned {answer['status']}: {answer['document']}")
        return answer["status"], loads_exact(line.decode())["document"]

    def mutate(self, batch, profile="default", expect=0):
        return self.data("mutate", "-", input=dumps_exact(batch), profile=profile, expect=expect)

    def put(self, collection, identity, body, expected="any", profile="default", expect=0):
        self.counter += 1
        return self.mutate({"idempotency_key": f"fixture-{self.counter}", "operations": [
            {"op": "put", "collection": collection, "id": identity, "body": body,
             "expected": expected}]}, profile=profile, expect=expect)

    def admin(self, operation, payload=None, check=True):
        arguments = ["--config", self.work / "admin-client.json", operation]
        if payload is not None:
            arguments.append(write_private(self.work / "admin-operation.json", payload))
        result = self.run("kasumictl", *arguments, check=check)
        return json.loads(result.stdout) if result.returncode == 0 else None

    def health(self):
        context = ssl.create_default_context(cafile=str(self.root / "tls/ca.pem"))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        # The installation's certificates carry no authority key identifier,
        # which newer Python releases require by default.
        context.verify_flags &= ~ssl.VERIFY_X509_STRICT
        context.load_cert_chain(str(self.root / "profiles/client.pem"),
                                str(self.root / "profiles/client-key.pem"))
        connection = http.client.HTTPSConnection("localhost", self.ports["admin"],
                                                 context=context, timeout=60)
        try:
            token = (self.root / "profiles/control.token").read_text().strip()
            connection.request("GET", "/health", headers={"Authorization": f"Bearer {token}"})
            response = connection.getresponse()
            body = response.read()
            require(response.status == 200, f"/health returned {response.status}")
            return json.loads(body)
        finally:
            connection.close()

    def group(self, tenant=TENANT):
        return next(group for group in self.health()["groups"] if group["tenant"] == tenant)

    def storage(self):
        """The node database's compaction figures: under the tenant in
        12140939, at the top level in cf9959f1."""
        health = self.health()
        group = next(group for group in health["groups"] if group["tenant"] == TENANT)
        storage = group.get("storage") or health.get("storage")
        require(storage is not None, "/health reports no storage figures")
        return storage

    # --- raw store observations ------------------------------------------
    def root_garbage(self):
        """The count of garbage records in each native root slot, read as
        the file is."""
        return [len(records) for records in self.garbage_records()]

    def garbage_records(self):
        """Each root slot's garbage records as `(tag, file name)`: tag 1 is a
        segment, tag 3 a directory arena."""
        data = (self.root / "data/node.kv/root.kvroot").read_bytes()
        slots = []
        for slot in range(2):
            at = ENVELOPE_BYTES + slot * ROOT_SLOT_BYTES
            records = []
            if len(data) >= at + ROOT_SLOT_BYTES:
                count = struct.unpack_from("<I", data, at + GARBAGE_COUNT_AT)[0]
                for index in range(min(count, MAX_GARBAGE)):
                    entry = at + GARBAGE_AT + index * GARBAGE_ENTRY_BYTES
                    tag, identifier = data[entry], struct.unpack_from("<Q", data, entry + 8)[0]
                    suffix = {1: "kvseg", 3: "kvdir"}.get(tag, "unknown")
                    records.append((tag, f"{identifier:016x}.{suffix}"))
            slots.append(records)
        return slots

    def copy(self, destination, sessions=(), node_files=()):
        """The stopped installation without scratch files, bearer tokens and
        the named backup sessions and node files."""
        leave_out = {self.root / "backups/local/sessions": set(sessions),
                     self.root / "data/node.kv": set(node_files)}
        shutil.copytree(self.root, destination / "installation", symlinks=True,
                        ignore=lambda directory, names: [
                            name for name in names
                            if name.endswith(".token")
                            or Path(directory) == self.root / "scratch"
                            or name in leave_out.get(Path(directory), ())])
        (destination / "installation/scratch").mkdir(exist_ok=True)


# --- workload ------------------------------------------------------------
ACCOUNTS = {
    "name": "accounts", "write_mode": "mutable", "retention_class": "operational",
    "schema": {"type": "object", "required": ["email"],
               "properties": {"email": {"type": "string"}, "balance": {"type": "number"}}},
    "indexes": [
        {"name": "balance", "fields": [{"path": "/balance", "kind": "number"}]},
        {"name": "region_status", "fields": [{"path": "/region", "kind": "string"},
                                             {"path": "/status", "kind": "string"}]},
        {"name": "email", "fields": [{"path": "/email", "kind": "string"}], "unique": True},
        {"name": "tags", "fields": [{"path": "/tags", "kind": "string_array"}]},
        {"name": "scores", "fields": [{"path": "/scores", "kind": "number_array"}]},
        {"name": "credit", "fields": [{"path": "/credit", "kind": "decimal"}]},
        {"name": "active", "fields": [{"path": "/active", "kind": "boolean"}]},
        {"name": "status", "fields": [{"path": "/status", "kind": "string"}]},
        {"name": "notes", "fields": [{"path": "/notes", "kind": "string"}],
         "text": {"analyzer": "english_v1"}},
        {"name": "memo_ja", "fields": [{"path": "/memo", "kind": "string"}],
         "text": {"analyzer": "japanese_v1"}},
    ],
}
LEDGER = {
    "name": "ledger", "write_mode": "append_only", "retention_class": "archivable_history",
    "schema": {"type": "object", "required": ["account", "seq", "amount"]},
    "indexes": [
        {"name": "account_seq", "unique": True,
         "fields": [{"path": "/account", "kind": "string"}, {"path": "/seq", "kind": "number"}]},
        {"name": "amount", "fields": [{"path": "/amount", "kind": "decimal"}]},
    ],
}
BLOBS = {"name": "blobs", "write_mode": "mutable", "retention_class": "operational",
         "schema": {"type": "object"}, "indexes": []}
NOTES = {"name": "notes", "write_mode": "mutable", "retention_class": "operational",
         "schema": {"type": "object"}, "strict_read_audit": True,
         "indexes": [{"name": "title", "fields": [{"path": "/title", "kind": "string"}],
                      "text": {"analyzer": "unicode_v1"}}]}
REGIONS = ["eu", "jp", "us", "br"]
WORDS = ["ledger", "harbor", "quick", "brown", "fox", "invoice", "settlement", "mist",
         "river", "audit", "garden", "copper", "window", "signal"]
MEMOS = ["東京タワーに行きました", "大阪で会議があります", "京都の庭園は静かです", "横浜港の夜景"]


def account(index, random_source):
    body = {
        "email": f"user{index}@example.test",
        "balance": [index * 1.25, 9007199254740993 + index, -index, 0][index % 4],
        "region": REGIONS[index % len(REGIONS)],
        "status": ["open", "closed", "frozen"][index % 3],
        "tags": sorted(random_source.sample(["vip", "new", "trial", "legacy", "b2b"], index % 4)),
        "scores": [index % 7, (index * 3) % 11],
        "credit": f"{index * 100}.{index % 100:02d}",
        "active": index % 2 == 0,
        "notes": " ".join(random_source.choice(WORDS) for _ in range(6)),
        "memo": MEMOS[index % len(MEMOS)],
        "profile": {"name": f"Übung {index} ☃", "level": None if index % 5 == 0 else index % 5},
    }
    if index % 6 == 0:
        del body["region"]
    return body


def blob(label, size, random_source):
    data = base64.b64encode(random_source.randbytes(size * 3 // 4)).decode()
    return {"label": label, "data": data}


class Workload:
    def __init__(self, installation, seed):
        self.installation = installation
        self.random = random.Random(seed)
        self.receipts = []
        self.backups = []
        self.credentials = []
        self.round = 0

    def setup(self):
        target = self.installation
        incarnation = json.loads(target.profile("default").read_bytes())["resource"]["incarnation"]
        self.incarnation = incarnation
        for definition in (ACCOUNTS, LEDGER, BLOBS):
            target.admin("create-collection", definition)
        snapshot = target.admin("read-policy-limits",
                                {"tenant": TENANT, "expected_incarnation": incarnation})
        limits = snapshot["limits"]
        # The smallest hot audit budget: the tenant audit stream is archived
        # into tenant-audit-archives within a few hundred writes.
        limits["audit_retention"]["hot_bytes"] = 131072
        limits["max_documents"] = 2_000_000
        # A short change feed: overwritten large images leave it quickly, and
        # a snapshot holds at most two of them. One commit must still fit.
        limits["history"]["max_feed_events"] = 16
        limits["history"]["max_feed_bytes"] = 2 << 20
        limits["max_page_size"] = 500
        target.admin("set-limits", limits)
        policy = snapshot["policy"]
        policy["grants"] += [
            {"principal": "app", "collection": "accounts", "actions": ["read", "write"]},
            {"principal": "app", "collection": "ledger", "actions": ["read", "write"]},
            {"principal": "auditor", "collection": None, "actions": ["read", "audit"]},
        ]
        target.admin("set-policy", policy)
        target.admin("activate-schema", {
            "activation_id": "notes-v1", "expected_incarnation": incarnation,
            "expected_schema_epoch": target.admin("read-policy-limits", {
                "tenant": TENANT, "expected_incarnation": incarnation})["schema_epoch"],
            "read_set": [], "changes": [{"kind": "create", "definition": NOTES}]})
        for family, principal, scopes in (
                ("11111111-2222-4333-8444-555555555501", "app", ["read", "write"]),
                ("11111111-2222-4333-8444-555555555502", "auditor", ["read", "audit"]),
                ("11111111-2222-4333-8444-555555555503", "app", ["read"])):
            request = {"family_id": family, "principal": principal, "tenant": TENANT,
                       "resource": {"kind": "database", "incarnation": incarnation},
                       "scopes": scopes, "lifetime_seconds": 3600}
            name = f"{principal}-{family[-2:]}"
            target.run("kasumid", "credential", "create", target.profile("control"),
                       write_private(target.work / "credential.json", request),
                       target.profile(name))
            self.credentials.append({"family_id": family, "principal": principal,
                                     "scopes": scopes, "profile": name})
            target.renewed.append(name)
        revoked = self.credentials[2]
        target.run("kasumid", "credential", "revoke", target.profile("control"),
                   revoked["family_id"])
        target.renewed.remove(revoked["profile"])

    def documents(self):
        target, random_source = self.installation, self.random
        for index in range(48):
            target.put("accounts", f"acct-{index:03d}", account(index, random_source), "absent")
        # Overwrites, merge patches and deletes of existing documents.
        for index in range(0, 48, 5):
            body = account(index + 100, random_source)
            body["email"] = f"user{index}@example.test"
            target.put("accounts", f"acct-{index:03d}", body)
        for index in range(1, 48, 7):
            target.data("patch", "accounts", f"acct-{index:03d}", json.dumps(
                {"status": "closed", "profile": {"level": 9}, "notes": None}))
        for index in range(3, 48, 11):
            target.data("delete", "accounts", f"acct-{index:03d}")
        # The application principal writes through its own credential.
        for index in range(48, 56):
            target.put("accounts", f"acct-{index:03d}", account(index, random_source),
                       "absent", profile="app-01")
        for sequence in range(36):
            account_id = f"acct-{sequence % 4:03d}"
            target.put("ledger", f"{account_id}-{sequence:04d}", {
                "account": account_id, "seq": sequence, "amount": f"{sequence * 7}.{sequence:02d}",
                "memo": random_source.choice(WORDS)}, "absent",
                profile="app-01" if sequence % 2 else "default")
        target.put("notes", "note-1", {"title": "Résumé of the misty harbor", "pinned": True})
        target.put("notes", "note-2", {"title": "harbor signals at dawn", "pinned": False})
        target.put("blobs", "blob-live", blob("live", 96_000, random_source), "absent")
        target.put("blobs", "blob-small", {"label": "small", "data": "x"}, "absent")
        # One atomic batch over three collections with an exact-version check.
        _, current = target.data("get", "accounts", "acct-002")
        version = current["result"]["document"]["version"]
        batch = {"idempotency_key": "atomic-transfer-1", "operations": [
            {"op": "patch", "collection": "accounts", "id": "acct-002",
             "patch": {"balance": 4242}, "expected": {"version": version}},
            {"op": "put", "collection": "ledger", "id": "acct-002-9000",
             "body": {"account": "acct-002", "seq": 9000, "amount": "4242.00"},
             "expected": "absent"},
            {"op": "delete", "collection": "notes", "id": "note-2"}]}
        target.mutate(batch)
        self.receipts.append({"profile": "default", "batch": batch})
        # Retained rejections: a unique index, a failed precondition, and an
        # append-only overwrite refused by the collection's write mode.
        duplicate = {"idempotency_key": "duplicate-email-1", "operations": [
            {"op": "put", "collection": "accounts", "id": "acct-dup",
             "body": {"email": "user10@example.test"}, "expected": "absent"}]}
        target.mutate(duplicate, expect=None)
        self.receipts.append({"profile": "default", "batch": duplicate})
        stale = {"idempotency_key": "stale-version-1", "operations": [
            {"op": "put", "collection": "accounts", "id": "acct-004",
             "body": {"email": "user4@example.test", "balance": 1},
             "expected": {"version": 1}}]}
        target.mutate(stale, expect=None)
        self.receipts.append({"profile": "default", "batch": stale})
        mine = {"idempotency_key": "app-insert-1", "operations": [
            {"op": "put", "collection": "accounts", "id": "acct-app",
             "body": {"email": "app@example.test", "balance": 77, "region": "jp",
                      "status": "open"}, "expected": "absent"}]}
        target.mutate(mine, profile="app-01")
        self.receipts.append({"profile": "app-01", "batch": mine})
        target.data("get", "notes", "note-1")

    def backup(self):
        target = self.installation
        checkpoint = target.work / f"checkpoint-{len(self.backups)}.json"
        created = json.loads(target.run("kasumid", "backup", "create", target.profile("default"),
                                        "local", checkpoint).stdout)
        target.run("kasumid", "backup", "verify", target.profile("default"), "local",
                   created["session_id"])
        self.backups.append({"destination": "local", "session_id": created["session_id"],
                             "checkpoint": json.loads(checkpoint.read_bytes())})

    def roll_segment(self, interval):
        """Seal the first segment at its 64 MiB limit while little in it is
        still live, so the cycle that reclaims it soon copies little.

        Two large documents are overwritten, one is deleted and one stays
        for the tests to read back in 48 KiB body chunks. The rest of
        the segment fills with large writes the collection refuses for a
        stale expected version: each is journaled with its whole body and
        keeps a permanent rejection receipt, but leaves no document version,
        change image or history body behind. Small writes then pass
        snapshots, which purge the journal, before the segment rolls. Only
        the newest segment is ever written and no cycle evacuates it, so the
        one being filled is the newest when the fill starts."""
        target = self.installation
        filling = max(self.segments())
        for attempt in range(4):
            target.put("blobs", f"blob-churn-{attempt % 2}",
                       blob(f"churn {attempt}", LARGE_BYTES, self.random))
        target.data("delete", "blobs", "blob-churn-0")
        refused = 0
        while True:
            sizes = self.segments()
            if max(sizes) != filling or sizes[filling] >= SEGMENT_BYTES - 12 * LARGE_BYTES:
                break
            status, _ = target.put("blobs", "blob-churn-1",
                                   blob(f"refused {refused}", LARGE_BYTES, self.random),
                                   expected={"version": 1}, expect=None)
            require(status != 0, "a large write with a stale version was accepted")
            refused += 1
            require(refused != 8 or self.segments()[filling] > sizes[filling],
                    "refused writes do not reach the journal")
        require(max(self.segments()) == filling, "a large write rolled the segment")
        self.backup()
        self.progress(f"segment {filling:x} filled by {refused} refused large writes")
        self.churn(2 * interval)
        require(max(self.segments()) == filling,
                "the segment rolled while large values were still live")
        while max(self.segments()) == filling:
            self.churn(4)
        self.progress(f"segment {filling:x} sealed")
        return filling

    def compact(self, limit=4000):
        """Write until every sealed segment has been evacuated and unlinked,
        no cycle runs and nothing is owed an unlink.

        The large writes leave enough directory arena bytes that the cycle
        is due as soon as the segment they filled is sealed."""
        target = self.installation
        for step in range(limit):
            storage = target.storage()
            if (storage["compaction_phase"] == "idle" and storage["garbage_files"] == 0
                    and target.root_garbage() == [0, 0] and len(self.segments()) == 1):
                return storage
            self.churn(1)
            if step % 50 == 49:
                self.progress("compacting")
        raise ValueError("a sealed segment was never reclaimed")

    def segments(self):
        """Each segment file's size by identifier. A file reclaimed while it
        is listed is left out."""
        sizes = {}
        for path in (self.installation.root / "data/node.kv").glob("*.kvseg"):
            try:
                sizes[int(path.stem, 16)] = path.stat().st_size
            except FileNotFoundError:
                pass
        return sizes

    def progress(self, message):
        storage = self.installation.storage()
        print(f"{time.strftime('%H:%M:%S')} {message}: {storage['compaction_phase']} cycle "
              f"{storage['compaction_cycle']}, {storage['segment_files']} segments "
              f"{storage['segment_bytes']} bytes, {storage['arena_files']} arenas "
              f"{storage['arena_bytes']} bytes, trigger {storage['compaction_trigger_bytes']}, "
              f"{storage['garbage_files']} garbage", file=sys.stderr, flush=True)

    def churn(self, writes):
        """Small writes: journal entries for snapshots, audit records for
        archive segments and directory growth for compaction cycles."""
        target = self.installation
        for _ in range(writes):
            step = self.round
            self.round += 1
            identity = f"churn-{step // 4 % 24:02d}"
            kind = step % 4
            if kind == 0:
                body = account(1000 + step, self.random)
                body["email"] = f"{identity}-{step}@example.test"
                target.put("accounts", identity, body)
            elif kind == 1:
                target.data("patch", "accounts", identity,
                            json.dumps({"status": "frozen", "balance": step}))
            elif kind == 2:
                target.put("ledger", f"churn-{step:06d}", {
                    "account": "churn", "seq": 100000 + step, "amount": f"{step}.00"}, "absent")
            elif (step // 4) % 3:
                target.data("delete", "accounts", identity)
            else:
                target.data("patch", "accounts", identity, json.dumps({"region": "br"}))


QUERIES = [
    ("all accounts by id", {"collection": "accounts", "sort": ["/email"], "limit": 500}),
    ("number range", {"collection": "accounts", "filter": {"/balance": {"gte": 10, "lt": 60}},
                      "sort": ["-/balance"]}),
    ("exact large number", {"collection": "accounts", "filter": {"/balance": 9007199254740994}}),
    ("compound strings", {"collection": "accounts",
                          "filter": {"/region": "jp", "/status": {"in": ["open", "frozen"]}},
                          "sort": ["/status", "/email"]}),
    ("missing field", {"collection": "accounts", "filter": {"/region": {"exists": False}},
                       "sort": ["/email"]}),
    ("negation", {"collection": "accounts",
                  "filter": {"not": {"/status": "open"}, "/active": True}, "sort": ["/email"]}),
    ("multikey contains", {"collection": "accounts",
                           "filter": {"and": [{"/tags": {"contains": "vip"}},
                                              {"/tags": {"contains": "b2b"}}]},
                           "sort": ["/email"]}),
    ("number array", {"collection": "accounts", "filter": {"/scores": {"contains": 6}},
                      "sort": ["/email"]}),
    ("decimal range", {"collection": "accounts",
                       "filter": {"/credit": {"gte": "1000.00", "lte": "2500.50"}},
                       "sort": ["/credit"]}),
    ("unique point", {"collection": "accounts", "filter": {"/email": "user10@example.test"}}),
    ("select", {"collection": "accounts", "filter": {"/region": "eu"},
                "select": ["/email", "/profile/name"], "sort": ["/email"], "limit": 7}),
    ("aggregate", {"collection": "accounts", "group_by": ["/region"],
                   "aggregate": {"count": {"count": "*"}, "sum": {"sum": "/balance"},
                                 "max": {"max": "/balance"},
                                 "mean": {"avg": "/balance", "scale": 3}}}),
    ("indexed count", {"collection": "accounts", "filter": {"/status": "closed"},
                       "aggregate": {"count": {"count": "*"}}}),
    ("english stemming", {"collection": "accounts",
                          "search": {"index": "notes", "query": "invoices settlement"},
                          "limit": 20}),
    ("english prefix", {"collection": "accounts",
                        "search": {"index": "notes", "query": "harb", "mode": "prefix"},
                        "sort": ["/email"], "limit": 50}),
    ("japanese", {"collection": "accounts", "search": {"index": "memo_ja", "query": "東京"},
                  "sort": ["/email"], "limit": 50}),
    ("ledger seek", {"collection": "ledger", "filter": {"/account": "acct-001"},
                     "sort": ["/seq"], "paging": "seek", "limit": 500}),
    ("ledger decimal sum", {"collection": "ledger", "filter": {"/account": "acct-002"},
                            "aggregate": {"total": {"sum": "/amount"},
                                          "entries": {"count": "*"}}}),
    ("all ledger", {"collection": "ledger", "sort": ["/account", "/seq"], "limit": 500}),
    ("unicode text", {"collection": "notes", "search": {"index": "title", "query": "résumé"}}),
    ("all notes", {"collection": "notes", "allow_scan": True, "limit": 500}),
    ("all blobs", {"collection": "blobs", "allow_scan": True, "limit": 500}),
]


def manifest(installation, workload, commit):
    """Everything the serving build answers about the installation now."""
    target = installation
    target.renew()
    _, collections = target.data("collections")
    queries = []
    for name, request in QUERIES:
        # An audited read waits for its own audit record; allow it a retry.
        for attempt in range(5):
            status, answer = target.data("query", "--json", json.dumps(request), "--all",
                                         expect=None)
            if status == 0:
                break
            time.sleep(2)
        require(status == 0, f"query {name} failed: {answer}")
        result = answer["result"]
        queries.append({"name": name, "request": request, "revision": result["revision"],
                        "rows": summarize(result["rows"]), "aggregates": result["aggregates"]})
    documents = {}
    for name, request in QUERIES:
        if name.startswith("all "):
            rows = next(query["rows"] for query in queries if query["name"] == name)
            documents[request["collection"]] = [
                {"id": row["id"], "version": row["version"], "body": row["body"]} for row in rows]
    absent = []
    for collection, identity in (("accounts", "acct-003"), ("accounts", "acct-dup"),
                                 ("notes", "note-2"), ("blobs", "blob-churn-0"),
                                 ("accounts", "never-written")):
        _, answer = target.data("get", collection, identity)
        require(answer["result"]["document"] is None, f"{collection}/{identity} still exists")
        absent.append({"collection": collection, "id": identity})
    receipts = []
    for receipt in workload.receipts:
        status, answer = target.data("resolve-mutation", "-", input=dumps_exact(receipt["batch"]),
                                     profile=receipt["profile"], expect=None)
        require(status == 0, f"resolving {receipt['batch']['idempotency_key']}: {answer}")
        receipts.append({"principal": "app" if receipt["profile"].startswith("app") else
                         "administrator", "batch": receipt["batch"], "resolution": answer["result"]})
    credentials = []
    for credential in workload.credentials:
        status = json.loads(target.run("kasumid", "credential", "status",
                                       target.profile("control"),
                                       credential["family_id"]).stdout)
        credentials.append({**credential, "status": status})
    for name in ("default", "control"):
        profile = json.loads(target.profile(name).read_bytes())
        status = json.loads(target.run("kasumid", "credential", "status",
                                       target.profile("control"), profile["family_id"]).stdout)
        credentials.append({"family_id": profile["family_id"], "principal": profile["principal"],
                            "profile": name, "status": status})
    backups = []
    for backup in workload.backups:
        status = json.loads(target.run("kasumid", "backup", "status", target.profile("default"),
                                       backup["destination"], backup["session_id"]).stdout)
        backups.append({**backup, "status": status})
    health = target.health()
    group = next(group for group in health["groups"] if group["tenant"] == TENANT)
    control = next(group for group in health["groups"] if group["tenant"] != TENANT)
    marker = json.loads((target.root / "data/installation.json").read_bytes())
    node = target.root / "data/node.kv"
    return {
        "format": 1,
        "written_by": {"commit": commit,
                       "kasumid_sha256": sha256_file(target.binaries / "kasumid"),
                       "schedule": target.schedule},
        "installation": {"directory": str(target.root), "tenant": TENANT,
                         "incarnation": workload.incarnation,
                         "installation_id": marker["installation_id"],
                         "database_id": marker["database_id"],
                         "control_incarnation": marker["control_incarnation"],
                         "ports": target.ports},
        "collections": collections["result"]["collections"],
        "documents": documents,
        "absent": absent,
        "queries": queries,
        "receipts": receipts,
        "policy_limits": target.admin("read-policy-limits", {
            "tenant": TENANT, "expected_incarnation": workload.incarnation}),
        "status": target.admin("manage", {"operation": "status"}),
        "credentials": credentials,
        "backups": backups,
        "tenant_audit": group["retention"],
        "control_audit": control["retention"],
        "service_audit": health.get("service_audit"),
        "storage": target.storage(),
        "node_files": sorted(path.name for path in node.iterdir()),
        "tenant_audit_archive_objects": len(list(
            (target.root / "data/tenant-audit-archives").iterdir())),
        "in_flight": None,
    }


def kill_with_garbage(installation, sealed):
    """Kill the serving build at the first observation of a root slot that
    lists garbage files, the `sealed` segment among them unless it is gone,
    with a writer running. The writer only touches the `inflight` documents,
    so every other answer of the last manifest holds. The writes drive the
    cycle that reclaims the sealed segment."""
    target = installation
    sealed = f"{sealed:016x}.kvseg"
    node = target.root / "data/node.kv"

    def listed():
        records = target.garbage_records()
        names = {name for slot in records for _, name in slot}
        ready = names and (sealed in names or not (node / sealed).exists())
        return [len(slot) for slot in records] if ready else [0, 0]

    written = 0
    garbage = [0, 0]
    deadline = time.monotonic() + 7200
    writer = target.session()
    while max(garbage) == 0:
        require(time.monotonic() < deadline, "no root slot ever listed garbage files")
        request = {"id": 10_000_000 + written, "argv": ["put", "accounts", f"inflight-{written % 8}",
                   json.dumps({"email": f"inflight-{written}@example.test", "balance": written}),
                   "--key", f"inflight-{written}"]}
        writer.stdin.write((json.dumps(request) + "\n").encode())
        writer.stdin.flush()
        written += 1
        # The write is in flight: watch the root until it answers.
        while True:
            garbage = listed()
            if max(garbage) > 0:
                break
            if select.select([writer.stdout], [], [], 0)[0]:
                require(writer.stdout.readline(), "the kasumictl session ended")
                break
    target.kill()
    records = target.garbage_records()
    return {"collection": "accounts", "id_prefix": "inflight-", "writes_sent": written,
            "root_garbage_records": [[list(record) for record in slot] for slot in records]}


def generate(arguments):
    os.umask(0o077)
    work, out = Path(arguments.work).resolve(), Path(arguments.out).resolve()
    require(not work.exists(), f"{work} exists")
    out.mkdir(parents=True, exist_ok=True)
    schedule = {"patched": True, "snapshot_interval": SNAPSHOT_INTERVAL,
                "compaction_slack_bytes": COMPACTION_SLACK_BYTES}
    interval = schedule["snapshot_interval"]
    target = Installation(work, arguments.base_port, schedule)
    workload = Workload(target, seed=12140939)
    first, second = arguments.first_bin_dir, arguments.second_bin_dir

    def save(name, document, node_files=()):
        destination = out / name
        require(not destination.exists(), f"{destination} exists")
        destination.mkdir()
        # The second backup holds the history it exported; the tests read
        # only the destination marker, and the copies stay small.
        target.copy(destination, [backup["session_id"] for backup in workload.backups[1:]],
                    node_files)
        write_private(destination / "manifest.json",
                      dumps_exact(document, indent=1, sort_keys=True).encode())
        print(f"saved {name}", file=sys.stderr)

    def tail(writes):
        """Leave entries after the last snapshot, away from the next one,
        with the compaction cycle idle and nothing owed an unlink."""
        workload.churn(writes)
        while True:
            storage = target.storage()
            if (8 <= target.group()["retention"]["next_sequence"] % interval <= interval - 24
                    and storage["compaction_phase"] == "idle" and storage["garbage_files"] == 0
                    and target.root_garbage() == [0, 0]):
                return
            workload.churn(1)

    target.init(first)
    target.serve(first)
    workload.setup()
    workload.documents()
    workload.backup()
    target.admin("manage", {"operation": "rotate_data_key"})
    workload.progress("documents written")
    sealed = workload.roll_segment(interval)
    # Killed while its root lists the files the cycle after the seal
    # reclaims, the sealed segment among them, as if right after unlinking
    # them: the copy leaves them out, and the store stays small.
    killed = manifest(target, workload, "12140939")
    in_flight = kill_with_garbage(target, sealed)
    listed = sorted({name for slot in target.garbage_records() for _, name in slot})
    save("12140939-killed", {**killed, "in_flight": in_flight}, listed)

    # The first build recovers its own interrupted store, finishes the
    # cycle and stops cleanly, then the second build serves it, as the
    # deployed store was first served by its writer.
    target.serve(first)
    workload.compact()
    tail(12)
    workload.progress("first build settled")
    clean = manifest(target, workload, "12140939")
    target.stop()
    save("12140939-clean", clean)

    target.serve(second)
    workload.churn(interval + 20)
    workload.compact()
    tail(12)
    workload.progress("second build settled")
    served = manifest(target, workload, "cf9959f1")
    target.stop()
    save("cf9959f1-clean", served)
    return {"out": str(out), "copies": sorted(path.name for path in out.iterdir())}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    generating = commands.add_parser("generate")
    generating.add_argument("--first-bin-dir", required=True)
    generating.add_argument("--second-bin-dir", required=True)
    generating.add_argument("--work", required=True)
    generating.add_argument("--out", required=True)
    generating.add_argument("--base-port", type=int, required=True)
    arguments = parser.parse_args(argv)
    try:
        result = generate(arguments)
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        print(f"deployed_format_fixture: {error}", file=sys.stderr)
        return 1
    finally:
        for child in CHILDREN:
            if child.poll() is None:
                child.kill()
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
