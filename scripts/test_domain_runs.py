"""Domain runners against stand-in executables; never release evidence.

The stand-ins are small scripts that speak the product's command surface
(serve, session, ready, credential observe, ...). They prove custody, timing and
adapter behaviour. They do not prove anything about Kasumi itself.
"""
import base64
import copy
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

import attempt_index
import domain_run
import process_ha_topology as topology
from test_process_ha import fixture_control_placement
import release_gate
import repeatable_assembly as owned
import run_ha_soak as soak
import verify_release_acceptance as acceptance

TARGET = acceptance.REFERENCE
PRODUCT = r'''
import json, signal, sys, time
from pathlib import Path
args = sys.argv[1:]
knobs = Path(__file__).with_name("behavior.json")
behavior = json.loads(knobs.read_text()) if knobs.exists() else {}
if args[:1] == ["serve"]:
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(behavior.get("stop_exit", 0)))
    while True:
        time.sleep(.05)
if "session" in args:
    store = {}
    for line in sys.stdin:
        request = json.loads(line)
        words = request["argv"]
        if words[0] == "put":
            store[words[2]] = json.loads(words[3])
            result = {"receipt": {"revision": len(store)}}
        else:
            body = store.get(words[2])
            if request["id"] == behavior.get("corrupt_reply"):
                body = {"cycle": -1}
            result = {"document": {"id": words[2], "body": body, "version": 1}}
        print(json.dumps({"id": request["id"], "status": 0,
                          "document": {"ok": True, "result": result}}), flush=True)
    sys.exit(0)
if args[-1:] == ["ready"]:
    counter = Path(__file__).with_name("ready-polls")
    seen = int(counter.read_text()) if counter.exists() else 0
    counter.write_text(str(seen + 1))
    sys.exit(0 if seen >= behavior.get("ready_failures", 0) else 1)
if args[:2] == ["credential", "observe"]:
    import hashlib
    counter = Path(__file__).with_name("credential-observations")
    n = int(counter.read_text()) + 1 if counter.exists() else 1
    counter.write_text(str(n))
    print(json.dumps({"profile_sha256": hashlib.sha256(Path(args[2]).read_bytes()).hexdigest(),
                      "bearer_sha256": f"{n:064x}", "expires_at_ms": 1800000000000 + n}))
    sys.exit(0)
if args[:2] == ["audit", "status"]:
    counter = Path(__file__).with_name("archive-observations")
    n = int(counter.read_text()) + 1 if counter.exists() else 0
    counter.write_text(str(n))
    stream = "12345678-1234-4234-8234-123456789abc"
    head = ({"stream_id": stream, "object": {"first_sequence": n - 1, "next_sequence": n,
                                            "ciphertext_sha256": "1" * 64}} if n else None)
    print(json.dumps({"persistence_failed": False, "position": {"stream_id": stream,
                      "pruned_before": n, "archive_head": head}}))
    sys.exit(0)
print(json.dumps({"ok": True, "argv": args}))
sys.exit(behavior.get("fail", {}).get(args[0], 0))
'''


class DomainFixture(unittest.TestCase):
    """A journal root holding synthetic frozen evidence and nine installed stand-ins."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="kasumi-domain-run-unit-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        attempt_index.create(self.root, "unit-journal", "unit-host", TARGET)
        self.evidence = self.root / "functional"
        source = self.evidence / "source"
        (source / "scripts").mkdir(parents=True)
        for script in Path(domain_run.__file__).resolve().parent.glob("*.py"):
            shutil.copyfile(script, source / "scripts" / script.name)
        (source / "release/oci").mkdir(parents=True)
        (source / "release/oci/base-image.json").write_text("{}")
        release = self.evidence / "target/release"
        release.mkdir(parents=True)
        self.binaries = {}
        for name in sorted(acceptance.package.BINARIES):
            path = release / name
            path.write_text("#!" + sys.executable + "\n# stand-in " + name + "\n" + PRODUCT)
            path.chmod(0o755)
            self.binaries[name] = (path, release_gate.sha256(path))
        self.rewrite_inventory()
        self.functional = {"source_commit": "1" * 40, "source_tree": "2" * 40,
                           "source_archive_sha256": "3" * 64, "lockfile_sha256": "4" * 64,
                           "source_files_sha256": release_gate.sha256(
                               self.evidence / "source-files.json")}
        (self.evidence / "evidence.json").write_text(json.dumps(self.functional))
        patcher = patch.object(domain_run.package, "verify_evidence",
                               side_effect=lambda _: (self.functional, {}, TARGET, self.binaries))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.install()

    def rewrite_inventory(self):
        self.files = release_gate.inventory(self.evidence / "source")
        (self.evidence / "source-files.json").write_text(json.dumps(self.files))

    def behave(self, **knobs):
        (self.evidence / "target/release/behavior.json").write_text(json.dumps(knobs))

    def install(self):
        """Nine installed nodes in three groups, plus the operator's soak plan."""
        plan = {"schema": topology.SCHEMA, "nodes": [],
                "binaries": {name: str(self.binaries[name][0])
                             for name in ("kasumid", "kasumi-authority")}}
        installed = self.root / "installed"
        for role_index, role in enumerate(("data", "control", "authority")):
            peers, configs = [], []
            for index in range(3):
                node_id = role_index * 3 + index + 1
                name = f"{role}-{index + 1}"
                home = installed / name
                for child in ("persistent", "scratch"):
                    (home / child).mkdir(parents=True, mode=0o700)
                der = ("synthetic leaf " + name).encode()
                (home / "leaf.pem").write_bytes(b"-----BEGIN CERTIFICATE-----\n"
                                                + base64.b64encode(der)
                                                + b"\n-----END CERTIFICATE-----\n")
                peers.append({"node_id": node_id, "endpoint": f"https://127.0.0.1:{20000 + node_id}",
                              "certificate_pins": [hashlib.sha256(der).hexdigest()]})
                configs.append((home, {
                    "mode": "replicated", "tenants": [{"tenant": "unit"}] if role == "data" else [],
                    "target_recovery": None, "database_path": str(home / "persistent/node.kv"),
                    "persistent_disk": {"roots": {"node": str(home / "persistent")}},
                    "scratch_disk": {"directory": str(home / "scratch")},
                    "signer_verifier": {"identity": {"node_id": node_id},
                                        "database_path": str(home / "persistent/verifier.kv")},
                    "replication": {"node_id": node_id,
                                    "listener": {"tls": {"certificate": str(home / "leaf.pem")}}}}))
                plan["nodes"].append({"id": name, "role": role, "group": role,
                                      "config": str(home / "config.json")})
            for home, config in configs:
                config.update(fixture_control_placement(role))
                config["replication"].update(peers=peers,
                                             initial_voters=[peer["node_id"] for peer in peers])
                (home / "config.json").write_text(json.dumps(config))
        self.topology = installed / "topology.json"
        self.topology.write_text(json.dumps(plan))
        files = {}
        for name in ("default-profile.json", "operator.json", "admin.json", "manage.json",
                     "checkpoint.json"):
            files[name] = installed / name
            files[name].write_text(json.dumps({"synthetic": name}))
        self.soak_plan = installed / "soak-plan.json"
        self.soak_plan.write_text(json.dumps({
            "schema": soak.PLAN_SCHEMA, "profile": str(files["default-profile.json"]),
            "collection": "soak", "readiness": [str(files["admin.json"])],
            "maintenance": {
                "archival": [{"binary": "kasumid",
                              "arguments": ["audit", "status", str(files["operator.json"])]}],
                "backup": [{"binary": "kasumid", "arguments": [
                                "backup", "create", str(files["operator.json"]), "local",
                                str(files["checkpoint.json"])]},
                           {"binary": "kasumid", "arguments": [
                               "backup", "status", str(files["operator.json"]), "local", "unit"]}],
                "membership-maintenance": [{"binary": "kasumictl", "arguments": [
                    "--config", str(files["admin.json"]), "manage", str(files["manage.json"])]}]}}))

    def soak(self, attempt, *extra):
        output = self.root / "runs" / attempt
        output.parent.mkdir(exist_ok=True)
        soak.main(["--evidence", str(self.evidence), "--journal", str(self.root),
                   "--attempt-id", attempt, "--output", str(output),
                   "--topology", str(self.topology), "--plan", str(self.soak_plan), *extra])
        return output

    def reference(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
        return owned.ref(self.root, path)

    def host(self):
        return {"id": "unit-host", "physical_machine": "aarch64", "execution_machine": "aarch64",
                "emulated": False,
                "reservation": {"id": "unit", "starts_at": "2020-01-01T00:00:00+00:00",
                                "ends_at": "2999-01-01T00:00:00+00:00", "cpu_count": 4,
                                "memory_bytes": 16 << 30, "disk_bytes": 128 << 30},
                "preflight": self.reference("host.json", {
                    "schema": 3, "os": "Linux", "machine": "aarch64", "requested_target": TARGET,
                    "errors": [], "translated": False, "effective_memory_bytes": 16 << 30}),
                "attestation": self.reference("host-attestation.txt", b"unit attestation\n")}

    def gate(self, custody, details, artifacts=None):
        """Compose the gate as the bundle composer would, with matching manifest inputs."""
        report = json.loads((custody / "report.json").read_text())
        configs = {item["id"]: {"id": item["id"], "file": owned.ref(
            self.root, custody / item["file"]["path"])} for item in report["configurations"]}
        identity = {"source_commit": "1" * 40, "source_tree": "2" * 40,
                    "source_archive_sha256": "3" * 64, "lockfile_sha256": "4" * 64,
                    "source_files_sha256": self.functional["source_files_sha256"],
                    "patches_sha256": "5" * 64, "configurations_sha256": "6" * 64}
        record = domain_run.gate_record(self.root, custody / "report.json", identity, self.host(),
                                        configs, artifacts or {}, details)
        return record, identity, configs

    def accept(self, record, identity, configs, artifacts=None, candidates=None):
        gate = {"id": record["id"], "evidence": self.reference("gate.json", record)}
        files = {"scripts/" + path.name: {"sha256": release_gate.sha256(path)}
                 for path in (self.evidence / "source/scripts").glob("*.py")}
        files.update({name: entry for name, entry in self.files.items()
                      if not name.startswith("scripts/")})
        binaries = {TARGET: {name: digest for name, (_, digest) in self.binaries.items()}}
        return acceptance.verify_gate(self.root, gate, identity, files, configs, binaries,
                                      artifacts or {}, candidates or {})

    def rewrite(self, custody, change):
        """Tamper inside a run, then re-seal the report and outcome around it."""
        report = json.loads((custody / "report.json").read_text())
        change(report)
        (custody / "report.json").write_text(json.dumps(report))
        outcome = json.loads((custody / "outcome.json").read_text())
        outcome["products"] = [{"id": "report", "file": owned.ref(custody, custody / "report.json")}]
        (custody / "outcome.json").write_text(json.dumps(outcome))


class SoakTests(DomainFixture):
    # Short enough to test, long enough for owned children on a loaded host.
    SHORT = {"duration_seconds": 30, "heartbeat_seconds": 10, "session_seconds": 10,
             "startup_seconds": 120, "drain_seconds": 120}

    def qualifying(self):
        """Shrink the qualifying contract itself, in the runner and the verifier alike."""
        for target, name, value in ((soak, "QUALIFYING", self.SHORT),
                                    (acceptance, "SOAK_SECONDS", self.SHORT["duration_seconds"]),
                                    (acceptance, "HEARTBEAT_SECONDS", self.SHORT["heartbeat_seconds"])):
            patcher = patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_short(self, attempt="soak-1"):
        with patch.object(soak, "main", wraps=soak.main):
            output = self.root / "runs" / attempt
            output.parent.mkdir(exist_ok=True)
            with domain_run.Run(soak.KIND, soak.RUNNER, soak.MODULES, self.evidence, output,
                                self.root, attempt, dict(soak.QUALIFYING),
                                domain_run.QUALIFYING) as run:
                soak.execute(run, dict(soak.QUALIFYING), self.topology, self.soak_plan, .02)
        return output

    def test_rehearsal_runs_every_phase_and_is_rejected_as_evidence(self):
        self.behave(ready_failures=2)
        duration, interval = self.SHORT["duration_seconds"], self.SHORT["heartbeat_seconds"]
        custody = self.soak("rehearsal-1", "--rehearsal-seconds", str(duration),
                            "--rehearsal-heartbeat-seconds", str(interval))
        report = json.loads((custody / "report.json").read_text())
        outcome = json.loads((custody / "outcome.json").read_text())
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["qualification"], domain_run.REHEARSAL)
        self.assertEqual(outcome["qualification"], "rehearsal-not-release-evidence")
        details = report["details"]
        # Startup (three readiness polls) and drain sit outside the measured interval.
        self.assertEqual(len(details["startup_polls"]), 2)
        self.assertGreater(details["phases"]["measured"], 0)
        self.assertGreaterEqual(details["phases"]["drain"] - details["phases"]["measured"], duration)
        beats = [json.loads(line) for line in (custody / "heartbeats.jsonl").read_text().splitlines()]
        self.assertEqual([beat["elapsed_seconds"] for beat in beats], list(range(0, duration + 1, interval)))
        self.assertEqual(beats[0]["successful_operations"], 0)
        self.assertTrue(all(later["successful_operations"] > earlier["successful_operations"]
                            for earlier, later in zip(beats, beats[1:])))
        self.assertEqual({event["id"] for event in details["maintenance"]},
                         acceptance.SCENARIOS["ha-soak"])
        self.assertGreaterEqual(len(details["sessions"]), 2)
        daemons = [json.loads((custody / item["receipt"]["path"]).read_text())
                   for item in report["processes"] if item["id"] in
                   {member["process_id"] for member in report["topology"]}]
        self.assertEqual(len(daemons), 9)
        for record in daemons:
            self.assertEqual((record["stop"]["signal"], record["process_exit_code"],
                              record["cleanup"]["signals"]), ("SIGTERM", 0, []))
            self.assertLessEqual(record["started_elapsed_seconds"], details["phases"]["measured"])
            self.assertGreaterEqual(record["stop"]["elapsed_seconds"], details["phases"]["drain"])
            self.assertGreaterEqual(record["duration_seconds"], duration)
        entries = attempt_index.replay(self.root)
        self.assertEqual(entries["rehearsal-1"]["begin"]["kind"], "ha-soak")
        # The same code, honestly labelled: the adapter refuses it.
        record, identity, configs = self.gate(custody, soak.gate_details(self.root, custody / "report.json"))
        with self.assertRaisesRegex(ValueError, "non-qualifying rehearsal"):
            self.accept(record, identity, configs)
        # Relabelling the report cannot promote it: its parameters are not the contract.
        self.rewrite(custody, lambda report: report.update(qualification=domain_run.QUALIFYING))
        record, identity, configs = self.gate(custody, soak.gate_details(self.root, custody / "report.json"))
        with self.assertRaisesRegex(ValueError, "differ from the qualifying contract"):
            self.accept(record, identity, configs)

    def test_qualifying_run_is_accepted_and_tampering_is_rejected(self):
        self.qualifying()
        custody = self.run_short()
        details = soak.gate_details(self.root, custody / "report.json")
        record, identity, configs = self.gate(custody, details)
        kind, attempt = self.accept(record, identity, configs)
        self.assertEqual((kind, attempt), ("ha-soak", "runs/soak-1/outcome.json"))
        entries = attempt_index.replay(self.root)
        self.assertEqual(entries["soak-1"]["terminal"]["receipt"]["path"],
                         "attempts/soak-1/attempt.json")
        # The journaled attempt can be selected only by a gate of its own kind.
        attempts = [{"id": "soak-1", "receipt": entries["soak-1"]["terminal"]["receipt"]}]
        acceptance.verify_attempts(self.root, attempts, {attempt: "ha-soak"})
        with self.assertRaisesRegex(ValueError, "attempt of another kind"):
            acceptance.verify_attempts(self.root, attempts, {attempt: "recovery"})

        def rejected(message, change, **kwargs):
            altered = copy.deepcopy(record)
            other_identity, other_configs = copy.deepcopy(identity), copy.deepcopy(configs)
            change(altered, other_identity, other_configs)
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                self.accept(altered, other_identity, other_configs, **kwargs)

        # Wrong runner identity: another frozen file, or the right path with other bytes.
        other = self.evidence / "source/scripts/gate_process.py"
        rejected("registered frozen runner", lambda r, i, c: r.update(runner={
            "source_path": "scripts/gate_process.py", "sha256": release_gate.sha256(other)}))
        rejected("domain runner is not frozen source",
                 lambda r, i, c: r["runner"].update(sha256="0" * 64))
        # Wrong source or candidate.
        def other_source(r, i, c):
            i["source_commit"] = "9" * 40
            r["identity"] = dict(i)
        rejected("another frozen source or candidate", other_source)
        rejected("candidate/source identity mismatch",
                 lambda r, i, c: r["binaries"].update(kasumid="0" * 64))
        # Shortened duration, in the claim or in the interval.
        rejected("soak gate details differ",
                 lambda r, i, c: r["details"].update(duration_seconds=2))
        rejected("domain interval differs",
                 lambda r, i, c: r.update(finished_at=r["started_at"]))
        # Missing or substituted evidence.
        rejected("omitted or substituted an original owned process",
                 lambda r, i, c: r["processes"].pop())
        rejected("scenarios differ from the run's recounted raw rows",
                 lambda r, i, c: r["scenarios"].pop())
        rejected("scenarios differ from the run's recounted raw rows",
                 lambda r, i, c: r["scenarios"][0].update(iterations=99))
        rejected("soak topology differs",
                 lambda r, i, c: r["topology"][0].update(certificate_sha256="0" * 64))
        rejected("not exactly one manifest configuration", lambda r, i, c: c["soak-plan"].update(
            file=self.reference("other-plan.json", {"schema": "another operator plan"})))
        rejected("configurations differ from the files the run consumed",
                 lambda r, i, c: r.update(configuration_ids=r["configuration_ids"][:-1]))
        # A changed retained byte breaks its own reference.
        beats = custody / "heartbeats.jsonl"
        original = beats.read_bytes()
        beats.write_bytes(original.replace(b'"unexpected_errors": 0', b'"unexpected_errors": 1', 1))
        with self.assertRaises(ValueError):
            self.accept(record, identity, configs)
        beats.write_bytes(original)
        self.accept(record, identity, configs)

        # Re-sealed forgeries: the adapter recomputes from the raw replies and
        # the daemons' own receipts, not from the report's numbers.
        def forged_heartbeats(report):
            rows = [json.loads(line) for line in beats.read_text().splitlines()]
            rows[1]["successful_operations"] += 1000
            beats.write_text("".join(json.dumps(row) + "\n" for row in rows))
            report["details"]["heartbeats"] = owned.ref(custody, beats)

        def dropped_replies(report):
            workload = custody / "workload.jsonl"
            lines = workload.read_text().splitlines()
            workload.write_text("".join(line + "\n" for line in lines[:-2]))
            report["details"]["workload"] = owned.ref(custody, workload)

        def early_drain(report):
            phases = report["details"]["phases"]
            phases["drain"] = phases["measured"] + self.SHORT["duration_seconds"] - 0.5

        def unlisted_maintenance(report):
            report["details"]["maintenance"] = report["details"]["maintenance"][:-1]

        for message, change in (
                ("heartbeats differ from the recomputed raw workload", forged_heartbeats),
                ("replies are not all accounted for", dropped_replies),
                ("shorter than the contract", early_drain),
                ("maintenance roster differs", unlisted_maintenance)):
            with self.subTest(forgery=message), self.assertRaisesRegex(ValueError, message):
                self.resealed(custody, change)
        self.accept(record, identity, configs)

    def resealed(self, custody, change):
        """A careful forger: tamper, then re-seal the report, outcome and gate around it."""
        snapshot = custody.with_name(custody.name + "-snapshot")
        shutil.copytree(custody, snapshot)
        self.addCleanup(shutil.rmtree, snapshot, True)
        try:
            self.rewrite(custody, change)
            record, identity, configs = self.gate(
                custody, soak.gate_details(self.root, custody / "report.json"))
            self.accept(record, identity, configs)
        finally:
            shutil.rmtree(custody)
            shutil.copytree(snapshot, custody)
            shutil.rmtree(snapshot)

    def test_corrupted_read_fails_the_run_and_the_failure_stays_journaled(self):
        self.qualifying()
        self.behave(corrupt_reply=5)
        with self.assertRaisesRegex(ValueError, "errors, mismatches or a stalled heartbeat"):
            self.run_short("soak-corrupt")
        custody = self.root / "runs/soak-corrupt"
        report = json.loads((custody / "report.json").read_text())
        self.assertEqual(report["status"], "failed")
        rows = [json.loads(line) for line in (custody / "workload.jsonl").read_text().splitlines()]
        self.assertEqual([row["sequence"] for row in rows if row["verdict"] == "mismatch"], [5])
        entries = attempt_index.replay(self.root)
        attempts = [{"id": "soak-corrupt",
                     "receipt": entries["soak-corrupt"]["terminal"]["receipt"]}]
        acceptance.verify_attempts(self.root, attempts, {})
        # The failed attempt cannot be hidden, and cannot be selected as a pass.
        with self.assertRaisesRegex(ValueError, "omits a native attempt admission"):
            acceptance.verify_attempts(self.root, [], {})
        with self.assertRaisesRegex(ValueError, "selected attempt failed"):
            acceptance.verify_attempts(self.root, attempts,
                                       {"runs/soak-corrupt/outcome.json": "ha-soak"})

    def test_daemon_that_exits_nonzero_on_stop_fails_the_gate(self):
        self.qualifying()
        self.behave(stop_exit=3)
        with self.assertRaisesRegex(ValueError, "did not exit cleanly on its requested stop"):
            self.run_short()
        custody = self.root / "runs/soak-1"
        report = json.loads((custody / "report.json").read_text())
        self.assertEqual(report["status"], "failed")
        receipts = [owned.read(owned.check_ref(custody, row["receipt"]))
                    for row in report["processes"]]
        failed_stops = [r for r in receipts if (r.get("stop") or {}).get("signal") == "SIGTERM"]
        self.assertEqual(len(failed_stops), 9)
        self.assertTrue(all(r["cleanup"]["drained"] and r["process_exit_code"] == 3
                            for r in failed_stops))
        self.assertEqual(owned.read(custody / "outcome.json")["status"], "failed")

    def test_preflight_failure_is_journaled_without_child_custody(self):
        self.soak_plan.write_text(json.dumps({"schema": "other"}))
        with self.assertRaisesRegex(ValueError, "soak plan"):
            self.soak("soak-preflight", "--rehearsal-seconds", "6")
        entries = attempt_index.replay(self.root)
        attempts = [{"id": "soak-preflight", "receipt": entries["soak-preflight"]["terminal"]["receipt"]}]
        outcome = json.loads((self.root / "runs/soak-preflight/outcome.json").read_text())
        self.assertEqual((outcome["status"], outcome["dispatch_started"]), ("failed", False))
        acceptance.verify_attempts(self.root, attempts, {})

    def test_plan_cannot_run_commands_outside_each_maintenance_family(self):
        binaries = {name: "/candidate/" + name for name in ("kasumid", "kasumictl", "kasumi-authority")}
        plan = json.loads(self.soak_plan.read_text())
        self.assertEqual(soak.check_plan(plan, binaries)["archival"],
                         [["/candidate/kasumid", "audit", "status", plan["maintenance"]["archival"][0]["arguments"][2]]])
        for kind, step, message in (
                ("backup", {"binary": "kasumid", "arguments": ["audit", "status", "/x"]}, "outside its product command family"),
                ("archival", {"binary": "sh", "arguments": ["-c", "true"]}, "malformed"),
                ("membership-maintenance", {"binary": "kasumictl", "arguments": ["--config", "/x", "suspend"]}, "outside its product command family")):
            changed = copy.deepcopy(plan)
            changed["maintenance"][kind] = [step]
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, message):
                soak.check_plan(changed, binaries)
        changed = copy.deepcopy(plan)
        del changed["maintenance"]["backup"]
        with self.assertRaisesRegex(ValueError, "fields differ"):
            soak.check_plan(changed, binaries)

    def test_renewal_requires_the_same_profile_and_a_new_later_expiring_bearer(self):
        original = {"profile_sha256": "1" * 64, "bearer_sha256": "2" * 64, "expires_at_ms": 1000}
        renewed = dict(original, bearer_sha256="3" * 64, expires_at_ms=2000)
        self.assertEqual(soak.credential_observation(renewed, original["profile_sha256"], original),
                         renewed)
        for change in ({"profile_sha256": "4" * 64}, {"expires_at_ms": 1000},
                       {"bearer_sha256": original["bearer_sha256"]}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                soak.credential_observation({**renewed, **change}, original["profile_sha256"], original)

    def test_soak_archival_requires_forward_progress_on_the_original_stream(self):
        stream = "12345678-1234-4234-8234-123456789abc"
        baseline = {"persistence_failed": False, "position": {
            "stream_id": stream, "pruned_before": 0, "archive_head": None}}
        head = {"stream_id": stream, "object": {"first_sequence": 0, "next_sequence": 2,
                                               "ciphertext_sha256": "1" * 64}}
        advanced = {"persistence_failed": False, "position": {
            "stream_id": stream, "pruned_before": 2, "archive_head": head}}
        soak.archive_progress(baseline, advanced)
        with self.assertRaisesRegex(ValueError, "no new records"):
            soak.archive_progress(advanced, advanced)
        changed = copy.deepcopy(advanced)
        changed["position"]["stream_id"] = changed["position"]["archive_head"]["stream_id"] = str(uuid.uuid4())
        with self.assertRaisesRegex(ValueError, "original soak stream"):
            soak.archive_progress(baseline, changed)

    def test_heartbeats_count_only_replies_received_before_each_second(self):
        rows = [{"received_elapsed_seconds": second, "verdict": verdict}
                for second, verdict in ((.2, "ok"), (.9, "ok"), (1.0, "ok"), (1.5, "error"),
                                        (2.2, "mismatch"), (2.9, "ok"))]
        self.assertEqual(soak.heartbeat_rows(rows, 3, 1), [
            {"elapsed_seconds": 0, "successful_operations": 0, "unexpected_errors": 0, "integrity_mismatches": 0},
            {"elapsed_seconds": 1, "successful_operations": 2, "unexpected_errors": 0, "integrity_mismatches": 0},
            {"elapsed_seconds": 2, "successful_operations": 3, "unexpected_errors": 1, "integrity_mismatches": 0},
            {"elapsed_seconds": 3, "successful_operations": 4, "unexpected_errors": 1, "integrity_mismatches": 1}])
        put, get = soak.cycle_requests("unit", "soak", 7)
        good = json.dumps({"id": get["id"], "status": 0, "document": {"ok": True, "result": {
            "document": {"body": soak.cycle_body("unit", 7)}}}})
        self.assertEqual(soak.judge("unit", get, good), "ok")
        self.assertEqual(soak.judge("unit", get, good.replace('"cycle": 7', '"cycle": 8')), "mismatch")
        self.assertEqual(soak.judge("unit", get, good.replace('"status": 0', '"status": 3')), "error")
        self.assertEqual(soak.judge("unit", put, good), "error")
        self.assertEqual(soak.judge("unit", get, "not json"), "error")


if __name__ == "__main__":
    unittest.main()
