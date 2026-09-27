"""Synthetic admission and real process-custody tests; never HA qualification."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import gate_process
from process_ha_owned import OwnedProcesses
import process_ha_topology as topology


class TopologyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="kasumi-process-ha-synthetic-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.plan_path = self.root / "plan.json"
        self.plan = {"schema": topology.SCHEMA,
                     "binaries": {"kasumid": str(Path(sys.executable).resolve()),
                                  "kasumi-authority": str(Path(sys.executable).resolve())}, "nodes": []}
        self.configs = {}
        for role_index, role in enumerate(("data", "control", "authority")):
            peers = []
            for index in range(3):
                node_id = role_index * 3 + index + 1
                name = f"{role}-{index + 1}"
                root = self.root / name
                root.mkdir(mode=0o700)
                for child in ("persistent", "scratch"):
                    (root / child).mkdir(mode=0o700)
                # Deliberately not an X.509 credential: these tests inspect the
                # topology parser, not product TLS authentication or trust.
                der = ("synthetic leaf " + name).encode()
                cert = root / "leaf.pem"
                cert.write_bytes(b"-----BEGIN CERTIFICATE-----\n" + base64.b64encode(der)
                                 + b"\n-----END CERTIFICATE-----\n")
                peers.append({"node_id": node_id, "endpoint": f"https://127.0.0.1:{20000 + node_id}",
                              "certificate_pins": [hashlib.sha256(der).hexdigest()],
                              "failure_domain": name})
                config = {"mode": "replicated", "tenants": [{"tenant": "synthetic"}] if role == "data" else [],
                          "target_recovery": None, "database_path": str(root / "persistent/node.kv"),
                          "persistent_disk": {"roots": {"node": str(root / "persistent")}},
                          "scratch_disk": {"directory": str(root / "scratch")},
                          "signer_verifier": {"identity": {"node_id": node_id},
                                              "database_path": str(root / "persistent/verifier.kv")},
                          "replication": {"node_id": node_id, "initial_voters": [], "peers": [],
                                          "listener": {"tls": {"certificate": str(cert)}}}}
                self.configs[name] = config
                self.plan["nodes"].append({"id": name, "role": role, "group": role,
                                           "config": str(root / "config.json")})
            for index in range(3):
                self.configs[f"{role}-{index + 1}"]["replication"].update(
                    peers=copy.deepcopy(peers), initial_voters=[p["node_id"] for p in peers])
        self.write()

    def write(self):
        self.plan_path.write_text(json.dumps(self.plan))
        for node in self.plan["nodes"]:
            Path(node["config"]).write_text(json.dumps(self.configs[node["id"]]))

    def inspect(self):
        self.write()
        return topology.inspect(self.plan_path, os.environ)

    def test_nine_distinct_roots_and_current_leaf_pins(self):
        result = self.inspect()
        self.assertEqual(result["qualification"], "local-input-inspection-only")
        self.assertEqual(len(result["nodes"]), 9)
        topology.verify_unchanged(result, os.environ)

    def test_shared_disk_owner_is_rejected(self):
        self.configs["data-2"]["persistent_disk"] = self.configs["data-1"]["persistent_disk"]
        with self.assertRaisesRegex(ValueError, "overlap"):
            self.inspect()

    def test_nested_scratch_owner_is_rejected(self):
        parent = Path(self.configs["data-1"]["persistent_disk"]["roots"]["node"])
        nested = parent / "scratch"
        nested.mkdir(mode=0o700)
        self.configs["data-2"]["scratch_disk"]["directory"] = str(nested)
        with self.assertRaisesRegex(ValueError, "overlap"):
            self.inspect()

    def test_control_process_cannot_host_data_or_target(self):
        for field, value in (("tenants", [{"tenant": "synthetic"}]), ("target_recovery", {})):
            with self.subTest(field=field):
                old = self.configs["control-1"][field]
                self.configs["control-1"][field] = value
                with self.assertRaisesRegex(ValueError, "must not host"):
                    self.inspect()
                self.configs["control-1"][field] = old

    def test_independent_group_and_voter_rosters_are_required(self):
        self.configs["control-1"]["replication"]["peers"][0]["endpoint"] = "https://127.0.0.1:1"
        with self.assertRaisesRegex(ValueError, "peer sets differ"):
            self.inspect()

    def test_shared_tls_leaf_cannot_be_hidden_by_pem_whitespace(self):
        first = Path(self.configs["data-1"]["replication"]["listener"]["tls"]["certificate"])
        second = Path(self.configs["data-2"]["replication"]["listener"]["tls"]["certificate"])
        second.write_bytes(b"\n" + first.read_bytes().replace(b"\n", b"\r\n"))
        with self.assertRaisesRegex(ValueError, "TLS identities"):
            self.inspect()

    def test_verifier_must_belong_to_local_physical_node_and_storage(self):
        self.configs["data-1"]["signer_verifier"]["database_path"] = self.configs["data-2"]["database_path"]
        with self.assertRaisesRegex(ValueError, "outside"):
            self.inspect()

    def test_immutable_input_check_rejects_changed_configuration(self):
        original = self.inspect()
        self.configs["data-1"]["tenants"].append({"tenant": "changed"})
        self.write()
        with self.assertRaisesRegex(ValueError, "inputs changed"):
            topology.verify_unchanged(original, os.environ)

    def test_duplicate_json_and_symlink_roots_are_rejected(self):
        self.plan_path.write_text('{"schema":1,"schema":2}')
        with self.assertRaisesRegex(ValueError, "duplicate JSON"):
            topology.inspect(self.plan_path, os.environ)
        alias = self.root / "alias"
        alias.symlink_to(Path(self.configs["data-1"]["scratch_disk"]["directory"]), target_is_directory=True)
        self.configs["data-1"]["scratch_disk"]["directory"] = str(alias)
        with self.assertRaisesRegex(ValueError, "canonical"):
            self.inspect()


class ProcessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="kasumi-process-owned-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.executable = gate_process.executable_identity([str(Path(sys.executable).resolve())], self.root, os.environ)
        self.command = [self.executable["path"], "-c", "import time; time.sleep(60)"]

    def test_nine_real_processes_are_distinct_and_all_drain(self):
        with OwnedProcesses(self.root / "output", self.root, os.environ, 30) as owner:
            for index in range(9):
                owner.spawn(f"node-{index}", self.command, self.executable)
            owner.assert_alive()
            pids = {row["process"].pid for row in owner.attempts}
            self.assertEqual(len(pids), 9)
        for row in owner.attempts:
            self.assertTrue(row["record"]["cleanup"]["drained"])
            self.assertEqual(gate_process.group_members(row["process"].pid), [])
            self.assertEqual(row["record"]["status"], "drained")
            self.assertEqual(row["record"]["cleanup"]["signals"], ["SIGTERM"])
            self.assertEqual(row["record"]["process_exit_code"], -signal.SIGTERM)

    def test_real_sigkill_and_restart_keep_distinct_original_receipts(self):
        observation = self.root / "observation.json"
        observation.write_text('{"scope":"synthetic-process-test"}\n')
        with OwnedProcesses(self.root / "output", self.root, os.environ, 30) as owner:
            original = owner.spawn("node", self.command, self.executable)
            with self.assertRaisesRegex(ValueError, "already owned"):
                owner.spawn("node", self.command, self.executable)
            record = owner.crash("node", observation)
            self.assertEqual(record["process_exit_code"], -signal.SIGKILL)
            self.assertTrue(record["fault"]["sent"])
            self.assertEqual(Path(record["fault"]["observation"]).read_bytes(), observation.read_bytes())
            restarted = owner.spawn("node", self.command, self.executable)
            self.assertNotEqual(original, restarted)
            owner.assert_alive()

    def test_exception_and_interruption_drain_all_owned_processes(self):
        with self.assertRaisesRegex(ValueError, "interrupted"):
            with OwnedProcesses(self.root / "output", self.root, os.environ, 30) as owner:
                owner.spawn("node", self.command, self.executable)
                os.kill(os.getpid(), signal.SIGTERM)
                owner.assert_alive()
        self.assertTrue(owner.attempts[0]["record"]["cleanup"]["drained"])
        self.assertEqual(owner.attempts[0]["record"]["received_signals"], [signal.SIGTERM])

    def test_enclosing_sealed_ledger_prevents_spawn(self):
        ledger = self.root / "groups.jsonl"
        ledger.write_text('{"schema":1,"kind":"closed"}\n')
        with patch.dict(os.environ, {gate_process.GROUP_LEDGER_ENV: str(ledger)}):
            with OwnedProcesses(self.root / "output", self.root, os.environ, 30) as owner:
                with self.assertRaisesRegex(ValueError, "admission is closed"):
                    owner.spawn("node", self.command, self.executable)
        self.assertIsNone(owner.attempts[0]["process"])

    def test_enclosing_open_ledger_retains_actual_birth_and_executable(self):
        ledger = self.root / "groups.jsonl"
        ledger.write_bytes(b"")
        with patch.dict(os.environ, {gate_process.GROUP_LEDGER_ENV: str(ledger)}):
            with OwnedProcesses(self.root / "output", self.root, os.environ, 30) as owner:
                owner.spawn("node", self.command, self.executable)
                rows, closed = gate_process.read_group_ledger(ledger)
                self.assertFalse(closed)
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["group"], owner.attempts[0]["process"].pid)
                self.assertEqual(rows[0]["executable_sha256"], self.executable["sha256"])
                self.assertEqual(rows[0]["leader_birth"], owner.attempts[0]["record"]["leader_birth"])
        self.assertEqual(owner.attempts[0]["record"]["cleanup"]["signals"], ["SIGTERM"])

    def test_child_cannot_replace_enclosing_ledger_or_overflow_it(self):
        ledger = self.root / "groups.jsonl"
        ledger.write_bytes(b"")
        with patch.dict(os.environ, {gate_process.GROUP_LEDGER_ENV: str(ledger)}):
            environment = dict(os.environ)
            environment[gate_process.GROUP_LEDGER_ENV] = str(self.root / "substituted.jsonl")
            with OwnedProcesses(self.root / "wrong-ledger", self.root, environment, 30) as owner:
                with self.assertRaisesRegex(ValueError, "replace the enclosing"):
                    owner.spawn("node", self.command, self.executable)
            self.assertIsNone(owner.attempts[0]["process"])
            with patch.object(gate_process, "MAX_GROUP_LEDGER_BYTES", 511):
                with OwnedProcesses(self.root / "full-ledger", self.root, os.environ, 30) as owner:
                    with self.assertRaisesRegex(ValueError, "capacity exhausted"):
                        owner.spawn("node", self.command, self.executable)
            self.assertIsNone(owner.attempts[0]["process"])
            self.assertEqual(ledger.read_bytes(), b"")

    def test_deadline_and_changed_executable_identity_cannot_admit(self):
        with OwnedProcesses(self.root / "output", self.root, os.environ, .05) as owner:
            with self.assertRaisesRegex(ValueError, "exact admitted"):
                owner.spawn("node", self.command, {**self.executable, "sha256": "0" * 64})
            time.sleep(.06)
            with self.assertRaisesRegex(ValueError, "deadline expired"):
                owner.spawn("node", self.command, self.executable)


if __name__ == "__main__":
    unittest.main()
