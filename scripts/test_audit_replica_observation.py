import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import uuid

import run_audit_replica_observation as audit


class InstalledReplicaEvidence(unittest.TestCase):
    def test_all_original_ciphertexts_are_distinct_and_match_one_verified_link(self):
        with tempfile.TemporaryDirectory() as private:
            root = Path(private).resolve()
            payload = b"encrypted object used only in this filesystem test"
            link = {
                "object_id": str(uuid.uuid4()),
                "ciphertext_sha256": hashlib.sha256(payload).hexdigest(),
                "first_sequence": 0,
                "next_sequence": 1,
            }
            ref = {"object": link, "ciphertext_bytes": len(payload)}
            nodes = {}
            rows = {}
            outputs = {}
            for n in ("a", "b", "c"):
                directory = root / n
                directory.mkdir()
                nodes[n] = {
                    "database_path": str(directory / "data"),
                    "tenant_audit_cache": str(directory),
                }
                source = directory / (link["object_id"] + ".audit")
                source.write_bytes(payload)
                path = root / (n + ".captured")
                rows[n] = audit.copy_segment(nodes[n], ref, path)
                outputs[n] = audit.owned.ref(root, path)
            audit.check_copies(ref, nodes, rows, outputs)
            duplicate = copy.deepcopy(rows)
            duplicate["b"].update(device=rows["a"]["device"], inode=rows["a"]["inode"])
            with self.assertRaises(ValueError):
                audit.check_copies(ref, nodes, duplicate, outputs)
            self.assertEqual((root / "b.captured").read_bytes(), payload)
            physical = root / "b" / (link["object_id"] + ".audit")
            physical.write_bytes(b"z" * len(payload))
            with self.assertRaises(ValueError):
                audit.copy_segment(nodes["b"], ref, root / "changed")
            physical.unlink()
            physical.symlink_to(root / "a" / physical.name)
            with self.assertRaises(OSError):
                audit.copy_segment(nodes["b"], ref, root / "redirected")

    def test_current_page_rejects_an_unverified_replica_or_broken_predecessor(self):
        retained = {"stream_id": "s", "archive_segments": 1}
        old = {"first_sequence": 0, "next_sequence": 3}
        new = {"first_sequence": 3, "next_sequence": 5}
        ref = {
            "object": new,
            "stream_id": "s",
            "previous": old,
            "record_count": 2,
            "ciphertext_bytes": 50,
        }
        pg = {
            "tenant": "t",
            "incarnation": "i",
            "stream_id": "s",
            "through_index": 2,
            "results": [
                {"index": 1, "cache": "verified", "object": new, "reference": ref}
            ],
        }

        def run(page):
            return audit.check_page(page, "t", "i", retained, 2, 2, new, [])

        self.assertEqual(run(pg), (1, old))
        for fn in (
            lambda row: row.update(cache="missing"),
            lambda row: row.update(index=9),
            lambda row: row["reference"].update(record_count=1),
            lambda row: row["reference"].update(previous={"next_sequence": 2}),
        ):
            bad = copy.deepcopy(pg)
            fn(bad["results"][0])
            with self.assertRaises(ValueError):
                run(bad)

    def test_cache_root_defaults_to_the_installed_database_directory(self):
        cfg = {"database_path": "/var/lib/t/node.kv", "tenant_audit_cache": None}
        self.assertEqual(
            audit.cache_root(cfg), Path("/var/lib/t/tenant-audit-archives")
        )

    def test_transport_replays_native_requests_and_current_replica_bytes(self):
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as private:
            custody = Path(private).resolve()
            original = Path("/original/private/audit")
            source = Path("/original/functional/source")
            ids = ("data-one", "data-two", "data-three")
            attempt = "audit-transport-test"
            stream, incarnation = str(uuid.uuid4()), str(uuid.uuid4())
            payload = b"three retained ciphertext files"
            link = {
                "first_sequence": 0,
                "next_sequence": 5,
                "ciphertext_sha256": hashlib.sha256(payload).hexdigest(),
                "object_id": str(uuid.uuid4()),
            }
            ref = {
                "stream_id": stream,
                "object": link,
                "previous": None,
                "record_count": 5,
                "ciphertext_bytes": len(payload),
            }
            configs = {n: {"database_path": str(original / n / "data")} for n in ids}
            nodes = [{"id": n, "config": str(original / n / "node.json")} for n in ids]
            paths = {"kasumid": "/bin/kasumid", "kasumictl": "/bin/kasumictl"}
            plan = {
                "data_profile": "/original/data.json",
                "operator_profile": "/original/operator.json",
            }
            inputs = ([1, 2, 3], "tenant", incarnation, "audit_fixture", configs)
            position = {
                "stream_id": stream,
                "archive_segments": 0,
                "pruned_before": 0,
                "archive_head": None,
            }
            observed = {
                "tenant": "tenant",
                "incarnation": incarnation,
                "position": position,
            }
            membership = {
                "mode": "replicated",
                "incarnation": incarnation,
                "observation": "local_committed_state",
                "node_id": 1,
                "leader": 1,
                "raft_voters": [1, 2, 3],
                "raft_applied_index": 10,
                "raft_snapshot_index": None,
                "raft_membership_index": 2,
            }
            receipt_calls = []

            def request(name, obj):
                audit.domain_run.durable_json(custody / (name + ".json"), obj)
                return str(original / (name + ".json"))

            body = {"step": 1, "sha256": hashlib.sha256(attempt.encode()).hexdigest()}

            def original_response(step, cmd):
                if step.startswith("membership"):
                    return membership
                if step == "audit-before":
                    return observed
                if step == "collection":
                    return {"revision": 1}
                if step == "put":
                    return {"ok": True, "result": {"receipt": {"revision": 2}}}
                if step.startswith("read-"):
                    return {"ok": True, "result": {"document": {"body": body}}}
                if step.startswith("position-"):
                    return {
                        **observed,
                        "position": {
                            **position,
                            "archive_segments": 1,
                            "pruned_before": 5,
                        },
                    }
                if step == "capacity":
                    return {
                        "tenant": "tenant",
                        "incarnation": incarnation,
                        "stream_id": stream,
                        "capacity": {
                            "hot_budget_bytes": 128 << 10,
                            "starts_at_bytes": 96 << 10,
                            "drains_to_bytes": 64 << 10,
                            "max_segment_bytes": 8 << 20,
                        },
                    }
                if step == "page-000":
                    self.assertEqual(
                        json.loads((custody / "verify-000.json").read_text()),
                        {"limit": 8, "cursor": None},
                    )
                    return {
                        "tenant": "tenant",
                        "incarnation": incarnation,
                        "stream_id": stream,
                        "through_index": 1,
                        "snapshot_head": link,
                        "results": [
                            {
                                "index": 0,
                                "object": link,
                                "reference": ref,
                                "cache": "verified",
                            }
                        ],
                    }
                if step.startswith("copy-"):
                    name = next(n for n in ids if step == "copy-" + n + "-0000")
                    self.assertEqual(
                        cmd[-1], str(original / ("data-" + name + "-0000.audit"))
                    )
                    return {
                        "path": str(
                            audit.cache_root(configs[name])
                            / (link["object_id"] + ".audit")
                        ),
                        "object_id": link["object_id"],
                        "sha256": link["ciphertext_sha256"],
                        "bytes": len(payload),
                        "device": 1,
                        "inode": 1 + ids.index(name),
                    }
                self.fail("unexpected audit component step " + step)

            def query(step, cmd):
                receipt_calls.append((step, cmd))
                return original_response(step, cmd)

            for name in ids:
                (custody / ("data-" + name + "-0000.audit")).write_bytes(payload)
            result = audit.measure(
                attempt,
                original,
                custody,
                source,
                paths,
                "/bin/python",
                plan,
                nodes,
                inputs,
                request,
                query,
                lambda: None,
            )
            self.assertEqual((result["reads"], len(result["objects"])), (32, 1))
            report = {
                "details": {
                    "result": result,
                    "polls": {"startup": [{"id": "readiness"}]},
                },
                "evidence_root": str(source.parent),
                "custody_root": str(original),
                "attempt_id": attempt,
                "binaries": {"kasumid": "s", "kasumictl": "c"},
                "processes": [{}] * 9 + [{"id": step} for step, _ in receipt_calls],
            }
            expected = dict(receipt_calls)

            def receipt(captured, item, step, cmd, cwd, digest, timeout):
                self.assertEqual((captured, cwd), (custody, source))
                if step == "startup-0000":
                    self.assertEqual(
                        (cmd, digest, timeout),
                        (
                            [
                                paths["kasumid"],
                                "tenant-audit",
                                "status",
                                plan["operator_profile"],
                            ],
                            "s",
                            60,
                        ),
                    )
                    return 0, json.dumps(observed).encode()
                self.assertEqual(
                    (step, cmd, timeout), (item["id"], expected[step], 180)
                )
                self.assertEqual(
                    digest,
                    {"kasumid": "s", "kasumictl": "c", "python": "p"}[
                        Path(cmd[0]).name
                    ],
                )
                return 0, json.dumps(original_response(step, cmd)).encode()

            with patch.object(audit.observation, "original_command", receipt):

                def replay():
                    return audit.replay_operations(
                        custody, report, plan, nodes, inputs, paths, "/bin/python", "p"
                    )

                self.assertEqual(replay(), result)
                (custody / "data-data-three-0000.audit").write_bytes(b"changed")
                with self.assertRaisesRegex(ValueError, "original voter ciphertext"):
                    replay()
                (custody / "data-data-three-0000.audit").write_bytes(payload)
                report["processes"][-1]["id"] = "substituted"
                with self.assertRaisesRegex(
                    ValueError, "missing, repeated or reordered"
                ):
                    replay()

    def test_replay_refuses_early_readiness_success_followed_by_another_poll(self):
        from unittest.mock import patch

        report = {
            "details": {"polls": {"startup": [{}, {}]}},
            "evidence_root": "/old/functional",
            "custody_root": "/old/audit",
            "binaries": {"kasumid": "hash"},
            "processes": [],
        }
        status = {
            "tenant": "t",
            "incarnation": "i",
            "position": {"stream_id": str(uuid.uuid4())},
        }
        with (
            patch.object(
                audit.observation,
                "original_command",
                return_value=(0, json.dumps(status).encode()),
            ),
            self.assertRaisesRegex(ValueError, "successful native audit readiness"),
        ):
            audit.replay_operations(
                Path("/moved"),
                report,
                {"operator_profile": "/old/profile"},
                [],
                ([], "t", "i", "c", {}),
                {"kasumid": "/bin/kasumid"},
                "/bin/python",
                "p",
            )
