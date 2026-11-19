import copy
import hashlib
import json
from pathlib import Path
import os
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
