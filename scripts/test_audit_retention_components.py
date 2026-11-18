import copy
import json
import unittest

import audit_retention_components as audit


class AuditEvidence(unittest.TestCase):
    def test_replacement_cannot_admit_a_gap_missing_bytes_or_substituted_state(self):
        refs = []
        for i in range(3):
            refs.append(
                {
                    "stream_id": "s",
                    "previous": refs[-1]["object"] if refs else None,
                    "object": {
                        "first_sequence": i,
                        "next_sequence": i + 1,
                        "ciphertext_sha256": format(i, "064x"),
                    },
                    "ciphertext_bytes": 96,
                    "record_count": 1,
                }
            )
        value = {
            "case": "replacement",
            "source_bundle_sha256": "a" * 64,
            "replacement_bundle_sha256": "a" * 64,
            "chain": refs,
            "replacement": {
                "stream_id": "s",
                "archive_segments": 3,
                "archive_head": refs[-1],
                "pruned_before": 3,
                "archive_bytes": 288,
            },
        }

        def check(x):
            return audit.observation(
                "replacement", (audit.PREFIX + json.dumps(x)).encode()
            )

        self.assertEqual(check(value), value)
        for fn in [
            lambda v: v["chain"][1].update(previous=None),
            lambda v: v["replacement"].update(archive_segments=4),
            lambda v: v["replacement"].update(archive_bytes=100),
            lambda v: v["chain"][1].update(ciphertext_bytes=(8 << 20) + 1),
            lambda v: v.update(replacement_bundle_sha256="b" * 64),
        ]:
            item = copy.deepcopy(value)
            fn(item)
            with self.assertRaises(ValueError):
                check(item)

    def test_outage_requires_original_no_prune_and_observed_recovery(self):
        before = {
            "stream_id": "s",
            "next_sequence": 50,
            "pruned_before": 0,
            "hot_bytes": 90,
            "archive_segments": 0,
        }
        after = {
            **before,
            "hot_bytes": 40,
            "pruned_before": 10,
            "archive_segments": 1,
            "archive_head": {"stream_id": "s", "ciphertext_bytes": 730},
        }
        value = {
            "case": "maintenance",
            "budget": {"hot_bytes": 100},
            "starts_at": 75,
            "drains_to": 50,
            "before": before,
            "after": after,
            "committed_segments": 1,
            "failures": 2,
            "outage": {
                "position": before,
                "revision": 60,
                "committed_index": 60,
                "failures": 2,
            },
        }

        def check(v):
            return audit.observation("outage", (audit.PREFIX + json.dumps(v)).encode())

        self.assertEqual(check(value), value)
        for fn in [
            lambda v: v["outage"].update(failures=0),
            lambda v: v["outage"].update(position=after),
            lambda v: v["outage"].update(committed_index=61),
            lambda v: v.update(committed_segments=0),
        ]:
            item = copy.deepcopy(value)
            fn(item)
            with self.assertRaises(ValueError):
                check(item)

    def test_permanent_count_must_exceed_original_absence_or_late_replay(self):
        cases = {
            "custody": {
                "case": "custody",
                "commands": 4096,
                "audit_events": 8400,
                "reopened_command": "command-00000000",
                "replayed_command": "command-00000000",
            },
            "receipts": {
                "case": "mutation-receipts",
                "restored_count": 100_000,
                "prior_count": 100_000,
            },
        }
        for case, row in cases.items():
            with self.subTest(case=case), self.assertRaises(ValueError):
                audit.observation(case, (audit.PREFIX + json.dumps(row)).encode())
