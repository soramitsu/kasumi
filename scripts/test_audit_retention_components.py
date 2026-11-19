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


class TransportedNativeAuditTests(unittest.TestCase):
    def test_transport_replays_original_command_working_directory_output_and_hash(self):
        import os
        from pathlib import Path
        from tempfile import TemporaryDirectory
        import sys
        from unittest.mock import patch
        import repeatable_assembly as owned

        with TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            original = base / "old-machine" / "evidence"
            source = original / "source"
            source.mkdir(parents=True)
            initial = base / "original-custody"
            initial.mkdir()
            interpreter = str(Path(sys.executable).resolve(strict=True))
            command = [interpreter, "-I", "-B", "-S", "-c", "print('original')"]
            checksum = owned.sha256(interpreter)
            proc = owned.run_owned(initial, "witness", command, str(source),
                                   {"PATH": os.defpath, "LC_ALL": "C"}, 7200)
            report = {"processes": [proc], "observed": {"witness": "original"}}
            custody = initial.rename(base / "transported")

            def replay(evidence, selected, perform):
                self.assertEqual(evidence, original)
                raw = perform("witness", command, checksum)
                return {"witness": raw.decode().strip()}

            with patch.object(audit, "replay", replay):
                self.assertEqual(audit.replay_retained(custody, report, original, {}), report["observed"])
                for mutation in (
                    lambda item: item["processes"].clear(),
                    lambda item: item["processes"].append(copy.deepcopy(proc)),
                    lambda item: item["processes"][0].update(id="replacement"),
                    lambda item: item["processes"][0]["executable"].update(sha256="0" * 64),
                    lambda item: item["observed"].update(witness="operator declaration"),
                ):
                    candidate = copy.deepcopy(report)
                    mutation(candidate)
                    with self.assertRaises(ValueError):
                        audit.replay_retained(custody, candidate, original, {})
                raw = owned.check_ref(custody, proc["stdout"])
                raw.write_bytes(b"changed after transport\n")
                with self.assertRaises(ValueError):
                    audit.replay_retained(custody, report, original, {})


class LifecycleAuditComponentTests(unittest.TestCase):
    def test_requires_actual_ceiling_replay_reopen_and_drains(self):
        row = {"selected_intents": 10001, "resident_legacy_intents": 1, "previous_max_intents": 10000,
               "installed_max_intents": 1, "bytes": 29_000_000, "sha256": "ab" * 32,
               "replayed_first_revision": 3, "fresh_store_reopen": True, "both_stores_drained": True}

        def observe(value):
            return audit.observation("lifecycle", ("KASUMI_LIFECYCLE_HISTORY " + json.dumps(value)).encode())

        self.assertEqual(observe(row), row)
        for changes in ({"selected_intents": 10000}, {"previous_max_intents": 9999},
                        {"resident_legacy_intents": 10001}, {"bytes": 10001}, {"sha256": "missing"},
                        {"fresh_store_reopen": False}, {"both_stores_drained": False}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                observe({**row, **changes})
