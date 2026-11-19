import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import observe_audit_retention as audit


class AuditCollectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.evidence = self.root / "functional"
        self.evidence.mkdir()
        (self.evidence / "evidence.json").write_text('{"candidate":1}')
        self.custody = self.root / "custody"

    def substitute(self, obj, name, **kwargs):
        mock = patch.object(obj, name, **kwargs)
        self.addCleanup(mock.stop)
        return mock.start()

    def mock_originals(self):
        self.substitute(audit, "source", return_value={"source_commit": "f" * 40})
        self.custody.mkdir()
        self.components = {"custody-1": {"commands": 4097}, "receipts-1": {"restored_count": 100001},
                           "lifecycle-1": {"selected_intents": 10001}, "incarnations-1": {"reopened": 100001}}
        self.replica = {"voters": 3, "clean_processes": 9}
        self.native_replay = self.substitute(audit.native, "verify_components", return_value=self.components)
        self.replica_replay = self.substitute(audit.replicas, "replay", return_value=self.replica)
        for stage in ("native", "replicas"):
            (self.custody / stage).mkdir()
            (self.custody / stage / "report.json").write_text(json.dumps({"stage": stage}))

    def test_composition_replays_both_components_and_rejects_substitution(self):
        self.mock_originals()
        observed = audit.combined(self.evidence, self.custody)
        self.assertEqual(observed["lifetime_counts"], {"commands":4097, "receipts":100001, "lifecycle":10001, "incarnations":100001})
        self.assertEqual(observed["outstanding_lifetime_categories"], ["sessions"])
        self.assertEqual(len(observed["verified_scenarios"]), 5)
        self.assertNotIn("permanent-identity-lifetime-ceiling", observed["verified_scenarios"])
        report = self.custody / "report.json"
        report.write_text(json.dumps(observed))
        self.assertEqual(audit.verify(self.evidence, self.custody), observed)
        self.native_replay.assert_called_with(self.evidence, self.custody / "native")
        self.replica_replay.assert_called_with(self.evidence, self.custody / "replicas")
        for key, replacement in (("qualification", "qualifying"), ("status", "passed"),
                                 ("outstanding_lifetime_categories", []),
                                 ("native_report_sha256", "0" * 64),
                                 ("replica_report_sha256", "0" * 64),
                                 ("functional_sha256", "0" * 64),
                                 ("lifetime_counts", {**observed["lifetime_counts"], "sessions":10001})):
            with self.subTest(key=key):
                forged = copy.deepcopy(observed)
                forged[key] = replacement
                report.write_text(json.dumps(forged))
                with self.assertRaises(ValueError):
                    audit.verify(self.evidence, self.custody)
        report.write_text(json.dumps(observed))
        (self.custody / "native/report.json").write_text("substituted original")
        with self.assertRaises(ValueError):
            audit.verify(self.evidence, self.custody)
        self.native_replay.side_effect = ValueError("original process differs")
        with self.assertRaisesRegex(ValueError, "original process"):
            audit.verify(self.evidence, self.custody)

    def test_component_subdirectory_must_be_owned(self):
        self.mock_originals()
        native = self.custody / "native"
        external = self.root / "moved"
        native.rename(external)
        native.symlink_to(external, target_is_directory=True)
        with self.assertRaises(ValueError):
            audit.combined(self.evidence, self.custody)
        self.native_replay.assert_not_called()

    def test_ordinary_failure_preserves_receipt_and_runs_second_stage(self):
        self.substitute(audit, "source", return_value={})
        def fail(evidence, directory, *args):
            directory.mkdir()
            (directory / "original").write_text("provider refused")
            raise ValueError("original installation failure")
        self.substitute(audit.replicas, "capture", side_effect=fail)
        second = self.substitute(audit.native, "capture")
        with self.assertRaisesRegex(ValueError, "incomplete audit observation"):
            audit.collect(self.evidence, self.custody, "journal", "attempt", "plan", "topology")
        second.assert_called_once_with(self.evidence, self.custody / "native")
        self.assertEqual((self.custody / "replicas/original").read_text(), "provider refused")
        progress = json.loads((self.custody / "report.json").read_text())
        self.assertEqual(progress["status"], "failed")
        self.assertEqual(progress["stages"]["native"]["status"], "complete")
        self.assertIn("original installation failure", progress["stages"]["replicas"]["error"])

    def test_interruption_preserves_status_before_propagation(self):
        self.substitute(audit, "source", return_value={})
        self.substitute(audit.replicas, "capture", side_effect=KeyboardInterrupt())
        second = self.substitute(audit.native, "capture")
        with self.assertRaises(KeyboardInterrupt):
            audit.collect(self.evidence, self.custody, "journal", "attempt", "plan", "topology")
        self.assertEqual(json.loads((self.custody / "report.json").read_text())["status"], "interrupted")
        second.assert_not_called()


if __name__ == "__main__":
    unittest.main()
