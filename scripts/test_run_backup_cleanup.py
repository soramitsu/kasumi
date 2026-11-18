import json
from pathlib import Path
import unittest
import uuid

import run_backup_cleanup as cleanup


class BackupCleanup(unittest.TestCase):
    def setUp(self):
        self.root = Path("/private/installed")
        self.session = str(uuid.uuid4())
        self.saved = {"backup_id": self.session, "tenant": cleanup.install.TENANT, "revision": 6,
                      "resident_sha256": "1" * 64, "manifest_ciphertext_sha256": "2" * 64,
                      "key_lineage_digest": "3" * 64, "source_incarnation": "original"}
        self.created = {"session_id": self.session, "checkpoint": str(self.root / "checkpoint.json")}
        self.status = {"intent": {"session_id": self.session, "tenant": self.saved["tenant"], "revision": 6,
                                  "source_incarnation": "original"},
                       "outcome": {"outcome": "complete", "checkpoint": self.saved, "intent_ciphertext_sha256": "4" * 64},
                       "source_purpose_sha256": "5" * 64}

    def test_original_completed_checkpoint_must_match_both_reads(self):
        cleanup.validate_checkpoints(self.created, self.saved, self.status, self.saved, self.root)
        for change in ({"revision": 7}, {"manifest_ciphertext_sha256": "a" * 64}, {"source_incarnation": "replacement"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                cleanup.validate_checkpoints(self.created, self.saved, self.status, {**self.saved, **change}, self.root)
        with self.assertRaises(ValueError):
            cleanup.validate_checkpoints({**self.created, "session_id": str(uuid.uuid4())}, self.saved, self.status, self.saved, self.root)

    def test_installed_protocol_reads_same_backup_through_a_new_daemon(self):
        binaries = {"kasumid": "/bin/kasumid", "kasumictl": "/bin/kasumictl"}
        steps = []

        def command(step, cmd, key):
            steps.append((step, cmd, key))
            if step.startswith("listeners"):
                value = {"listeners": [18000, 18001, 18002]}
            elif step.startswith("health"):
                value = {"lifecycle": "serving"}
            elif step == "create":
                value = self.created
            elif step.startswith("verify"):
                value = self.saved
            else:
                value = self.status
            return json.dumps(value).encode()

        observed = []
        result = cleanup.run_protocol(self.root, 18000, "/bin/python", binaries, Path("/source"), {}, command,
                                     lambda i, cmd: observed.append(("start", i, cmd)),
                                     lambda i: observed.append(("stop", i)), lambda: self.saved,
                                     lambda key, step: None)
        self.assertEqual([row[:2] for row in observed], [("start", 1), ("stop", 1), ("start", 2), ("stop", 2)])
        commands = dict((key, cmd) for key, cmd, _ in steps)
        self.assertEqual(commands["status-1"], commands["status-2"])
        self.assertEqual(commands["verify-1"], commands["verify-2"])
        self.assertIn(self.session, commands["resolve-abort"])
        self.assertEqual(result["completion-uncertainty"], ["resolve-abort"])

    def test_native_plan_counts_three_independent_late_uploads_and_cleanup_sweeps(self):
        listings = {}
        for _, crate, target, name, _, _ in cleanup.CASES:
            listings.setdefault((crate, target), []).append(name)
        selected = {key: (key[1], str(i) * 64) for i, key in enumerate(listings)}
        calls = []

        def process(step, cmd, digest):
            key, = (key for key, (_, h) in selected.items() if h == digest)
            names = listings[key]
            calls.append(step)
            if "--list" in cmd:
                return "".join(name + ": test\n" for name in names).encode()
            name = cmd[cmd.index("--exact") + 1]
            return (f"running 1 test\ntest {name} ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
                    f"{len(names) - 1} filtered out; finished in 0.01s\n").encode()

        scenarios = cleanup.run_cases(selected, Path("/frozen"), process, lambda *args: None, {})
        self.assertEqual(len(set(calls)), len(calls))
        self.assertEqual(scenarios["late-upload"], ["late-upload-1", "late-upload-2", "late-upload-3"])
        self.assertEqual(scenarios["archive-isolation"], ["archive-isolation-1"])
        self.assertEqual(set(scenarios), cleanup.acceptance.SCENARIOS[cleanup.KIND])


if __name__ == "__main__":
    unittest.main()
