"""Failure-preserving checks for native installed release evidence."""

import json
from pathlib import Path
import sys
import tempfile
import unittest

import repeatable_assembly as owned
import run_installed as installed
import verify_release_acceptance as acceptance


class InstalledEvidence(unittest.TestCase):
    def test_native_refusals_only_accept_the_named_original_exit(self):
        with tempfile.TemporaryDirectory() as private:
            root = Path(private).resolve()
            cmd = [
                str(Path(sys.executable).resolve()),
                "-I",
                "-c",
                "raise SystemExit(4)",
            ]
            item = owned.run_owned(
                root, "family-denied", cmd, str(root), {"PATH": "/usr/bin:/bin"}, 60
            )
            proc = {
                "id": "family-denied",
                "receipt": item["receipt"],
                "log": item["stdout"],
                "executable": item["executable"],
            }
            original = acceptance.domain_expected_exits("installed")
            acceptance.check_processes(root, [proc], 60, expected_exits=original)
            for kind, name in (
                ("installed", "renew"),
                ("correctness", "family-denied"),
                ("installed", "live-admin-refused"),
            ):
                with self.subTest(kind=kind, name=name), self.assertRaises(ValueError):
                    acceptance.check_processes(
                        root,
                        [{**proc, "id": name}],
                        60,
                        expected_exits=acceptance.domain_expected_exits(kind),
                    )

    def test_tls_rejection_binds_the_log_suffix_and_original_process(self):
        with tempfile.TemporaryDirectory() as private:
            root = Path(private)
            service = root / "services"
            service.mkdir()
            probe = {"pid": 51, "birth": "native process birth", "log_offset": 0}
            (service / "daemon-0001.json").write_text(
                json.dumps({"process_group": 51, "leader_birth": probe["birth"]})
            )
            log = service / "daemon-0001.log"
            event = json.dumps({"fields": {"event": "tls_reload_failed"}}) + "\n"
            log.write_text(event)
            self.assertTrue(installed.verify_rejection(root, "daemon-0001", probe))
            for key, value in (
                ("pid", 52),
                ("birth", "reused"),
                ("log_offset", len(event)),
            ):
                with self.subTest(key=key), self.assertRaises(ValueError):
                    installed.verify_rejection(
                        root, "daemon-0001", {**probe, key: value}
                    )
            log.write_text(
                event + json.dumps({"fields": {"event": "listening"}}) + "\n"
            )
            self.assertFalse(
                installed.verify_rejection(
                    root, "daemon-0001", {**probe, "log_offset": len(event)}
                )
            )

    def test_frozen_intent_binds_scope_policy_and_collection(self):
        root = Path(__file__).resolve().parents[1]
        intent = owned.read(root / installed.INTENT)
        self.assertEqual(set(intent), {"tenant", "policy", "limits", "collections"})
        self.assertEqual(intent["tenant"], "smoke")
        self.assertEqual(set(intent["collections"]), {installed.COLLECTION})
        self.assertGreater(len(intent["limits"]), 10)
        self.assertEqual(
            set(acceptance.SCENARIOS["installed"]),
            {
                "offline-initialize",
                "native-mtls",
                "mcp",
                "one-hour-jwt",
                "renewal",
                "revocation",
                "wrapping-rotation",
                "signer-rotation",
                "certificate-rotation",
                "invalid-tls-replacement",
                "restart",
                "backup",
                "restore",
                "operator-key-backup",
                "exclusive-stopped-admin-recovery",
                "oauth-discovery",
            },
        )


if __name__ == "__main__":
    unittest.main()
