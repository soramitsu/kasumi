"""Exercise secret-scan exceptions with synthetic data and the real scanner.

Set GITLEAKS_BIN to the checksum-verified workflow binary to require these tests.
Without that override, discovery skips them when Gitleaks is not installed.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import tomllib
import unittest


CONFIG = Path(__file__).resolve().parents[1] / ".gitleaks.toml"
REVIEWED_MANIFEST = (
    "docs/evidence/first-release-207ae69-check-20260920/source-before.json"
)


class SecretScanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        requested = os.environ.get("GITLEAKS_BIN")
        cls.scanner = shutil.which(requested if requested is not None else "gitleaks")
        if cls.scanner is None:
            if requested is not None:
                raise RuntimeError("GITLEAKS_BIN must identify an executable scanner")
            raise unittest.SkipTest("Gitleaks is not installed; set GITLEAKS_BIN to run")
        version = subprocess.run(
            [cls.scanner, "version"], capture_output=True, text=True, check=False
        )
        if version.returncode != 0 or version.stdout.strip() != "8.30.1":
            raise RuntimeError("Secret-scan tests require workflow-pinned Gitleaks 8.30.1")

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="kasumi-secret-scan-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.digest = hashlib.sha256(b"synthetic secret-scan regression fixture").hexdigest()

    def write(self, relative, content):
        target = self.source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)

    def scan(self, mode="dir"):
        report = self.root / "report.json"
        report.unlink(missing_ok=True)
        command = [
            self.scanner, mode, "--config", str(CONFIG), "--redact=100",
            "--ignore-gitleaks-allow", "--gitleaks-ignore-path", os.devnull,
            "--no-color", "--report-format", "json", "--report-path", str(report),
        ]
        if mode == "git":
            command.append("--log-opts=--all --full-history -m")
        result = subprocess.run(
            command + ["."], cwd=self.source,
            capture_output=True, text=True, check=False,
        )
        # Never include scanner output or matched values in assertion diagnostics.
        self.assertIn(result.returncode, (0, 1), "Scanner failed to execute")
        self.assertTrue(report.is_file(), "Scanner did not produce a report")
        findings = json.loads(report.read_text())
        self.assertEqual(result.returncode, int(bool(findings)))
        self.assertTrue(
            all(finding["Secret"] == "REDACTED" for finding in findings),
            "Scanner report must redact every detected value",
        )
        return findings

    def rules(self, mode="dir"):
        return {finding["RuleID"] for finding in self.scan(mode)}

    def checksum_entry(self):
        return json.dumps({"crates/kasumi-client/src/api.rs": self.digest}, indent=2) + "\n"

    def test_reviewed_checksum_entry_is_allowed(self):
        self.write(REVIEWED_MANIFEST, self.checksum_entry())
        self.assertEqual(self.rules(), set())

    def test_checksum_exception_does_not_cover_other_paths(self):
        for relative in (
            "docs/evidence/unreviewed/source-before.json",
            REVIEWED_MANIFEST + ".bak",
            "nested/" + REVIEWED_MANIFEST,
        ):
            with self.subTest(path=relative):
                self.write(relative, self.checksum_entry())
                self.assertIn("generic-api-key", self.rules())
                (self.source / relative).unlink()

    def test_credential_field_at_reviewed_path_is_detected(self):
        self.write(REVIEWED_MANIFEST, json.dumps({"api_key": self.digest}) + "\n")
        self.assertIn("generic-api-key", self.rules())

    def test_other_detectors_remain_enabled_at_reviewed_path(self):
        # Construct the synthetic token at runtime so the test source is scannable.
        token = "ghp_" + self.digest[:36]
        self.write(REVIEWED_MANIFEST, json.dumps({"api_key": token}) + "\n")
        self.assertIn("github-pat", self.rules())

    def test_inline_ignore_cannot_hide_findings(self):
        self.write(
            "synthetic.txt", "api_key = " + self.digest + " # gitleaks:allow\n"
        )
        self.assertIn("generic-api-key", self.rules())

    def lineage_fixtures(self):
        config = tomllib.loads(CONFIG.read_text())
        groups = []
        for rule in config["rules"]:
            if rule["id"] != "generic-api-key":
                continue
            for allow in rule.get("allowlists", []):
                if allow["description"] != (
                    "Reviewed backup key-catalog lineage digest in historical recovery evidence"
                ):
                    continue
                self.assertEqual(allow["condition"], "AND")
                self.assertEqual(allow["regexTarget"], "match")
                for expression in allow["regexes"]:
                    self.assertRegex(expression, r'^\^key_lineage_digest: "[a-f0-9]{64}"\$$')
                    for path_expression in allow["paths"]:
                        prefix = r"^(?:\./)?"
                        self.assertTrue(path_expression.startswith(prefix))
                        self.assertTrue(path_expression.endswith("$"))
                        relative = re.sub(r"\\(.)", r"\1", path_expression[len(prefix):-1])
                        groups.append((relative, expression[1:-1]))
        self.assertEqual(len(groups), 13, "All reviewed log digest exceptions must be exercised")
        return groups

    def test_exact_reviewed_lineage_digests_are_allowed(self):
        lines = {}
        for relative, fixture in self.lineage_fixtures():
            lines.setdefault(relative, []).append(fixture)
        for relative, fixtures in lines.items():
            self.write(relative, "\n".join(fixtures) + "\n")
        self.assertEqual(self.rules(), set())

    def test_changed_lineage_digest_at_reviewed_paths_is_detected(self):
        expected_paths = set()
        for relative, fixture in self.lineage_fixtures():
            self.write(relative, re.sub(r"[a-f0-9]{64}", self.digest, fixture) + "\n")
            expected_paths.add(relative)
        findings = self.scan()
        self.assertEqual({finding["RuleID"] for finding in findings}, {"generic-api-key"})
        self.assertEqual(
            {Path(finding["File"]).as_posix() for finding in findings},
            expected_paths,
        )

    def test_reviewed_lineage_digest_at_other_path_is_detected(self):
        fixtures = [fixture for _, fixture in self.lineage_fixtures()]
        self.write("unreviewed.log", "\n".join(fixtures) + "\n")
        self.assertIn("generic-api-key", self.rules())

    def test_reviewed_lineage_digest_at_nested_paths_is_detected(self):
        expected_paths = set()
        for relative, fixture in self.lineage_fixtures():
            nested = "nested/" + relative
            self.write(nested, fixture + "\n")
            expected_paths.add(nested)
        findings = self.scan()
        self.assertEqual({finding["RuleID"] for finding in findings}, {"generic-api-key"})
        self.assertEqual(
            {Path(finding["File"]).as_posix() for finding in findings}, expected_paths
        )

    def test_lineage_exception_does_not_hide_same_line_credentials(self):
        expected_paths = set()
        for relative, fixture in self.lineage_fixtures():
            self.write(relative, fixture + ', api_key: "' + self.digest + '"\n')
            expected_paths.add(relative)
        findings = self.scan()
        self.assertEqual({finding["RuleID"] for finding in findings}, {"generic-api-key"})
        self.assertEqual(
            {Path(finding["File"]).as_posix() for finding in findings},
            expected_paths,
        )

    def git(self, *arguments):
        result = subprocess.run(
            [
                "git", "-c", "core.hooksPath=" + os.devnull,
                "-c", "commit.gpgsign=false", "-c", "user.name=Secret scan test",
                "-c", "user.email=secret-scan-test@example.invalid", *arguments,
            ],
            cwd=self.source, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, "Synthetic Git fixture command failed")

    def test_deleted_credential_is_still_detected_in_history(self):
        self.git("init", "--initial-branch=main")
        self.write("synthetic.txt", "api_key = " + self.digest + "\n")
        self.git("add", "synthetic.txt")
        self.git("commit", "-m", "Add synthetic history control")
        self.git("rm", "synthetic.txt")
        self.git("commit", "-m", "Remove synthetic history control")
        self.assertEqual(self.rules(), set())
        self.assertIn("generic-api-key", self.rules("git"))


if __name__ == "__main__":
    unittest.main()
