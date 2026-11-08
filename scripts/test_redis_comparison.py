"""Failure and process ownership checks for the Redis comparison harness."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch


SOURCE = Path(__file__).resolve().parents[1] / "benchmarks/redis-comparison/run.py"
spec = importlib.util.spec_from_file_location("redis_comparison", SOURCE)
comparison = importlib.util.module_from_spec(spec)
spec.loader.exec_module(comparison)


class RedisComparisonFailureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.harness = comparison.Harness(SimpleNamespace(
            work=str(self.root / "work"), output=str(self.root / "output"),
            driver="driver", kasumi_bin=str(self.root), base_port=47100,
            load_clients=1, idle_seconds=0, kasumi_cache_bytes=None))
        self.harness.work.mkdir()
        self.harness.output.mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    def compact_observations(self, observations):
        self.harness.arguments.compact_before = "finish"
        self.harness.arguments.recovery_timeout = 60
        self.harness.observers["kasumi"] = ("kasumictl", "control", {})
        with patch.object(self.harness, "storage", side_effect=observations) as storage, \
                patch.object(comparison.time, "sleep"), \
                patch.object(comparison.dev_standalone, "run",
                             return_value=subprocess.CompletedProcess([], 0, b"", b"")):
            result = self.harness.compact("kasumi")
        self.assertEqual(storage.call_count, len(observations))
        return result

    @staticmethod
    def compaction_status(cycle, idle, requested):
        return {"compaction_cycle": cycle, 'compaction_phase{phase="idle"}': idle,
                "compaction_requested": requested, "status_age_seconds": 0}

    def test_compact_finish_accepts_a_request_consumed_by_the_running_cycle(self):
        result = self.compact_observations([
            self.compaction_status(7, 0, 0), self.compaction_status(7, 0, 1),
            self.compaction_status(7, 1, 0),
            self.compaction_status(7, 1, 0)])
        self.assertEqual((result["cycle_before"], result["cycle_after"]), (7, 7))

    def test_compact_finish_waits_for_an_idle_request_to_be_consumed(self):
        result = self.compact_observations([
            self.compaction_status(7, 1, 0), self.compaction_status(7, 1, 1),
            self.compaction_status(8, 0, 0), self.compaction_status(8, 1, 0),
            self.compaction_status(8, 1, 0)])
        self.assertEqual(result["cycle_after"], 8)

    def test_compact_finish_accepts_no_eligible_older_files(self):
        result = self.compact_observations([
            self.compaction_status(7, 1, 0),
            self.compaction_status(7, 1, 0), self.compaction_status(7, 1, 0)])
        self.assertEqual(result["cycle_after"], 7)

    def test_compact_finish_rejects_stale_idle_and_requires_two_fresh_publications(self):
        stale = self.compaction_status(7, 1, 0) | {"status_age_seconds": 3600}
        result = self.compact_observations([
            self.compaction_status(7, 1, 0), stale, self.compaction_status(7, 1, 0),
            stale, self.compaction_status(7, 0, 0), self.compaction_status(7, 1, 0),
            self.compaction_status(7, 1, 0)])
        self.assertEqual(result["fresh_idle_publications"], 2)

    def test_compact_finish_does_not_count_response_latency_as_publication_freshness(self):
        self.harness.arguments.compact_before = "finish"
        self.harness.arguments.recovery_timeout = 60
        self.harness.observers["kasumi"] = ("kasumictl", "control", {})
        clock = [0.0]
        observations = []

        def storage(system):
            observations.append(clock[0])
            status = self.compaction_status(7, 1, 0)
            if len(observations) == 2:
                # The server sampled an old status, then its response stalled.
                # Its age exceeds elapsed time before the metrics request, but
                # is less than elapsed time when the delayed response arrives.
                clock[0] += 10
                status["status_age_seconds"] = 6
            return status

        def sleep(seconds):
            clock[0] += seconds

        with patch.object(self.harness, "storage", side_effect=storage), \
                patch.object(comparison.time, "monotonic", side_effect=lambda: clock[0]), \
                patch.object(comparison.time, "sleep", side_effect=sleep), \
                patch.object(comparison.dev_standalone, "run",
                             return_value=subprocess.CompletedProcess([], 0, b"", b"")):
            result = self.harness.compact("kasumi")
        self.assertEqual(observations, [0.0, 1.0, 12.0, 13.0])
        self.assertEqual(result["fresh_idle_publications"], 2)

    def test_failed_readiness_stops_the_server_before_setup_returns(self):
        server = MagicMock()
        server.alive.return_value = False
        with patch.object(comparison, "Server", return_value=server), \
                patch.object(comparison, "free_port_block", return_value=47100), \
                patch.object(comparison.dev_standalone, "run",
                             return_value=subprocess.CompletedProcess([], 0, b"", b"")):
            with self.assertRaisesRegex(RuntimeError, "serve exited"):
                self.harness.setup_system("kasumi")
        server.start.assert_called_once()
        server.stop.assert_called_once()

    def test_cache_override_changes_only_the_generated_native_cache_cap(self):
        self.harness.arguments.kasumi_cache_bytes = 8 << 20
        configuration = self.harness.work / "kasumi/installation/kasumi.json"
        settings = {"persistent_disk": {"native_storage": {"byte_limit": 1 << 30,
                                                          "cached_files": 64}},
                    "admission": {"max_inflight_bytes": 2 << 30}}

        def initialize(command, **options):
            configuration.parent.mkdir(parents=True)
            configuration.write_text(json.dumps(settings))
            return subprocess.CompletedProcess([], 0, b"", b"")

        server = MagicMock()
        server.alive.return_value = False
        with patch.object(comparison, "Server", return_value=server), \
                patch.object(comparison, "free_port_block", return_value=47100), \
                patch.object(comparison.dev_standalone, "run", side_effect=initialize):
            with self.assertRaisesRegex(RuntimeError, "serve exited"):
                self.harness.setup_system("kasumi")
        settings["persistent_disk"]["native_storage"]["byte_limit"] = 8 << 20
        self.assertEqual(json.loads(configuration.read_text()), settings)
        self.assertEqual(configuration.stat().st_mode & 0o777, 0o600)
        server.stop.assert_called_once()

    def test_collection_failure_stops_both_watchers_and_the_server(self):
        profiles = self.harness.work / "kasumi/installation/profiles"

        def initialize_then_refuse(command, **options):
            if command[1] == "init":
                profiles.mkdir(parents=True)
                profile = {
                    "administrative_members": {"1": {"endpoint": "https://localhost:47102",
                                                       "certificate_pins": ["a" * 64]}},
                    "identity": {}, "server_ca": "ca", "bearer_file": "token",
                }
                for name in ("operator", "control"):
                    (profiles / f"{name}.json").write_text(json.dumps(profile))
                return subprocess.CompletedProcess([], 0, b"", b"")
            return subprocess.CompletedProcess([], 1, b"", b"synthetic refusal")

        server = MagicMock()
        watchers = [MagicMock(), MagicMock()]
        for watcher in watchers:
            watcher.poll.return_value = None
        with patch.object(comparison, "Server", return_value=server), \
                patch.object(comparison, "free_port_block", return_value=47100), \
                patch.object(comparison.dev_standalone, "run", side_effect=initialize_then_refuse), \
                patch.object(comparison.dev_standalone, "data", return_value=(0, {"ok": True})), \
                patch.object(comparison.subprocess, "Popen", side_effect=watchers):
            with self.assertRaisesRegex(RuntimeError, "create-collection failed"):
                self.harness.setup_system("kasumi")
        server.stop.assert_called_once()
        for watcher in watchers:
            watcher.send_signal.assert_called_once_with(comparison.signal.SIGINT)
            watcher.wait.assert_called_once_with(timeout=30)

    def test_failed_workload_preserves_measurement_and_fails_the_case(self):
        server = SimpleNamespace(pid=123)
        report = {"system": "kasumi", "workload": "point-read", "operations": 2,
                  "errors": 1, "first_error": "transport unavailable", "logical_bytes_written": 0}
        sample = {"rss_bytes": 10, "footprint_bytes": 10, "peak_footprint_bytes": 10}
        peak = MagicMock()
        peak.__enter__.return_value = SimpleNamespace(peak_rss=10, peak_footprint=10)
        with patch.object(self.harness, "compact", return_value=None), \
                patch.object(self.harness, "storage", return_value=None), \
                patch.object(self.harness, "drive", return_value=report), \
                patch.object(comparison.procstat, "sample", return_value=sample), \
                patch.object(comparison.procstat, "PeakSampler", return_value=peak), \
                patch.object(comparison.procstat, "delta", return_value={"cpu_seconds": 1}):
            with self.assertRaisesRegex(RuntimeError, "point-read reported errors"):
                self.harness.measured("kasumi", server, [], "point-read", 1)
        recorded = json.loads(self.harness.results.read_text())
        self.assertEqual(recorded["errors"], 1)
        self.assertEqual(recorded["phase"], "workload")
        self.assertEqual(recorded["first_error"], "transport unavailable")

    def test_failure_diagnostics_retain_logs_without_copying_installation_credentials(self):
        directory = self.harness.work / "kasumi"
        (directory / "tmp").mkdir(parents=True)
        (directory / "server.log").write_text("server failure\n")
        (directory / "tmp/kasumi-daemon-123-example.log").write_text("failure class\n")
        (directory / "tmp/credentials.json").write_text("private fixture")
        (directory / "kasumi.json").write_text("private fixture")
        logs = self.harness.retain_failure_logs("kasumi")
        self.assertEqual(set(logs), {"kasumi/server.log", "kasumi/kasumi-daemon-123-example.log"})
        self.assertEqual((self.harness.output / "kasumi/server.log").read_text(), "server failure\n")
        self.assertEqual(len(list((self.harness.output / "kasumi").iterdir())), 2)


if __name__ == "__main__":
    unittest.main()
