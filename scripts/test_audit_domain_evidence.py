import copy
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import audit_domain_evidence as audit
import repeatable_assembly as owned


class ComposedAuditEvidence(unittest.TestCase):
    def test_only_original_contiguous_installation_and_libtest_stage_accepted(self):
        ids = ["s" + str(i) for i in range(9)] + ["first-read", "membership-after"]
        installed = [{"id": n} for n in ids]
        listing = [{"id": "list-" + name} for name, _ in
                   (audit.native.ENGINE, audit.native.RAFT, audit.native.AUTHORITY)]
        targets = listing + [{"id": f"{case}-{i}"} for case, _, _, repeats in audit.native.CASES
                             for i in range(1, repeats + 1)]
        remaining = [{"id": "distinct-physical-session"}]
        rows = installed + targets + remaining
        self.assertEqual(audit.original_stages(rows), (installed, targets, remaining))
        bad = [rows[:-2] + remaining, installed[:-1] + targets + remaining,
               installed + targets[:2] + list(reversed(targets[2:])) + remaining,
               installed + targets + targets[:1] + remaining]
        for roster in bad:
            with self.assertRaises(ValueError):
                audit.original_stages(roster)

    def test_segment_maximum_is_measured_across_each_archive_producer(self):
        with self.subTest("actual maximum can come from an installed replica"):
            installed = {"capacity": {"capacity": {"hot_budget_bytes": 4099, "starts_at_bytes": 3075,
                         "drains_to_bytes": 2049, "max_segment_bytes": 8 << 20}},
                         "objects": [{"reference": {"ciphertext_bytes": 715}}]}
            measured = {"replacement-1": {"chain": [{"ciphertext_bytes": 356}]}}
            for name in ("maintenance-1", "outage-1", "outage-2", "outage-3"):
                measured[name] = {"budget": {"hot_bytes": 128}, "starts_at": 96, "drains_to": 64,
                                  "after": {"archive_head": {"ciphertext_bytes": 203}}}
            self.assertEqual(audit.archive_measurements(installed, measured),
                             {"maximum_segment_bytes": 715, "maintenance_start_percent": 75,
                              "maintenance_target_percent": 50})
        for field in ("hot_budget_bytes", "starts_at_bytes", "drains_to_bytes", "max_segment_bytes"):
            bad = copy.deepcopy(installed)
            bad["capacity"]["capacity"][field] = 0
            with self.assertRaises(ValueError):
                audit.archive_measurements(bad, measured)
        for value in (True, 0, (8 << 20) + 1):
            bad = copy.deepcopy(measured)
            bad["outage-3"]["after"]["archive_head"]["ciphertext_bytes"] = value
            with self.assertRaises(ValueError):
                audit.archive_measurements(installed, bad)
        measured["replacement-1"]["chain"].append({"ciphertext_bytes": 1010})
        self.assertEqual(audit.archive_measurements(installed, measured)["maximum_segment_bytes"], 1010)

    def test_counts_are_lifted_from_distinct_original_raw_processes_and_a_new_session_floor(self):
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            custody = root / "transported"
            custody.mkdir()
            measured, processes = {}, []
            session = "permanent-sessions"
            for i, (name, (step, key)) in enumerate(audit.HISTORIES.items()):
                measured[step] = {key: audit.acceptance.PERMANENT_HISTORY_LIMITS[name] + i + 1}
            for step in [*measured, session]:
                raw = custody / step
                raw.write_bytes(step.encode())
                processes.append({"id": step, "log": owned.ref(custody, raw)})
            counts = audit.original_counts(root, custody, processes, measured, session,
                                           audit.acceptance.BACKUP_SESSION_FLOOR)
            self.assertEqual({c["log"]["path"] for c in counts},
                             {"transported/" + s for s in [*measured, session]})
            self.assertEqual(counts[-1]["acceptance_floor"], 100001)
            self.assertNotIn("former_limit", counts[-1])
            for step, n in ((session, 100000), ("custody-1", 100001)):
                with self.assertRaises(ValueError):
                    audit.original_counts(root, custody, processes, measured, step, n)
            (custody / "lifecycle-1").write_text("substituted")
            with self.assertRaises(ValueError):
                audit.original_counts(root, custody, processes, measured, session, 100001)

    def test_scenario_requires_all_execution_receipts_in_original_order(self):
        session = "real-session-driver"
        facts = {name: [{"step": s, "expected_exit": 0, "exit_code": 0} for s in steps]
                 for name, steps in audit.scenarios(session).items()}
        audit.compare_scenarios(facts, session)
        for name in facts:
            bad = copy.deepcopy(facts)
            bad[name].pop()
            with self.assertRaises(ValueError):
                audit.compare_scenarios(bad, session)
        bad = copy.deepcopy(facts)
        bad["archive-outage"].reverse()
        with self.assertRaises(ValueError):
            audit.compare_scenarios(bad, session)
        bad = copy.deepcopy(facts)
        bad["permanent-identity-lifetime-ceiling"][-1]["exit_code"] = 101
        with self.assertRaises(ValueError):
            audit.compare_scenarios(bad, session)


class SessionProcessBinding(unittest.TestCase):
    def test_relocates_witness_by_original_parent_pid_and_pins_native_full_cohort(self):
        import hashlib
        import json
        import run_audit_retention as runner

        command = ["/frozen/target/engine-12345", "--exact", "a::" + runner.SESSION_TEST]
        sha, commit = "1" * 64, "2" * 40
        with TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            original = root / "original"
            custody = root / "relocated"
            relative = Path("sessions/full-317-1795111111/witness.json")
            witness_path = custody / relative
            witness_path.parent.mkdir(parents=True)
            head = {"count": 200002}
            hashed = "3" * 64
            witness = {
                "schema": "kasumi-backup-session-floor-v1", "qualification": "component",
                "architecture": {"arch": "aarch64", "os": "linux", "family": "unix"},
                "test": {"name": command[2], "executable": command[0], "executable_sha256": sha,
                         "source_commit": commit, "parent_process_id": 317},
                "processes": [{"argv": [command[0], "--exact", command[2], "--include-ignored", "--nocapture",
                                        "--test-threads=1"], "process_id": 320, "seconds": 10.4}],
                "case": "backup-sessions", "cohort": "full", "floor": 100001, "crosses_floor": True,
                "observed_distinct_sessions": 100001, "failed_terminal_outcomes": 257, "verify": {"head_after": head},
                "independent": {"streams": {s: {"sha256": hashed}
                                            for s in ("pre-restart", "post-restart", "post-replay")}},
            }

            def log(observation, **changes):
                data = json.dumps(observation).encode()
                witness_path.write_bytes(data)
                row = {k: observation[k] for k in
                       ("case", "cohort", "floor", "observed_distinct_sessions", "failed_terminal_outcomes")}
                row.update(witness=str(original / relative), witness_sha256=hashlib.sha256(data).hexdigest(),
                           pre_restart_stream_sha256=hashed, post_restart_stream_sha256=hashed,
                           post_replay_stream_sha256=hashed, head=head)
                row.update(changes)
                return ("running 1 test\ntest " + command[2] + " ... ok\n" + runner.SESSION_PREFIX
                        + json.dumps(row) + "\ntest result: ok. 1 passed; 0 failed; 0 ignored;"
                        " 0 measured; 26 filtered out; finished in 123.00s\n").encode()

            def verify(raw):
                return runner.session_installation(original, custody, raw, command, sha, 27,
                                                   {"process_group": 317, "duration_seconds": 123.5}, commit)

            self.assertEqual(verify(log(witness)), (witness_path.parent, witness))
            for mutate in (lambda w: w["test"].update(parent_process_id=318),
                           lambda w: w["test"].update(source_commit="f" * 40),
                           lambda w: w["test"].update(executable_sha256="0" * 64),
                           lambda w: w["architecture"].update(arch="x86_64"),
                           lambda w: w.update(observed_distinct_sessions=100000),
                           lambda w: w.update(failed_terminal_outcomes=256),
                           lambda w: w.update(cohort="reduced"),
                           lambda w: w["processes"][0]["argv"].append("--skipped"),
                           lambda w: w["processes"][0].update(process_id=317),
                           lambda w: w["processes"][0].update(seconds=200),
                           lambda w: w["processes"].extend([dict(w["processes"][0], seconds=120)])):
                changed = copy.deepcopy(witness)
                mutate(changed)
                with self.assertRaises(ValueError):
                    verify(log(changed))
            for kwargs in ({"witness": str(custody / relative)}, {"witness_sha256": "0" * 64},
                           {"post_replay_stream_sha256": "0" * 64},
                           {"witness": str(original / "sessions/full-316-1795111111/witness.json")}):
                with self.assertRaises(ValueError):
                    verify(log(witness, **kwargs))
            raw = log(witness)
            renamed = witness_path.parent.with_name("substituted")
            witness_path.parent.rename(renamed)
            witness_path.parent.symlink_to(renamed, target_is_directory=True)
            with self.assertRaises(ValueError):
                verify(raw)


if __name__ == "__main__":
    unittest.main()
