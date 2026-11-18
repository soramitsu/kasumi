import json
import unittest
import uuid

import run_observability_probes as obs
import verify_release_acceptance as acceptance


def response(identifier, body, *, status=200, cache="no-store"):
    return (obs.PREFIX["http"] + json.dumps({"id": identifier, "status": status, "cache_control": cache,
            "content_type": "text/plain" if isinstance(body, str) else "application/json",
            "body": body if isinstance(body, str) else json.dumps(body)}) + "\n").encode()


def native(identifier, fields):
    return (obs.PREFIX["native"] + json.dumps({"id": identifier, "fields": fields}) + "\n").encode()


class Observability(unittest.TestCase):
    epoch = {"topology_version": 17, "installed_routes": 128, "actual_membership": 0}

    def ready(self, healthy, **change):
        return {"ready": True, "groups": [{"tenant": f"tenant-{index}", "quorum": True} for index in range(128)],
                "readiness_coverage": {"membership_epoch": self.epoch, "covered_epoch": self.epoch, "complete": True,
                "fresh": True, "expected_groups": 129, "examined_groups": 129, "healthy_groups": healthy,
                "detail_limit": 128, "oldest_probe_age_seconds": 0.5, **change}}

    def test_each_epoch_component_must_be_an_exact_integer_and_match(self):
        for key in self.epoch:
            changed = {**self.epoch, key: self.epoch[key] + 1}
            with self.subTest(component=key), self.assertRaises(ValueError):
                obs.installed_coverage(self.ready(129, covered_epoch=changed), 129)
        for invalid in (17, None, {}, {**self.epoch, "extra": 0}, {**self.epoch, "installed_routes": True}):
            with self.subTest(epoch=invalid), self.assertRaises(ValueError):
                acceptance.check_readiness_epoch(invalid)

    def test_129_groups_requires_raw_metric_and_fresh_negative_probe(self):
        metrics = {"ready": 1, "local_group_details": 128, "readiness_groups_expected": 129,
                   "readiness_groups_examined": 129, "readiness_groups_healthy": 129}
        for key, value in self.epoch.items():
            metrics["readiness_epoch_" + key] = value
            metrics["readiness_covered_epoch_" + key] = value
        text = "".join(f"kasumi_{key} {value}\n" for key, value in metrics.items())
        prefix = response("healthy-129", self.ready(129)) + response("after-rejected-membership", self.ready(129))
        data = prefix + response("negative-group-129", self.ready(128)) + response("metrics-129", text)
        self.assertEqual(obs.verified("readiness", data)["covered_epoch"], self.epoch)
        for changed in ({"examined_groups": 128}, {"healthy_groups": 129}, {"fresh": False},
                        {"oldest_probe_age_seconds": 30}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                obs.verified("readiness", prefix + response("metrics-129", text)
                             + response("negative-group-129", self.ready(128, **changed)))
        with self.assertRaises(ValueError):
            obs.verified("readiness", data.replace(b"readiness_epoch_actual_membership 0", b"readiness_epoch_actual_membership 1"))

    def test_recovery_needs_matching_protected_and_native_committed_read(self):
        fields = {"operation_id": str(uuid.uuid4()), "phase": "prepare", "updated_revision": 51,
                  "phase_pending": False, "terminal": False}
        self.assertEqual(obs.verified("recovery", response("recovery-status", fields)
            + native("recovery-status", fields)), fields)
        for change in ({"operation_id": str(uuid.uuid4())}, {"updated_revision": 52}, {"phase": "finished"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                obs.verified("recovery", response("recovery-status", fields) + native("recovery-status", {**fields, **change}))

    def test_capture_rejects_a_wrong_http_status_private_cache_or_substituted_log(self):
        for log in (response("x", {}, status=503), response("x", {}, cache="private"),
                    response("x", {}) + response("x", {})):
            with self.assertRaises(ValueError):
                obs.rows(log)
        with self.assertRaisesRegex(ValueError, "exact observations"):
            obs.verified("backup", b"all sessions completed\n")

    def test_point_read_does_not_project_an_aggregate(self):
        identifier = str(uuid.uuid4())
        row = {"session_id": identifier, "backup_id": identifier, "revision": 9, "checkpoint_revision": 9,
               "source_incarnation": "registered", "checkpoint_incarnation": "registered",
               "source_purpose_sha256": "a" * 64, "intent_ciphertext_sha256": "b" * 64,
               "manifest_ciphertext_sha256": "c" * 64}
        self.assertEqual(obs.verified("backup", native("completed-session-status", row)), row)
        with self.assertRaises(ValueError):
            obs.verified("backup", native("completed-session-status", {**row, "checkpoint_revision": 10}))

    def test_authority_records_actual_quorum_and_persisted_voter_replacement(self):
        original, final = [1, 2, 3], [1, 3, 4]
        data = {}
        for i, step in enumerate(("issuer-capacity", "issuer-enroll", "issuer-replace", "issuer-revoke")):
            data[step] = {"operation_id": str(uuid.uuid4()), "command_sha256": f"{i:064x}",
                          "admitted_revision": i * 3 + 1, "progress_revision": i * 3 + 2,
                          "observer": 1, "leader": 1, "term": 2,
                          "voters_before": final if i == 3 else original, "effective_voters": final if i >= 2 else original,
                          "phase": {"kind": "draining" if i == 3 else "completed"},
                          "requested_voters": final if i == 2 else None, "target": {1: 4, 3: 2}.get(i)}
        data["issuer-peer-denial"] = {"removed": 2, "remaining_refusals": 3}
        self.assertEqual(obs.issuer_maintenance(data)["replaced_voters"], final)
        for key, change in (("issuer-replace", {"effective_voters": original}), ("issuer-revoke", {"phase": {"kind": "completed"}}),
                            ("issuer-revoke", {"admitted_revision": 2}), ("issuer-enroll", {"leader": None}),
                            ("issuer-peer-denial", {"remaining_refusals": 1})):
            with self.subTest(key=key, change=change), self.assertRaises(ValueError):
                obs.issuer_maintenance({**data, key: {**data[key], **change}})

    def test_structured_events_preserve_failure_class_and_exclude_sensitive_fields(self):
        events = [{"fields": {"event": "tls_reload_failed"}}, {"fields": {"event": "engine_warning"}},
                  {"fields": {"event": "original_engine_open_failed", "failure_class": "io_storage_full"}}]
        self.assertEqual(len(obs.verified("logs", native("structured-events", events))["events"]), 3)
        events[0]["fields"]["token"] = "secret-span-token"
        with self.assertRaisesRegex(ValueError, "disclosed"):
            obs.verified("logs", native("structured-events", events))

    def test_archive_metrics_must_match_due_bytes_and_failed_worker(self):
        value = {"groups": [{"tenant": "tenant-a", "retention": {"archive_backlog_bytes": 40, "hot_bytes": 90,
                 "hot_budget_bytes": 100}, "audit_maintenance": {"failures": 1, "committed_segments": 0}}],
                 "service_audit": {"retention": {"archive_backlog_bytes": 0}}}
        text = 'kasumi_local_group_audit_archive_backlog_bytes{tenant="tenant-a"} 40\nkasumi_service_audit_archive_backlog_bytes 0\n'
        prefix = response("archive-outage", value)
        self.assertEqual(obs.verified("backlog", prefix + response("archive-outage-metrics", text))["archive_backlog_bytes"], 40)
        with self.assertRaises(ValueError):
            obs.verified("backlog", prefix + response("archive-outage-metrics", text.replace("40", "30")))


if __name__ == "__main__":
    unittest.main()
