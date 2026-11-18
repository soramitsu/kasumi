import copy
import hashlib
import json
import unittest

import concurrency_workloads as work
import run_concurrency as runner


class ConcurrentHistory(unittest.TestCase):
    def history(self, name):
        keys = work.documents("attempt", name)
        def row(i, start, end):
            return {"id": i, "sent_ns": start, "finished_ns": end}
        def line(i, data):
            return json.dumps({"id": i, "status": 0, "document": {"ok": True, "result": data}})
        def receipt(i):
            batch = work.batch("attempt", name, i, "docs")
            digest = hashlib.sha256(json.dumps(batch, separators=(",", ":")).encode()).hexdigest()
            return line(i, {"idempotency_key": batch["idempotency_key"], "request_digest": digest,
                            "receipt": {"revision": i+1, "versions": {f"/docs/{k}": i+1 for k in keys}}})
        def doc(i, k):
            return {"id": k, "body": work.payload("attempt", name, i), "version": i+1}
        role = "snapshot" if name == "snapshot-writes" else "read"
        rows = {"seed":[row(0, 1, 2)],"write":[row(1, 3, 10)],role:[row(1, 4, 9)]}
        observed = ({"snapshot": {"revOther": 456, "revision": 2, "incarnation":"inc", "queries":[],
                    "documents":[{"key":{"collection":"docs","id":k},"document":doc(1,k)} for k in keys]}}
                    if role == "snapshot" else {"document":doc(0,keys[1])})
        replies = {"seed":[receipt(0)],"write":[receipt(1)],role:[line(1, observed)]}
        return rows, replies

    def test_atomic_snapshots_and_reads_recount_each_original_interval(self):
        for name in ("reads-writes", "snapshot-writes"):
            rows, replies = self.history(name)
            self.assertEqual(list(work.replay_data("attempt", name, "docs", "inc", (1,1), rows, replies)), [1,2])
            self.assertEqual([r["elapsed_ns"] for r in work.samples(name, rows)], [7,5])

    def test_disjoint_inflight_intervals_rejected(self):
        rows, _ = self.history("reads-writes")
        rows["read"][0].update(sent_ns=10, finished_ns=20)
        with self.assertRaisesRegex(ValueError,"in flight"):
            work.samples("reads-writes", rows)

    def test_torn_snapshot_and_substituted_write_are_rejected(self):
        rows, replies = self.history("snapshot-writes")
        torn = copy.deepcopy(replies)
        data = json.loads(torn["snapshot"][0])
        data["document"]["result"]["snapshot"]["documents"][0]["document"]["version"] = 1
        torn["snapshot"][0] = json.dumps(data)
        with self.assertRaisesRegex(ValueError,"torn"):
            work.replay_data("attempt","snapshot-writes","docs","inc",(1,1),rows,torn)
        reply = json.loads(replies["write"][0])
        reply["document"]["result"]["request_digest"] = "0"*64
        replies["write"][0] = json.dumps(reply)
        with self.assertRaisesRegex(ValueError,"atomic pair"):
            work.replay_data("attempt","snapshot-writes","docs","inc",(1,1),rows,replies)

    def test_read_cannot_ignore_a_completed_write(self):
        rows, replies = self.history("reads-writes")
        rows["read"][0].update(sent_ns=11,finished_ns=13)
        with self.assertRaisesRegex(ValueError,"original committed"):
            work.replay_data("attempt","reads-writes","docs","inc",(1,1),rows,replies)

    def test_membership_and_physical_snapshot_require_new_committed_positions(self):
        before = {"mode":"replicated","incarnation":"test","node_id":2,"leader":2,
                  "observation":"local_committed_state","raft_voters":[1,2,3],"raft_applied_index":100,
                  "raft_membership_index":4,"raft_snapshot_index":None,"revision":5}
        for name, field in (("membership-writes","raft_membership_index"),("snapshot-writes","raft_snapshot_index")):
            result = {"changed":True,"publish_control_route_required":True}
            with self.assertRaisesRegex(ValueError,"no new"):
                runner.checks(name,before,before,[1,2,3],"test",result)
            after = dict(before,raft_applied_index=200)
            after[field]=190
            runner.checks(name,before,after,[1,2,3],"test",result)
            after[field]=201
            with self.assertRaisesRegex(ValueError,"ahead"):
                runner.checks(name,before,after,[1,2,3],"test",result)

    def test_live_maintenance_identity_brackets_a_complete_original_write(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as temp:
            d = Path(temp)
            fields = ["S", "1", "23"] + ["0"] * 16 + ["201"]
            sample = {"stat": "23 (kasumid) " + " ".join(fields), "time_ns": 3}
            proof = {"write_id": 1, "before": sample, "after": dict(sample, time_ns=10)}
            path = d / "maintenance-live.json"
            path.write_text(json.dumps(proof))
            row = {"id":1,"sent_ns":4,"finished_ns":9}
            rows = {"maintenance":[{"id":1,"sent_ns":2,"finished_ns":11}],"write":[row]}
            runner.live_write(d, rows, {"process_group":23,"leader_birth":"linux:201"})
            with self.assertRaisesRegex(ValueError, "another or exited"):
                runner.live_write(d, rows, {"process_group":23,"leader_birth":"linux:202"})
            row["finished_ns"] = 11
            with self.assertRaisesRegex(ValueError, "span"):
                runner.live_write(d, rows, {"process_group":23,"leader_birth":"linux:201"})

    def test_unapplied_membership_status_remains_pending(self):
        self.assertTrue(runner.pending("reads-writes", {"raft_applied_index":5},
                                       {"raft_voters":None,"raft_membership_index":None}))
        self.assertFalse(runner.pending("membership-writes", {"raft_applied_index":5},
                                        {"raft_voters":[1,2,3],"raft_membership_index":6}))
