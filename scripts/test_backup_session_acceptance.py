"""Adversarial unit fixtures for independent native session evidence replay."""
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
import uuid

import backup_session_acceptance as sessions


class SessionEvidenceTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.nonce = str(uuid.uuid4())
        self.digest = "7a" * 32

    def file(self, name, raw):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        return hashlib.sha256(raw).hexdigest()

    def journal(self, name, rows):
        return self.file(name, b"".join(sessions.canonical(row) + b"\n" for row in rows))

    def test_originals_require_distinct_planned_requests_and_permanent_failure_cohort(self):
        rows = []
        for ordinal in range(258):
            rows.append(dict(ordinal=ordinal, session_id=sessions.session_id(self.nonce, ordinal),
                             request_id=f"floor-{ordinal:06d}", kind="aborted", stage="populate",
                             checkpoint=None, outcome={"reason": f"permanent {ordinal}"}, seconds=0.25,
                             resolution=None))
        plan = dict(sessions=258, kill_reserve=2, nonce=self.nonce)
        for mutation in ("none", "duplicate", "missing", "wrong-id", "short-failure-cohort", "unplanned-resolution"):
            with self.subTest(mutation=mutation):
                db = sqlite3.connect(":memory:")
                try:
                    current = copy.deepcopy(rows)
                    if mutation == "duplicate":
                        current[-1] = current[0]
                    elif mutation == "missing":
                        current.pop()
                    elif mutation == "wrong-id":
                        current[9]["session_id"] = current[10]["session_id"]
                    elif mutation == "unplanned-resolution":
                        current[7].update(stage="resolve", resolution={})
                    elif mutation == "short-failure-cohort":
                        for row in current[:2]:
                            row.update(kind="complete", checkpoint={}, outcome=None)
                    digest = self.journal("original.jsonl", current)
                    report = dict(original_journal_sha256=digest, originals=len(current),
                                  original_failed=sum(row["kind"] == "aborted" for row in current))
                    if mutation == "none":
                        self.assertEqual(sessions.index_originals(db, self.root, plan, report), (258, {}))
                    else:
                        with self.assertRaises((ValueError, sqlite3.IntegrityError)):
                            sessions.index_originals(db, self.root, plan, report)
                finally:
                    db.close()

    def test_destination_hashes_selected_files_and_sorts_original_names(self):
        target = sessions.session_id(self.nonce, 0)
        prefix = "sessions/" + target + "/"
        leaves = {prefix + "outcome.kasumi": b"terminal", prefix + "objects/body": b"old object",
                  prefix + "intent.kasumi": b"selected intent"}
        lines = []
        total_size = 0
        for relative, raw in leaves.items():
            if relative.endswith(".kasumi"):
                tag = 1 if relative.endswith("intent.kasumi") else 2
                raw = (b"KSMSES01" + bytes([tag]) + bytes(7) + uuid.UUID(target).bytes
                       + len(raw).to_bytes(8, "little") + hashlib.sha256(raw).digest()
                       + raw + bytes(sessions.SLOT_CAPACITY - len(raw)))
            total_size += len(raw)
            digest = self.file("persistent/destination/" + relative, raw)
            lines.append(f"{relative}\t{len(raw)}\t{digest if relative.endswith('.kasumi') else '-'}\n")
        census = sessions.index_destination(self.db, self.root)
        self.assertEqual(census, {"files": 3, "bytes": total_size, "intents": 1,
                                  "outcomes": 1, "session_objects": 1,
                                  "sha256": hashlib.sha256("".join(sorted(lines)).encode()).hexdigest()})
        raw = leaves[prefix + "intent.kasumi"]
        digest = hashlib.sha256(raw).hexdigest()
        sessions.check_ciphertext(self.db, target, "intent", len(raw), digest)
        for kind, size, hashed in (("intent", len(raw) + 1, digest), ("intent", len(raw), self.digest),
                                   ("outcome", len(raw), digest)):
            with self.subTest(kind=kind, size=size), self.assertRaises(ValueError):
                sessions.check_ciphertext(self.db, target, kind, size, hashed)

    def test_destination_rejects_symlink_without_following_it(self):
        self.file("external/file", b"unowned")
        dest = self.root / "persistent/destination"
        dest.mkdir(parents=True)
        (dest / "session").symlink_to(self.root / "external", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "unowned"):
            sessions.index_destination(self.db, self.root)

    def test_terminal_extent_and_ciphertext_across_compaction_and_interrupted_rename(self):
        target = uuid.uuid4()
        payload = b"original encrypted outcome"
        fields = (bytes([2]) + bytes(7) + target.bytes + len(payload).to_bytes(8, "little")
                  + hashlib.sha256(payload).digest() + payload)
        padding = bytes(sessions.SLOT_CAPACITY - len(payload))
        for version, tail, valid in ((1, padding, True), (1, b"", False), (2, padding, True),
                                     (2, b"", True), (2, b"\x00", False),
                                     (2, padding[:-1] + b"X", False)):
            with self.subTest(version=version, extent=len(tail), valid=valid):
                record = f"KSMSES0{version}".encode() + fields + tail
                path = self.root / "outcome.kasumi"
                path.write_bytes(record)
                if valid:
                    self.assertEqual(sessions.terminal_digests(path, str(target), "outcome"),
                                     (hashlib.sha256(record).hexdigest(), len(payload),
                                      hashlib.sha256(payload).hexdigest()))
                else:
                    with self.assertRaises(ValueError):
                        sessions.terminal_digests(path, str(target), "outcome")

    def test_bounded_page_chain_resolves_claim_and_terminal_ordinals(self):
        self.db.execute("CREATE TABLE position(ord INTEGER PRIMARY KEY, claim INTEGER, id TEXT, digest TEXT)")
        ids = [sessions.session_id(self.nonce, i // 2) for i in range(4)]
        for i, identifier in enumerate(ids):
            self.db.execute("INSERT INTO position VALUES(?,?,?,?)", (i + 1, int(i % 2 == 0), identifier, self.digest))
        first = dict(index=0, scanned_from=1, scanned_through=2, entries=1, first_session=ids[0],
                     last_session=ids[0], next={"after_ordinal": 2, "after_row_sha256": self.digest})
        second = dict(index=1, scanned_from=3, scanned_through=4, entries=1, first_session=ids[2],
                      last_session=ids[2], next=None)
        obs = dict(pages=[first, second], head={"count": 4, "last_applied_revision": 8}, sessions=2,
                   completed=1, aborted=1, pending=0, max_page_entries=1,
                   aggregate=dict(last_binding_revision=8, completed=1, aborted=1, claimed_without_terminal=0))
        sessions.check_pages(self.db, obs, 2, 1)
        for index, change in ((0, {"next": {"after_ordinal": 2, "after_row_sha256": "00" * 32}}),
                               (1, {"scanned_from": 2}), (1, {"entries": 257}), (0, {"first_session": ids[2]})):
            altered = copy.deepcopy(obs)
            altered["pages"][index].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                sessions.check_pages(self.db, altered, 2, 1)

    def test_kill_requires_barrier_in_original_stdout_between_dispatch_and_completion(self):
        marker = "KASUMI_FLOOR_WRITE_OUTSTANDING"
        payload = {"process_id": 22, "ordinal": 3}
        process = dict(stage="kill", signal=9, exit_code=None, process_id=22,
                       stdout="logs/kill.stdout", stderr="logs/kill.stderr", argv=["test-bin", "--exact", "suite"])
        receipt = dict(process, target=3, marker=marker, seconds_from_marker_to_reap=0.02,
                       marker_payload=payload, operation_returned=False)
        dispatch = b"test suite ... KASUMI_FLOOR_DISPATCH 3\n"
        barrier = marker.encode() + b" " + json.dumps(payload).encode() + b"\n"
        for label, output in (("passed", dispatch + barrier), ("no-barrier", dispatch),
                              ("duplicate", dispatch + barrier * 2), ("returned", dispatch + barrier +
                              b"KASUMI_FLOOR_WRITTEN 3\n"), ("wrong-order", barrier + dispatch),
                              ("wrong-request", dispatch.replace(b"3", b"9") + barrier)):
            self.file(process["stdout"], output)
            with self.subTest(label=label):
                if label == "passed":
                    self.assertEqual(sessions.original_kill(self.root, receipt, process, "kill", 3, marker), payload)
                else:
                    with self.assertRaises(ValueError):
                        sessions.original_kill(self.root, receipt, process, "kill", 3, marker)


if __name__ == "__main__":
    unittest.main()
