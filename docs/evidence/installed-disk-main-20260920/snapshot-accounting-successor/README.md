# Snapshot accounting successor

TARGET ONLY, UNCOMPILED. This proposal is based on actual master after root's 102 corrections, including the separately reviewed causal history/schema fixtures. It does not rewrite the original run-88 resident-snapshot proposal or erase run-98 failures. No actual source changes, Cargo calls, Rust builds or tests were made.

Run 98's six staged integration failures compare SnapshotAccounting::bytes against a helper which selected only resident stream bytes. That comparison was incorrect: accounting.rs deliberately adds staged_terminal_head.encoded_bytes to its quota. The correction preserves exact equality and the existing terminal quota.

The verified policy mapping is:

| Stream records | Resident materialization estimate | SnapshotAccounting quota |
| --- | --- | --- |
| 0–4, 6–20, 23 (RecoveryCompletionHistory) | included | included |
| 5 ordinary permanent receipts | excluded | excluded; separate receipt byte budget |
| 21 permanent staged terminal rows | excluded | included via terminal head encoded_bytes |
| 22 permanent target-resolution rows | excluded | excluded; separate target-resolution byte budget |
| Eight-byte prefix and 56-byte terminal framing | included | included |

All permanent heads remain in the Header record. target_resolution::snapshot_limit adds only ordinary-receipt and target-resolution encoded bytes to max_snapshot_bytes, corroborating the quota distinction. Full snapshot images, stored permanent rows, exact replay checks and independent limits remain unchanged.

The cfg test-utils helper is directly renamed snapshot_accounted_bytes, with no alias. It authenticates complete framing/digest/EOF, obtains the resident byte sum and adds kind21 framed bytes with checked arithmetic. All six supported exact accounting assertions across guarded_staging, history, staged_transactions and schema_activation use the new name. No tested payload, count, deadline, quota, tolerance, workload or operation budget is changed.

The same audit found a production estimate defect: StreamSummary::resident_bytes iterated only kinds[..21], so it omitted resident RecoveryCompletionHistory kind23. It now examines all supported kinds and excludes only permanent point kinds5/21/22. This adds the real kind23 contribution to materialization_workspace (three times resident bytes) without charging permanent table lengths as RAM. These existing functions remain documented estimates, not hard-RSS or allocator bounds.

A new canonical-stream regression constructs a validated RecoveryCompletionHistory record for an existing coordinator operation, writes a real encrypted snapshot image, authenticates and semantically visits it, decodes the exact history, and checks full resident bytes, the exact added frame size, materialization estimate, incremental versus rebuilt accounting, and the renamed helper. Its historical point IDs satisfy the record codec; the test explicitly does not claim coordinator phase-protocol validation. Existing tests for permanent aggregate exclusion and checked overflow remain intact.

manifest.json records all seven before/proposed hashes, rustfmt stdin and git apply --check. The new test and all affected integration cases remain unexecuted pending root's coordinated gate. Snapshot work revision4 remains a separate frozen proposal with its claim-transfer callback-panic review blocker; this accounting patch does not depend on or fix that foundation.
