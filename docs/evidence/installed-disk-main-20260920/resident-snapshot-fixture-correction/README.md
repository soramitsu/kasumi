# Resident snapshot accounting fixture correction

TARGET ONLY, UNCOMPILED. No actual source edits or builds while root-owned run88 freezes source. Five-file proposal: engine test_utils.rs and guarded_staging.rs, history.rs, staged_transactions.rs, schema_activation.rs integration fixtures. No production implementation, quota, payload, timeout, or policy changes.

## Correct comparison

snapshot_bytes() is resident semantic accounting. The complete first-release snapshot also streams permanent mutation receipts, staged terminal rows, and target resolutions. The old tests incorrectly equated those two quantities (run88 examples: 5526 versus 6407; 266457 versus 283144; 5482 versus 6381).

The new feature-gated snapshot_resident_bytes(&SnapshotImage) helper calls the existing snapshot_codec::inspect on the actual encrypted image reader, then returns StreamSummary::resident_bytes. Inspection consumes and authenticates all typed frames, counts, terminal digest, and EOF; it does not strip permanent records or reserialize resident state. Six existing direct comparisons now keep exact equality between incremental resident accounting and this independently inspected resident stream. The shared staged/schema apply helpers still make the comparison after every original operation, including rejected operations. Full snapshot generation, restore/replay, permanent head/receipt identity, and encrypted restart checks remain unchanged. No >=, slack, adjusted budgets, or compatibility path is introduced.

## Concrete permanent-stage assertions

The payload cleanup case now checks that the resident upload maps are empty, reserved terminal bytes are zero, and the permanent head has exactly two rows. It reads both original transaction identities through the actual Database staged point-read path and checks exact manifest, outcome, expiry, and empty received_chunks. That path calls staged_terminal::Row::validate, whose staging::validate_snapshot_record compares stored/uploaded byte/operation/assertion counters with an empty SnapshotChunks value; a nonzero retained upload counter therefore rejects the point read. This replaces the previous vacuous all() over an empty resident map.

After the original permanent-quota denial, the complete terminal head must be unchanged and the rejected identity must be NotFound. The separate original resident-snapshot quota denial also preserves its exact terminal head and proves the refused identity is absent. Existing 512-chunk workload and every limit/deadline expression remain unchanged.

## Receipt and remaining validation

Proposed-only rustfmt stdin and git apply --check passed. The manifest records before/proposed SHA256s and confirms unchanged integration function names and duration/limit expressions. No Cargo/test result exists for this proposal. Root should run the affected four integration binaries after applying in a coordinated source checkpoint; run88 evidence remains untouched. contracts crash-directory and typed shutdown failures are owned separately by root and are outside this patch.
