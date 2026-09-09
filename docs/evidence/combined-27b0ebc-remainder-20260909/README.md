# Combined snapshot validation failure

Frozen source `27b0ebcee94d6e73d1674149a6a6fa6ffea4f0ab` continued after
the initial cohort's empty test selection. The corrected lease-retention module
passed all five tests in 1.476 seconds. The snapshot-validation module then
passed four tests and failed one in 15.402 seconds:
`receipt_original_scope_and_position_are_checked_in_both_snapshot_paths`.

After two restores, full-state validation accepted the retained original scope,
but indexed validation rejected a staged record because the header omits the
streamed restore lineage. The indexed validator passed that incomplete header
directly to the staged-scope validator. This was an actual implementation
failure, not a timing or test-selection failure. The unchanged regression also
checks authenticated scope, digest, revision and lineage substitutions.

Both process groups drained, source and lock hashes remained unchanged, and
the later 20 gates did not run. The cohort remains failed. The narrow successor
`61b5f0b` selects the original scope's exact verified closing link from the
encrypted lineage index; its execution has separate evidence.

[evidence.json](evidence.json) retains actual features, executable hashes,
deadlines and process receipts. [preservation.json](preservation.json) binds
the copied raw logs, dispatcher, plan and source inventory. The actual engine
test executable was separately copied and hash-verified before target reuse.
These are macOS ARM64 focused correctness checks, with one compiler job and
one test thread. They do not establish capacity, performance, endurance or
complete release acceptance.
