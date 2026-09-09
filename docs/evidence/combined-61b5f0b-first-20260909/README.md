# Indexed-lineage fix and target materialization checks

Source `61b5f0b09b8f0e96114b7a94e0b8216bb76f22ae` selects the exact verified
original lineage link before validating each indexed staged record. The
unchanged snapshot regression now passes, including two successive restores and
authenticated scope/revision substitutions.

| Executed gate | Actual result | Seconds |
| --- | --- | ---: |
| Snapshot validation | 5 passed | 35.156 |
| Shutdown and immediate reopen | 1 passed | 8.159 |
| Restore and original receipts | 1 passed | 14.210 |
| Actual target materialization | 9 passed | 119.804 |

The dispatcher stopped after the final row because its required test name
omitted the `service::tests::issuer_tests::` prefix. Cargo returned zero and all
nine actual target tests passed, including
`service::tests::issuer_tests::target_materialization_tests::dropping_target_on_non_runtime_thread_retains_shutdown_work_until_real_drain`.
This cohort retains its failed required-name guard outcome. The remaining 17
gates were not dispatched here; a separate continuation runs only those gates
on the unchanged source.

All four process groups drained and source/tree/lock hashes stayed unchanged.
[evidence.json](evidence.json) binds the actual commands, test executables,
features, original 900-second deadlines and process receipts.
[preservation.json](preservation.json) hashes the copied raw logs, dispatcher,
plan and source inventory; actual executables were separately preserved before
target reuse. These macOS ARM64 focused checks do not establish final release,
capacity, performance or endurance acceptance.
