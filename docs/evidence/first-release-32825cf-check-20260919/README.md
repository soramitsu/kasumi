# Combined ownership checkpoint: failed Control genesis fixture

Frozen source `32825cfe42497ea0fe700199d4cd9f475acccebd` / tree
`7ce63492e2ccac83c5245463bf1dacaffa678d22` ran unchanged on macOS ARM64 with
Rust 1.97.1. This **failed** cohort retained all 26 planned gates, 124 mandatory
cases, original commands/deadlines and stop-on-first-failure ordering.

| Gate | Outcome | Seconds | Test result |
| --- | --- | --- | --- |
| workspace-all-targets-check | passed | 132.968 | workspace all targets/features compiled |
| workspace-format | passed | 1.625 | workspace formatting |
| complete-store-library | passed | 88.924 | 143 passed, 0 failed, 2 ignored |
| strict-store | passed | 18.798 | store all targets/features, warnings denied |
| complete-serving-library | passed | 36.252 | 23 passed, 0 failed, 0 ignored |
| engine-database-worker-outcomes | passed | 264.368 | 4 passed, 0 failed, 0 ignored |
| engine-audit-worker-outcomes | passed | 7.546 | 2 passed, 0 failed, 0 ignored |
| engine-control-genesis | failed | 1.877 | 4 passed, 1 failed, 0 ignored |

All mandatory cases in the seven passing gates were observed: 48 store, 12
serving, four database-worker and two audit-worker cases. The two ignored store
entries were the explicitly configured live MinIO test and a subprocess helper
exercised by its passing crash-recovery parent. This is neither strict workspace
lint nor a full workspace test result.

The failed case was
`bootstrap::control_genesis::tests::control_genesis_rejects_wrong_storage_purpose_before_deployment_publication`.
Its expectation that `open_replicated(...).await.is_err()` was false. Source review
identified a test setup defect: `initialize_catalogs_fixture` selects `NodeControl`
for the reserved Control tenant, so the fixture actually supplied the permitted
purpose. The production `ReplicatedGenesis::require_domain` check remained intact;
this result does not demonstrate acceptance of a genuinely wrong purpose.
Successor `d14c4b3` constructs explicit fixture-purpose storage and asserts that
purpose before exercising rejection and unchanged durable state. That correction
must pass on a newly frozen successor; it does not erase this failed run.

All 18 later gates were withheld and remain **UNRUN** on this source, including
server ownership/lifecycle, TLS, native receipts, authority enrollment and explicit
original voters. Their exact names remain in `summary.json` and the original
plan/evidence. The source excludes the later five NodeDisk exclusive/live-shrink
regressions (`9c8309c`), filesystem backup durability regressions (`db4b123`) and
audit outage corrections. No final capacity, platform, live-service, production
build, performance, endurance or release-artifact acceptance is claimed.

Every dispatched process group drained without signals, residual processes or
inspection errors. Source comparison passed throughout. Twelve raw files were
copied unchanged from
`/Users/mtakemiya/dev/kasumi-release-evidence/20260919-32825cf-ownership`;
`copied-files.json` records their verified SHA-256 values. Original evidence
includes the source manifest, dependency lock, runner, process-helper, tool and
executable hashes. `preserved-executables.json` indexes all three binaries; their
bytes and hashes were reverified at their durable external paths during
preservation. The large binaries remain external and are not committed here.
