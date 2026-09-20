# Combined ownership checkpoint: failed private-directory fixtures

Frozen source `be2667d804e483dce2b3bcc408ecb7cb7f3ae66a` / tree
`5cc19f163e7f0b7b53ef53da9dfc998578ba0f20` ran unchanged on macOS ARM64 with
Rust 1.97.1 on September 19, 2026. This **failed** cohort retained 31 gates and
141 mandatory cases, original commands/deadlines and stop-on-first-failure order.
Eight gates passed, the ninth failed, and 22 later gates did not run.

| Gate | Outcome | Seconds | Test result |
| --- | --- | --- | --- |
| workspace-all-targets-check | passed | 139.991 | workspace all targets/features compiled |
| workspace-format | passed | 1.572 | workspace formatting |
| complete-store-library | passed | 96.498 | 150 passed, 0 failed, 2 ignored |
| strict-store | passed | 18.997 | store all targets/features, warnings denied |
| complete-serving-library | passed | 15.589 | 23 passed, 0 failed, 0 ignored |
| engine-database-worker-outcomes | passed | 161.378 | 4 passed, 0 failed, 0 ignored |
| engine-audit-worker-outcomes | passed | 7.858 | 2 passed, 0 failed, 0 ignored |
| engine-control-genesis | passed | 1.600 | 5 passed, 0 failed, 0 ignored |
| server-serving-owner | failed | 293.785 | 1 passed, 5 failed, 0 ignored |

All 55 mandatory store cases passed, including the seven new NodeDisk and
filesystem-backup regressions. The two ignored store entries are the live MinIO
test and a subprocess helper exercised by its passing parent. Corrected Control
genesis passed. This is not a complete workspace test or strict workspace lint
result, installed NodeDisk admission qualification, or production acceptance.

Five serving-owner fixtures failed with `operator material must be owner-only`.
Their installation directories need private permissions before opening the
production owner. The failures occur before the intended ownership assertions;
correct fixture setup without weakening production permission checks and validate
on a new frozen revision. The original failure is retained in
[server-serving-owner.log](server-serving-owner.log).

All 22 later gates, including the five audit gates, remain **UNRUN** on this
source. Their exact names and the completed outcomes are in
[summary.json](summary.json). All nine dispatched process groups drained and
source comparison passed throughout. Later integration and pending MCP changes
are outside this run; no final platform, live-provider, capacity, performance,
endurance or release-artifact acceptance is claimed.

The original `evidence.json` scope string ends with "Prepared only". Its terminal
`status: failed`, timestamps and per-gate records establish actual execution.
This summary corrects the interpretation without modifying the original bytes.

Thirteen raw files were copied unchanged from
`/Users/mtakemiya/dev/kasumi-release-evidence/20260919-be2667d-ownership` on
September 20. [copied-files.json](copied-files.json) records their SHA-256 values;
gate logs, plan, runner and source-manifest hashes were verified against the
original evidence. [preserved-executables.json](preserved-executables.json)
indexes four test binaries retained at their external paths; their bytes and
hashes were reverified during preservation. The binaries remain outside Git.

The preceding failed [`32825cf` cohort](../first-release-32825cf-check-20260919/README.md)
also remains preserved. No failed attempt is replaced by its successor's evidence.
