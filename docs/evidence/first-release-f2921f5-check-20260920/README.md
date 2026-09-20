# Frozen MCP and ownership successor: retired-source deadline failure

Native macOS ARM64 / Rust 1.97.1 ran clean source `f2921f5` against the
38-gate / 225-mandatory-case plan. Sixteen gates passed. The seventeenth gate,
`server-retired-source`, passed its preparation-panic case but failed
`retired_registration_rejection_retains_new_owner_until_cancelled_waiter_drains`
with `deadline has elapsed`. The remaining 21 gates were not dispatched.
The original failing log does not identify the elapsed phase; a separately
retained diagnostic reproduction will establish that before correction.

Passing scope includes workspace all-targets/features compilation and formatting,
9 terminal SDK ownership tests, 60 upstream SDK protocol tests, all 11 MCP
response-fencing cases, the owned engine fence and three adapter/native response
cases, 154 store library tests, strict store lint, 23 serving library tests,
six engine worker outcome tests, five Control genesis tests and all six serving
owner fixtures. The two ignored store entries remain the live MinIO case and
subprocess helper exercised by its passing parent. Full workspace tests and
strict workspace lint were not run by this scoped plan.

All 17 dispatched process groups drained without survivors or cleanup errors.
The frozen source remained unchanged. Raw files were copied unchanged from
`/Users/mtakemiya/dev/kasumi-release-evidence/20260920-f2921f5-ownership-mcp`;
`copied-files.json` binds their exact bytes. Eleven preserved test executables
remain in that external directory; their hashes were independently rechecked
and recorded in `summary.json`.

The plan retains the original gates, cases and deadlines, adds SDK ownership
and upstream protocol gates, and corrects three added MCP module identifiers.
This is failed scoped evidence. Subsequent authority/proposal ownership changes,
the admitted redb and OpenRaft work, all final native/live/capacity/endurance
qualification and release acceptance remain open.
