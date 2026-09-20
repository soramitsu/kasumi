# Frozen ownership successor: compiler failure

The clean `e9f39b2` source ran the retained 31-gate / 141-mandatory-case plan on
native macOS ARM64 with Rust 1.97.1. The first workspace all-targets/features
compilation gate failed after 154.208 seconds. All 30 subsequent gates remained
unrun; no ownership test or final acceptance gate passed in this attempt.

The diagnostic is an ambiguous `Result` alias in
`crates/kasumi-server/src/local_recovery_tests.rs:28`, introduced in the earlier
local cleanup synchronization fixture. Its imported `anyhow::Result` and
`kasumi_types::Result` conflict. The correction explicitly selects
`anyhow::Result<()>`; it must be qualified on a new frozen source.

This source includes the private installation directory repair for both serving
ownership fixture constructors. Production permission checks are unchanged.
Pending MCP/auth and owned response-fence work is excluded from this source.

The dispatched process group drained without survivors or cleanup errors, and
source comparison remained unchanged. Original raw files are copied unchanged
from `/Users/mtakemiya/dev/kasumi-release-evidence/20260920-e9f39b2-ownership`;
`copied-files.json` binds their bytes. Exact source/tree, commands, deadlines,
compiler/tool hashes and lockfile identity remain in `evidence.json` and the plan.
No failed attempt or original gate was removed to obtain a passing successor.
