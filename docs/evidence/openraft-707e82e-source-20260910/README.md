# OpenRaft shutdown interleavings: source only

The uninstalled upstream patch is frozen at
`707e82ea457e93d197dd4b98a70916c958a86420`, tree
`31a700dff2a78e0e11d14ae7587bbbb77272956c`. It includes the preceding `bed7bad`
shutdown changes and adds actual Tokio task regressions for cancellation after
core completion, both core/ticker failures, and a runtime-aborted core. The new
fixture invokes `Raft::shutdown` with controlled children; it does not instantiate
a consensus core or storage. The earlier actual-core integration tests remain.

All compilation and tests are **UNRUN**. Direct Rust 1.97.1 parsing/formatting and
whitespace checks are the only execution. Upstream nightly formatting options
were unavailable, so this is not a passing upstream formatting gate.

`patch.diff` preserves the complete patch against upstream `8815cdba` byte for
byte. `source-review.md` is copied from the frozen source and describes the exact
scope. `manifest.json` binds both files to their SHA-256 values. The original
`bed7bad` artifact remains unchanged. Kasumi's dependency and lockfile are unchanged;
upstream qualification and Kasumi's subordinate worker drain remain required.
