# Bounded SDK decoding: focused client checks

These are client-only checks on macOS ARM64 with Rust 1.97.1, one Cargo job and
one test thread. Both attempts retained clean, unchanged source. Exact commands,
tool/lock/source/executable hashes and process-group drains are recorded per
attempt. The shared host and reused compilation target are described in
`shared-host-scope.json`; these are not performance or final release gates.

| Check | `2b9061d` | `fb172be` |
|---|---|---|
| Snapshot parsing, framing, semantics and ownership | 13 passed, 39.114 s | 13 passed, 9.226 s |
| Bearer metadata redaction | 1 passed, 0.438 s | 1 passed, 0.401 s |
| Strict client Clippy, all targets/features | Failed, 23.792 s | Passed, 11.740 s |
| Client library, no default features | Not run | Passed, 18.592 s |

The first strict run found an import needed only in tests and two collapsible
conditionals. Successor `fb172be8137316b5bf59e2a64acfef97a9c3b786` changes those
three lint sites without warning suppression. Session 1904 exited 101; session
9240 exited 0. Every owned child process group drained.

The snapshot tests cover original response reservation ownership, cancellation
and panic during decoding, bounded error payloads, literal private-marker keys,
query document versions relative to collection epochs, framing and header
rejection, and approved retry error classification. The bearer test verifies
redacted debug output while preserving the actual authorization value.

These commands did not compile the engine, store, server or Raft crates and did
not exercise a listener, live native endpoint, MCP service or provider. Required
native pool, staged operations, local recovery, TLS, combined workspace and
production gates remain in `prepared-broader-gates-not-run.json`. The SDK branch
is combined with the shutdown/receipt work for further validation; it is not
integrated into the release branch as a validated implementation.

The separately prepared vendored JSON dependency correction was absent from
both attempts. Combined dependency/SDK behavior and other SDK decode boundaries
still require their own checks. SDK-accounted ownership does not claim a hard
RSS bound or include transport allocations made before its adapter.
