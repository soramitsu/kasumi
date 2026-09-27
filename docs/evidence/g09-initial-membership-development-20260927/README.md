# G09 initial membership development checkpoint, 2026-09-27

This is a changing-source development checkpoint, **not a frozen cohort or
release qualification**. It uses the existing main checkout and warm default
Cargo target on native macOS ARM64, Rust `1.97.1 (8bab26f4f 2026-07-14)`.
The checkout started at `f7450a3af8026b7db324797af2d610c1da0711ba`; the working
tree includes the explicitly scoped test/audit fixes and parallel schema work.
`source.sha256` identifies the lifecycle and audit sources used by these runs.
It is not a signed artifact manifest or a complete frozen source inventory.
`Cargo.lock` SHA-256 is
`0e3d0606a21b7471003c0bc10101363392225095d486d5084e89c2d559954c17`.

## Verified commands

Commands run from the repository root; raw outputs are retained alongside this
record. All listed commands exited zero.

| Command | Result | Log |
| --- | --- | --- |
| `cargo test --locked -p kasumi-server --lib three_runtime_nodes_resolve_lost_start_and_initialize_over_protected_tls` | 1/1, 66.43 s | [lost Start/Initialize](lost-start-initialize.log) |
| `cargo test --locked -p kasumi-engine --lib target_journal::open_tests` | 18/18, 6.64 s | [journal](target-journal.log) |
| `cargo test --locked -p kasumi-engine --lib target_initial_intent` | 4/4, 0.12 s | [custody](initial-intent.log) |
| `cargo test --locked -p kasumi-server --lib audit_native_tls_fixed_history_and_original_authorization_release` | 1/1, 82.86 s | [audit TLS](audit-native-tls.log) |
| `cargo test --locked -p kasumi-engine --test schema_activation complete_schema_inventory_is_authorized_audited_and_never_truncated` | 1/1, 22.20 s | [complete schema inventory](complete-schema-inventory.log) |
| `cargo test --locked -p kasumi-server --lib native_schema_activation_is_atomic_scoped_permanent_and_private` | 1/1, 7.09 s after the assertion repair below | [native schema](native-schema-activation-repaired.log) |
| `cargo test --locked -p kasumi-server --lib three_runtime_nodes_replicate_with_control_quorum_over_audited_pinned_mtls -- --nocapture` | 1/1, 316.48 s | [full recovery](full-recovery.log) |

The server harness emits the existing Apple linker warning about the large
unwind table, and its vendored `rmcp` dependency emits three dead-code warnings.
Scoped Rust formatting and `git diff --check` pass.

## What the recovery test proves

The real installed three-node fixture uses Control, issuer and target native
services, encrypted materialization, pinned mutual TLS, and actual owned Raft
children. It discards a successful Start reply and then a successful Initialize
reply. Both deliberate failure hooks must have been consumed; an unrelated
error cannot stand in for the requested failure injection.

The protected status calls and coordinator continuation resolve the original
accepted phase/attempt for each step. Initialize has a separate marker and
custody association and preserves the Start prebind. Committed and applied
first-membership history is required. Weak database identities verify that the
Start continuation retains its actual child and Initialize plus its continuation
retain all three original children. These weak observations do not keep drained
children alive and prevent allocator reuse from concealing a replacement.

The test rejects a source credential, changed attempt, wrong status method,
replayed Execute and a resolved Control phase. It checks fresh Control reads at
admission and both response-release fences. The coordinator's current source
existing-attempt branch issues status only; it does not repeat BeginEffect or
Execute.

## Initial build repair and remaining work

The first current-source server test build failed before execution: the audit
CLI constructed the retired three-field cursor, while its native test indexed
typed audit records as JSON and constructed the same incomplete cursor. The CLI
now uses `SecurityAuditStatus::snapshot_cursor()`, retaining the archive root,
hot tail and complete current cursor contract. The test uses typed sequence
fields and copies the complete original snapshot anchors. The audit TLS test
above covers that repaired caller, including historical paging and retry.

The first separate native schema activation run failed **0/1** in 4.42 seconds:
its complete-inventory response correctly included the preexisting `docs`
collection, but its test compared that response to the two named collections.
The original failure is retained in [the native schema log](native-schema-activation.log).
The owning schema workstream corrected the assertion: All must contain exactly
`balances`, `docs` and `journal`, and the two Named definitions must match their
corresponding All rows. The repaired run is listed separately above.

The existing full coordinator fixture
`three_runtime_nodes_replicate_with_control_quorum_over_audited_pinned_mtls`
reached durable `Finished` at approximately 285 seconds and passed in 316.48
seconds. It proves Control member failover, all three materializations and
initialization, target quorum isolation and healing, completion, source fencing
and retirement, activation, all confirmations, and route publication. It checks
the restored document, rejects the original source context, drains original
facades, reopens from the original operator bootstrap, and verifies the retained
activation facts and replacement route. The existing fixture permits at most one
completed drain diagnostic for an abandoned call with the exact deadline error;
it forbids a retained owner. A pass is not evidence that no such diagnostic
occurred.

Temporary conservative UnknownOutcome replies during PrepareComplete/Complete
and authority waits resolved within the original 600-second recovery deadline.
They were not treated as absence, and the run was never restarted or interrupted.
While it remained live, a temporary test-utils-only diagnostic change was compiled
with `--no-run`; [that build log](recovery-diagnostics-build.log) is retained as
intermediate work, not functional evidence. The original run then passed, so
those now-unneeded diagnostic changes were removed exactly. Neither production
error responses nor authority was changed. The lifecycle/audit source hashes
were rechecked after that removal.

These passes do not prove process-crash recovery at every pending phase,
authority after an expired original initial phase, exact deletion, the required
separate nine-process HA topology, the segmented native KV release, live BPNG
deployment, or a frozen qualified Kasumi release. G09 remains open. Raw log
integrity is recorded in `logs.sha256`.
