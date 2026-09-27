# G09 other-leader inspection development checkpoint, 2026-09-27

This is local development evidence on changing source, **not an immutable
release or G09 qualification**. The earlier designated-leader checkpoint and
its hashes remain historical and are not relabeled for this source.

## Contract

The fresh read-only inspection has two independently verified observations:
the original designated node signs its exact accepted Initialize-to-Start local
association; the actual current leader corroborates the same committed first
fact through its own authenticated original Start and a current linearizable
quorum. The final status embeds the exact signed association. Control retains a
required association head and the precise causal phase/revision relationship.
Read routing keeps the identical request and absolute cap. Historical bytes
never create the original execution owner or renew Start/Initialize authority.

The original custodian must remain reachable to retrieve its fresh association.
Permanent loss before retrieval, OS process crashes, the broader phase-boundary
crash matrix, nine-process HA and immutable release qualification remain open.

## Executed results and retained failures

| Command | Observed result | Log |
| --- | --- | --- |
| `cargo check --locked -p kasumi-client` | exit 0, 7.71 s | [client-check.log](client-check.log) |
| `cargo check --locked -p kasumi-engine -p kasumi-client` | exit 0, 21.47 s | [engine-client-check.log](engine-client-check.log) |
| `cargo test --locked -p kasumi-engine --lib initial_membership_inspection_tests` | 9/9, 3.34 s | [inspection-reducer.log](inspection-reducer.log) |
| `cargo test --locked -p kasumi-engine --lib target_journal::open_tests` | 18/18, 3.29 s | [target-journal-final.log](target-journal-final.log) |
| `cargo check --locked -p kasumi-server` | exit 101: production backup opener used a test-only constructor | [default-server-backup-gap.log](default-server-backup-gap.log) |
| `cargo test --locked -p kasumi-server --lib three_runtime_nodes_inspect_expired_initialize_on_another_elected_leader -- --nocapture` | compiled, then SIGABRT worker stack overflow at about 16 s; no inspection result | [native-first-stack-overflow.log](native-first-stack-overflow.log) |
| `cargo check --locked -p kasumi-server` after the owner-bound opener and stack repair | exit 0, 11.76 s | [default-server-final-check.log](default-server-final-check.log) |
| Exact rebuilt server test executable, `runtime::lifecycle_tests::three_runtime_nodes_inspect_expired_initialize_on_another_elected_leader --exact --nocapture` | 1/1, 479.01 s | [native-other-leader-final.log](native-other-leader-final.log) |
| Same exact server test executable, `runtime::lifecycle_tests::three_runtime_nodes_resolve_lost_start_and_initialize_over_protected_tls --exact --nocapture` | 1/1, 75.92 s | [lost-start-initialize-final.log](lost-start-initialize-final.log) |

**29 distinct cases pass across four test commands.** The two native cases ran
the same exact server executable. The second case separately discards actual
successful Start and Initialize replies while retaining the original children,
resolves their exact separate accepted markers through protected status, and
rejects repeat execution. The engine reducer and journal executables are hashed
separately. Ten directly changed protocol/proof/runtime files pass scoped
`rustfmt --check`; `git diff --check` passes. These are focused checks, not a
workspace-wide release gate.

The first native source inventory is `source-before-native.sha256`; the reducer
and failed native executable hashes are retained separately. These hashes do
not describe later backup enrollment or stack repair source.

The final native command ran
`target/debug/deps/kasumi_server-cc7c9b9a2f2be7df` directly after the combined
server test build. Its SHA256 is retained in
`native-other-leader-final.binary.sha256`. The exact changed Rust files and build
manifests are retained in `source-before-native-retry.tar.gz`, with a 42-file
inventory and base commit `aa2343538c571d54d204ef479a3b0000ad5ff49f`.
The inventory verified before and after execution.

During execution, HEAD was changed externally to
`065e5719a693313275a7a6ccf31c4b58db9ee826`. All 42 captured files still matched;
all 39 non-documentation paths changed between those commits are covered by
the inventory. The observed transition is recorded separately and does not
turn this development binary into a qualified new-HEAD release artifact.

## Native result

At 209.49 seconds the fixture positively resolved inspection on actual elected
node 2, with the original node 1 association. It asserted an identical final
inspection request and absolute cap on routes 1 and 2, original credential
expiry, exact unchanged Start/Initialize records and causal identities, old
Weak-owner disappearance, no original Start owner on replacement children and
no membership/application proposal permission. It used real installed Control,
issuer, target journals, encrypted storage and pinned mutual TLS.

The same run continued through recovery Finished at 428.94 seconds, source
retirement, activation, routing and restored-document checks. All original nodes
were signaled together; sequential owner joins took 85.79 ms, 3.917 microseconds
and 1.125 microseconds. The fixture asserted actual owner disappearance and then
ordinary serving reopen with retained activation facts. The total test time was
479.01 seconds. These are controlled service/child shutdowns and reopens, not
OS process crashes or a nine-process deployment. The existing drain policy can
cancel and then join overdue TLS tasks; success does not claim universally
graceful TLS shutdown.

## Stack investigation and verified repair

The macOS crash report's triggered frames show a TLS certificate parse nested
under the exact Control authority read during Initialize. There is no repeated
recursive call cycle in that stack. The recorded debug disassembly allocates
`0xd4650` bytes for `perform`'s poll frame, `0x57e80` for `execute_owned`, and
further authority-read/transport frames on the same worker stack. The triggered
frames and selected disassembly are retained beside the failed log.

The new inspection proof construction/poll paths were split into separately
boxed helper methods so the Initialize frame does not retain their large
temporaries. A separate boxed dispatch constructor keeps the large future out
of its caller's poll frame, in the same admitted task and cancellation scope.
The normal Tokio worker stack size is preserved. Final debug disassembly shows
`perform_owned` at `0xb3a20` and `execute_owned` at `0x448d0`: together these two
frames use 213,472 fewer bytes (about 208 KiB). The final native run passes the
original failure point and the entire other-leader recovery path on that default
stack. Both before/after disassembly and the initial failure are retained.

## Installed backup boundary

The combined source also removes the production dependency on a test-only
filesystem destination constructor. Each canonical source node explicitly
enrolls its namespace using its real installed encrypted verifier. In this
shared-disk fixture, target materializers retain the original source namespace
opened with that source's real installed verifier. They do not reopen another
node's namespace using their own identity. This is not a distributed filesystem
or source-backup HA acceptance claim.

The ownerless local runtime fixture retains its runtime and key-rotation
coverage; actual installed standalone backup/verification is exercised by the
existing local recovery fixture. Noncanonical cluster scenarios finish before
backup operations and configure no filesystem destinations.
