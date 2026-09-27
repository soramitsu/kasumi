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

## Results retained so far

| Command | Observed result | Log |
| --- | --- | --- |
| `cargo check --locked -p kasumi-client` | exit 0, 7.71 s | [client-check.log](client-check.log) |
| `cargo check --locked -p kasumi-engine -p kasumi-client` | exit 0, 21.47 s | [engine-client-check.log](engine-client-check.log) |
| `cargo test --locked -p kasumi-engine --lib initial_membership_inspection_tests` | 9/9, 3.34 s | [inspection-reducer.log](inspection-reducer.log) |
| `cargo check --locked -p kasumi-server` | exit 101: production backup opener used a test-only constructor | [default-server-backup-gap.log](default-server-backup-gap.log) |
| `cargo test --locked -p kasumi-server --lib three_runtime_nodes_inspect_expired_initialize_on_another_elected_leader -- --nocapture` | compiled, then SIGABRT worker stack overflow at about 16 s; no inspection result | [native-first-stack-overflow.log](native-first-stack-overflow.log) |

The first native source inventory is `source-before-native.sha256`; the reducer
and failed native executable hashes are retained separately. These hashes do
not describe later backup enrollment or stack repair source.

## Stack investigation and repair under verification

The macOS crash report's triggered frames show a TLS certificate parse nested
under the exact Control authority read during Initialize. There is no repeated
recursive call cycle in that stack. The recorded debug disassembly allocates
`0xd4650` bytes for `perform`'s poll frame, `0x57e80` for `execute_owned`, and
further authority-read/transport frames on the same worker stack. The triggered
frames and selected disassembly are retained beside the failed log.

The new inspection proof construction/poll paths were split into separately
boxed helper methods so the Initialize frame does not retain their large
temporaries. The normal Tokio worker stack size is preserved. A native rerun
is required to establish the repair and exercise other-leader inspection.

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
