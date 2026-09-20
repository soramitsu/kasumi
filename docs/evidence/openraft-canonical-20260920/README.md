# OpenRaft custody source transferred to the canonical checkout

`vendor/openraft-0.9.25` preserves the official OpenRaft v0.9.25 workspace at
`8815cdba2826f74e848acef361ad03f93bb1c3f8`, its original licenses, and the retained
core/ticker, state-machine/snapshot, membership-observer and replication patches
through upstream checkpoint `169b2497f0f80c56817ea37ea6523f899d519167`.

The checkpoint archive/full patch/provenance and the exact then-uncommitted
leadership/vote collector patch were preserved here before copying the source.
Every transferred file matched the last historical source inventory. The transfer
receipt records those hashes. Historical attempts 24–29 are copied unchanged;
these are historical focused checks, not qualification of subsequently edited
source. Attempt 25 failed before execution because of an incorrect package name.

All subsequent edits and commands use `/Users/mtakemiya/dev/kasumi` on master.
The local runner requires that working directory, retains before/after vendor
source inventories and original logs, bounds each child process group to 1,200
seconds, and writes build output only under `target/openraft-qualification`.
Parent workspace source can be under independent development; these focused
upstream checks do not qualify a final Kasumi binary or release.

Root dependency integration must patch `openraft` to
`vendor/openraft-0.9.25/openraft` and exclude `vendor/openraft-0.9.25` from the
Kasumi workspace. Its upstream sibling macros and workspace manifest are retained.
Root Cargo manifests/lockfiles and Kasumi shutdown adapters are owned separately.

The collector checkpoint archive records the canonical implementation before the
separate incoming-stream change. Attempt 31 passed 90 integration cases (22
lifecycle, 13 client API, 41 membership, 14 snapshot-streaming); attempt 32 passed
210 feature-enabled unit tests; attempt 33 passed singlethreaded all-target
compilation. Attempt 34 retained a pre-existing redundant-wildcard Clippy failure.
Removing only that redundant pattern produced strict Clippy success in attempt 35.
Every successful canonical receipt has unchanged vendor input and a drained child
process group. Attempt 30 passed its four tests but the wrapper rejected one
fixture-generated log appearing in the source inventory; that original receipt
and generated log remain intact. Later attempts move generated fixture logs into
their own evidence directory before the after-source inventory.

The stable custody checkpoint is `custody-checkpoint.json` and the deterministic
`custody-source.tar`. Its delta applies after the retained `replication-full.patch`
against the official base; it is not a replacement for that earlier patch.
Attempts 46–49 all use source inventory
`70cce233f67865044d8550bd613c7696abfbe0b47f7fa0d436199a9a709bffa6`:

- 227 feature-enabled unit cases passed, including generic snapshot data.
- 91 integration cases passed: 23 lifecycle, 13 client API, 41 membership and 14 snapshot-streaming.
- Singlethreaded all-target compilation passed.
- Strict all-target Clippy with `-D warnings` passed.

Those final receipts preserve identical source bytes/modes and drained child
process groups. Eight incoming-owner regressions preserve held children, original
receive/close errors, failed ownership, cancellation and premature-transfer
rejection. A separate actual-constructor runtime-count regression proves initial
storage cancellation precedes every spawn. Full production-provider validation of
the integrated Kasumi SnapshotBufferOwner remains a separate gate.

Failure attempt 37 (moved notification sender during compilation) remains intact,
as do the earlier generated-log and strict-Clippy failures. Eleven upstream script
executable bits omitted by the initial copy were restored from the preserved
archive; `executable-mode-restoration.json` records each path. No source bytes
changed during that correction. Final inventories include modes.

The standalone upstream `Cargo.lock` is intentionally retained for reproducible
leaf checks, despite the upstream `.gitignore` rule. The root owner must explicitly
retain it when staging or packaging this vendor tree. The root Cargo manifest now
patches OpenRaft to this source; these leaf checks still do not qualify a final
Kasumi binary, every platform, external transport/storage worker, or the release.
