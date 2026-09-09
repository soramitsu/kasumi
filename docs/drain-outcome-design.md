# Canonical drain outcomes

This source-only design starts from Kasumi
`7234f9a49cfd91e91f78d40efe96ea259ebc9527` (tree
`12f49d4a41392ccf8e13b0d48ab7130034f3eb2f`). Its leaf review was performed on
`635e330d4ed56021c2c966fd14cbb89fe5d56f85`; the reviewed leaf implementations are
unchanged in the starting revision. This is not runtime failure evidence.

## Source findings

| Owner | Concrete source behavior | Required distinction |
| --- | --- | --- |
| TenantStore | `crates/kasumi-store/src/lib.rs`, `TenantStore::shutdown`, awaits handles in place, then discards join results. | Requested abort is expected; a joined panic is a completed failure. A cancelled waiter leaves the handle installed. |
| SecurityAudit | `security_audit.rs`, `SecurityAudit::shutdown`, discards the archive worker's join result, then drains work and store. | Preserve a terminal worker failure while still draining every registration and store owner. `drain()` alone is not shutdown: admission remains open. |
| Security audit retention | `security_audit_retention.rs`, `start_worker` and `maintenance_inner`, turn blocking join failure into the ordinary maintenance-failure counter. A durable write failure also marks `sequence.failed`. | Retryable archive connectivity remains an operational error; blocking panic or permanent persistence failure requires retained terminal evidence. |
| Database | `service.rs`, `shutdown_inner`, discards seal-monitor/audit-worker joins and returns only the group result. `spawn_seal_monitor` uses `check.await.unwrap_or(false)`. | An outer Result alone cannot recover a blocking panic already converted to normal completion. WorkFence tracks resource lifetime, not outcome. |
| Tenant audit worker | `audit_maintenance_service.rs`, `maintain_tenant_audit`, flattens a blocking join failure into the same error path counted by the worker. | Separate terminal worker failure from ordinary archival/proposal errors without aborting uncertain publication. |
| RuntimeWorker | `runtime_worker.rs`, direct drain consumes JoinError; LiveTrustBackgroundWork implementation discards it. | Keep exact terminal evidence after the handle has been joined and removed. |
| Live signer trust | `live_trust.rs`, worker registry contains Weak references only; drained/dropped worker can disappear before verifier shutdown. | Keep bounded completion evidence separately from resource-bearing runtime owners; do not introduce a strong-reference cycle. |
| OpenRaft 0.9.25 | `raft/mod.rs:893–907` always returns Ok, despite `raft_inner.rs:227–250` retaining core failure. `core/tick.rs:129–148` takes the ticker join before the await in shutdown. | Core failure must be reported after joining. Ticker ownership must remain installed through a cancelled waiter. The ticker owns a notification sender, not a proven TenantStore owner. |

OpenRaft is pinned by lockfile checksum
`a97014fb78acb77be3a40ac2da305f6dd3a6b243f3a908ace87d29b3972eaafd`.
Reviewed source SHA-256 values: `raft/mod.rs`
`2efdb0cde8f4f0f38acd76efdb93efff0f39419180ca05f0592e945ee8579c23`,
`raft/raft_inner.rs`
`b37263518c95ccf2e8660676b7e114ca7a16e4e9b0f201130c5dfdcfdb771fe8`,
`core/tick.rs`
`767b5df3e865b315c7bdcfb1ef271d5879647a16e758f0aeaf3f2212c7596671`.
The OpenRaft patch is a separate owned workstream. Its intended shutdown returns
`Result<(), Fatal<NodeId>>` only after retained core and ticker joins. Kasumi must
still wait for its separately tracked storage and blocking-job owners before
classifying a resulting error as completed.

## Contract

The canonical internal cross-crate API is `DrainResult = Result<(), DrainFailure>`.
`Ok(())` proves all owners in the operation's closed admission scope drained and
there is no retained terminal failure. An error carries `DrainCompletion`:

- `Complete`: the exact owned handles/resources actually drained, but their work
  failed. Return this failure without retrying a completed shutdown forever.
- `Retained`: some ownership remains, or completion cannot yet be established.
  Keep that exact owner and retry its idempotent drain. Never reopen or reacquire
  a different resource as part of retry.

`DrainIssue` retains the original error source in a stable Arc. A joined Tokio
JoinError must remain downcastable; replacing it with a message is insufficient.
An owner-held `DrainReport` retains its first observed issue across cancellation
and repeated drains. Repeated observations of one failed owner reuse the same
issue identity. Aggregation never appends another equivalent issue on every retry.
The report is bounded by the owned component inventory, not process lifetime.

Completion is a separate fact from retained error evidence. Empty error state,
an absent handle without established join completion, or an opaque legacy error
is never proof of completion. Each parent drains its complete inventory even when
one child fails. It records the child's issue before awaiting another child.

`startup_owner::Runtime::close` changes directly to this result. `finish` retries
only Retained errors, retaining their issues. Complete failure returns once.
Cold initialization's synchronous default `handoff(&mut self) -> anyhow::Result<()>`
and its TenantEnrollment selector remain intact: a handoff error keeps the actual
runtime in the acknowledged ticket for its retained cleanup task.

Existing opaque shutdown adapters initially classify errors as Retained unless
source inspection establishes the complete closed inventory already drained.
They persist diagnostics at the adapter owner, including when a later call returns
success. No compatibility shutdown overload or unit-returning forwarding wrapper
will be added. Leaf APIs can then change directly with their real callers.

## Implementation chunks and test matrix

| Chunk | Positive and failure gates |
| --- | --- |
| Shared types/report | Original error downcast survives cloning; one issue remains one issue through repeated merge; independent owners retain independent causes; completion is explicit. |
| Startup owner | A real joined task panic returns Complete and causes exactly one cleanup attempt; Retained then Complete keeps the first error; cancelling a drain after one failed owner joins and while another remains paused preserves both evidence and exact remaining handle. |
| Resources/adapters | All owners are attempted; diagnostics survive cancellation before the next await; retained failure never releases the owner; completed failure returns without an endless retry. Preserve existing buffered-ticket cancellation and handoff-rejection regressions. |
| TenantStore/SecurityAudit | Requested abort is accepted; actual panic is reported; two-handle cancellation retains first panic; archive outages preserve hot history and retry semantics; real file reopen waits for all store ownership. |
| Database/blocking work | Inner blocking panic is retained even when the outer monitor is cancelled; registered work drains before file reuse; maintenance failure does not change committed writes or uncertain archive publication. |
| LiveTrust | Dropped resource-bearing worker retains terminal completion evidence; cancelled drain and multiple workers preserve outcomes without an Arc cycle. |
| OpenRaft integration | Cancel after core completion while ticker remains paused; retry still joins exact ticker. Normal stop succeeds; core/storage fatal and panic report only after core, ticker and Kasumi storage owners drain. |

All tests in this matrix are required work, not pass claims. No Cargo, native,
container, VM or platform gate has run for this design. Panic reporting presumes
unwinding execution; process abort or termination requires separate crash/restart
evidence. The first chunk does not claim to repair the unchanged leaf suppressions.
