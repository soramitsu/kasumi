# Retained OpenRaft shutdown outcomes

This vendored source is based on upstream v0.9.25, commit
`8815cdba2826f74e848acef361ad03f93bb1c3f8`. The published crate checksum is
`a97014fb78acb77be3a40ac2da305f6dd3a6b243f3a908ace87d29b3972eaafd`.
It preserves and extends the retained source patch `707e82e`; the canonical Kasumi Cargo manifest patches OpenRaft to this workspace's
`openraft` package. Upstream license and copyright files are unchanged.

## Core and ticker contract

`Raft::shutdown` directly returns `Result<(), ShutdownError<NodeId, RuntimeJoinError>>`.
The core and ticker handles are joined in place. Cancelling any shutdown waiter
leaves its actual handle or completed outcome in the Raft owner. Both tasks join
before a failure returns. The core keeps its `Fatal` classification for ordinary
Raft APIs and independently retains the original runtime error in an `Arc`.
The ticker retains its original error in its own `Arc`. `core_join_error()` and
`ticker()` expose these shared errors without formatting or reconstruction.
Repeated observations preserve pointer identity even after earlier reports or a
calling Raft clone have been dropped. `Fatal::Cancelled` remains distinct from
normal `Fatal::Stopped`; a stored error never becomes success on retry.

`AsyncRuntime::JoinError` now requires `OptionalSync + 'static` in addition to its
existing bounds. Only TokioRuntime implements that trait in this source tree;
Tokio's original JoinError satisfies the bounds without a wrapper. There is no
compatibility shutdown alias. At least one Raft owner must remain alive through
the drain; this patch does not add process-global custody for dropping all owners.

The actual-task unit tests cover all four normal/panic core/ticker combinations,
cancellation of two waiters after the core joins while the ticker remains held,
actual core and ticker aborts, and repeated results. Tokio task IDs bind retained
errors to the exact spawned children; Arc pointer tests establish original error
identity and independent core/ticker allocations. Real consensus-core lifecycle
tests cover clean repeated shutdown, a core panic observed first by an ordinary
client API, and a later core panic after an abandoned shutdown waiter.

## State-machine and snapshot builder custody

A second ownership layer retains the state-machine worker and its current
snapshot builder in two fixed cells outside RaftCore. A successful previous
builder is joined before the slot can be reused; failures are retained permanently
and stop the worker. The core directly polls the worker's retained join cell as
part of its event loop, and the worker directly polls the snapshot child while
waiting for commands. No helper or reaper task is detached. An actual worker
panic now stops the core with Fatal::Panicked instead of leaving it running until
a request timeout reports Fatal::Stopped. Ordinary storage errors are retained as
the original Arc<StorageError>, and runtime errors as the original Arc<JoinError>.
ShutdownTaskError exposes both kinds without reconstructing them from text.

Shutdown joins core, ticker, worker and snapshot builder in that order, regardless
of earlier failures. Cancellation while joining any cell preserves the handle or
terminal result. Successful worker completion or a worker panic cannot discard a
held snapshot child. A child failure observed by the worker shares the same Arc
in both reports. The cells are fixed in count; existing command queues and
storage-owned allocations are not a completed resource-budget audit.

The four actual Worker/controlled-storage regressions cover cancelled and
concurrent drain waiters, worker panic and returned storage error, all six
normal/panicking-worker versus normal/panic/storage-failing-snapshot combinations,
live worker detection of snapshot failure, and 32 successive snapshots with a
maximum of one active builder and every actual builder dropped. The real consensus
lifecycle test now requires a worker panic to stop the core and repeated shutdown
to preserve the original worker JoinError.

## Replication streams and snapshot sender custody

`RaftInner` now owns a per-group replication registry. Each owner has exactly one
stream handle/outcome and one reusable snapshot-sender handle/outcome. Retiring a
stream closes its producer channel but never drops its handle or starts a join
helper. Snapshot cancellation is a request to stop; its real handle is still
joined before reuse or final shutdown. All original runtime/storage failures are
retained separately by stream and sender, identified by a non-reused owner ID and
peer ID in `ShutdownError::replications()`. The live core directly polls this
inventory and fences on an actual child failure even if no callback was sent.

`Config::max_retained_replication_owners` defaults to 128 and is validated in both
Config validation and Raft construction as 1..=4096. Active, retiring, pending
preparation and failed owners all consume the same limit. Each admitted owner
reserves both task cells before child creation; maximum task slots are twice the
configured owner count. The bounded vector's capacity is allocated at construction.
No unresolved or failed owner is evicted. Only joined successful children release
a slot; after the core joins, an unspawned preparation reservation can also clear.
Failures keep consuming capacity and remain failures on every shutdown retry.

New membership proposals preflight replacement headroom before appending their
entry (two generations for joint membership); initialization and campaigns also
check headroom. Excess work gets a typed TaskCapacity rejection or an election is
not started. Existing active streams remain intact when new topology is rejected,
and ordinary writes continue using them. A rebuild that cannot fit retains one
latest network intent with one inflight per target, closes new write/read admission,
and continues processing committed application/storage/protocol commands. It never
postpones a rebuild at the head of the engine command queue. A later completed
owner wakes the core to retry the pending replacement. New committed progress is
passed to replacement streams at construction. This is a conservative admission
policy; operators need room for active and replacing membership generations.

The four registry tests use real Tokio handles, held joins, original task IDs and
Arc identity, including independent stream/sender panic, runtime cancellation,
failed-capacity retention and 128 successful reuses of one slot. Three actual
cluster tests cover a held network call that panics after shutdown cancellation,
a snapshot sender panic without its normal callback stopping the live core, and
a rejected topology change while existing replication and committed writes still
progress. Fixture hooks resume an injected panic outside their own registry lock
so an intentional task panic does not poison unrelated test transport state.

## Validation record

The first targeted upstream-only run passed all five core/ticker unit tests.
The first integration invocation selected a nonexistent `tests` binary and failed
before execution; its receipt/log is retained. The corrected `life_cycle`
invocation passed all five t11_shutdown tests, including the real-core cases.
Its source inventory difference was exactly the fixture-generated
`tests/_log/ut.2026-09-20-05`, preserved under that attempt's generated-logs directory.

State-machine ownership tests initially failed to compile because the fixture
was outside the sealed storage trait's module; that failed attempt is preserved.
Moving the fixture into the storage test module fixed that without changing the
production sealing contract. The four new custody tests then passed. All 14
lifecycle tests, five snapshot-building tests, and the enabled state-machine test
passed; its separate pre-existing ignored test remains ignored, not a pass.

Attempt receipts, source inventories, the exact full patches, generated Cargo.lock,
compiler identity and stdout/stderr are retained outside the source checkout in
`../openraft-core-ticker-validation-20260920/`. The isolated target is
`../openraft-target-20260920/`; no Kasumi build was run for this patch. Further final
frozen-source checks are recorded there individually. These are focused macOS
ARM64 checks, not the entire upstream Makefile/feature/platform qualification.

The frozen replication checkpoint passed 206 feature-enabled unit tests, all 18
lifecycle, 41 membership and 14 snapshot-streaming integration tests, plus
all-target compilation with singlethreaded/serde/storage-v2/single-term-leader.
The initial new integration invocation used an incorrect package name and failed
before execution; that unchanged-source receipt is preserved as attempt 25.
Successful frozen checks are attempts 24, 26 and 27.

## Leadership-read, vote-round and conflict-response custody

The pending collector change retains one actual task per leadership check or vote
round. That task polls its peer RPC futures directly; there are no peer tasks to
detach on quorum completion, a higher vote, a timeout or a panic. Conflict response
delivery is synchronous in the owning core. A responder panic therefore belongs
to the core's original runtime error.

An outer fixed-capacity auxiliary registry survives caller and shutdown-waiter
cancellation. Active, retiring, unspawned and failed collectors share the configured
`max_retained_auxiliary_owners` limit (default 128; validated 2..=4096). Leadership
reads leave one slot for election work. New reads receive typed TaskCapacity;
elections preflight admission. Capacity exhaustion never stops committed storage
or application commands. Every actual collector is joined in place; original
failures remain in ShutdownError::auxiliary() with stable kind and owner ID.

Three actual-handle registry regressions passed before transfer to the canonical
checkout: independent read/vote panics through cancelled drains and reserved
capacity, runtime abort identity/live wakeup, and successful bounded slot reuse.
Four cluster regressions exercise actual leadership/vote network calls,
cancelled caller/shutdown, capacity pressure alongside committed writes, and
quorum completion dropping remaining peer futures in the same actual task. The
canonical collector checkpoint passed all four, 210 feature-enabled unit tests,
90 integration tests and singlethreaded all-target compilation. Strict Clippy
passed after removing one redundant upstream wildcard; its prior failure remains
recorded. These checks qualify that checkpoint only, not a complete release.

## Incoming snapshot and startup custody

An incoming `Streaming` stays in its Raft owner while closing for replacement,
final publication or shutdown. The snapshot data cannot be taken before close
succeeds; premature public transfer returns the same owner instead of unwinding. Cancellation leaves the data and any pending child in place. Original
receive and close I/O errors and their classified StorageErrors are separately
retained in Arcs, exposed through ShutdownError::incoming_snapshot(). Failed
streams cannot be overwritten. A poll unwind leaves an explicit poisoned-owner
marker; later drains retain that uncertain data without polling it again. The
actual RPC or shutdown task remains responsible for its original runtime panic.
A scope guard notifies the live core once on an incoming failure, including
unwinding; a failed RPC cannot leave the consensus core reporting healthy.

The data type's poll_shutdown must join its underlying children before returning;
Kasumi's SnapshotBufferOwner separately retains actual blocking jobs and original
runtime outcomes. Eight owner tests use the real Raft shutdown cell and actual
held I/O children to cover cancellation, independent errors, failed replacement,
final transfer and unwinding. These fixtures complete the core beforehand and do
not claim to exercise a full cluster's storage failure path. The existing full
lifecycle/client/membership/snapshot cohort passed after this change.

Raft construction now completes initial storage loading before spawning ticker,
worker or core. A cancellation regression polls the actual constructor into held
storage loading on an isolated runtime and checks the actual live-task count
before and after dropping it. No child can be detached at that await.

## Remaining resource census

This crate's explicitly spawned child families and incoming snapshot cell now
have retained custody. This still does not establish a complete Kasumi node drain.
Application/network/storage implementations can own additional workers and source
leases; Kasumi must drain those owners and retain all original failures before
installation-lock release or physical cleanup. G07 and full dependency/platform
qualification remain open. Canonical attempt receipts and exact checkpoint hashes
are under `docs/evidence/openraft-canonical-20260920` in the containing Kasumi tree.
