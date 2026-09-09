# Typed store and service drain outcomes

This source-only checkpoint starts at `b02c60ff62d3002f1379c38477aaa9c17f045013`
and includes startup acquisition retention `9bc7854f9d170bfa16a675635cd2f1f5653bf2d2`
as local cherry-pick `1c6127c`. The latter is already in the integration branch
and must not be applied a second time. No Cargo, native, VM or container gate has
run for this patch. Direct Rust 1.97.1 rustfmt and whitespace inspection are the
only completed checks.

## Implemented ownership boundary

TenantStore stops its two lease workers cooperatively, including dormant catalog
handoff, timers and provider refresh waits. Explicit shutdown never aborts them.
Every actual JoinError is therefore a terminal failure, including an abort that
another actor requested before shutdown. Handles remain installed through a
cancelled join; their first errors stay in the owner-held DrainReport. Completion
is returned only after every handle joins. Caller-owned store/node references
must still drop before reopening the physical database.

TenantStorageSet now has one canonical shutdown for an owned application/custody
pair. Its report persists the first domain's outcome before awaiting the other.
Provisional existing-catalog acquisition retains its New/Borrowed distinction and
never closes a borrowed serving domain. Registered initializer tasks propagate
drain errors and retain both opening and drain objects with typed error context.

SecurityAudit retains every admitted async job in an owned registry. Admission,
finished-handle reaping and the shutdown census share the registry lock. Cancelling
a record, maintenance, verification or export caller drops only its reply waiter.
Actual job handles remain until joined; queued blocking record work keeps its
supervisor after caller cancellation. Each registry entry charges 4096 bytes to
the node governor until reaped. The separately reserved automatic maintenance
worker does not depend on a fresh registry reservation. Terminal join/persistence
failures close admission and retain original error objects. Ordinary archive
connectivity/publication errors remain retryable and never authorize pruning.
Already admitted maintenance waiters reuse the first terminal issue instead of
dispatching further work after that failure.

Audit shutdown joins its automatic worker, admitted job registry and work fence,
then the store; only a completed inventory releases the maintenance reservation.
Repeated shutdown returns the same Arc issue identities. Request result delivery
and task joining are separate: ordinary request validation/connectivity errors go
to their reply channel; terminal worker/persistence errors remain in the owner
even when that reply is abandoned.

## Canonical signatures and integration

These APIs now return `kasumi_types::drain::DrainResult` directly:

- TenantStore::shutdown and TenantStorageSet::shutdown.
- SecurityAudit::shutdown, Database::shutdown, RetiredCustody::shutdown.
- TargetJournal::shutdown, TargetReplica::close, TargetServingReplica::close.
- InstalledSignerVerifier::shutdown and Administration::shutdown.
- TargetRecoveryRuntime::shutdown, Generation::close and shutdown_target.

Database::detach_retired_custody retains its typed business result and propagates
the drain cause. Parent reports merge child issues before another await. Target
replica wrappers mark closed/release their registration after a Complete failure,
while their database retains the original issues for repeated calls. Generation
keeps failed routing identities until detach succeeds, and never releases its
physical node while any child reports Retained. Administration continues its
complete inventory after a child failure. Opaque Raft/lease/phase errors remain
Retained until the same owner establishes completion; joined RuntimeWorker errors
at TargetRecoveryRuntime's boundary are recorded before its next await.

Root owns the remaining NodeRuntime/AuthorityRuntime adapter reconciliation.
Their shutdown methods, serve cleanup, fixture callers and startup Runtime impls
are deliberately not changed here. The integration branch's newer data-node
enrollment Resources patch replaces that file's older direct cleanup calls; it
is not duplicated in this worktree. The canonical missing ReadableTable import
fix `198bb6ca8986073ecdeebb2a749b16f4ebd75027` also remains a root integration input.
The isolated checkpoint therefore is not a claim that all workspace callers
type-check before those explicitly owned integration changes land.

## Remaining structural work

- Database still suppresses its seal-monitor/audit-worker joins and inner blocking
  monitor/maintenance failures. This patch propagates store/audit failures; it
  does not invent outcomes the unchanged leaves already discarded.
- LiveTrustBackgroundWork still returns unit and its Weak registry can lose a
  dropped worker's completion evidence. InstalledSignerVerifier's typed store
  forwarding does not solve that separate worker-ownership contract.
- Kasumi's installed OpenRaft 0.9.25 still needs the separately reviewed retained
  core/ticker shutdown patch and dependency qualification. Typed wrappers alone
  cannot establish an ownership promise the installed dependency does not provide.
- Target replica Drop remains a best-effort detached close with error logging,
  not an independently joinable abandoned-owner registry. Explicit close is the
  ownership boundary covered here.
- StopLocal deletion, phase replacement and expired-generation collection remain
  fail-closed on a Complete worker failure. Durable resolution/reporting of that
  failure before forward cleanup or reopening is required lifecycle work. This
  checkpoint does not claim full forward recovery or physical cleanup completion.
- Older acquisition helpers that combine an opening error with formatted drain
  context retain the original opening object but can lose the second drain's
  typed issues after Resources drops. The new store cleanup paths use typed
  context; an aggregate original-error contract for those older helpers remains.

## Regression sources, all UNRUN

- `dormant_store_workers_stop_cooperatively_and_external_abort_is_reported`
- `cancelled_store_drain_retains_joined_panic_and_pending_physical_owner`
- `cancelled_record_and_drain_retain_actual_blocking_panic_before_physical_reopen`
- `cancelled_maintenance_retains_publication_panic_and_unpruned_history`

The first two use actual Tokio workers, distinguish cooperative stop from an
external abort, retain the original JoinError across cancelled/repeated drains,
and reopen the real encrypted catalog after the pending physical owner releases.
The audit tests cancel actual record_transport/maintain callers, inject real
blocking-record or archive-publication task panics, cancel a shutdown waiter,
check stable error identity, and reopen the physical database to verify no record
or hot-history loss. They are controlled fault tests, not process-crash evidence.
Existing shutdown/retention fixtures now inspect their typed results. Combined
compiler, formatting gate, strict Clippy, regression execution and platform/release
gates remain required; no release readiness is asserted.
