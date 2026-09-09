# Startup drain outcome ownership

This source correction starts from `e9c76e7`, which retains the cold startup
owner changes in `da4c8c3` and the prepared/borrowed existing-catalog protocol.
It does not establish complete worker, authority request, or physical storage
drain. All compiler, test and native gates remain unrun.

## Concrete review findings and this correction

In `da4c8c3`, `startup_owner.rs:135–148` popped a finished task and kept its
failure only in the drain future's local variable. With a failed last task and
another pending task, cancelling the drain discarded the only failure evidence;
the next drain could return success. The registry now stores the first unreported
failure alongside its handles. Drains await handles in place and remove only
terminal handles. Cancellation preserves both the remaining tasks and previously
joined failure. The failure is consumed only at a completed return with no yield.
Admission also reaps completed tasks through the same stored outcome.

In `da4c8c3`, `startup_owner.rs:100–105` treated a successful `send(Err(error))`
as observed failure delivery. A receiver cancelled while that error was buffered
lost the error and left an apparently successful registry task. Both successful
runtimes and failed opens now use the private acknowledgement ticket. Unclaimed
runtimes are closed and joined; unclaimed errors return through their registry
task. A claimed error is returned synchronously to its actual recipient.

`NodeStore::drain_initializers` had the same local-failure cancellation gap for
panicked catalog tasks. Its registry now retains unreported join failure across
cancellation. Both fresh initialization and existing-catalog admission use the
same reaper. This change does not alter prepared/borrowed store ownership or
authorize adoption of incomplete catalogs.

In `da4c8c3`, `administration.rs:2136–2174` ignored lease, database and retired
custody shutdown errors. Administration now returns its first reported error
after attempting its inventory; an owner-local mutex retains that error if a
caller cancels before the inventory finishes. Original generation handles stay
in their existing maps throughout the drain. NodeRuntime propagates that result
and retains observed failures across its own subsequent awaits. It marks itself
closed only after a complete attempt without a reported error, so a failed
attempt can retry these exact owners.

The initial NodeStopping audit is attempted once. A retry does not submit a new
event to the audit store that the previous attempt has already closed. If the
first audit await was cancelled before its outcome was observed, the next drain
reports that uncertainty. No timer, retry or closed-store error supplies a
successful audit outcome.

The existing `finish` task still retains its first drain failure even after a
later retry succeeds. It does not reopen files, acquire new credentials, or
replace a runtime. This correction preserves that contract; it does not interpret
suppressed failures from lower-level APIs as evidence of success.

The catalog outcome handoff was subsequently completed at the source level in
`docs/catalog-outcome-handoff.md`. Fresh and existing preparation failures now
use the same acknowledged ticket as successful owners. Unclaimed ordinary errors
return through registered `Result<()>` tasks and survive a cancelled node drain;
claimed errors are consumed synchronously by their actual recipient. This removes
former remaining item 5 without changing any public constructor contract. These
new regressions remain unrun.

## Remaining concrete structural work

1. **Return worker outcomes from leaf drains.** `TenantStore::shutdown`
   (`kasumi-store/src/lib.rs`) ignores background JoinErrors. SecurityAudit's
   shutdown ignores its archive-worker JoinError. Database shutdown ignores
   monitor/audit-worker joins. Change these drains to return a typed result that
   distinguishes a joined task failure from an incomplete drain, and retain
   already-observed failures in owner state across cancellation. Explicitly
   requested aborts may count as expected cancellation; task panic must not.
   Continue draining registered blocking work and all other owners before
   reporting a terminal failure.
2. **Propagate signer worker failures.** `RuntimeWorker` exposes a JoinError,
   but its `LiveTrustBackgroundWork::drain` implementation discards it and the
   trait returns `()`. Change the trait future to a typed drain result, propagate
   it through `LiveSignerTrust::drain_background_work`,
   `InstalledSignerVerifier::shutdown`, startup Resources, NodeRuntime and
   AuthorityRuntime. Retain each installed worker handle until its join ends;
   accumulate failure evidence in the owning verifier, not in an expendable
   waiting future.
3. **Expose actual Raft shutdown outcome.** Pinned OpenRaft 0.9.25
   `src/raft/mod.rs:893–907` always returns `Ok(())` after joining the core, even
   though `raft_inner.rs:227–252` records a panic/fatal result internally. Kasumi's
   RaftGroup and CustodyRaftGroup correctly wait their storage-drain counters,
   but merely propagating OpenRaft's public result cannot report that failure.
   A reviewed dependency API change should expose the stable terminal core and
   ticker join result, preserve ticker ownership if its drain is cancelled, and
   distinguish normal shutdown from panic/storage failure. Wrappers must retain
   this report after their storage counters reach zero. A typed drain completion
   with terminal failure is preferable to retrying an irrecoverably failed task
   forever.
4. **Drain admitted authority work, not only the proposal mutex.**
   `IndependentAuthority::shutdown` (`service.rs:720–723` in `da4c8c3`) closes
   the request semaphore and waits the proposal lock. `execute` admits a permit
   before awaiting the initial barrier and spawning an owned job; that job can
   still be before the proposal lock when shutdown acquires it. Signer/control
   observation fences can also retain authority owners outside the lock.
   Introduce an authority request tracker with atomic admission closure and
   explicit work registrations. Register before the first request await; move
   registration with detached jobs and any fence that retains live authority
   work. Shutdown must close admission, await those actual registrations without
   holding the proposal lock, and then drain Raft/storage. Test an admitted job
   paused before proposal-lock registration and a cancelled initiating request.


None of these APIs should use Arc counts to guess ownership or close borrowed
cached handles. Runtime/authority serving-loop cancellation and the ordering of
process-wide admission closure remain separate acceptance work.

## Verification

Source only. Rust 1.97.1 rustfmt parsed and formatted the touched sources; Git
whitespace checks passed. No Cargo, tests, native processes, Docker or VM ran.

New regression sources:

- `startup_owner::tests::cancelled_drain_preserves_joined_failure_before_another_pending_owner`
  consumes a failed task, polls the next pending handle, actually drops the drain
  future, and then requires the retried drain to return the original failure.
- `startup_owner::tests::buffered_failed_open_requires_an_actual_recipient_before_forgetting_its_error`
  abandons a buffered error ticket and separately checks acknowledged error
  delivery does not leave a duplicate registry failure.
- `storage_domains::catalog_initialization::tests::cancelled_catalog_drain_preserves_a_joined_panic_while_another_owner_waits`
  uses two real Tokio handles and an owned NodeStore; a joined task panic must
  survive dropping the drain while the second owner remains pending.
- `runtime::lifecycle_tests::failed_runtime_shutdown_retains_owner_and_retries_without_reopening_audit`
  opens a production-file-keyring standalone installation, seals its audit,
  requires shutdown failure and continued exclusive ownership, then retries
  shutdown without a fresh open before releasing the installation lock.

Run these together with all existing startup-owner/catalog ownership tests,
workspace compilation, strict Clippy and formatting. Follow with real TLS
authority/data lifecycle cancellation and injected worker failures only after
the remaining drain API work is complete. These source regressions are not
physical crash, filesystem durability, HA, or production release evidence.
