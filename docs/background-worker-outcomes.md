# Background worker terminal outcomes

This first-release API replaces `LiveTrustBackgroundWork` with a concrete
`BackgroundWork` control/completion cell. A cell contains admission flags,
notifications, bounded outcome slots and a node-memory charge. Its typed fields
have no task closure, storage, verifier persistence, runtime or administrator
back-reference. Original opaque error payloads are a separate limitation below.

The process-local custody inventory owns exactly one actual child JoinHandle per
registration. There is no supervisor or helper task. A drain awaits the exact child
in place and publishes completion synchronously after its actual join, preserving
the original JoinError in one stable DrainIssue. Concurrent and repeated drain
calls return clones of that same issue. Cancelling or aborting a drain waiter
leaves the original handle installed and cannot erase an earlier failure.

Nonblocking observation and registry reaping first try to acquire the child's join
mutex. Contention never replaces an active drain waiter's waker. Only an already
finished child is polled once; an unexpected Pending result leaves it installed.
No terminal outcome is inferred from an is_finished flag. Missing or unjoinable
custody remains explicitly Retained and cannot authorize cache reuse.

Finished children remain enumerable until a drain or reaping operation actually
observes their join. Successful observations then release custody immediately.
Failed observations retain their outcome entry until a drain synchronously reports
the error. This prevents an unobserved failure from disappearing when every public
facade drops. There is no automatic orphan-drain or busy retry task.
`pending_background_custody(after, limit)` returns bounded, ordered pages of local
cells; draining one resumes its join or reports its completed original outcome.
The ordered custody map seeks directly beyond the cursor and visits at most the
requested 1–256 entries. These IDs and cells are process-local inventory, never
wire authority, durable evidence, or a remote management API.

Live signer trust strongly retains cells. Registration, successful reaping and
close share its state mutex; only a concrete future enters the API, and rejected
admission never spawns or polls it. Successful churn reuses registry capacity.
Failed or unjoined cells cannot be reaped as successes. A subsequent
registration observes the failure, retains its report, closes admission and wakes
the admitted workers. A child failure does not synchronously close its enclosing
trust: sealing currently occurs when a subsequent registration observes failure,
or when an owner explicitly closes/drains. All admitted workers must still drain,
including after an earlier failure or cancellation.

The store cache retains a `BackgroundWorkScope` alongside its weak verifier
pointer. The scope shares logical state and completion metadata without typed
persistence, clock, administrator or runtime references. Dropping the verifier
closes its scope. Reopening checks this retained scope even when the weak pointer
has expired: every child must have joined, and any failure must have been reported
through drain. Replacing the cache cannot silently erase an unobserved failure.

## Capacity and configuration

`SignerVerifierConfig.max_background_workers` is a required positive operational
capacity per domain. It is separate from immutable verifier identity. Before
opening verifier storage, startup uses the node's shared admission owner to reserve:

```
domain_count * (max_background_workers * 16384 + 135168) bytes
```

The per-domain 135168 bytes include four times the bounded 32 KiB logical trust
record and 4096 bytes of registry overhead. All arithmetic is checked. The complete
configured domain set participates in the reservation. Registry slots, actual child
custody, and completion cells retain the shared charge through actual cleanup and
reporting. The installer calls `Reservation::retain(bytes)` before sharing this
static charge: bytes remain reserved, while the in-flight operation slot is
released. Idle installed metadata does not consume request-operation capacity.
Cells still held by their callers continue occupying a registration slot even after success; successful registry reaping
alone does not discard a caller's metadata charge. Failed admission spawns nothing.
These are workspace estimates, including child and join bookkeeping, alongside
sampled RSS; opaque panic payloads and task allocations are not exact allocator accounting.

`InitializeSignerVerifier` additionally requires explicit `admission` settings.
Ordinary data/Control and authority runtimes share their configured NodeAdmission
with verifier and audit work. The single target reconciliation monitor reserves
its one worker slot against that same node admission owner.

## Retained panic payload limitation

Preserving an original `JoinError` also preserves its opaque panic payload. An
arbitrary `panic_any(Arc<Runtime>)` can therefore retain a resource owner through a
report and can create a cycle back to the cell or logical trust scope. The concrete
registry avoids a built-in cell-to-task/runtime cycle, but it does not prove that
arbitrary panic payloads are resource-free. Its completed outcome establishes the
exact child join, not physical release of objects embedded in that payload.

This is a deliberate diagnostic contract at this checkpoint. Errors are not
silently stringified or discarded. Terminal panic normalization or separate
diagnostic custody across affected components remains an open requirement before
the broad panic-safe release gate; arbitrary-payload physical reopen is unproven.

## Source validation and integration

Only direct Rust 1.97.1 formatting and Git whitespace checks have run. Compiler,
Clippy, all new tests and native process fixtures remain unrun.

New regression sources cover original panic/cancel JoinError identity, concurrent
and cancelled joins, aborted drain waiters, completed-but-unobserved children,
retained orphan custody and memory charges, bounded successful churn,
closed/capacity rejection before task polling, dropped resource owners without a registry cycle, closed-cache joining,
unreported failures after facade drop, and reservation rejection before storage
open. Existing native signer renewal cancellation/reopen assertions are preserved
and migrated to the concrete API.

New tests, all unrun:

- `closing_cannot_cross_an_admitted_but_not_yet_spawned_worker`
- `repeated_and_concurrent_drains_preserve_original_join_error`
- `actual_child_abort_keeps_its_original_cancelled_join_error`
- `cancelled_drain_retains_exact_child_and_charge_after_all_facades_drop`
- `finished_child_remains_in_custody_until_actual_join_observation`
- `never_started_close_is_terminal_and_cannot_later_spawn`
- `nonblocking_observation_preserves_the_active_join_waiter`
- `shared_capacity_rejection_never_spawns_and_completed_cells_keep_their_charge`
- `live_close_waits_for_actual_worker_registration_publication`
- `close_and_capacity_reject_unpolled_work_and_success_churn_is_bounded`
- `cancelled_multiworker_drain_keeps_original_failure_and_seals_registration`
- `resource_owner_drops_after_actual_join_without_a_registry_cycle`
- `dropped_closed_verifier_keeps_cache_fence_until_actual_background_join`
- `failed_worker_outcome_survives_facade_drop_and_blocks_silent_cache_replacement`
- `complete_domain_worker_budget_is_reserved_before_verifier_storage_open`

Integration requires root's shared-admission changes in NodeRuntime and
AuthorityRuntime: the final SignerVerifierConfig::open argument is the same
Arc<NodeAdmission> used by that runtime. Authority configuration and enrollment use
the required admission field. RuntimeLease::shutdown returns DrainResult; callers
must preserve Complete versus Retained while collecting their other owners.

The local lease/phase, target-generation and administration adapters merge these
typed outcomes before awaiting later owners. Target monitor reservation occurs
before journal storage opens; registration rejection drains the actual unpublished
target runtime and preserves both registration and drain failures.

The pre-existing authority-enrollment detached outer task and verifier initializer
still need their separate panic/cancellation ownership hardening. This checkpoint
does not claim to repair those outer acquisition boundaries, introduce catalog
deletion/replacement, or complete the production release execution gates.
