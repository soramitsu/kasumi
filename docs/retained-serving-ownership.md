# Retained serving ownership — source checkpoint

This patch is based on `d4a5e52` in the Kasumi integration repository. It changes
only the serving/listener ownership boundary and one synchronous authority gate.
It is a first-release replacement: there are no compatibility wrappers or aliases.
All Rust compilation, Clippy, native execution and tests described here are UNRUN.
Direct Rust 1.97.1 rustfmt parsing/formatting and `git diff --check` are the source
checks for this checkpoint; these are not compilation or functional evidence.

## Actual owner and acknowledged result

`NodeRuntime::serve` and `AuthorityRuntime::serve` are synchronous constructors of
a `Send + 'static` result future. Before that future exists, the process registry
retains both a supervisor JoinHandle and a separate `Arc` containing the actual
boxed runtime-plus-task inventory. Dropping an unpolled future signals shutdown.
Dropping a polled future, or aborting a task awaiting it, cannot drop the runtime.
The supervisor runs with a mutable borrow of that inventory. Preparation capture
covers polling unwinds of the serving phase and each drain attempt; owners are
outside both caught futures. A drain panic is a stable retained issue and is
retried with a 1-to-30-second backoff. A typed Complete failure ends cleanup while
preserving its original issue objects; an opaque failure never proves completion.

A waiter acknowledges the result only after joining the exact supervisor. The
registry retains unacknowledged outcomes and their metadata charge. The explicit
`NodeRuntime::drain_serving` and `AuthorityRuntime::drain_serving` methods stop and
join their process-kind inventories after the operator stops admitting new
instances. Cancelling a drain preserves each unfinished handle and each observed
error. Tests use a private registry or an exact database-ID selector so they never
stop other test instances.

If the supervisor itself is aborted, the registry still has the actual composite.
A later waiter or explicit drain joins that original handle, records its actual
JoinError, and restarts cleanup only. If an owner destructor panics after the
inventory is taken but before completion is published, no owner can be proven
available. The registry records a stable unavailable-census issue and remains
pending. It does not respawn empty supervisors or declare completion.

Registration reserves 4096 bytes from the runtime's existing audit admission
governor before startup publication. `retain(4096)` releases the temporary
operation slot while retaining the complete metadata charge until acknowledgement
and supervisor join. This call depends on the concurrent canonical
`Reservation::retain` public visibility change owned by the worker/verifier patch;
this checkpoint deliberately does not duplicate its `admission.rs` edit.

The registry's admission fence is per immutable database identity and runtime kind.
Any prior unacknowledged serving owner, including a completed successful orphan
that has not been joined, blocks replacement of that identity. Other identities
remain available. Startup checks before publishing a new runtime; `serve` rechecks
under the registry insertion lock. A replacement already opened before the check
raced with a prior failure is retained and drained without polling its serving
phase. Its result preserves the original prior diagnostic object. Explicit
join/acknowledgement permits the next instance. These are process-local ownership
checks, not durable incarnation fencing or distributed recovery evidence.

## Listener, connection, and Hyper stream inventory

`tls::serve_tls` now constructs a concrete `ServingListener` future with a separate
`Arc<ListenerInventory>`. Runtime `ServingTasks::spawn_listener` retains this
inventory before dispatching the listener task. On shutdown it first joins its
installed maintenance/listener handles and then independently drains every nested
listener inventory. An external listener abort therefore cannot destroy the
nested connection census. A caught accept-loop polling panic, I/O error, or TLS
snapshot error reaches that same cleanup path.

Each listener owns separate bounded task sets for socket connections and Hyper
executor work. Hyper 1.11.1 from the pinned Cargo.lock dispatches `H2Stream` in
`src/proto/h2/server.rs:317` and `UpgradedSendStreamTask` for successful CONNECT at
line 510. The checked executor limit is twice `max_connections *
max_http2_streams`, covering both tasks during an upgrade transition. The reviewed
server/auto-builder production paths did not dispatch additional housekeeping
through this executor. HTTP/1 requests remain within their tracked connection
future. Application work detached by a handler is owned by that subsystem's
separate inventory and is not inferred joined from a socket.

Limits reject zero capacities/timeouts, `max_connections > Semaphore::MAX_PERMITS`,
and checked stream-budget multiplication overflow before constructing the
semaphore or accepting a socket. Completed successful task history is reaped;
the first terminal task failure seals that executor, bounding retained failures
by the concurrent installed inventory. Each actual JoinError is retained before
another await. Timeout cleanup records which still-running task IDs this owner
aborted and then joins them; completed external cancellations remain errors.
Admission and reaping use one mutex. Synchronous reaping uses Tokio 1.53.1
`try_join_next_with_id`, never `poll_join_next_with_id` with a noop waker, and a
sealed executor never reaps inside a late spawn callback. Active drains keep
their actual wakeup registration.

Authority serving cleanup closes admission and response release synchronously
through the same `IndependentAuthority::close_admission` used by its normal
shutdown. Node cleanup closes retained serving leases before listener draining.
Runtime resource shutdown still uses the existing typed adapters and their
existing unresolved opaque leaf boundaries.

## Added regression sources — all UNRUN

- `unpolled_serving_waiter_drop_retains_physical_owner_through_cancelled_drain`:
  real NodeStore, installation lock and held worker survive an unpolled waiter
  drop and a cancelled drain, then reopen exclusively after the exact join.
- `serving_poll_and_drain_panics_keep_actual_owner_and_original_failures`:
  actual run/drain polling panics, stable original payload objects, real physical
  owner retained until the held worker completes.
- `aborted_serving_supervisor_keeps_inventory_for_joined_cleanup_only`:
  actual supervisor abort, original JoinError/task identity and resumed cleanup.
- `unacknowledged_failure_fences_only_its_installation_and_drains_refused_replacement`:
  prior identity remains fenced, unrelated identity is admitted, raced replacement
  is physically drained without running, original diagnostic survives.
- `panicking_owner_destructor_retains_unavailable_census_without_respawn_churn`:
  actual destructor panic and repeated pending drains preserve a stable issue and
  never install another supervisor into the missing census.
- `serving_registration_retains_memory_without_an_inflight_operation_slot`:
  a one-operation governor can admit work while retaining the registry bytes.
- `actual_standalone_unpolled_serve_and_serving_panic_retain_installation_until_join`:
  an actually initialized standalone NodeRuntime, exact-instance drain,
  cancellation/panic, installation and encrypted file exclusion, then encrypted
  audit reopen and a new runtime open/shutdown.
- `aborted_listener_retains_http1_and_http2_requests_until_exact_nested_join`:
  real TLS requests retaining a physical NodeStore across listener abort and
  cancelled drain; both protocol cases require exact joined completion and reopen.
- `sealed_executor_late_spawn_preserves_the_actual_drain_waker`: a real retained
  task must wake its original drain after a late sealed executor submission.
- `unsupported_listener_capacity_returns_error_without_spawning_owners`: actual
  listener construction with oversized/overflowing limits returns a typed error
  and has no connection or stream tasks.

The first two pre-existing ServingTasks tests retain their direct JoinError and
physical-owner assertions. This patch does not weaken their outcome checks.

## Limits and integration work

Root must reconcile the authority admission configuration/open changes from
`ed0507a`, the separate worker/lease typed API patch, and its public
`Reservation::retain` visibility change. The obsolete two serve drain-to-anyhow
mapping hunks from `71fc4e3` are replaced by the new composite owner close path;
the NodeRuntime/AuthorityRuntime shutdown adapters themselves are unchanged.
Final combined compilation, strict Clippy, the complete tests, and production
builds without fixture features remain required.

A complete separate AuthorityRuntime real-TLS cancellation/panic fixture,
CONNECT upgrade task tests, deadlines under heavy concurrent renewal/reconcile,
and the full release cancellation/crash matrix are still required. This source
checkpoint is not a production-readiness result. The raw `ServingListener` helper
still requires its caller to retain the inventory separately before exposing an
abortable listener task; the production Node/Authority paths do so. Fixture/bench
raw helper callers are not granted that stronger outer-owner guarantee here.

Opaque panic payloads are a remaining cross-cutting release requirement. An
original JoinError or captured panic can contain `panic_any(Arc<Runtime>)` or
another resource-bearing value and can form a diagnostic-to-runtime cycle.
Preserving the original payload is intentional; this patch neither strips the
cause nor proves arbitrary payload disposal. Its Complete claims describe the
explicit registered task/resource census, not hidden resources inside arbitrary
panic objects. String-payload tests do not establish that broader cleanup claim.
Likewise, arbitrary destructor side effects, process abort, exhausted allocators,
and dropping the entire Tokio runtime are outside the proven in-process drain
contract. The retained registry allows later cleanup while an executor is alive;
it cannot make external detached work or opaque suppressed leaf errors complete.
