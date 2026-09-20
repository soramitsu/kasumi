# Retired-source startup ownership

`runtime::open_retired_source` now puts each newly returned `RetiredCustody` in
an external preparation inventory before looking up its Raft handle or registering
its peer route. Both replicated and local transport preparation run inside the
existing unwind-capture boundary. A failed registration or preparation panic
finishes that inventory before returning its original error. A `Retained` child
outcome keeps the exact custody owner in the inventory and retries cleanup; it
cannot authorize an early return to a caller that selects `RecoveringControl`.
A completed drain failure remains an actual typed `DrainFailure` context, retaining
its original `Arc<DrainIssue>` values alongside the original preparation error.

The inventory contains only the newly acquired custody service. It does not own
the borrowed audit service, node, cluster network, or any existing resident route.
Failed registration never unregisters the occupied route. Successful preparation
transfers the actual custody `Arc` to the caller and leaves it running.

This private helper requires an already retained caller task. Its current callers
are the data startup task, the serving maintenance task running administration
reconciliation, and the target serving monitor. Those parents must join their
current operation before closing resident storage; cancelling a reply or a drain
waiter must not abort the actual preparation task. No nested Data startup registry
is introduced, avoiding a parent drain that holds the registry while its child
tries to register there.

This patch alone does **not** establish that cancelling the entire consuming
`NodeRuntime::serve` future retains its local runtime/JoinSets. That separate root
integration gap requires the retained outer-serving owner. The target caller also
depends on its concrete retained worker protocol. Unwind capture is not protection
against arbitrary task abortion, process abort, destructor panic or cleanup panic.
Partial owners inside `RetiredCustody::open_replicated` that have not returned to
this helper remain a separate lower-level constructor ownership scope.

Two new source regressions are **UNRUN**:

- `retired_registration_rejection_retains_new_owner_until_cancelled_waiter_drains`
  creates three encrypted replicas with the canonical explicit Application
  bootstrap, commits a real encrypted backup and source retirement, detaches the
  source's custody, and attempts a real `ClusterNetwork::register_group` against
  an occupied route. An actual core callback holds shutdown pending. The test
  abandons the public startup reply and first drain waiter, verifies the new owner
  remains alive, releases the callback, joins the original registration error,
  and strictly reopens the installed encrypted custody. The distinct resident
  database, its existing route and the shared audit store remain available.
- `retired_preparation_panic_drains_only_new_custody_owner` uses the same actual
  retirement fixture and injects a panic immediately after the returned custody
  owner enters the inventory. The original typed preparation panic must return
  only after its custody store closes, while resident and audit owners stay live.

The fixture uses test-only local wrapping and in-process consensus transport. Its
cluster registration has TLS identity/pin configuration, but it does not establish
TLS process coverage, live authority admission or a production deployment gate.
The held callback has an explicit failure timeout and a guard that releases it on
test failure; a timeout is never treated as successful cleanup. The second test
uses no fault in the cleanup implementation. Neither test injects a typed Retained
leaf failure, and no Rust compilation or runtime test has run for this patch.
Pinned Rust 1.97.1 direct formatting and whitespace checks are the only local gates.
