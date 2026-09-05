# Database shutdown and immediate reopen investigation

The fourth full-size matrix exposed an incomplete shutdown boundary. The
one-tenant replicated case loaded 1,000,000 exact 1 KiB documents, reached its
recovery phase, and failed opening the same durable file:

```text
opening durable database: Database already open. Cannot acquire lock.
```

The [retained run04 report](../benchmarks/results/release-matrix-macos-arm64-20260905-04/replicated-1.json)
also records a separate availability failure: balanced traffic completed 10 of
1,000 operations, then a read returned `UNAVAILABLE` after 5,001,772 microseconds;
989 operations were unattempted. Owned reads, shared reads, durable writes,
90/10 traffic, and the later indexed-equality workload each completed all 1,000
operations. The shutdown fix must not be described as proof that this read
deadline failure is resolved. See the [read-barrier investigation](read-barrier-investigation.md).

The preceding [run03 replicated result](../benchmarks/results/release-matrix-macos-arm64-20260905-03/replicated-1.json)
completed all six workloads and verified recovery. That earlier success does
not invalidate the later ownership failure or establish repeatability. Run04
was explicitly interrupted before the shutdown changes; its exact terminal
status and retained measurements are documented in [TERMINATION.md](../benchmarks/results/release-matrix-macos-arm64-20260905-04/TERMINATION.md).

## Ownership boundary and changes

Pinned OpenRaft 0.9.25's public shutdown can finish while its snapshot worker
still owns the state-machine backend and durable storage. Kasumi previously
treated that return as the end of storage ownership. Merely dropping the
benchmark's top-level handles or retrying an exclusive file lock would not
establish that all worker operations had finished.

The [Raft storage lifetime tracker](../crates/kasumi-raft/src/lifetime.rs) now
ties a drain lease to each actual storage/backend owner. Clones and blocking
jobs retain that lease, including when the async caller awaiting a blocking job
is canceled. Field destruction releases the resource before signaling that its
lease has drained. [RaftGroup shutdown](../crates/kasumi-raft/src/lib.rs) waits
for this ownership drain after upstream shutdown and before releasing the
tenant-group claim, including when upstream shutdown reports an error.

[TenantStore shutdown](../crates/kasumi-store/src/lib.rs) permanently seals
access, discards owned keys, and aborts and joins both key-lease tasks. Their
handles remain owned across cancellation of the shutdown future, so a later
caller can finish the join. Background registration and refresh cannot restart
a closed store.

The public [Database shutdown](../crates/kasumi-engine/src/service.rs) stops new
admission, cancels and drains tracked work, joins its seal monitor, drains Raft,
shuts down the key store, and releases resident generations and cursors. A
trusted embedding caller must still drop its own database/store/node handles
before reopening the same file. Previously returned plaintext documents remain
the caller's property; shutdown cannot recall them.

[Server lifecycle cleanup](../crates/kasumi-server/src/runtime.rs) separately
signals and joins listeners, allowing them to drain nested connection tasks.
It aborts and joins reconciliation before taking the final generation inventory,
then uses complete database/store shutdown. The same listener drain applies
during incomplete startup. The benchmark also uses complete database shutdown;
it adds no file-lock retry, failed-operation retry, or enlarged deadline.

## Focused evidence and limits

- The real Raft [snapshot shutdown regression](../crates/kasumi-raft/tests/shutdown.rs)
  pauses the snapshot callback, proves upstream shutdown has returned while
  Kasumi shutdown remains pending, and rejects a second group claiming that
  store. Releasing the callback allows immediate file reopen and recovery of
  the acknowledged value, without sleep or retry. The resource-drop ordering
  and canceled blocking-persistence ownership tests also pass in
  [the focused Raft log](../benchmarks/results/macos-validation-20260905-shutdown/1-test.log).
- [Store regressions](../crates/kasumi-store/src/tests.rs) hold a real background
  decrypt probe, cancel the first shutdown caller, then verify a subsequent
  shutdown joins the probe, releases the node, and permits immediate durable
  reopen. A second regression fences background registration racing shutdown.
  Both pass in [the store log](../benchmarks/results/macos-validation-20260905-shutdown/1-test.log).
- The [Database regression](../crates/kasumi-engine/tests/shutdown.rs) performs
  four immediate close/reopen rounds with batches and durable receipts, an
  active cursor, a triggered snapshot, concurrent shutdown callers, and a
  retained plaintext handle. It passes in [the engine log](../benchmarks/results/macos-validation-20260905-shutdown/1-test.log).
  The work-registration drain also has a separate regression.
- The server regression
  `startup_and_serving_drains_finish_live_tls_requests_before_reopening_node`
  passes in [its focused log](../benchmarks/results/macos-validation-20260905-shutdown/1-test.log), covering
  live TLS request ownership during startup and serving cleanup.
- The [embedded smoke result](../benchmarks/results/shutdown-lifecycle-smoke-macos-debug.json)
  completes raw/local/replicated/text modes with 100 exact 1 KiB documents,
  eight operations per workload, and 1/3 tenants. The
  [one-tenant](../benchmarks/results/network-shutdown-lifecycle-smoke-macos-debug-1.json)
  and [three-tenant network results](../benchmarks/results/network-shutdown-lifecycle-smoke-macos-debug-3.json)
  complete all native RPC/MCP workloads and clean server restarts with real
  OpenBao, TLS, and authentication. These are development smoke measurements.

These tests establish specific ownership and lifecycle behavior. They do not
prove that run04's precise background owner was uniquely identified, that its
quorum deadline miss is fixed, or that the million-document matrix now passes.
The implementation has concrete regressions reproducing the unsafe ownership
boundary; the refreshed macOS and Linux gates cover these corrections, while the
full-size matrix remains separate release evidence.

## Timing and preservation

The updated benchmark records `shutdown_seconds` separately from
`recovery_seconds`. Shutdown covers complete database closure/store release, or
SIGTERM through successful `kasumid` exit. Recovery starts afterward and covers
reopen/process spawn, key access, reconstruction, readiness, and a verified read
per tenant. Final cleanup is excluded. Earlier reports did not time shutdown;
their recovery timer also began after close and must not be relabeled as a
combined close/reopen measurement.

After-workload RSS, disk size and available process peak are now checkpointed
before closing. Successful shutdown is checkpointed before reopening, and
verified recovery before final cleanup. Failure retains those observations;
missing values remain null. The existing capacity reporter derives a partial
run04 report without modifying its raw data. The [capacity protocol](../benchmarks/CAPACITY.md)
defines the fields and their sampling limits. None of these documents declares
Kasumi v1 release validation complete.
