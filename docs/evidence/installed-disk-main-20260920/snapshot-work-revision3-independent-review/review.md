# Independent review: snapshot work foundation revision 3

Reviewed only the target proposal, its complete source copies/tests, and the
separate reservation cancellation retirement dependency. No source edits,
Rust compilation, Cargo invocation, or test execution were performed. Work stayed
in `/Users/mtakemiya/dev/kasumi` on `master`.

Reviewed foundation patch SHA256:
`3c9c8ed4acd39f9e2d8a9572baa3898f4c3fa34cef44335737d41e5a87d0e520`.
Dependency patch SHA256:
`c9c6d4ffd79170509130bb8a284db6888e0b2ed262b0dc6acf69a8618934ee8d`.

## Finding: P1 — Proxy wake can synchronously reenter an owner lock

**Location:** proposed `crates/kasumi-engine/src/admission/snapshot_work.rs`,
lines 145–152 and 411–447 (especially 420 and 434).

`Owner::poll_finish` holds the operation's `resource` mutex while invoking
`SnapshotOperation::poll_cleanup` and `poll_discard`. Those methods receive the
proxy `Context`. Calling `cx.waker().wake_by_ref()` from either poll method is
legal and synchronously enters `WorkWake::notify`, which takes the registered
external executor waker and immediately calls `waiter.wake()`.

Although `notify` releases its own **waiter** mutex before the callback, the
outer `resource` mutex remains held. An executor waker callback capturing the
public report and calling `report.completion()` takes `control` and then blocks
on that same `resource` mutex. The original cleanup poll cannot return until the
callback returns, so the operation deadlocks. `report.visit(...)` has the same
lock dependency. A similar issue is possible for wake activity under the
`control` lock during `poll_join`; the deterministic cleanup path is sufficient
to establish the bug without relying on Tokio's internal behavior.

The prepared `ReentrantWake::check_unlocked` test (test lines 720–726) checks
only `wake.waiter.try_lock()`. It does not challenge `resource` or `control`, so
it can pass while this deadlock remains. The fixture's current `poll_cleanup`
ignores its Context entirely (test line 149).

**Required correction:** separate proxy notification recording from external
executor callback dispatch while owner locks are held, and deliver a pending
notification only after the relevant owner locks have been released. Preserve
missed-wake avoidance and counted proxy ownership. Add a cleanup/discard fixture
that wakes its Context and an executor callback which safely inspects owner
completion. For a failure test that cannot hang the suite, first assert both
owner mutexes are available with `try_lock` in that callback. Also cover the
callback/panic and cancellation boundary through the deferred notification path.

This blocks integration of revision 3 as a reentrancy-safe foundation.

## Reviewed lifetime and safety boundaries without another concrete finding

- Each raw proxy Waker owns one Arc count. Clone increments once; consuming
  wake/drop reconstruct exactly that count into `OwnedWake`; borrowed wake uses
  `ManuallyDrop<Arc<_>>`. Callback unwind still drops the consuming `OwnedWake`,
  while borrowed unwind leaves the original count untouched. No public raw Arc
  or Weak path was found for the funded Owner/WorkWake allocations.
- Typed and erased Owner release paths both recover the sized owner through
  `Arc::into_inner`. The concrete value is moved out before its fields are
  destroyed; its last `OwnedWake` field retains the original charge through
  all earlier Owner fields. Outstanding proxy Wakers extend that same charge.
- `WorkWake` destroys its waiter before its final Reservation. The separate
  dependency drops the Charge (including its final cancellation Arc) under the
  memory-state lock before publishing bytes, operation credit or the free slot.
  QueryCancellation's concrete state contains atomics and no user destructor.
- Normal Complete failure retirement removes the core census reference, while
  report/work references still retain actual charge. The generation comparison
  prevents a stale report from removing a reused slot. Pending successful output
  stays Retained until claim or positive discard.
- `notify`, replaced-waiter release and `ClearWaiter` do destroy executor wakers
  outside the waiter mutex. This fixes that particular lock boundary, but does
  not address the owner-lock finding above.
- The allocator observer uses exact live allocation address ranges, forwards
  System allocation contracts unchanged, and uses atomics/yielding in dealloc.
  Its gate releases on unwind. No additional allocator recursion or pointer
  dereference defect was found statically.

These observations are static review, not a compilation, unsafe-code proof,
allocator qualification or execution of the twelve prepared tests. Production
snapshot adapters, admission/prepare fencing, shutdown integration, trusted
operation coefficients and Tokio/task allocator bounds remain explicitly open
as documented by the proposal. Arbitrary diagnostic/panic backing is likewise
not established as bounded by this foundation.
