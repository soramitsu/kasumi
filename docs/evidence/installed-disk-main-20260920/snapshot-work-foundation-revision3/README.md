# Snapshot work foundation, revision 3

TARGET ONLY, UNCOMPILED. No actual source edit or Rust build/test. The original revision-2 package foundation.patch 047dcc8abcff53eff8eee12d663ac9be41a66cedaa1902c7a6fb35e116a90f80 remains unchanged. This package replaces that foundation, not its public operation contract or the future production adapter.

## Stack and exact funding boundary

Apply the separate root-owned reservation-cancellation-retirement patch first. The manifest's before_sha256 is the source after that dependency; actual_before_dependency_sha256 also records current source. Its explicit dependency fixes the final cancellation Arc held in the core Charge: that backing is destroyed before its byte/slot credits are published. This package's admission.rs includes that already-applied dependency in its proposed hash, but foundation.patch does not repeat the dependency hunk.

The replacement foundation introduces private counted typed Owner and erased report/census handles. Every strong-release path invokes Arc::into_inner on the actual sized Owner. The erased trait's private Arc<Self> receiver dispatch restores the concrete type; no public Arc/Weak is exposed and no per-clone allocation is introduced. At the final count, Arc::into_inner frees the actual Arc backing before any contained field is destroyed.

Owner's final field is a counted wake handle. The one original operation Reservation now belongs to WorkWake, after its waiter. The same reservation therefore covers Owner resources until their real destruction and follows any outstanding proxy waker afterwards. Operation capacity remains occupied for that actual lifetime, including a proxy retained by an executor or a concurrent wake. The formula still sums actual arc_bytes<Owner<O>>, arc_bytes<WorkWake>, the concrete cancellation-state component, the existing named Tokio workspace estimate, and trusted O::backing_bytes. The concrete type-derived sizes account for changed handle layouts; the original max_inflight_operations and capacity policies remain unchanged. Fixed census layout cost remains type-derived in MemoryCore bookkeeping.

A private RawWaker vtable is necessary because the standard Arc<Wake> conversion would release the charge from inside the still-allocated final Arc payload. Each raw Waker owns one strong count; clone adds one, wake/drop consume one through OwnedWake, and wake_by_ref borrows via ManuallyDrop without consuming or adding a count. RAII retains correct consumed-count destruction through an executor callback panic. The raw pointer never escapes except as the standard private Waker payload. No unsafe API is public. No Weak exists for either funded owner allocation.

notify takes the current waiter under the mutex, then wakes outside it. Notifications coalesce until finish installs its next waiter before polling. finish clones executor wakers before locking and destroys replaced counts after unlocking; ClearWaiter takes the stored count and destroys it outside the waiter lock, before releasing the serialized finish guard. Thus wake/clone/drop callbacks do not run under the waiter mutex. Poison recovery preserves this same ordering.

ready now retires a Complete typed failure from the census after joining and positive cleanup. Successful unclaimed outputs remain Retained. Existing report views continue to own the original failure and charge; stale generation checks are unchanged. This removes the otherwise unnecessary core→owner→core cycle after a normally delivered Complete failure.

## Prepared tests

The original seven tests remain, with their workloads/assertions intact. Five additional tests cover:

1. Capacity-one Complete typed failure delivered through ready and failed claim, with original failure identity, no redundant drain, and subsequent admission.
2. Eight concurrent final report drops gated at the actual System.dealloc event for the Owner Arc. While allocation destruction is paused, the operation payload is undestroyed and byte/operation credits remain unavailable; both owner and wake backing free exactly once.
3. A cloned proxy outliving every owner/report view, including consuming and borrowed wake calls. The actual WorkWake deallocation is gated and cannot return capacity early.
4. Cancelled finish destroying its executor waiter outside the waiter mutex and before a successor wait, without losing actual operation custody.
5. Reentrant executor wake/destructor callbacks, intentional waiter poison, and callback panic for both borrowed and consuming proxy wake. Actual charge persists after borrowed panic and releases only after consumed final ownership.

The deallocation observer is cfg(test) only, forwards the exact allocator contracts to System, and arms two exact live allocation address ranges. Its allocation callback uses atomics and yield_now, no formatting, callbacks or additional allocation. Test gate Drop releases the pause on assertion failure. This is evidence preparation only: all 12 tests and compilation still require coordinated execution before integration.

## Unchanged limitations

This remains a foundation with no production snapshot_api adapter, per-engine job admission/prepare fence, shutdown caller integration, trusted redb transaction workspace coefficients, or bounded arbitrary panic/anyhow payload claim. The named Tokio workspace is an estimate, not a proof of task/pool allocator layout or stacks. An opaque run/start/join/cleanup panic remains in charged retained census custody. Claimed outputs must independently own transferred backing/leases. The ordinary installed-memory Box<Reservation> final allocation tail reported by root is a separate open G02 correction, not solved by this owner implementation.

The separate revision2-to-revision3.patch is only the review delta after both old foundation and root cancellation dependency; do not apply it in addition to the replacement foundation.patch.
