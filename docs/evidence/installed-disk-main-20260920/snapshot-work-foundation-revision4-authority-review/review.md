# Independent revision-4 snapshot work review

Verdict: **blocked on one output-transfer unwind defect**. The earlier synchronous mutex reentry issue is corrected, and the existing allocation/credit retirement ordering remains intact by static inspection. This is a read-only source review; no actual source edit, Cargo command, compilation or runtime test was performed.

Reviewed immutable proposal: `snapshot-work-foundation-revision4/foundation.patch`, SHA256 `3fe0e296155fd6c2cb15f506ba6fbd0b25fe646bd188f5627accffd99da18022`; manifest SHA256 `6e86ff61d75bb4a5df82f0a940d99ecbb560449033e679fa4dac631a7163167f`. See `receipt.json` for exact reviewed proposed-file hashes. Repository remains `/Users/mtakemiya/dev/kasumi`, `master`.

## P1: a deferred callback can unwind claim after removing its output

Location: proposed `crates/kasumi-engine/src/admission/snapshot_work.rs:653–678`.

`claim()` enters a `DeferWake` scope, takes `resource.output`, releases the control/resource guards, retires its now-Complete census entry, and constructs its successful return. The outer `DeferWake` is then destroyed. If a notification was queued during the claim, its destructor invokes the original executor waker. That callback is expressly allowed to panic by the new revision's tests. An executor panic at this point prevents delivery of the output and unwinds its local/return ownership after the census entry has already disappeared. `poll_discard` was never called, and the retained owner now has `output=None` and reports Complete. Therefore a nontrivial output can lose its actual registered custody without proof of discard or successful delivery.

The registered waiter can overlap this synchronous claim: `ready()/finish(false)` sets `cleanup_complete` and releases the resource mutex before returning through `ClearWaiter`, while `claim()` does not serialize against that waiter lifecycle. A concurrent proxy notification can be recorded while claim's scope is active. The implementation also deliberately preserves pending notification/registration across an owner-scope unwind, as exercised by its last new test. This is not the rejected hypothetical of synchronously blocking on another drain inside a wake callback; the only callback behavior required is the supported panic.

The proposal author independently confirmed this interleaving. Revision 4 remains unchanged for review and must not be described as integration-ready.

Required correction: conserve the exact output in registered custody until delivery can no longer be prevented by a wake-capable destructor/callback. After the destructive output take, no deferred-dispatch guard, `completion()` callback dispatch, Waker destruction, or Tokio guard release that can invoke external executor code may remain on the return path unless an unwind guard restores the output and its still-retained census state. Merely removing claim's outer deferral is insufficient because `retire_complete()` calls `completion()`, whose guard can dispatch. Merely adding a Tokio serial try-lock is also insufficient by itself because releasing that guard can wake an arbitrary registered executor.

A narrow implementation can use an explicitly retained transfer state with positive rollback, or separate callback flushing from a final callback-free transfer section using the synchronous owner/census mutexes. A direct helper that bypasses callback dispatch must prove the same completion/generation preconditions; it must not treat a temporarily absent output as successful delivery. Do not release serialized finish custody across await as a workaround.

Required regression: prepare a real successful Output with identity and destructor counters; install a real panicking executor waiter and queue a notification; invoke actual claim under catch_unwind. Require that a failed delivery retains the exact output and census owner, does not invoke ordinary output destruction or free its charge, and permits one subsequent safe claim or positive discard. Also exercise the interleaving with the registered finish waiter, or a deterministic test hook at that boundary. Keep the current cancellation, panic identity and allocation deallocation tests.

## Accepted synchronous wake boundary

Every relevant run/start/join/finish/close/completion/visit scope enters deferral before acquiring its control/resource mutexes. The later declared mutex guards therefore drop before `DeferWake` dispatches on normal return. The nested poll_finish/poll_join scopes share one already charged inline counter. The last exiting scope extracts its registered waiter under the wake-state mutex and invokes it only after that mutex has unlocked. During an existing panic, scope exit restores the counter but keeps the pending registration rather than invoking a second arbitrary callback.

The new `cleanup_and_discard_wakes_reenter_actual_completion_only_after_owner_unlock` test checks both real Owner mutexes and then calls the public `report.completion()` path. It therefore covers the original defect, not just the proxy waiter mutex. The second new test checks the original operation failure remains intact through an external deferred wake panic, cancelling the unwound future and retrying through a new drain. The third checks nested scopes and preserved notification after unwind. These tests are prepared but unexecuted.

Precise accepted limit: callbacks execute outside their triggering synchronous Owner control/resource/wake-state lock scopes. Another thread can acquire a later scope before callback execution; ordinary cross-thread contention remains possible. `Owner.serial` is the Tokio mutex that deliberately spans the finish await to protect the single registered waiter. A nonblocking wake callback may poll another drain, which returns Pending; synchronously blocking until a second drain completes while the first owns serial is outside the supported executor-wake contract. No claim of universal arbitrary callback reentry or global lock exclusion is made. This limit does not excuse the claim-output defect above.

## Preserved allocation and custody properties

- The fixed snapshot census allocation remains included in MemoryCore's admitted bookkeeping before allocation.
- Concrete Owner, WorkWake, cancellation state/Arc, named existing Tokio workspace and trusted operation backing are calculated before the actual operation reservation and inert builder. No new helper allocation is introduced by deferral.
- Typed Owner, erased Owner and WorkWake final strong releases route through concrete `Arc::into_inner` before destruction of their fields. No Weak owner escapes. The RawWaker's owned count uses OwnedWake on consuming wake/drop; borrowed wake uses ManuallyDrop and preserves its count through callback panic.
- Owner's last field retains WorkWake, whose last field retains the original Reservation. A proxy waker can therefore retain the actual reservation beyond all report/worker handles. The applied reservation cancellation-retirement dependency destroys its retained cancellation backing before publishing reusable byte/operation/slot credit.
- Complete typed failure is removed from the fixed census, while report views retain the original failure and charge. A run/start/join/cleanup panic remains Retained. Cancellation does not move the child or output out of the owner; ClearWaiter removes only the delivery registration outside its synchronous mutex.
- The prepared allocator tests gate actual System.dealloc for concrete Owner/WorkWake allocations rather than using an early field-destructor observation. They remain unexecuted; this review does not qualify custom allocator behavior or unsafe RawWaker code by testing.

The foundation still lacks production snapshot adapters, per-engine preparation/shutdown fences, precise operation workspace coefficients and qualified arbitrary diagnostic bounds. Those previously documented limitations remain; this review does not broaden readiness claims.
