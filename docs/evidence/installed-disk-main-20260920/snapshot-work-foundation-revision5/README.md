# Snapshot work foundation, revision 5

TARGET ONLY, UNCOMPILED, NO PRODUCTION ADAPTER. No actual source edits, Rust compilation, Cargo calls or test execution were performed. The work remains in the current repository on master.

Revision 4 is preserved byte-for-byte at foundation.patch SHA256 3fe0e296155fd6c2cb15f506ba6fbd0b25fe646bd188f5627accffd99da18022, as are revisions 2 and 3. This package replaces the foundation; revision4-to-revision5.patch is its review-only delta, not an additional patch to apply with foundation.patch. The already-applied root cancellation retirement dependency c9c6d4ffd79170509130bb8a284db6888e0b2ed262b0dc6acf69a8618934ee8d is included in the actual baseline and must not be applied again.

## Corrected claim boundary

Independent revision-4 review found a second real ownership defect: claim moved Output out, retired its census entry, and then dropped its outer DeferWake. If a pending external executor wake panicked from that guard, the undelivered output unwound without poll_discard while its owner reported Complete.

claim now dispatches already pending notifications before locking or touching the retained output. Like DeferWake, this preflight avoids invoking an arbitrary callback during an existing unwind and preserves its notification. Callback code may close or even claim the owner; claim therefore checks closing/join/error/cleanup/output eligibility only after preflight returns.

The final transfer section is deliberately callback-free. It acquires only the std control/resource/census mutexes, takes the output and retires the exact matching census generation directly, unlocks, drops the extra census/report owner counts, then returns the original output. It invokes no adapter callback, completion(), retire_complete(), dispatching DeferWake, Tokio guard, or executor Waker clone/drop/wake after the take. Poison handling recovers the existing std guards without formatting or user destructors; indexed access uses get_mut. The borrowed SnapshotWork keeps its actual Owner strong count alive throughout, so the two extra count drops cannot run resource, operation, output, panic-payload or wake destruction. Those drops are outside the locks.

This pure section does not need proxy deferral: it calls no external code while locked. A notification dispatched on another thread may contend for these ordinary mutexes, but the transfer thread cannot synchronously call back into that executor to form a cycle. WorkWake retains the normal deferral counter for all owner scopes that may execute adapter or diagnostic code. No allocation, charge, policy cap, task or retained resource is introduced by the final transfer protocol.

## Preserved revision-4 wake and retirement foundation

Cleanup/discard and JoinHandle polling record proxy notifications until their triggering control/resource guards are released. Nested/concurrent scopes use the already charged inline WorkWake state. run/start/close/completion/visit remain guarded, and all executor clone/replacement/drop callbacks stay outside the wake-state mutex. An existing unwind restores the deferral count and preserves notification/registration for a later scope or cancelled-waiter teardown. External callback panic after a normal poll leaves the operation's original outcome outside that callback's unwind.

finish retains its Tokio serial gate across its await to protect the single executor registration. Actual report.completion() reentry does not acquire that asynchronous gate. Executor callbacks must remain nonblocking and must not synchronously wait for a recursively started finish/drain of the same owner; the public report documents this limit. There is no claim that all owner locks remain globally unheld by every concurrent thread during an executor callback.

The private counted typed/erased Owner handles, counted RawWaker, actual Arc::into_inner backing retirement and Complete-failure census release are unchanged. Owner's last field retains WorkWake and its original operation Reservation; external proxy wakers keep that reservation and operation slot until their actual final backing release. Fixed census capacity and all existing byte formulas remain unchanged except for the already type-derived WakeState layout from revision 4. No compatibility alias or bypass is added.

## Prepared tests

All fifteen prior tests remain, including actual owner/proxy System.dealloc gates, cleanup/discard executor calls to actual report.completion(), nested lock deferral, callback panic/cancellation/retry, original failure identity and operation-capacity checks.

Two new deterministic tests cover the revised transfer:

1. A real executor registration has a queued notification, and its callback panics during claim. The original output's exact resident Reservation identity remains in resource.output, its destructor count stays zero, the original census entry and full operation charge remain retained, and a later claim returns that same output/lease. After owner retirement, the independently claimed output lease remains charged until its actual Drop.
2. A preflight executor callback itself successfully claims the output. The outer claim rechecks state and returns the original Complete report rather than delivering a second result. The exact output Reservation identity and destructor count prove a single transfer.

All seventeen tests are prepared but unexecuted. manifest.json records exact before/proposed hashes, formatting and git apply --check. Static review is not compilation, unsafe-code qualification or behavioral evidence.

## Remaining release work

The production snapshot adapter, per-engine preparation fence, shutdown wiring, retained redb transaction/database close adoption and precise operation workspace coefficients remain open. The named Tokio workspace is still an estimate; arbitrary diagnostic/panic payload backing is not proven bounded. Opaque operation/cleanup panic remains retained. Claimed outputs must independently fund their transferred backing. The separate installed-memory boxed-lease allocation tail remains independent G02 work. This foundation does not close those release requirements.
