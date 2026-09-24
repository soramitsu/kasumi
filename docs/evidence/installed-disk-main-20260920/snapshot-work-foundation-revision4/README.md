# Snapshot work foundation, revision 4

TARGET ONLY, UNCOMPILED. This replacement foundation has no production snapshot adapter. No actual source edit, Cargo invocation, Rust compilation or test execution was performed. Work remains solely in the current repository on master.

The original revision-3 foundation.patch SHA256 3c9c8ed4acd39f9e2d8a9572baa3898f4c3fa34cef44335737d41e5a87d0e520 and its whole package remain unchanged. The separate revision3-to-revision4.patch is a review delta, not an additional patch to apply with foundation.patch.

## Corrected callback boundary

The independent review established a synchronous reentry deadlock: cleanup/discard received a proxy Context while Owner.resource was held, and proxy notify immediately invoked an executor waker which could call report.completion(). The original test checked only the waiter's own mutex. JoinHandle polling under Owner.control required the same protection.

WorkWake now contains an inline WakeState: the one executor registration, an owner-scope count, and a pending-notification bit. Each owner lock scope enters deferral before acquiring any control/resource guard. Rust destroys the later lock guards before the deferral guard. A proxy notification coalesces while any entered scope remains, and the final exiting scope takes its waiter under the wake-state mutex and invokes it after releasing that mutex and its owner guards. Both concrete poll_finish and poll_join are protected; run, start, close, completion, visit and synchronous claim also protect their owner lock scopes. This also covers indirect notification from a diagnostic callback. Direct diagnostic callback recursion into the same owner remains prohibited by the existing borrowed-observation contract.

There is no helper allocation, task, thread, channel, detached supervisor or new capacity fallback. Nested/concurrent scopes share the already charged inline state. The concrete arc_bytes<WorkWake> formula automatically includes its changed layout; operation limits, census capacity, workload sizes and deadlines are unchanged. Wake callbacks execute outside their triggering owner lock scopes. Another thread can start a later owner scope before the callback executes; that callback may contend for its locks normally, while notifications made by the other scope remain deferred, avoiding the original synchronous cycle.

Executor clone and replaced/drop callbacks remain outside the wake-state mutex, as does ClearWaiter destruction before serialized finish unlock. A wake consumes its registration; the next poll installs a registration before testing actual child/cleanup progress. Notifications racing an active poll are retained until that poll's guards exit. During an existing unwind the deferral guard restores the count but does not run an arbitrary second callback; it preserves the pending notification/registration for the next owner scope, or the cancelled finish destroys the waiter outside locks. An external executor panic during ordinary deferred dispatch therefore occurs after all operation locks have released and outside the cleanup panic catcher. The original operation outcome stays intact and the unwound waiter may be cancelled and retried.

## Preserved ownership and admission

The counted Owner and WorkWake Arc retirement, private RawWaker ownership protocol, complete-failure census retirement, fixed generation checks and original diagnostic custody from revision 3 are preserved. Every actual final strong release goes through Arc::into_inner before fields/charge destruction. Owner's final field retains WorkWake, whose final field retains the original one operation Reservation; retained proxy wakers continue to hold that charge and its operation slot through their actual backing retirement.

The root-owned reservation cancellation retirement patch c9c6d4ffd79170509130bb8a284db6888e0b2ed262b0dc6acf69a8618934ee8d is now applied in the actual source. This revision's before hashes are against that actual source (admission.rs SHA256 521c90cf40c29899f95aaa02509b65e62af3827928236dff817deb309d8449da); foundation.patch does not repeat the dependency hunk. Do not apply the dependency again.

## Prepared tests and verification limits

The prior twelve tests remain, including actual System.dealloc gates for concurrent final Owner drops and final proxy backing, original panic identity, bounded admission, cancelled join custody, and poisoned wake-state callbacks. Their old wait-state accesses were adapted to the inline state without weakening their assertions.

Three additional tests cover:

1. Both cleanup and discard synchronously wake and return Pending. The external executor first checks both actual Owner mutexes with try_lock (to fail promptly rather than hang), then calls the public report.completion() path. Later polls complete the same original operation, preserve the exact typed failure identity, and release all byte/operation credit only after its real owners drop.
2. An external deferred executor wake panics after cleanup returns Pending. The original operation failure identity remains unchanged, resource panic remains empty, custody and charge persist, and cancellation plus a new drain reaches Complete using that same owner.
3. Nested actual control/resource lock scopes coalesce repeated notifications until both guards are gone. An existing unwind preserves notification/registration without invoking an executor, and a later actual report.completion() scope forwards the deferred callback and permits safe reentry.

Rustfmt stdin and exact git apply --check are recorded in manifest.json. All fifteen tests and compilation are still unexecuted. No behavioral or unsafe-code qualification is claimed from static preparation.

## Remaining release work

The production snapshot_api adapter, per-engine preparation/admission fence, shutdown integration, retained redb transaction and database close adoption, and precise trusted operation coefficients remain open. The existing Tokio workspace is a named estimate, not a proof of task/pool allocator layout or stacks. Arbitrary panic/anyhow diagnostic payloads remain unqualified. Opaque operation or cleanup panic remains in retained census custody. Claimed outputs must independently retain their backing and leases. The separate installed-memory Box<Reservation> allocation-tail correction is still open G02 work and is not solved by this patch.
