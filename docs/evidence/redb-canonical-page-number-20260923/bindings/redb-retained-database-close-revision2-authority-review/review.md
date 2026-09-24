# Independent review: retained database close, revision 2

Verdict: no blocking finding in this bounded prerequisite. Review is static and does not substitute for the five proposed runtime tests or coordinated vendor gates. No actual source edits or Rust build/tests were performed by this reviewer.

Reviewed immutable `close.patch` SHA-256 `8e96155d16c4021d20fae2c6d8f8ef3b052ea8d6de522f6e6c6cf5812a09a74d`, manifest `2704b3b6f7e7b16ed4f6e6a6c494e307356cb39bcbdcc54b964cacb9a23d9f8d`. Every proposed file hash and actual-source base hash matches. The base includes the exact run102 I/O-preservation prerequisite. Relative to preserved revision 1, only the two requested lock assertions change from arbitrary errors to exact `DatabaseAlreadyOpen`.

## Custody and terminal phases

`RetainedDatabase::close(&mut self)` operates on its exact inline `Database`; neither fallible closure owns the database. The exclusive borrow prevents a retained database reference from being used concurrently with close. The first request fences future `database()` access before examining the existing transaction tracker. The tracker count is the existing consuming-close precondition and includes read guards, write ownership, and savepoints. A busy owner records neither phase and can retry only after existing owners drain; admitted readers remain usable while waiting.

Before either terminal effect, settlement becomes Retained. Each separate observation is marked Entered before its closure and stores the exact returned error or original caught panic payload without cloning. Backend release is separately attempted after returned shutdown errors or caught shutdown panic. Repeated close never enters either phase again. The observation assignments replace only NotEntered/Entered cells, so they cannot drop a previously recorded user error or payload while trying to record a later phase.

A shutdown sync panic unwinds out of the state mutex scope before the backend phase. `TransactionalMemory::abandon` reaches storage/CheckedBackend close without reacquiring that poisoned state lock. `CheckedBackend::close` marks its closed flag before the physical backend invocation, including a panicking invocation. Later owner destruction may reach `abandon` again, but this flag prevents physical backend close replay. The wrapper prevents an actual Database destructor from running inside the caught terminal closure.

## Diagnostics and settlement

The new `prepare_close` extraction keeps both original phase results separate for retained callers. Newly failing `flush()` now propagates its original error immediately instead of being erased by `.is_ok()` and replaced by a subsequent OwnerFailed settlement. The already-fenced entry behavior is unchanged. The run102 mapping is essential: its `fail_owner` call still fences subsequent access while preserving the first backend I/O object.

Settled requires a returned shutdown result and positively successful backend close; it can coexist with an original shutdown error, which remains visible. Either panic or a backend error remains Retained. These statuses do not claim successful database semantics, destruction of allocation backing, or complete external drain. FileBackend close releases its lock; the actual file handle and database memory can still reside in the owner until disposal. Allocation credit and external cleanup therefore remain caller obligations.

## Tests and lock evidence

The five tests use a real FileBackend over an actual temporary file. They cover waiting on a live read, successful close/reopen of durable contents, a shutdown error with successful backend release, both original errors, a shutdown panic with separate backend release, and a backend-close panic. Original error cells and panic payload identities are compared across repeated close; effect counts remain fixed. The actual database address is checked across the backend-panic call. Three uncertain fixtures remain in fixed test-process custody rather than being dropped and labeled clean.

Revision 2 corrects the two lock proofs: a second independent file open must yield `DatabaseError::DatabaseAlreadyOpen`, the exact mapping of `TryLockError::WouldBlock` in the optimized FileBackend. Arbitrary unrelated open errors cannot satisfy them. This uses the same operating-system file-lock assumption as existing redb lock tests; unsupported-lock targets do not silently prove retention. Success tests verify durable reopening after actual disposal. Existing reader handles carry the transaction tracker guard, so the busy test is not a mere synthetic counter.

## Remaining scope

This is not a self-retaining lifetime guarantee. The adapter must put the wrapper and its backing charge into actual registered custody before dispatch and keep them through cancellation and uncertainty. Synchronous close contains no async suspension point, but cancellation/unwind of its surrounding caller can still drop the wrapper if that caller fails to preserve ownership. The existing consuming close API still loses a secondary error and must not remain a supported production bypass when Kasumi adopts the admitted boundary. No panic-size bound, memory coefficient, full NodeDatabase/staging migration, or release completion is established here.
