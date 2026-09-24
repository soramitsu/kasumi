# Independent installed-memory lease retirement review

Verdict: **no blocking finding in this bounded patch**. Full store/engine integration and strict workspace checks remain for the coordinated Cargo gates. This reviewer performed source/evidence inspection only; no actual source edits, compilation, Cargo commands or tests.

Reviewed final patch SHA256: `3b6b1cf0e86ac1e11d31818521353db6e46f84f3bc403404549fe46a168b8d39`. Manifest SHA256: `a0cb8a6082dff836a047dd2362e11cfee6ac92b1bc81e887d2228570861f87e0`. Exact proposed files and evidence hashes are recorded in `receipt.json`.

## Opaque retirement and unwind

The mandatory trait now returns DiskMemoryLease. Its private Option owns one private erased RetireLease Box; Drop takes the Option before invoking the consuming retirement method. No reference, raw Box, cloning method or alternative retirement entry point is exposed.

The concrete implementation transfers the named `self: Box<T>` into a shorter inner scope, moves T out, ends the allocation's scope, and only then calls `drop(reservation)`. This matters because simply binding `let value = *self; drop(value)` inside the original named Box parameter's scope permits early credit return. The actual allocation must retire before T's destructor is entered, including when that destructor panics and its fields unwind. The now-empty outer Option cannot invoke the same retirement again.

The production Reservation keeps its actual MemoryCore alive until its Drop returns resident credit; TestDiskLease does the equivalent through TestDiskMemory. Their concrete token allocations are still fully acquired before DiskMemoryLease::new allocates them. Size/alignment of the new inline opaque lease is compile-time checked against the original fat pointer, so existing owner/registry layout planning does not silently change. This patch adds neither a capacity fallback nor a second production compatibility path.

This does not guarantee arbitrary external provider destructors cannot panic or release their own credit incorrectly. Providers remain trusted to honor the required admission contract. The bounded claim here is that the lease's concrete Box allocation is retired before invoking the provider token destructor; all current supported providers satisfy that boundary.

## Allocator observer safety

The tests extend the store's existing cfg(test) global allocator. Allocation/reallocation calls keep their existing unchanged forwarding; deallocation forwards the exact original pointer/layout once to System.

The new observer is scoped to the executing thread with constant-initialized TLS cells. It compares the exact Box payload allocation pointer and clears that watched address before blocking, preventing repeated recognition. It never dereferences the allocation being freed. Its only raw dereference is a pointer to a separately live DeallocationObservation borrowed by the synchronous observe_deallocation call; that function cannot return or unwind past its reset guard until the active deallocation completes. Cross-thread coordination uses the observation's atomics, not an escaped borrow or application mutex.

The callback records entry and layout size before System.dealloc, waits using atomics/yielding, then records finished after System.dealloc returns. Its path performs no formatting, user callbacks, observer allocation or application-lock acquisition. The reset guard clears both TLS pointers on success/unwind. The panic test verifies an independent second observation after unwind. The PausedRetirement cleanup guard releases the gate and joins its actual worker even if a main-thread assertion unwinds, avoiding a silently detached blocked allocator thread.

## Migration and evidence

A repository source search found the two current NodeDiskMemoryAdmission implementations: engine MemoryCore and store TestDiskMemory. Both directly adopt DiskMemoryLease, alongside the internal Lease alias, public reexport and contract documentation. NodeDisk, ScratchDisk and DeviceDisk callers obtain the new mandatory type through the shared trait/alias; no call-site compatibility shim remains. The formulas retain the concrete Reservation/TestDiskLease token size and existing 4096-byte allocation allowance. Reservation counts, operation limits, memory budgets and workloads are unchanged.

The package's standalone-02 extraction records match the reviewed proposed lease/provider/observer/test bytes. Its retained process receipts report three tests passing in both debug and optimized native runs, plus the focused Box-local Clippy check. The actual test pauses the concrete admitted TestDiskMemory lease at System.dealloc, requires its byte and reservation-slot charge to remain unavailable, and verifies successor admission only after retirement. The destructor-panic test observes real completed deallocation before field credit release and checks the original panic payload and one destruction.

The retained counterfactual substitutes the incorrect named-Box local implementation and causes this same early-credit test to fail with exit 101; its process group drained. This establishes that the regression exercises the original ordering defect. These are package-author execution receipts, not tests run by this reviewer, and they are narrower than a full store/engine/workspace build. The existing production MemoryCore integration tests still need the coordinated gate after application.

Separate cancellation-Arc retirement, snapshot-work output custody, arbitrary diagnostic bounds, and other installed-owner allocation tails are outside this patch's readiness claim. This review does not mark the overall release or complete memory contract finished.
