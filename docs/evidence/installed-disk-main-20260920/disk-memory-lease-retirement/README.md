# Mandatory installed memory lease retirement

Target-only proposal on `/Users/mtakemiya/dev/kasumi` master. No actual source,
index, branch, worktree, Cargo build, or archived evidence was changed.

The required `NodeDiskMemoryAdmission::reserve_installed` return type becomes
`DiskMemoryLease`. The opaque lease owns a private erased retirement operation.
That consuming operation moves the concrete reservation token across an explicit
inner Box scope, retires its actual heap allocation, then drops the token that
returns resident byte and reservation-slot credit. No raw Box, optional old API,
compatibility conversion, or alternative public retirement path is exposed.

Both providers are directly migrated: engine `MemoryCore` and store
`TestDiskMemory`. The internal `Lease` alias and public export move together.
Provider formulas still admit the exact concrete token's Box allocation plus the
existing 4096-byte allowance. The opaque lease's inline size/alignment are
compile-time asserted equal to the previous fat pointer on every build target.
The native ARM64 probe measures 16 bytes/alignment 8 for both representations.
No memory, handle, reservation-count or workload policy is increased.

## Evidence and regression coverage

`standalone-02` contains retained owned native rustc/compiler/test receipts,
stdout, stderr, binaries, exact source inventories and extraction provenance.
This is literal extraction of the proposed lease/provider implementation plus
the existing extended store allocator observer and the three proposed tests.
It is not a full store/engine/workspace compilation or native release gate.
All its actual process groups drained without timeout or signal.

- Three proposed tests pass in both debug and optimized native builds.
- The first test pauses the exact `System.dealloc` boundary for a real admitted
  `TestDiskMemory` lease, challenges admission concurrently, and proves its bytes
  and slot remain unavailable until actual deallocation. It then observes one
  deallocation and successful successor admission at the unchanged limit.
- A token-destructor panic test proves the actual allocation is already gone
  before field unwind returns credit, retains the original panic, proves one
  destruction, and verifies the observer resets correctly for the next lease.
- Layout and pre-acquisition denial/overflow accounting stay unchanged.
- The existing `allocation_tests` allocator is extended with a scoped thread-local
  observer; no second global allocator is introduced. Observer callbacks use
  only thread-local cells, atomics and yielding. A test cleanup guard releases
  the paused deallocation and joins the actual worker even on assertion failure.
- `counterfactual-01` deliberately substitutes the incorrect named-Box local
  retirement. The actual new capacity regression fails with exit 101 while its
  process group drains. The original failed receipt and assertion output remain
  preserved. This confirms that the test detects the original early-credit bug.

The native language probe runs in debug and optimized forms and shows that
`let value = *self; drop(value)` inside the named Box parameter's scope is
insufficient: payload destruction precedes Box deallocation. Both a consuming
helper return and an explicit inner scope retire the allocation first. Existing
`List::remove` already destructures a temporary Box; it passes the same ordering
probe and needs no change for this specific tail.

`standalone-01` preserves the initially passing helper implementation tests and
its original targeted Clippy failure (`boxed_local`). That revision remains in
`revisions/consuming-helper`. The final explicit inner scope passes the targeted
Clippy check without any lint allowance. The extracted harness reports three
ordinary dead-code warnings for unrelated included helpers unused by extraction;
this is not a claim of full strict workspace Clippy success.

Full coordinated store/engine tests, strict workspace Clippy and native release
qualification remain unrun. The production core provider's integration must be
checked after the proposal is applied. The separate cancellation-Arc retirement
fix and snapshot-work foundation are neither folded into this patch nor claimed
complete by these tests.
