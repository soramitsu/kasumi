# Frozen disk allocation and startup successor

Clean native macOS ARM64 source `c681ba3` completed 17 passing gates. The complete
store-library gate had 154 passing, three failing and two ignored tests; all 29
later gates were unrun. All 18 dispatched process groups drained, the source
remained unchanged, and all 12 preserved executables were independently rehashed.
The 47-gate plan retains the preceding 46 gates and adds bounded startup
preparation coverage; its 252 mandatory cases remain required.

Three new allocation assertions observed exactly one allocation: first shrink
in the success path and descriptor Drop in two failure paths. The physical
identity failure and settlement checks themselves did not allocate. These
boundaries first lock dormant test-only `shrink_failure` and `after_file_close`
mutexes. The correction prepares both fixture mutexes during owner acquisition,
before measured I/O and destructor work, retaining the original zero-allocation
assertions. A passing successor is required to establish the diagnosis.

The Control genesis and new bounded preparation gates were not reached; no
resolution of the preceding stack overflow is claimed. Raw copies are indexed
by `copied-files.json`; exact executable originals remain in
`/Users/mtakemiya/dev/kasumi-release-evidence/20260920-c681ba3-ownership-disk-startup`.
No final release qualification is claimed.
