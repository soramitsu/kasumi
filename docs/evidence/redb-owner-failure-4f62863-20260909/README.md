# Typed redb admission-owner failure regressions

Frozen `4f628637f35439a51c0b63faf98534800c5a5f85`, tree
`5687fdc784d60083fac736fddc6e9f6ab585dc9f`, passes all20 focused prototype
tests on Rust1.97.1 / macOS ARM64: allocator candidate3 (8.191s) and growth
admission17 (8.025s). Both owned process groups67547/67714 drained. Source,
both tracked lockfiles and the explicitly pinned process helper stayed unchanged.

New tests establish failed-owner mutation/commit/drop/cache/new transaction
rejection, failed-owner commit preparation, and repeated healthy capacity denial
followed by successful admitted extension/reopen. The previous rollback and
actual-I/O failure tests also pass. The exact compiled features are default,
experimental-precommit-growth-admission and std. Both groups used the preserved
test executable SHA256
`af3c11663a8da6f05d2e5daa4e0b0a710260bde3aedd6b34b819275a983047ed`.

The initial runner attempt failed before dispatching Cargo because this older
prototype checkout has no scripts/gate_process.py. Its failed preflight and
original plan are retained. The successful runner explicitly pins the unchanged
helper from the frozen f4a472f checkout and verifies its digest before dispatch
and at terminal; it does not add a helper or alter prototype source.

No production dependency patch, Kasumi engine/store/server/Raft build, complete
upstream just test, fuzz or production disk-owner/response-fence integration was
performed by this cohort. Issued memory views remain outside the prototype's
revocation boundary. The full upstream source overlay is prepared separately.
Raw source/plan/logs/feature/executable evidence is preserved byte-for-byte.
