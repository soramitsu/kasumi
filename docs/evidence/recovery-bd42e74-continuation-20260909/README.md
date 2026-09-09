# Recovery, backup and signer continuation

Frozen `bd42e743fb52c4b30d1fee750882e37442acd69f`, tree
`f1d6baf6002d82d582af0047848ffa142b0010fe`, passed 30 actual tests across
16 gates, then failed the native issuer TLS test. The cohort remains failed.
Four later gates (native Control signer, indexed lineage, coherent lease
retention and strict workspace lint) were not run. Rust 1.97.1, macOS ARM64.

All five replicated Control recovery tests passed, including the previously
overflowing activation fixture. The fixture now hands off two sequential
heap-owned phase futures without increasing stack size, detaching work, dropping
assertions or changing original identities/deadlines. These tests use synthetic
signed target/issuer facts and do not prove source-unavailable physical recovery.

Other passing scopes: three backup dependency/workspace checks, cancelled restore
publication ownership, actual cold-history full backup and restore without the
source objects, public snapshot staging, six permanent target-prefix tests,
eight completion state-machine tests, three positive preparation status tests,
canonical Control completion and the authority signer coverage scenario.

The native issuer test compiled and ran, then rejected its publication bearer
fixture at `rpc_authority_tests.rs:1150`: `operator material must be owner-only`.
The caller placed the credential beneath the default temporary directory rather
than its existing explicitly private signer directory. Successor `d37e33e` changes
that one fixture path; it has no test result yet. Production permission checks
remain unchanged. The linker also reported an oversized compact-unwind section;
its complete diagnostic remains in the raw log.

The failed gate took 409.822 seconds including compilation; its test summary was
0 passed / 1 failed in 15.73 seconds, Cargo exit101. Exact process group95619 and
every previous group drained without signals or remaining children. All tracked
source, tree and lockfile hashes remained unchanged. Earlier failures remain
failed and this continuation does not validate later node-envelope, strict
initialization or audit-head changes.

Raw logs, runner, exact plan and source inventory are preserved byte-for-byte.
`evidence.json` SHA-256:
`7dacb95f397a2775b4acdd7930636a487aa9f23a689151ee79b66595c279bb9b`.
Exact executable copies remain at their hashed paths recorded in that file.

After the terminal result, another task reported that its unrelated compiler
cohort had owned a separate queue since 06:08 UTC, including intervals of source
hashing without a visible Cargo process. This overlaps the Kasumi continuation.
That task's later core process10719 began at06:22:22 UTC, after Kasumi drained;
it also overlaps another separately dispatched build cohort. These reports do not
establish exact earlier process timings. No quiet-host performance, resource-peak
or non-overlap conclusion is drawn from this functional evidence. Kasumi did not
signal those foreign processes and held subsequent native work pending explicit
coordination of both owners.
