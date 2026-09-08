# Immutable scope for every staged transaction operation

Validated source `c50ad3b34dd20fc0cdb488975ad0b9b7f7262b69` requires the original
tenant/incarnation/principal in Begin and every reference. Actual native tests
reproduce and close cross-principal stop-before-Begin, check all five operations,
and preserve same-principal renewal. SDK validation, ordered/guarded stop,
replication, restored lineage, snapshot semantics and encrypted history backup
also pass, alongside strict workspace Clippy, production check and formatting.

Manifests preserve original reproduction, failed earlier test compilation at
8286144, the final c50 gates and later 8fca3e6 validation of exact append outcome
resolution with the scoped DTO. Actual executable/log hashes and source trees
are retained. The 8fca history helper is fixture-only; c50 is the validated
consumer scope checkpoint. Its git archive is
`/tmp/kasumi-staged-scope-c50ad3b-source.tar`, SHA-256
`3280008fef3b1488d4e166da2ae6006eaf92bc92fb56350c0a185ee71a0a185f`.
These focused macOS checks do not close final-source capacity or release gates.
