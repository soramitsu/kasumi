# SDK literal decoding: retained small-gate failures

These are client-only checks on macOS ARM64 with Rust 1.97.1, one Cargo job,
an original 300-second gate deadline, and owned process-group cleanup. No
Kasumi engine, store, server or Raft artifact was compiled. No listener, native
API, provider, platform acceptance or production build ran. Every attempt kept
its source and lockfile unchanged. Local executable copies are identified by
the preserved-executables manifests; executable bytes are not checked in here.

`3027530` stopped at its first compilation after 21.647 seconds. Wildcard domain
imports shadowed the standard two-parameter `Result`, causing 140 cascading
compiler errors. No test ran and the remaining gates were not dispatched.

The explicit-import successor `0523c64` passed all nine new literal-decoder
tests in 8.482 seconds. Its snapshot cohort then passed 11 tests and failed two
in 2.274 seconds: assertions still expected the former snapshot-specific static
diagnostics after the shared decoder had adopted native-operation diagnostics.
The original ownership and peer-payload assertions remain required. Bearer,
strict lint and no-default-feature checks were not dispatched after the failure.

Both attempts are terminal and all owned process groups drained. A subsequent
source correction is also needed before combining canonical serialization:
request preflight must account for live borrowed-key sorting metadata. Existing
aggregate reservation ownership does not by itself enforce that decoded-work
limit. None of these results certify the separately prepared combined source.
