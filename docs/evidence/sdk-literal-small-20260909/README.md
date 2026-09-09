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

Combined canonical-serialization and SDK checkpoint `032686f` passed all nine
literal tests, all 16 snapshot/admission tests and the bearer test (26 total).
Strict client lint then rejected `sort_unstable_by` where a key expression is
sufficient in the canonical serializer. No-default-feature compilation did not
run. All four owned process groups drained and source stayed unchanged. The
subsequent expression-only correction must still pass the complete small cohort.

Successor `785dd7f` passed all five small gates: literal tests 9/9 (4.754 s),
snapshot/admission tests 16/16 (2.259 s), bearer redaction 1/1 (0.255 s), strict
client lint (14.008 s), and no-default-feature client compilation (9.467 s).
All source and lock identities remained unchanged and every process group
drained. The shared test executable SHA-256 is
`7e84a5f1caaf9ee22eaa9ee0d60a3198e7567e288e1d4fd8defc92c9f654d2c6`.
Evidence SHA-256 is
`739279cda8940698455b364cfcaf143ec4891b4e20d030c3fce8c43a20a12f24`.

This source is merged with the JSON dependency correction and shutdown/receipt
work in validation checkpoint `b1851d5`. That combination has not yet run native,
workspace or production gates. External-stock-consumer and actual SDK feed/schema
over TLS coverage also remain separate from these client-only tests.
