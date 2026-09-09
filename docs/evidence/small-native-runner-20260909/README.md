# Small standalone diagnostic runner checks

Checkpoint `a276db6` adds the private offline diagnostic runner and 16 pure
regression tests. It is integrated at `e6c80c8`; all 36 combined Python tests pass
with the recorded Python 3.12 interpreter. The original Python 3.9 source checks
and exact log hashes remain in this directory. No Cargo or native database
process was run for these checks.

The runner copies and verifies fixture-free executable hashes, records their
completed build evidence and original overall outcome, checks actual protected
readiness, preserves private initialization/recovery state, and requires an
explicit authorization denial from the still-unexpired old resource credential.
Mocked readiness, provenance, corpus, timeout and process cleanup counterexamples
are runner tests, not an actual TLS/database acceptance result.

The first Linux diagnostic remains unrun. The selected `3a8d512` Linux checkpoint
failed its workspace restart test even though its production binaries built;
a future successful diagnostic cannot amend that failure or produce a candidate.
See `scripts/validation/small-native-smoke.md` for the exact invocation and scope.
