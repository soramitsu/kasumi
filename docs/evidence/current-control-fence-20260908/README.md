# Owned current Control quorum fence

Source `42c018ec3ac83ce0104c033d5a81c0a7ddbab6ac` requires a current Control
leader quorum, exact installation/partition, policy epoch and committed member
set including learners. Its owned observation keeps the original finite,
revocable credential and bounded metadata/work reservation. Failure or canceled
release permanently closes the observation; a later quorum cannot revive it.

Three encrypted quorum tests, strict engine/Raft Clippy, production server check
and formatting passed. Exact source, lockfile, logs and executable hashes are in
the manifest. The initial stale-local-leader test failure and compile correction
are preserved. This observation alone grants no physical-verifier capability;
fresh authenticated issuer registry/directive binding, remote publication and
global retirement/drain remain unfinished. These are scoped macOS ARM64 gates.
