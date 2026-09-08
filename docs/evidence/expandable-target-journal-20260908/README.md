# Expandable target journal

Intermediate macOS ARM64 evidence for `ad71568`, integrated at `8c5cacf`.
Permanent intent/generation counts use checked 64-bit counters and have no fixed
lifetime quota. One configured byte budget retains per-intent completion and
per-generation stop/activation capacity. Capacity may change after old journal
owners drain; installation identity remains exact.

The encrypted journal test exhausts actual charged bytes, expands capacity,
retries the unchanged original phase, fills the budget again, publishes a reserved
permanent stop and reopens it. Unsupported/unversioned/missing heads and forged
wide counts fail without rewriting retained records. One focused journal test,
nine materialization-filter tests, a limits test and affected strict Clippy passed.
Combined source `a59ddb4` passed fixture-free server checks and the strict private
key reader test. Source/log/executable hashes are in `evidence.json`.

This exercises two actual phase identities; it is not the 100,001-record retention
gate or a physical capacity measurement. Final-source/platform gates remain open.
