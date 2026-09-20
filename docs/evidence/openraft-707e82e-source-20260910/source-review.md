# Retained OpenRaft shutdown outcomes

This is an uninstalled source patch against upstream v0.9.25, commit
`8815cdba2826f74e848acef361ad03f93bb1c3f8`. The published crate checksum is
`a97014fb78acb77be3a40ac2da305f6dd3a6b243f3a908ace87d29b3972eaafd`.
It does not change Kasumi's lockfile or claim dependency qualification.

The original shutdown joins the core but discards its retained fatal result.
It then removes the ticker handle before awaiting it. Cancelling that await
detaches the ticker; repeated shutdown returns success without observing it.

The patch changes shutdown directly to `Result<(), ShutdownError<NodeId>>`.
The result retains separate core and ticker failures. Both tasks join before any
failure returns; cancellation leaves their handles or terminal outcomes in their
owners. Unexpected runtime cancellation is `Fatal::Cancelled`, distinct from the
normal `Fatal::Stopped` return. There is no alternate compatibility shutdown API.

New source tests cover a real ticker owner retained across cancellation of two
joiners, normal and panicking ticker completion with repeated outcome observation,
an actually aborted ticker, and an actual Raft core callback that panics after
shutdown cancellation. Existing normal and panicked cluster shutdown tests also
require repeat calls to preserve their outcome.

The additional Raft-owner regressions are
`cancelled_shutdown_after_core_join_retains_ticker_and_both_failures` and
`aborted_core_still_drains_ticker_and_retains_distinct_cancellation`. They use the
actual `Raft::shutdown` implementation with controlled Tokio child tasks and a
test-only ticker constructor. The first covers all four normal/panic combinations,
abandons two waiters after the core result is retained while the ticker remains
held, and checks repeated final outcomes. The second actually aborts the core and
still requires the held ticker's later panic to be joined and reported separately.
Task-owned drop probes establish that core ownership ended and ticker ownership
remained through cancellation. This fixture does not instantiate a consensus
core, transport, state machine or storage; those remain separate integration gates.

All compilation and runtime tests remain **UNRUN**. Rust 1.97.1 rustfmt parsed the
changed Rust files, with warnings that upstream's nightly-only formatting
options are unavailable on stable. This does not constitute the upstream format
gate. Whitespace validation is separate. Upstream `make` and its feature matrices,
the Kasumi dependency integration, production builds and platform gates remain
required. The disabled mdBook guide points to the maintained lifecycle document.

The promise covers core and ticker joins. It does not establish that all state
machine, replication, snapshot, network, storage or application worker ownership
has drained. Kasumi must retain and join its actual subordinate storage owners and
report failures using its canonical complete-versus-retained drain contract before
this patch can support installation lock release or physical cleanup.
