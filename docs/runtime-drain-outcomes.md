# Runtime propagation of typed drain outcomes

This source checkpoint depends on the typed leaf change `fac23817`. NodeRuntime
and AuthorityRuntime change their canonical shutdown result to DrainResult. Their
startup Runtime adapters forward that outcome without converting a completed
failure into an endlessly retried opaque error.

NodeRuntime closes lease gates, attempts target cleanup and every remaining owned
component even after an error, and records each child failure before its next
await. A complete failure marks actual shutdown completion but retains the exact
issue Arcs. Repeated shutdown returns those same diagnostics. Retained children or
failed route/group removal keep the runtime open for another drain. The exclusive
standalone lock remains held until the runtime drops and is its last declared
resource-bearing field.

The current concrete RuntimeLease shutdown closes its gate and returns an error
only after its sole renewal JoinHandle has joined. That returned error is recorded
as complete. This does not recover failures already discarded by its old worker or
live-trust registry. The separate worker ownership change replaces those leaves.

AuthorityRuntime merges typed store, audit and verifier results while conservatively
retaining its authority on an opaque IndependentAuthority shutdown error. Every
component is attempted. Its consuming serve loop retains its service fields across
ordinary cooperative Retained retries. Node serve uses the same typed startup
finish contract. Both combine service/listener and cleanup errors as original
objects rather than dropping later errors through Result::and.

The existing standalone shutdown regression is updated to
`completed_runtime_shutdown_failure_retains_diagnostic_and_installation_lock`.
It seals an actual installed audit writer, requires completed failure, checks
every repeated issue Arc, proves the installation lock still excludes another
owner, then drops and reclaims that exact installation. The new canonical behavior
does not erase a completed failure on the second shutdown attempt.

This is source-only: direct Rust 1.97.1 formatting and whitespace checks passed;
compilation and all tests are **UNRUN**. It must be combined with the leaf and
listener-task changes before compilation. The remaining inner database monitor,
live-trust, authority and OpenRaft worker census limitations still apply. Dropping
or aborting a consuming serve future can still drop its runtime and JoinSets;
these cooperative loops do not establish cancellation-safe serving ownership.
A retained serving wrapper and panic-safe ownership through the listener phase
remain required. This checkpoint does not complete shutdown or release acceptance.
