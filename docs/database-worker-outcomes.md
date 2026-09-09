# Database worker shutdown ownership

This source checkpoint changes the installed database seal monitor and automatic
tenant-audit worker to retain their actual terminal failures. Explicit shutdown
signals a shared stop watch, joins each supervisor in place, and records original
errors before another await. It never aborts either supervisor. An unexpected
worker exit seals request work and response release immediately; its join handle
keeps the terminal cause for shutdown.

Each worker owns one bounded blocking-child cell in Database, outside its
cancellable supervisor future. The cell acquires its slot before dispatching
work, retains the actual JoinHandle through cancellation, and preserves the first
JoinError in a stable DrainIssue. A new run cannot replace an unclaimed attempt or
receive its output as a different operation. Shutdown joins the supervisor, drains
the retained child, and only then drains work registrations. This includes an
externally aborted supervisor whose still-running child subsequently panics.

Retention checks return only a boolean. Audit preparation returns its bounded
prepared segment, engine, maintenance pool, permit and work registration, with no
Database reference. A completed unclaimed result therefore does not create a
permanent owner cycle. Its explicit drain drops the permit and registration
before the work census. Physical store references remain owned until the
database's complete shutdown and its caller's final drop.

An audit worker waiting for the proposal gate or shared preparation permit has
not dispatched work. These waits observe shutdown and release their registrations
without requiring another tenant to drain first. Already-dispatched blocking work
and consensus proposals retain their ordinary owned completion path. Archive
connectivity and proposal errors remain retryable; a blocking-task panic or abort
is terminal and keeps its original typed cause. Existing archive-before-prune
rules are unchanged.

Four regression sources exercise actual encrypted stores and Tokio workers:

- `cancelled_database_drain_keeps_monitor_panic_before_pending_audit_child`:
  a real monitor blocking panic is joined while an actual audit child is held;
  cancelling and retrying shutdown preserves the original issue Arc and physical
  exclusion through completion.
- `aborted_database_monitor_retains_its_blocking_child_and_distinct_panic`:
  aborting the supervisor leaves its running child installed; a subsequent child
  panic and the distinct supervisor cancellation both survive repeated shutdown.
- `database_audit_blocking_panic_is_terminal_and_retained`: the actual installed
  audit worker fails closed after its blocking preparation panics, counts the
  failure, and returns the same original error on repeated drains.
- `database_shutdown_cancels_undispatched_shared_permit_wait_before_other_tenant_drain`:
  an aborted worker's successful unclaimed Prepared retains the shared permit.
  Another tenant still shuts down before that owner drains. Draining the first
  owner releases both permit and registration before physical reopen.

All held blocking callbacks have finite failure deadlines and a guard that
releases them on assertion failure. These are cancellation/panic tests, not
process-kill or host-failure tests. Direct Rust 1.97.1 formatting and whitespace
checks pass. Compilation and all four regressions remain **UNRUN** until the
combined frozen-source gate executes.

This change does not qualify OpenRaft's separate internal-worker census, install
the pending upstream shutdown patch, or turn Database Drop into an abandoned-owner
registry. Callers must retain Database through explicit shutdown; the server's
retained serving owner supplies that separate boundary. Opaque Raft failures
continue to require retained ownership. Final production, capacity and recovery
gates remain open.
