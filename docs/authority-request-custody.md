# Authority request child custody

This change replaces discarded authority command/lifecycle/maintenance join
handles with a fixed 32-slot registry backed by `BackgroundWork`. The installed
node governor reserves `authority_request_metadata_bytes()` before opening the
authority. Every supported opener now requires that charged budget; there is no
uncharged production opener or compatibility signature. The reservation covers
bounded task, registry, result-metadata, and join bookkeeping, not arbitrary
request bodies or opaque panic payload allocations.

The original request permit stays with accepted execution and then the returned
response fence. A one-shot channel delivers responses; the registry stores only
bounded terminal success/error metadata, never response fences or authority
references. A cancelled receiver destroys its undelivered response in the
original child. Original entry deadlines bound acknowledgement waiting and are
not restarted after preflight. Timeout returns `UnknownOutcome` after dispatch;
the existing permanent command/maintenance identity resolves the actual result.

`BackgroundWork` retains the actual child handle independently of cancellable
waiters. Admission observes real joins without a helper task or reaper. Normal
command rejections are successful worker completion and do not fence the node
or become resource-drain errors. A real child panic closes admission during
unwinding; actual joined panic/cancellation errors retain their original typed
error objects. Closing admission serializes with registry publication so a
shutdown census cannot miss an admitted child.

Shutdown returns the shared `DrainResult`. It joins request children before
waiting for original request/fence owners and the proposal mutex, persists
already observed issues before later awaits, and propagates typed completion
through server runtime/startup cleanup. An uncertain child census remains
`Retained`. Existing successful Raft storage-drain semantics are preserved.
An opaque Raft shutdown error remains `Retained` on subsequent retries; a later
opaque success cannot erase that earlier uncertainty.

This does not close G07. The installed OpenRaft API still lacks the full typed
core/ticker/network/storage-child outcome census required for release. Its
independent retained-error work and final qualification remain necessary.
Normal process-local response metadata lasts until registry join/reclamation;
it is not a permanent outcome archive. If the entire authority facade disappears
after normal execution, durable command/maintenance receipts remain the
authoritative resolution path. Global `BackgroundWork` custody still preserves
the actual handle and original panic/JoinError; it does not retain normal
business rejection metadata after the facade has gone away.

Added regression sources exercise a cancelled real public command caller,
acknowledgement timeout while real proposal work waits, actual panic and
cancelled/repeated drains, bounded registry exhaustion, metadata reservation
lifetime, and ordinary conflict without fencing. Existing tests retain their
normal successful-shutdown assertions. Only static formatting/diff validation
has run for this branch; Rust compilation and execution are pending the shared
frozen-checkpoint queue. No release acceptance is claimed.
