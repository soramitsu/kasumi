# Cold startup owner and delivery

Cold node and authority opens run in registered tasks. The initiating future
receives a private ticket; successful oneshot delivery alone does not transfer
a runtime. The recipient consumes the ticket and returns the public runtime in
one synchronous transition. A rejected or buffered-and-abandoned ticket retains
its original runtime until shutdown has completed. Neither cancellation nor a
failed drain authorizes fresh admission, another physical file open or reuse of
a stopped serving instance.

`NodeRuntime::drain_startups` and `AuthorityRuntime::drain_startups` join their
registered startup owners. Callers must stop admitting new opens before a final
drain. Cancelling a drain retains unfinished handles. Terminal tasks are joined
and removed during the next admission or explicit drain; committed runtime
handles are never shut down by this registry. The successful recipient is then
responsible for normal runtime shutdown.

The startup task retains signer verifiers, service audit stores/writers, complete
storage pairs, databases and authority instances immediately after each opener
returns. Early errors run an explicit drain before returning their error. The
standalone installation lock stays with that partial owner until all successful
setup has finished and the runtime is ready for ticket delivery. Custody probes,
retired source runtimes and administration workers are retained before later
registration can fail. These stores belong to newly claimed exclusive physical
nodes opened in this startup operation; the scope does not accept another
runtime's borrowed cache owners.

A drain failure is recorded with structured logging. The same owner is retained
and only its idempotent shutdown is retried, starting at one second and doubling
to a maximum thirty-second delay. A persistent failure keeps the startup task
live and its resources unavailable for reopen. Once actual drain succeeds, its
first failure still returns as an error from the join or failed open. There is
no successful cleanup receipt derived merely from a failed attempt or timer.

The strict existing composite openers now have a separate source-only
[prepared/borrowed ownership protocol](existing-catalog-ownership.md). No global
cache sweep or Arc-count ownership inference is used. Remaining create-or-open
APIs, Control genesis publication, process-wide startup admission/resource limits,
and final acceptance remain open.

## Validation status

Source-only; no compilation, native process, tests or provider service has run.
Direct Rust 1.97.1 rustfmt and Git whitespace checks passed. New test sources cover
buffered cancellation, actual-recipient ownership, cancelled join plus failed
shutdown followed by real drain, and an actual production-file-keyring standalone
startup rejected by a missing audit head. The latter verifies repeat rejection,
retained missing state and exclusive node/installation reopen after completed
drain. All four tests, existing lifecycle/lease tests and combined strict gates
must run before this source provides functional evidence.
