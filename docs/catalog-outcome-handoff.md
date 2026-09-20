# Catalog preparation outcome handoff

Fresh pair installation and strict existing pair/custody acquisition retain the
same private outcome ticket for successful prepared owners and ordinary
preparation failures. Only the recipient's synchronous `claim` consumes an error.
A successful channel send, a buffered result or a dropped receiver cannot claim
that error. An unclaimed error returns from the registered catalog task.

`NodeStore` records `JoinHandle<Result<()>>` for catalog work. Both final drain
and the admission reaper unwrap the task outcome as well as its join result.
The existing owner-local first-unreported-failure slot retains failure across
cancellation while another task is pending. It is consumed only by a completed
return to a drain/admission caller, with no intervening await. Claimed preparation
errors do not create a duplicate registry failure.

Success publication remains unchanged: validation runs before taking the prepared
owner, then new weak slots and already registered renewal workers publish without
an await, allocation or further fallible work. An abandoned successful ticket
drains only its new unpublished owners. Existing cached domains remain explicitly
`Borrowed`; their providers, capabilities, deadlines and renewal tasks are not
replaced, shut down, or extended by an unsuccessful opener. Preparation cleans up
new provisional stores before transferring its ordinary error.

This changes no public constructor signature or format. It adds no creation or
existing-state fallback, does not erase partial durable catalog installation, and
does not make node drain close successfully handed-off/shared stores. Callers
must still stop new catalog admission before final node drain. Worker-level
shutdown outcomes and the other remaining items in `startup-drain-outcomes.md`
are separate work.

## Verification status

Source only, based on root `7c43d673ca92b5ae443891453c04189b3a1a82ef`.
No Cargo, compiler, Rust tests, native provider processes or containers ran.
Rustfmt 1.97.1 and Git whitespace checks are the available mechanical checks.

New regression sources:

- `storage_domains::catalog_initialization::tests::buffered_preparation_error_requires_claim_before_registry_forgets_it` runs actual fresh preparation through a failing key provider and retains its typed error until acknowledged. Buffered abandonment must reach node drain; a claimed error must not reappear. No catalog is published or disk content changed.
- `storage_domains::catalog_initialization::tests::cancelled_catalog_drain_preserves_unclaimed_preparation_error` joins an abandoned buffered error, actually drops a drain while another owned task waits, and requires a later completed drain to report the same typed error.
- `storage_domains::catalog_initialization::tests::admission_reaper_reports_unclaimed_preparation_failure_before_new_work` requires a new acquisition to report the prior unclaimed error before starting new work; after that report, explicit fresh installation may succeed.
- `storage_domains::existing_catalogs::tests::buffered_existing_preparation_failure_requires_claim_and_preserves_borrowed_owners` injects an actual wrong application wrapping key, tests both new and borrowed custody plus claim/abandon, checks exact raw disk hashes and borrowed deadlines/identity, drains, and reopens the physical node.

Earlier cancellation tests now explicitly expect the previously lost
receiver-closed preparation error from their final node drain and require the
following drain to succeed. Existing success-ticket, shared borrower and joined
panic tests retain their original assertions and use the typed task protocol.
All behavior above still requires execution on the final integrated source.
