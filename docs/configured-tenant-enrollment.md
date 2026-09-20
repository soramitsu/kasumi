# Explicit configured tenant enrollment

HA node enrollment head format 2 separates immutable genesis input from required
point-addressed tenant records. Completing genesis requires an exact record for
each original tenant, with its incarnation and observed persisted bootstrap
fingerprint. Missing records and earlier head formats are rejected directly.
There is no migration or compatibility decoder.

A later configured tenant is a staging template. HA startup reads the authenticated
tenant record before any tenant key provider, authority lease or catalog probe.
Unrecorded and incomplete templates remain dormant. A committed serving route
without a complete local enrollment is rejected. Complete enrollments require the
recorded incarnation and bootstrap fingerprint. Fresh original readmission also
requires this record. Canonical restore targets remain owned by their target runner.

General file-key configuration validation now checks the path structurally. It
does not open every configured keyring. Actual provider-identity distinctness is
checked for selected installed domains, all explicit genesis domains, and the
selected tenant during live preparation. Fresh/existing pair validation still
checks independent application and custody keys and authenticated bindings.

## Control approval and original creation

ApproveTenant selects a typed proposal from configured incarnation, placement,
policy, limits, immutable wrapping identities and authority identity. The proposal
requires approved voter identities and pins. It does not require a tenant database.
An explicit Control operation commits the complete proposal in the append-only
`tenant_enrollments` collection. PrepareTenant verifies that exact committed
proposal after an actual Control quorum barrier under the original credential.

Preparation reserves node admission capacity and captures one suspend-aware
60-second deadline. Its retained task owns the original context and administration
gate until recipient handoff or completed cleanup. For an unrecorded HA template,
it acquires one issuer-verified epoch-one grant with no recovery checkpoint. This
original creation grant never starts renewal. Before key generation it records a
permanent creation identity and exact request/proposal, then stores the original
grant without replacement. The fresh pair initializer runs once.

Preparation verifies the exact fresh bootstrap and drains its database, stores and
catalog initializers before recording Prepared with the bootstrap fingerprint.
It checks the original grant and request around that commitment, then closes the
creation lease. Only this completed outcome permits a fresh serving admission and
strict existing open. No absent file, missing catalog or missing bootstrap chooses
creation on a replay. The fresh serving owner remains dormant until the existing
all-voter readiness, initialization and Control activation gates pass.

A resident original owner is classified explicitly as borrowed. Preparation may
write its exact prepared marker, but its handles are never inserted into abandoned
preparation cleanup resources. No ordinary selection error is interpreted as a
missing owner.

## Handoff and shutdown

The private startup ticket calls a typed synchronous handoff hook before removing
its owned result. Failed handoff leaves the owner retained for drain. Other startup
owners use the default no-publication hook. Enrollment handoff rechecks the original
context/deadline, approved proposal and storage access, then takes the same mutex
used to close enrollment admission. It publishes one generation-map entry and an
exact response selection with no await or fallible work after publication. Native
data routing still waits for committed activation.

Abandoned tasks close only newly owned leases, groups, databases and stores. Node
initializers are joined before release. Failed drains remain observable and owned
by the retained startup registry. Administration shutdown closes enrollment
admission, joins retained enrollment tasks, unregisters original groups and drains
all owned generations. Claimed owners belong to Administration; borrowed owners
are not closed by the initializer registry.

## Validation status and remaining work

This is source-only work. Direct Rust 1.97.1 rustfmt and Git whitespace checks are
the only checks. No Cargo, compiler, test, native process or VM was run.

New unrun regression sources:

- `completed_genesis_requires_all_tenant_records_and_rejects_the_old_head_format`
- `explicit_tenant_dispatch_and_prepared_outcome_never_restore_creation_permission`
- `cancelled_preparation_of_borrowed_resident_preserves_its_original_storage_owner`
- `closure_before_actual_enrollment_handoff_rejects_publication_and_preserves_borrowed_owner`
- `rejected_actual_recipient_handoff_retains_owner_until_cancelled_drain_is_joined`

The actual replicated runtime fixture retains all beta onboarding and mismatched
voter assertions. It additionally requires both staged tenant records and custody
catalogs to be absent after restart, before explicit preparation. Those integrated
TLS assertions, successful HA creation, authority failures/expiry during creation,
process crashes at every dispatch boundary, and all production builds remain unrun.
The borrowed-owner tests use actual standalone file keys and storage; they do not
substitute for the HA process tests.

Partial creation is intentionally not resumable with another grant. Shared-node
physical catalog cleanup and a permanent explicit abort/replacement workflow remain
open. An incomplete record remains dormant and cannot be retried as a new creator.
Standalone tenant staging, required local enrollment and retained live preparation
are now implemented in the [standalone enrollment checkpoint](standalone-tenant-enrollment.md).
The [explicit Control genesis change](explicit-control-genesis.md) replaces runtime
absence-selected initialization and retains HA node enrollment through acknowledged
outcome and actual resource drain. Their new source tests and the typed startup
drain tests remain unrun; these changes do not complete the final release gates.

Integration must preserve the independent singleton-catalog API changes and their
node-enrollment fixture spelling, plus the local/operator ownership fixes. Earlier
branch execution results do not validate this source.
