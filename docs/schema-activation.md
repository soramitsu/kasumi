# Atomic schema activation

`SchemaChangeSet` is an administrative provisioning/migration command. It names
one permanent `activation_id`, the exact source incarnation and schema epoch,
a required immutable `read_set`, and up to 128 explicit create/replace actions
in at most 8 MiB of canonical JSON. At most 512 read assertions bind current
document versions/absence, collection epochs, snapshot epochs and a trusted
`Before` deadline. Referenced collections require current Read authority in
addition to each target's Admin authority.
Every replace also names the collection's exact document `data_epoch`. Duplicate
collection targets are invalid. No action edits document bodies or versions.

The database authorizes the current principal for every target before looking
up its permanent `(principal, activation_id)` identity. A matching request
returns the original success or deterministic failure even after ordinary
receipt expiry, later schema changes, encrypted restart or full restore. A
different request with that identity conflicts. `request.reference()` computes
the digest used by `schema_activation_status`; this read requires the same
principal and current administration authority on every original target and
durably audits release. Original dependency collections also require current
Read authority. The digest is an identity check, never authority.

Fresh ordered activation checks its immutable transaction assertions before
publishing any schema effects. A successful activation increments schema and
policy epochs, so its pre-transition Snapshot is not evaluated again on
response release or historical replay. Its original Before deadline and native
credential lifetime still fence that invocation's acknowledgement; an expired
acknowledgement is resolved through current status admission.

Status accepts `ReadSchemaActivation { reference, read_set }`. Its required
explicit current read-set belongs to this lookup only and does not alter the
stored effect identity. Current assertions are evaluated against a coherent
generation and retained through audited response encoding. A stale lookup
returns an error without changing the original committed receipt. The old bare
reference JSON request is rejected.

For a new accepted identity, every source fence, schema, existing document,
unique index and metadata quota is validated against one ordered state. All
definitions and their indexes become visible in one generation, with one
increment of `schema_epoch` and `policy_epoch`. A rejected action leaves every
definition and index unchanged and records the rejection when the mandatory
receipt/audit budget can fit it. Exhaustion that prevents recording an outcome
returns an explicit error and accepts no schema effects. A canceled or timed-out
caller must resolve the same identity: its serialized proposal can still finish.

`Limits.max_schema_activation_bytes` is a required positive 64-bit byte budget
(default 64 MiB). Permanent identities have no lifetime count ceiling. Each new
identity reserves its complete encoded key/value plus bounded error-outcome
headroom before publishing definitions; the terminal entry retains only its
exact byte charge. These records never expire or enter document archives.
Reducing the budget below retained bytes is refused. Both streaming and resident
snapshot validation check exact bytes. The former count field is rejected.

`read_schema` accepts explicit target names and returns a quorum-coherent
incarnation/schema epoch and each present definition/data epoch or explicit
absence. It works before initial provisioning and requires Admin, without a
Read grant. The Rust database, private native administrative listener and pinned
mTLS Rust admin SDK expose read, activation and status. Data RPC and MCP do not expose them.
Explicit single-collection administrative operations share the same validation
rules; an application installer should use `SchemaChangeSet` to provision its
dependent collection set together.

This contract currently covers resident schemas. A collection with archived
document references refuses schema/index replacement, including in a larger
bundle. Cold index/schema rebuilding needs a separately verified rebuild
generation before activation; it is not implemented by this operation.

`kasumictl read-schema <request.json>`, `activate-schema <request.json>` and
`schema-status <lookup.json>` use the same private native methods.

The focused suite covers 32-collection installation, all-or-nothing structured
and text indexes, failed/replayed requests, source fences, scoped administration,
revocation, serialized resource growth, cancellation, encrypted restart and full
restore. The new schema-fence tests and complete workspace gates must pass before this
branch is accepted; retained historical evidence does not establish that result.
