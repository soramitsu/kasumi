# Atomic schema activation

`SchemaChangeSet` is an administrative provisioning/migration command. It names
one permanent `activation_id`, the exact source incarnation and schema epoch,
and up to 128 explicit create/replace actions in at most 8 MiB of canonical JSON.
Every replace also names the collection's exact document `data_epoch`. Duplicate
collection targets are invalid. No action edits document bodies or versions.

The database authorizes the current principal for every target before looking
up its permanent `(principal, activation_id)` identity. A matching request
returns the original success or deterministic failure even after ordinary
receipt expiry, later schema changes, encrypted restart or full restore. A
different request with that identity conflicts. `request.reference()` computes
the digest used by `schema_activation_status`; this read requires the same
principal and current administration authority on every original target and
durably audits release. The digest is an identity check, never authority.

For a new accepted identity, every source fence, schema, existing document,
unique index and metadata quota is validated against one ordered state. All
definitions and their indexes become visible in one generation, with one
increment of `schema_epoch` and `policy_epoch`. A rejected action leaves every
definition and index unchanged and records the rejection when the mandatory
receipt/audit budget can fit it. Exhaustion that prevents recording an outcome
returns an explicit error and accepts no schema effects. A canceled or timed-out
caller must resolve the same identity: its serialized proposal can still finish.

`Limits.max_schema_activations` is a required first-release field (default 4096,
valid 1–100,000). These operational records never expire or enter archived
document collections. Reducing their quota below the retained count is refused.
Snapshot accounting and recovery validate their exact retained byte count.

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
`schema-status <reference.json>` use the same private native methods.

The focused suite covers 32-collection installation, all-or-nothing structured
and text indexes, failed/replayed requests, source fences, scoped administration,
revocation, serialized resource growth, cancellation, encrypted restart and full
restore. Complete workspace regression evidence is captured with this change.
