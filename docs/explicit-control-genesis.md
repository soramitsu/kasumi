# Explicit replicated Control genesis

The first-release replicated bootstrap has a required tagged `genesis` value:
`application` or `control` with its complete payload. Missing tags, missing Control
payloads, missing lifecycle choices and unsupported variants are rejected. There
is no decoder for the earlier empty-Control bootstrap.

Explicit HA node enrollment freezes initial topology and the lifecycle installation
identity from its original input. Every initial voter receives the same payload.
Control requires the reserved namespace and NodeControl storage purpose; ordinary
replicated application bootstraps require their application purpose and reject the
Control namespace. The lifecycle root must bind the exact Control incarnation,
and each initial voter must match the topology endpoint and failure domain.

Control is installed as one deterministic logical baseline containing its reserved
schema, current topology document and explicit disabled/installed lifecycle state.
Its logical revision and revision base are 1. This does not create a Raft log entry,
applied position, membership, leader, quorum observation or lifecycle signature.
Subsequent committed commands advance from that base using their actual Raft index.
The baseline uses the normal bounded encrypted snapshot format and accounting.

The immutable deployment binding in both encrypted domains includes the tagged
bootstrap. The initial encrypted snapshot must exactly match that binding. Existing
opens verify the original baseline image; they never compare a later operational
topology to the genesis topology or reset current membership, routes or lifecycle
policy. The local enrollment receipt retains the original Control incarnation and
bootstrap fingerprint, bound to the original enrollment input. Startup requires
that receipt and compares it to the actual installed image and binding. The same
fingerprint participates in the existing cross-voter initialization check.

Runtime no longer creates a missing schema, topology or lifecycle installation.
Leaders require the installed schema and current topology through their ordinary
quorum read path. Followers require an actual observed leader and applied Raft
state before inspecting their own current schema, topology and lifecycle state.
Local inspection is not a current quorum proof. Approved later routes and policy
changes retain their existing authorization and validation rules.

Explicit HA enrollment now uses the existing retained Data startup registry.
Caller cancellation loses only its reply. Newly acquired nodes, audit writers,
pairs and databases remain in retained Resources until actual typed drain
completion. Both successful and failed results use acknowledged handoff; cancelled
enrollment can be joined through `NodeRuntime::drain_startups` after stopping new
startup admission. Completed enrollment is still required to reopen normally;
failed or interrupted partial installation is never adopted automatically.

The local runtime test fixture explicitly installs its schema and topology before
serving, matching the production standalone initialization contract. Lifecycle
integration and native RPC fixtures use actual NodeControl storage and the
mandatory Control baseline. Exact lifecycle installation replay still exercises
native credential-resource/RBAC checks. Existing lifecycle policy, recovery,
quorum-loss and strict-reopen assertions remain.

## Source validation and limits

Added tests (written, not run in this source-only task):

- `replicated_genesis_requires_explicit_tag_payload_and_lifecycle_kind`
- `control_genesis_is_deterministic_bounded_and_part_of_bootstrap_identity`
- `applied_control_requires_exact_schema_and_document_without_resetting_current_routes`
- `control_genesis_rejects_wrong_storage_purpose_before_deployment_publication`
- `strict_control_reopen_rejects_partial_genesis_without_catalog_or_raft_mutation`
- `cancelled_ha_genesis_retains_actual_node_and_error_until_acknowledged_drain`
- `failed_control_genesis_drains_actual_pair_before_returning_enrollment_error`

The engine tests include a snapshot round-trip at revision base 1 and actual
encrypted-store/public-open rejection checks. The lifecycle integration fixture
asserts real applied Raft state and a logical revision above that base after its
first lifecycle replay command. Enrollment cancellation pauses after actual Control
database creation, abandons the reply and first drain, proves physical exclusion,
then joins the retained error and reopens encrypted catalogs. The early-error test
exhausts the Control document budget after actual pair acquisition.

Rust 1.97.1 direct formatting and Git whitespace checks are the only execution in
this task. Compilation, Rust tests, native TLS processes, cross-platform gates,
capacity, crash injection, and production acceptance remain unrun. The checkpoint
tests establish ordinary early-error and cancellation ownership, not process-kill
durability or complete worker-panic propagation. Leaf worker outcome work remains
the separate typed drain project. Initial topology remains subject to configured
per-document/schema/work limits; this patch does not remove those limits.
