# Service audit installation and reopen

The service audit has one permanent stream identity and sequence space per installed
security catalog. `SecurityAudit::initialize` (or `initialize_with_archive`) creates
its canonical head only during explicit provisioning. It requires empty audit
namespaces. The caller must own the new node and security catalog; this is not an
operator repair command for an existing installation.

`SecurityAudit::open` and `open_with_archive` require an existing head. An empty hot
log does not authorize genesis creation. A missing, unsupported or inconsistent
head rejects admission before a writer starts. There is no legacy-head decoder,
implicit stream assignment or open-or-create API. Installed daemons and stopped
standalone operator operations use this existing path and existing security
catalogs. Standalone initialization explicitly provisions the stream. HA
`provision-node` explicitly creates the node file, security catalog and stream and
drains their owners; Control/application/issuer bootstrap enrollment remains a
separate operation.

Reopen validates one immutable encrypted read root: canonical metadata, the hot
sequence interval, exact hot byte accounting, the current archive reference and
any retained pending publication/ciphertext pair. Hot records are read one at a
time within the configured budget, after reserving the service maintenance
workspace. A pending publication must retain its exact ciphertext digest, range
and predecessor. Reopen does not need archive connectivity. It does not scan all
permanent archive history; explicit audit verification/export retains that role.
The same checks apply when sharing an existing in-process writer, together with
its original governor, destination, retention budget and current cached head.
An uncertain live writer cannot be reauthorized through another open.

The source regressions in `security_audit_existing_tests.rs` use private production
file keyrings, security capabilities and identity-bound node files. They cover
create/drain/immediate reopen, unchanged stream/sequence, duplicate creation,
missing empty/nonempty heads, corrupt format/counters/hot records, incomplete
pending publication and deleted-head rejection while a writer remains live.
Failed opens compare all logical audit namespaces and released admission charges.
Existing archival and cancellation regressions keep explicit first creation and
strict reopens.

This checkpoint is source-only. No compiler, functional, native or release gate
has run on it. Required focused gates are `security_audit::existing_tests`, the
complete `security_audit::tests` and retention tests, standalone provisioning and
local recovery tests, and native runtime restart coverage, followed by the combined
workspace checks. Runtime-owned target fixture adapters must be reconciled before
compiling the combined source.

Standalone endpoint selection is a separate open UX item: initialization should
accept explicit loopback native/MCP/admin ports before committing initial Control
topology. Editing listener configuration after init alone is insufficient to
change that retained topology.
