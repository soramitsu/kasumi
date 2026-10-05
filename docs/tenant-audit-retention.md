# Tenant audit retention

Production standalone, Control, ordinary HA and target bootstrap install audit
placement and the shared node maintenance reserve before Raft replay. The leader
checks for work every 250 ms. Maintenance starts at 75% of the configured hot byte
budget and drains toward 50%, publishing verified, encrypted immutable segments
of at most 8 MiB. Permanent stream sequence numbers survive pruning and restore.
A failed or uncertain publication cannot authorize deletion of hot records.

Every runtime configuration must contain `tenant_audit_placements`, with exactly
one row for Control (`__kasumi_control`) and each configured application tenant,
including dormant staged tenants. Every row explicitly chooses
`{"kind":"local_replica_only"}` or a nested external destination. Missing, empty,
incomplete, duplicate or extra rows and obsolete `tenant_audit_archives` fields
are rejected. Local replica only keeps encrypted history beneath the store's
durable data directory in `tenant-audit-archives`. External placement selects an
additional filesystem or S3 destination; every replica still preserves the exact
required ciphertext in its own installed cache before applying pruning.
The preparing leader publishes and reads back its installed destination before
proposing a pruning transition. External publication is not repeated during
committed application. A publication failure during preparation leaves the hot
prefix intact and retryable without stopping Raft. A single encrypted pending
segment binds the stream, prior archive root and exact hot prefix; retries and restart
reuse its object identity and ciphertext. A changed prefix cannot adopt it.
For HA, configure the same S3 namespace on members if every leader must publish
to one external archive. Distinct member destinations do not receive additional
copies from other leaders. Every replica's private filesystem archive remains a
required durable copy independently of external placement.
Control makes its own explicit placement choice. Service security audit and retired
custody storage have separate configurations.

This fragment explicitly chooses local replica only for Control and an installed
S3 destination for one application tenant:

```json
{
  "tenant_audit_placements": {
    "__kasumi_control": {"kind": "local_replica_only"},
    "default": {
      "kind": "external",
      "destination": {
        "kind": "s3",
        "endpoint": "https://archive.example.internal:9000",
        "region": "us-east-1",
        "bucket": "kasumi-audit",
        "prefix": "deployment-a/default",
        "credentials_file": "/etc/kasumi/private/archive-credentials.json",
        "ca_certificate": "/etc/kasumi/private/archive-ca.pem"
      }
    }
  }
}
```

The credential file is read as one fresh atomic snapshot for every request.
Publish a replacement with owner-only permissions using atomic rename; a missing,
malformed or inaccessible replacement fails the request. Configuration does not
capture a constructor-time secret or fall back to environment credentials.
A filesystem choice uses
`{"kind":"external","destination":{"kind":"filesystem","directory":"/absolute/path"}}`.
Its directory must belong to an explicitly installed persistent root and must be
outside recovery generation deletion roots. It cannot be the private replica
cache itself. Standalone initialization installs its `data` and `backups` roots;
choose a separately named archive directory within an installed root.
Archive placement is durably bound to the installation: changing or deleting a
choice cannot silently redirect an existing archive on restart. A failed S3
operation does not switch to a different destination. Recovery target templates
require their own `audit_placement`; even a target with the same tenant name
chooses independently of the serving tenant's map. Staging publishes the tenant
entry and its selected placement together, and retries must retain that choice.

The following table describes placement coverage only. All other required runtime
and target template fields remain required; these choices are not complete
deployment configurations.

| Configured groups | Required placement choices |
| --- | --- |
| Ordinary `tenants` includes `acme`, and a target template also names `acme` | The map contains Control and source `acme`; `target_recovery.tenants.acme.audit_placement` is independently required and may differ. |
| Ordinary `tenants` is empty, with only target template `restore-only` | The map contains only Control; `target_recovery.tenants.restore-only.audit_placement` supplies the target choice. A `restore-only` map row is an unknown extra row and rejects. |
| Placement coverage for a Control-only role | The map contains only Control. The dedicated Control-only process topology remains an open integration gate; this row does not qualify that topology. |

The [target journal installation](target-node-installation.md) freezes the full
template-name and placement roster before the first target materialization or
archive side effect. Removing, adding or changing that roster rejects even when
no target archive has yet been published.

Application and Control maintenance share 128 MiB per node: a 64 MiB preparation
and proposal lane and a separate 64 MiB replica-application lane. Service security
audit reserves another 64 MiB. Installation fails if that capacity cannot be
reserved. Reserved maintenance can continue when ordinary admission is full;
these reservations do not increase for every tenant. Queued work retains its
storage owners and reservations until it actually finishes, and shutdown drains
workers and proposals before releasing storage.

A backup or replacement snapshot carries all archive dependencies named by its
root. Reopen verifies retained dependencies before serving; missing or corrupt
local archives fail startup. Retain wrapping keys required by archives and
completed backups. Filesystem contents are immutable history, not a disposable
cache that operators can remove to regain space.

The focused startup, archive failure, replay and backup dependency tests establish
these implemented boundaries. Live S3 fault drills, final disk-capacity accounting,
paginated tenant-history administration, and the full 3 GiB/endurance acceptance
remain open release gates. Existing service-audit commands are documented in the
standalone runbook and do not claim to export every tenant's retained history.
