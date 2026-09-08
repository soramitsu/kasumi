# Tenant audit retention

Production standalone, Control, ordinary HA and target bootstrap install audit
placement and the shared node maintenance reserve before Raft replay. The leader
checks for work every 250 ms. Maintenance starts at 75% of the configured hot byte
budget and drains toward 50%, publishing verified, encrypted immutable segments
of at most 8 MiB. Permanent stream sequence numbers survive pruning and restore.
A failed or uncertain publication cannot authorize deletion of hot records.

Every runtime configuration must contain `tenant_audit_archives`. An explicit
empty map selects the private filesystem archive beneath each store's durable
data directory, in `tenant-audit-archives`. An override selects an additional
filesystem or S3 destination for that tenant; each replica still preserves the
exact required ciphertext in its own installed cache before applying pruning.
The Control tenant can have its own override. Service security audit and retired
custody storage have separate configurations.

This fragment uses an installed S3 destination for one application tenant:

```json
{
  "tenant_audit_archives": {
    "default": {
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
```

The credential file is read as one fresh atomic snapshot for every request.
Publish a replacement with owner-only permissions using atomic rename; a missing,
malformed or inaccessible replacement fails the request. Configuration does not
capture a constructor-time secret or fall back to environment credentials.
Filesystem overrides use `{"kind":"filesystem","directory":"/absolute/path"}`.
Archive placement is durably bound to the installation: changing or deleting an
override cannot silently redirect an existing archive on restart. A failed S3
operation does not switch to a different destination.

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
