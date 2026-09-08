# Durable backup sessions

The storage layer provides explicitly managed session capabilities. A full backup
session has an operator-chosen UUID. Its immutable encrypted intent is published
before its data objects. A single create-only `outcome.kasumi` records either a
completed checkpoint or a permanent abort, bound to the exact intent ciphertext.
The two outcomes compete for the same object and cannot replace each other.

A managed destination separates `sessions/<uuid>/intent.kasumi` and
`outcome.kasumi` from `sessions/<uuid>/objects/`. Only the latter can be reclaimed.
Ordinary history and audit archive objects use separate destination namespaces.
An abort proof can be created only by authenticating both immutable control
records and their identities; it retains the current storage capability. Cleanup
rereads the exact abort ciphertext before enumeration or deletion and checks the
capability while working. A corrupted, missing, pending, completed, or uncertain
outcome grants no cleanup authority.

Cleanup enumerates at most 256 object identities, deletes that page, and starts
again at the namespace head on a later call. It does not promise a permanent empty
namespace: uploads admitted before abort can arrive after a pass. Repeated cleanup
catches them while retaining both permanent control records. No accumulated
in-memory object inventory or whole-directory sorting is required.

Filesystem operations use captured directory descriptors, no-follow child opens,
create-only hard links, owner-only files/directories, file synchronization, and
directory synchronization. Temporary upload files are UUID objects within the
same reclaimable object subtree. Metadata publication links the complete file
outside that subtree before removing the temporary link. Cleanup cannot follow a
substituted directory symlink or accept a caller-supplied path.

S3 uses conditional single-object PUTs, signed ListObjectsV2 head pages, strict
bounded XML parsing, and per-object DELETE restricted to generated session keys.
The credentials for every request are freshly read as one atomic bundle. A failed
publication may already exist and must be resolved by authenticated readback.

The source storage purpose and wrapping-key catalog remain exact historical
identities, including the original HA replica. They are separate from the current
verifier's storage capability. Intent and outcome must name the same application
tenant/incarnation and retain the same original purpose. An authorized replacement
replica can encrypt an outcome under the authenticated original catalog after
fresh authorization of its wrapping dependencies. Reserved control/audit/custody
purposes cannot be used as application backup sessions.

The engine and native SDK require `CreateBackupCheckpoint { destination,
session_id }`. Persist the chosen UUID before invoking creation. Repeating creation
for a completed session verifies and returns its original checkpoint, even after
later writes. A pending session with a published root resolves its complete graph
before completion. A pending session without a root may be explicitly aborted.
Uncertain storage reads never count as an absent root or grant cleanup authority.

Native `BackupSessionStatus`, `AbortBackupSession`, and `CleanupBackupSession`
operations use database administrator authorization and final response fences.
Cleanup additionally carries a live credential/policy/cancellation guard into each
filesystem worker and retains its admission charge and shutdown registration until
the worker exits. Stopping the API waiter therefore cannot leave untracked deletion
work. Every deletion checks that stricter request guard.

Only complete graph verification constructs a checkpoint. Key lineage is a
constant-space SHA-256 commitment with domain `kasumi.full-backup-key-catalog-stream.v1`,
checked 64-bit record count, and explicit final marker/count. It records the
permanent intent catalog, root catalog, manifest pages in authenticated backward
chain order, resident chunks in forward order, and cold-history manifests/chunks
in their canonical traversal order. Repeated catalogs remain records. The outcome
must use the exact intent catalog; it adds no uncommitted key dependency.

Restore requires the permanently completed session and compares the verified graph
with that exact checkpoint. Local recovery also compares the authenticated original
source purpose with the explicit local recovery request, including backups with no
cold history. Copied cold-history objects retain their original purpose and catalog,
and restored metadata persists the containing backup session namespace so reads and
subsequent backups continue to find the copied objects after restart.

Live session access requires the current immutable application installation and
incarnation, allowing the authenticated original HA writer node and epoch to differ
from the verifier. A historical completed session requires an exact retained
restore-lineage checkpoint. Historical cleanup of an older aborted session requires
a future explicit source-authorization operation; it is not granted by the current
live API.

Remaining release work: paginated wrapping-key retention reporting/CLI, transitive
audit archive dependencies, live S3 acceptance, and the final release capacity and
endurance gates. These are not certified by the focused session tests.

## Operator commands

Use an application database administrator profile on the native administrative
listener. An initialized standalone installation supplies `profiles/default.json`
and the `local` filesystem destination.

```sh
kasumid backup create /var/lib/kasumi/profiles/default.json local /secure/full-backup.json
kasumid backup status /var/lib/kasumi/profiles/default.json local SESSION_UUID
kasumid backup verify /var/lib/kasumi/profiles/default.json local SESSION_UUID
kasumid backup abort /var/lib/kasumi/profiles/default.json local SESSION_UUID "operator cancellation"
kasumid backup cleanup /var/lib/kasumi/profiles/default.json local SESSION_UUID 256
```

Creation writes a private `*.backup-attempt.json` beside the requested checkpoint
before connecting to the server. This journal retains the session UUID,
destination, application resource, endpoint, and TLS trust. Keep it with the
checkpoint. After a connection failure or uncertain reply, repeat the identical
creation command. The server resolves that original session; completed sessions
return the original checkpoint even after later writes. A fresh authorized
credential may resolve it after the original credential family is revoked.
Changed destinations, resources, endpoints, or TLS trust require explicit operator
resolution using the original session identity. Status and verification accept
that identity directly with a currently authorized installed client profile.

Checkpoint outputs require an absolute path under an existing owner-only
directory. Publication is atomic and never replaces a different checkpoint.
Verification prints the authenticated checkpoint for the selected completed
backup. Aborting a session that already completed reports its completed outcome;
inspect that outcome before attempting reclamation. Cleanup performs one bounded
pass, with a limit of 1–256 objects. Repeat head passes to catch delayed uploads;
`more_objects_observed: false` describes that pass and cannot promise that a late
upload will never arrive. Completed backups, shared archives, intents, and
permanent outcomes remain outside cleanup authority.

Keep every wrapping-key generation required by completed backups, retained
archives, and permanent session control records. The checkpoint's
`key_lineage_digest` commits its authenticated key dependencies; a checkpoint or a
successful cleanup pass does not authorize key retirement. Maintain a separate
operator-key backup using `backup-operator-keys` and verify it with
`verify-operator-keys`. Ordinary backup cleanup never reclaims those operator keys.
