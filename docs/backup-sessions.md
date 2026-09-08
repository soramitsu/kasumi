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

Implementation checkpoint: the destination primitives and authenticated session
records are complete. Full-backup engine orchestration, native status/abort/cleanup
commands, completed-outcome restore enforcement, and paginated wrapping-key
retention reporting are the next integration step; the existing backup creation
entry points have not yet switched to this managed namespace.
