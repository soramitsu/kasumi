# Persistent extent owner: source foundation

> **Historical: redb-era design record (superseded 2026-09-24).** This record
> describes the `NodeDisk` source foundation between 2026-09-09 and 2026-09-19,
> when the production dependency graph still used the published redb crate.
> Every redb statement below is historical. The
> [native Kasumi KV engine](native-kv-goal.md) cutover removed redb and its
> vendored fork in `503e9a2`. The separate `4f62863` owner-failure prototype
> was not itself merged. From `b2876ef` (2026-09-20) until `503e9a2`, the root
> Cargo patch selected the vendored `redb-4.2.0` admission fork, which carried
> its own `CapacityDenied` versus `OwnerFailed` distinction. The storage engine
> is now `kasumi-kv`. The
> [binding decisions](first-release-goals.md#binding-decisions-2026-09-26) set
> its storage model and owner contract, including `CapacityDenied` versus
> sticky `OwnerFailed`.
> Later source adopted `NodeDisk` as the installed physical owner for
> production storage. That adoption is tracked in the
> [release ledger](production-release.md#current-verified-status) and remains
> open under G02. The wiring and test statements below describe the source of
> that time, not current behavior.

At this checkpoint `NodeDisk` was an unwired storage primitive. No production
`NodeStore`, backup, archive or daemon constructor used it yet, and the
production dependency graph still used the published redb crate. Neither
scratch admission nor the tested redb transaction prototype alone supplied
persistent disk admission.

An installation provides exact private roots on one filesystem, extent capacity,
a maintenance reserve, a filesystem free-space floor, and explicit open-file,
directory-depth, name-length and census-work budgets. Startup walks opened
directory descriptors and counts rounded `max(length, allocated blocks)` for
every regular file. It rejects symlinks, special files, hard links, filesystem
crossings and overlapping roots. There is no tenant-sized buffer or in-memory
inventory of closed files: census space depends on bounded depth, and live file
metadata depends on the configured owner limit. Root and ancestor descriptors
require filesystem support for shared/exclusive directory locks; failure has no
path-based fallback.

An exclusive root lock conflicts with shared ancestor locks held by a nested
owner, in either enrollment order. Same-process aliases of an identical physical
root roster share the installed owner and cannot change its budgets. Different
rosters cannot share a root. Each census opens an independent directory file
description; duplicating its old cursor would incorrectly reuse the directory
offset. Cancellation, traversal exhaustion or I/O failure never publishes a
partially counted owner. A successful census synchronizes inspected files and
directories before publishing its aggregate.

`NodeDiskFile` binds its opaque descriptor to root, parent, relative name and
device/inode. It exposes no raw descriptor or `File` clone. Reopening an already-live inode
is rejected: only an explicit `NodeDiskFile::clone` shares its registered owner.
Duplicate acquisition does not create a second backend or change accounting. Its Arc clones keep
the same registered owner alive. Explicit reservations precede physical growth,
and a failed budget check changes neither the file nor accounting. Mutation
rechecks the descriptor/name binding; substitution closes admission and cannot
authorize deleting the replacement. The host, filesystem and embedding process
are trusted, as in the current store. All mutations inside these roots must use
this owner; an external writer that ignores its exclusive locks is outside that
ownership contract. Lifecycle incarnation bindings remain a separate required
boundary and are not replaced by this disk identity.

Persistent quota includes closed files. Device promises include reserved bytes
not yet observed in allocated blocks, including sparse extents after handle
close. A successful sync retires only promises represented by observed blocks;
it does not reduce persistent quota. An unused growth reservation remains
uncertain even if syncing its shorter file succeeds. Closing that handle seals
the owner until reconciliation, so reopening cannot double-charge the promise.
Unexpected physical allocation is conservatively charged and closes admission.
There is no allocation multiplier or promise that another process, filesystem
snapshot, device failure or filesystem metadata allocation cannot cause ENOSPC.

The installed owner remains strongly retained in-process after all service
handles close. `pause` seals new reservations and file enrollment, and reports
whether file/backend owners still live. Already reserved I/O can drain within
its exact extent while paused; application request admission must already be
sealed by the caller. `reconcile` requires zero live owners and keeps the exact
root locks while doing a complete new census. Only then may it replace old
aggregate charges and reopen admission. No handle or Arc destructor credits
persistent capacity. Removing the installed accounting owner itself is not yet
an implemented uninstall operation.

`shrink_file` and `delete_file` consume the sole descriptor owner. A live reader
or backend clone prevents the operation. Under the registration mutex they
verify the same physical object, perform truncation or unlink, synchronize the
file/parent as applicable, close the descriptor, and then release the verified
charge. Failure or uncertain directory synchronization keeps all prior charge
and closes admission. Whole-owner reconciliation may resolve this only after
every file owner has closed under the retained root locks.

`NodeDiskFile::shrink(&mut self, len)` shortens a settled file while retaining
its descriptor, exclusive lock and registration. It requires the sole strong file
owner, checked under the registration mutex; explicit reader/backend clones must
have drained. Growth that has not materialized or synchronized cannot be
reclaimed through this API. A larger requested length is rejected without effects.
The operation verifies the physical binding, truncates, synchronizes the file and
parent, and verifies the same binding and resulting extent again before publishing
checked quota and shared-device promise reductions. The resulting per-file budget
matches the synchronized extent, so closing and reopening cannot lose or charge
the old extent again. It grants no permission to truncate pages still needed by a
higher-level database; a future backend adapter must separately serialize its own
read/write users around this mutable owner.

Any uncertain truncate, synchronization, binding or accounting failure preserves
all prior byte/promise charges, marks the file unsettled, and closes both persistent
and shared filesystem admission. Dropping that failed descriptor cannot release
those charges or reopen admission. Only a complete census after all owners close
may reconcile the physical result. Precondition rejection for explicit clones or
unsettled growth changes no file or accounting. At this checkpoint it was an
isolated primitive: production constructors still used their existing redb
backend, and this change did not qualify the uninstalled redb preflight
prototype.

Scratch and persistent owners now use one `DeviceDisk` promise mutex and the
maximum free-space floor of its installed registrations. The quota transition
is calculated before publication. A shared mutex poison permanently closes
device admission; one owner's census cannot repair that shared uncertainty.
The process registry retains each device identity even after its last registration
closes. Each registration owns an exact contribution to shared pending bytes.
Dropping an uncertain registration or one with unreturned promises poisons that
retained device; it cannot erase the promise or reopen admission through a new
scratch-only owner. Healthy zero-promise owner teardown releases only its policy
registration, and persistent installed owners stay retained separately.
An owner-specific stat, sync or physical-binding failure closes both kinds of
new growth through its device registration. A successful exclusive persistent
census clears only that owner's uncertainty. Synthetic device/free-space test
seams are `cfg(test)` only, unavailable to production and fixture-feature builds.

The initial regression sources cover repeat census, service/Arc reopen without
double charge, unused reservations, sparse extent retention, reserved-I/O drain,
maintenance headroom, exact denial, clone-blocked reclamation, path substitution,
cancelled/exhausted census, invalid/overlapping roots, bounded open metadata,
shared scratch promises and shared poison. All 13 NodeDisk tests and both
DeviceDisk tests passed in the actual frozen `7a21995` store run on macOS ARM64.
That [cohort failed a separate store identity assertion](evidence/first-release-7a21995-check-20260909/README.md):
126 tests passed, one failed and two were ignored; strict store lint did not run.
Its complete raw log retains each primitive test result. This is scoped primitive
evidence on that source, not a passing store suite or production capacity gate.
The two device tests exercise dropping every handle and reopening after both
poison and abandoned uncertainty/pending promises. A deterministic file-close
pause also checks that an old destructor cannot unregister a newer owner of the
same inode, and a synthetic failed filesystem observation fences scratch until a
complete drained census. All fixture waits have a finite failure deadline.
The same cohort passed workspace compilation and formatting with Rust 1.97.1.
Later integration source still requires its own execution.

Historical (redb, superseded 2026-09-24): before production integration, the
redb owner would have had to cover creation, open/repair, ordinary writes,
close checkpoints and compaction as well as the admitted transaction subset.
The separate, uninstalled redb prototype at `4f628637` distinguished
`CapacityDenied` from `OwnerFailed` and retained backend failure. At that
checkpoint the production dependency graph did not contain that change. From
`b2876ef` (2026-09-20), the root Cargo patch selected the vendored
`redb-4.2.0` admission fork. That fork carried its own distinction: a
`CapacityDenied` result rolled back the transaction without fencing the owner,
and `OwnerFailed` latched and fenced it. The fork stayed selected until redb
was removed in `503e9a2`. At the `4f628637` checkpoint, backup and archive
publication and deletion still had to hold these exact owners through final
directory synchronization, and S3 objects needed their own installed capacity
policy. Runtime configuration, health/readiness reporting, durable startup
enrollment and cross-platform tests were open. The upstream redb and fuzz
gates were abandoned with redb.

## Exclusive-open and live-shrink source checkpoint

The September 19 successor adds five regression sources, all **UNRUN** until a
fresh frozen-source gate executes:

- `duplicate_live_inode_open_requires_explicit_owner_clone`
- `live_shrink_requires_the_only_mutable_file_owner`
- `live_shrink_cannot_release_unmaterialized_or_unsynced_growth`
- `live_shrink_retains_identity_and_lock_with_exact_reopen_accounting`
- `live_shrink_failure_retains_charges_through_drop_and_fences_shared_device`

They use real private files, file locks, distinctive payload bytes and the
installed accounting owners. These primitive cases do not exercise encryption. The failure case injects errors before truncation,
after actual truncation but before file sync, and after file sync but before parent
sync. It checks physical length, retained charges before and after descriptor Drop,
shared scratch exclusion, and recovery only through a drained census. It also
substitutes a path and verifies the unrelated replacement is never truncated.
The existing destructor/predecessor regression now requires duplicate acquisition
to fail while its new owner remains registered and healthy.

At this checkpoint only direct Rust 1.97.1 formatting and Git whitespace checks
had run for this successor. These cases did not execute redb, wire production
disk admission, qualify recoverable quota errors, or replace the release's
capacity and platform gates.

## Node envelope inspection and publication prerequisite

`NodeDiskFile::identity` returns the existing opaque journal identity after
checking its exact root, parent, name and descriptor. It grants no file access or
ownership. `sync_all_and_parent` retains that same owner while synchronizing the
file and its held parent, then checks the binding again before settling growth
promises. A failed sync retains prior charges and seals admission; retry or handle
Drop cannot reopen it. Existing length and bounded-read methods provide envelope
inspection without exposing a descriptor or creating a second acquisition.

Three additional real-file regression sources are **UNRUN**:

- `envelope_identity_and_durability_retain_custody_until_the_last_handle_closes`
- `envelope_inspection_and_publication_reject_inode_and_parent_substitution`
- `uncertain_envelope_parent_sync_preserves_charges_through_close_and_census`

At this checkpoint only direct Rust 1.97.1 formatting and Git whitespace checks
had run. These methods prepared the future canonical NodeFile adapter; they
added no alternate backend, production constructor, or recoverable redb
capacity contract. Production persistent disk admission was still unwired at
that time.
