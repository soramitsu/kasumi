# Persistent extent owner: source foundation

`NodeDisk` is an unwired storage primitive. No production `NodeStore`, backup,
archive or daemon constructor uses it yet, and the production dependency graph
still uses the published redb crate. Neither scratch admission nor the tested
redb transaction prototype alone supplies persistent disk admission.

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
device/inode. It exposes no raw descriptor or `File` clone. Its Arc clones keep
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
shared scratch promises and shared poison. They have not been compiled or run.
The two device tests exercise dropping every handle and reopening after both
poison and abandoned uncertainty/pending promises. A deterministic file-close
pause also checks that an old destructor cannot unregister a newer owner of the
same inode, and a synthetic failed filesystem observation fences scratch until a
complete drained census. All fixture waits have a finite failure deadline.
Direct Rust 1.97.1 formatting and whitespace checks are source checks only.

Before production integration, the redb owner must cover creation, open/repair,
ordinary writes, close checkpoints and compaction as well as the admitted
transaction subset. Its current prototype `GrowthDenied` callback also needs a
distinct owner-failure result so a poisoned or invalid descriptor cannot be
reported as ordinary capacity exhaustion. Backup/archive publication and
deletion must hold these exact owners through final directory synchronization;
S3 objects need their separate installed capacity policy. Runtime configuration,
health/readiness reporting, durable startup enrollment, cross-platform tests and
the full upstream redb/fuzz gates all remain open.
