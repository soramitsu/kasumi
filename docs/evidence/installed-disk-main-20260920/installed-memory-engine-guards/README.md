# Engine storage-memory integration — proposed, unimplemented

All work remains in /Users/mtakemiya/dev/kasumi on master. This layer depends on
node-disk-memory/metadata.patch and installed-disk-core-adapter/adapter.patch.
Neither proposal has been applied. Do not imply these checks currently exist.

## Required binding

The exact Arc<MemoryCore> retained by NodeAdmission must be pointer-identical to
both NodeDisk::memory() and ScratchDisk::memory() carried by each store. Policy
equality or a new adapter around the same settings is insufficient. TenantStorageSet
already requires its application and custody stores to share one NodeStore.

Add a checked NodeAdmission helper accepting the actual store; it compares a
trait-object coercion of memory().clone() to both physical owners without creating
another core or charging a duplicate owner. Reject mismatches before archive
construction, durable head writes, bootstrap binding writes, and child dispatch.

SecurityAudit::initialize/open must check before constructing default archives;
their explicit destination variants must check in open_inner before live-writer
lookup, maintenance acquisition or persistent head access. Supplied external
archive ownership needs its own future explicit-owner contract; this guard alone
does not prove a trait object's implementation shares a core.

Check application storage at the entrance of prepare_replicated_restore,
open_replicated_inner, open_existing_local, open_local_inner, restore_local,
open_target_replica, open_serving_target and RetiredCustody::open_replicated.
initialize_replicated takes an already-created Database; enforcing the construction
invariant covers its installation writes without a second admission parameter.

Database::new currently consumes an already-started RaftGroup and returns Arc.
It has nine call sites. Simply changing it to Result and dropping a mismatched
group is not an adequate failure-ownership contract. Validate a required typed
construction context before group creation, or preserve the supplied group in
an explicit retained cleanup result. Direct callers must be updated together;
do not keep an unchecked public compatibility constructor.

## Fixture propagation

Construct the intended core/facade before opening any disk, then pass its exact
Arc through persistent, scratch, audit and database setup. Existing reopen uses
that same core and a fresh runtime facade only after prior positive drain.
Fixed explicit payload caps retain their original boundary; add only the actual
new metadata components using the canonical planning helper. Configured total
caps must use resolved_fixture_total_bytes and add new metadata once.

Engine tests/common::security_audit and existing_security_audit currently create
a new default governor after receiving an already-open NodeStore. Replace that
contract with a required explicit facade; never discover or reconstruct a core
from a bare trait object. Update all integration fixtures and their reopen paths.
Pure codec fixtures may use an explicit bounded TestDiskMemory; fixtures executing
NodeAdmission-backed operations must use the actual MemoryCore for both layers.

## Validation

Reject a distinct core with identical policy before files/head or workers change;
verify the original owner's charges and healthy state remain unchanged. Accept
a fresh facade on the same core after the old facade closes. Preserve original
quota-denial assertions, metadata charge lifetime and actual-child shutdown tests.
This design alone does not provide those tests or close the release goal.
