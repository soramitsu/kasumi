# Existing catalog acquisition

`CustodyStore::open` and `TenantStorageSet::open_existing` acquire existing
storage through a retained catalog task. Both paths reject absent catalogs or
binding, generate no keys, and perform no metadata writes. A paired open holds
custody then application open gates. The custody binding is authenticated before
application keys are constructed. Both wrapped catalogs and the binding are
checked against one immutable encrypted read root; a borrowed cached catalog
must match that retained root exactly.

Every selected domain is explicitly `New` or `Borrowed`. New stores keep their
original capability and bounded first unwrap; their registered renewal workers
remain dormant. Borrowed stores retain their existing provider, gates, lease
anchor and renewal owner. A caller cannot use a different live gate to replace
that owner. An old handle already marked shut down is replaced only after its
registered worker list is observed drained; this opener never initiates shutdown
of an old cached handle.

A private ticket owns the prepared pair and gates. The recipient rechecks the
binding and accesses, then synchronously publishes only new slots and activates
already registered workers. There is no await, allocation or fallible operation
after the first new slot publication. A successful channel send is not ownership
transfer. Receiver cancellation, provider failure or failed binding validation
drains only new unpublished stores while retaining both relevant gates. Borrowed
handles are not shut down and their snapshot/capability deadlines are not moved.

`NodeStore::drain_initializers` now also joins these existing-catalog acquisition
tasks. Stop admitting new catalog work before final drain. Cancelled drains retain
unfinished handles; completed tasks are joined/reaped on the next acquisition.
A successful pair handoff transfers normal shutdown responsibility to its caller.

The pair create-or-open API has been removed. Fresh callers use
`initialize_catalogs`; existing callers use `open_existing`. See
[explicit catalog lifecycle](explicit-catalog-lifecycle.md) for durable recovery
intent and incomplete-state behavior. Direct single-store `TenantStore::open`
still requires a separate caller classification/removal. There is no process-wide
admission bound for arbitrary concurrent catalog requests.

## Validation status

Source-only. Rust 1.97.1 direct rustfmt and Git whitespace checks passed. No Cargo,
compiler, tests, native process, provider service or VM was started.

Seven new regression sources cover application unwrap failure and cancellation
after both new and borrowed custody selection, buffered new-pair abandonment,
missing binding, and unclaimed borrowed pairs whose binding changes before claim.
They check complete raw catalog/record hashes, untouched borrowed deadlines and
providers, drained new worker handles and physical node reopen after release.
The existing substituted-catalog test now exercises the public custody opener
and verifies borrowed handles survive rejection. All of these tests and the
normal lease/shutdown suite remain unrun.
