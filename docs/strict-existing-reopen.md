# Existing installation reopen

`TenantStorageSet::open_existing` requires both catalogs and their authenticated
custody binding. It unwraps the custody domain and checks the requested exact
application purpose before opening application keys, then compares the opened
catalogs and their distinct plaintext keys with that binding. It never calls
domain installation. The existing-only catalog requirement is checked inside
the per-tenant open gate, including after waiting for another opener; the
existing-only path cannot reach key generation or catalog publication.

`CustodyStore::open` already denotes an installed control domain and now uses
the strict catalog path. The default-off `test-utils` conveniences
`TenantStore::open_existing_fixture` and
`TenantStorageSet::open_existing_fixture` delegate to these same strict paths.
They do not expose fixture authority in production builds.

`open_existing_local(stores, audit)` accepts no initial policy, capacity defaults
or newly selected incarnation. Both domains must retain the exact local
deployment binding, the authenticated bootstrap manifest and all chunks must
exist, and the custody bootstrap commitment must match before startup. Missing,
unsupported or corrupt state is an error. Ordinary Raft replay and maintenance
startup remain part of opening an existing database; this API is not a promise
that a successful restart performs no storage writes.

Seven source regressions cover partial catalogs, a catalog disappearing while
an existing-only opener waits, missing/corrupt/authenticated-wrong domain
binding, exact standalone domain reopen after both stores drain, missing or
wrong local deployment, corrupt bootstrap manifest/body/custody commitment,
and the same committed local database reopening after complete shutdown.
These are uncompiled source tests until the scheduled frozen-source gates run.

The next integration boundary is explicit creation versus restart. At this
checkpoint `standalone::initialize` creates security state, while normal runtime
startup still creates initial Control and application state. Initial creation
must move into that explicit initialization boundary before standalone startup
can require strict reopen throughout. Operator recovery, selected restored
generations, activated-target recovery and original-serving readmission are
existing-installation paths. HA first enrollment and administrative tenant
creation require separately explicit installation handling. This checkpoint
adds the strict primitive; it does not yet claim all production callers use it.
