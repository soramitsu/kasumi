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

`open_existing_local(stores, audit, expected_incarnation)` requires a non-nil
installed incarnation and accepts no initial policy, capacity defaults
or newly selected incarnation. Both domains must retain the exact local
deployment binding, the authenticated bootstrap manifest and all chunks must
exist, and the custody bootstrap commitment must match before startup. Missing,
unsupported or corrupt state is an error. Ordinary Raft replay and maintenance
startup remain part of opening an existing database; this API is not a promise
that a successful restart performs no storage writes.

For standalone application catalogs, the decoded bootstrap tenant and incarnation
must also equal the authenticated storage purpose before engine installation or
Raft startup. An otherwise valid authenticated bootstrap cannot substitute a
different standalone generation.

The required expected incarnation is checked for every local purpose, including
Control whose storage purpose does not itself contain an incarnation. This
comparison uses the already decoded generation before startup. No second
whole-state decode or compatibility wrapper is used.

Nine source regressions cover partial catalogs, a catalog disappearing while
an existing-only opener waits, missing/corrupt/authenticated-wrong domain
binding, exact standalone domain reopen after both stores drain, missing or
wrong local deployment, corrupt bootstrap manifest/body/custody commitment,
an authenticated bootstrap naming another standalone incarnation, a nil or
mismatched configured Control incarnation, and the same
committed local database reopening after complete shutdown.
These are uncompiled source tests until the scheduled frozen-source gates run.

The next integration boundary is explicit creation versus restart. At this
checkpoint `standalone::initialize` creates security state, while normal runtime
startup still creates initial Control and application state. Initial creation
must move into that explicit initialization boundary before standalone startup
can require strict reopen throughout. Operator recovery, selected restored
generations, activated-target recovery and original-serving readmission are
existing-installation paths. Activated-target serving recovery now uses strict
node and domain opens; its engine path already requires the published bootstrap.
Original serving readmission now uses strict catalog opens and selects
`open_existing_replicated` or the local existing-only path. Strict replicated
open requires the exact immutable deployment in both domains, a published
bootstrap and custody digest, the decoded incarnation, and the retained physical
Raft node/group identity before engine installation. A live HA gate must bind
that exact node and incarnation too. The initial three-voter placement and
failure domains stay immutable, while current operational membership is
recovered by Raft and is never reset to the initial placement on reopen.

The explicit first-enrollment branch remains separate from existing-only mode.
Four additional source tests cover missing bootstrap/consensus identity,
corrupt manifest/body/custody commitment and authenticated wrong incarnation,
initial placement/policy/capacity substitution, and an encrypted three-replica
full close/reopen preserving committed state and membership using in-process
transport. No compiler or functional gate has run on this source yet.

HA first enrollment and administrative tenant creation still require their
explicit installation handling. The separate node-file opener review also
tracks redb writable-open effects on unrelated files; the regressions here
assert logical row non-mutation on rejection, not arbitrary file-byte
preservation. This checkpoint does not claim all production callers use strict
reopen or certify the unresolved persistent-disk integration.
