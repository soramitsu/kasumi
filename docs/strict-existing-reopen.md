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
`open_existing_replicated(node_id, stores, expected_incarnation, transport,
config, audit)` now returns `OpenedReplica { database, bootstrap }`. It accepts
no current initial policy, limits, endpoints or voter set. Under the bootstrap
open gate, it reads the authenticated original deployment bytes from both
domains, requires byte equality, decodes the exact replicated tag and typed
descriptor once, validates policy/limits/placement and canonical numeric voter
keys, and requires its incarnation to equal the non-nil expected UUID. It passes
that same descriptor through startup and returns it for an interrupted initial
enrollment. No second descriptor decode or write of reconstructed defaults is
needed. `RuntimeConfig::bootstrap` is no longer used by original-serving
readmission; current transport routes remain independently installed.

The initialization helper checks Raft's recovered `is_initialized` state before
initializing. OpenRaft treats any retained log or nondefault vote as initialized,
and its initialization command independently rejects non-pristine state. Thus a
reopened group cannot replace operational membership with its genesis voters.
The returned descriptor can only complete an enrollment that is still pristine.

Four additional source tests cover missing bootstrap/consensus identity,
corrupt manifest/body/custody commitment and authenticated wrong incarnation,
wrong genesis tag/domain/descriptor/canonical key or expected UUID, and real
committed endpoint/voter replacement followed by encrypted full close/reopen.
The latter installs a fourth learner, replaces a nonleader initial voter, then
reopens the current three voters through in-process transport and checks the
original deployment bytes, logical state, current membership and new endpoint.
Calling initialization again must leave that current membership intact.
No compiler or functional gate has run on this successor source yet.

HA first enrollment and administrative tenant creation still require their
explicit installation handling. The separate node-file opener review also
tracks redb writable-open effects on unrelated files; the regressions here
assert logical row non-mutation on rejection, not arbitrary file-byte
preservation. This checkpoint does not claim all production callers use strict
reopen or certify the unresolved persistent-disk integration.
