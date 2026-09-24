# Explicit catalog lifecycle

The first-release pair API has two operations: `initialize_catalogs` for explicit
fresh enrollment and `open_existing` for existing state. The former rejects any
installed catalog or physical orphan metadata. The latter authenticates both
catalogs and the binding and never generates keys. `TenantStorageSet::open` and
its create-or-open fixture helper are removed without aliases. Fresh fixture
setup uses `initialize_catalogs_fixture`; restart fixtures use
`open_existing_fixture`. Raw binding assembly is crate-private; explicitly
clocked fault fixtures retain a test-utils-only domain assembler. It is not a
production opener.

## Original target creation

The target journal persists the original Materialize command identity before
creating a node file. The returned `MaterializationNode::{Created, Existing}`
retains that decision for the caller. Only the original live `Created` owner may
initialize catalogs, once. Exact Materialize replay and ResumeMaterialization
strictly open the bound file and existing catalogs. Missing files or partially
initialized catalogs do not recover creation permission. Provider construction
and pair acquisition remain under the original operation, gates and deadline.

Generation shutdown joins all node catalog initializers before relinquishing the
physical owner or claiming deletion. Cancelling shutdown leaves the generation
owner and its unfinished initializer handles reachable for another drain.

## Local recovery preparation

Local recovery journal format 3 requires a preparation state. Unsupported older
records are rejected directly. The same encrypted atomic batch records each exact
phase/request/binding and its transition before work is dispatched:

1. Uncreated commits CreationDispatched before exclusive node creation.
2. The original live node initializes the fresh pair. A retry can only verify
   the exact file and both installed catalogs. It can record CatalogsReady when
   a complete catalog publication survived a lost result.
3. CatalogsReady commits MaterializationDispatched before invoking the restore.
4. Every later attempt requires the existing bootstrap and exact restored
   lineage; no bootstrap absence can choose a second restore.

Public local start/status/resume/stop operations run in a retained joinable owner.
Caller cancellation cannot release the installation lock while its operation is
still running. `drain_operations` joins those owners after admission stops.
Target resources remain owned through shutdown, and all catalog initializers
are joined before their nodes are released. Fresh standalone initialization also
retains its node, stores and database through every failure and final drain.

A stopped local generation claims the exact deterministic Prepared/Ready node
header before deletion. This supports cleanup after a lost physical-binding
journal commit. It neither opens nor recovers the KV engine. Empty, torn, linked, substituted
or unrelated files are preserved and prevent a successful cleanup receipt.

## Explicit incomplete states and integration requirements

A dispatched creation that did not publish a bound, complete catalog pair cannot
be resumed as a new creation. A dispatched restore without a valid completed
bootstrap cannot be rerun by this local coordinator. Both require permanent stop
and a new target incarnation. These are fail-closed incomplete recovery workflows,
not passing release recovery gates. Stopping a torn or unrecognized node file
also needs explicit operator resolution; the database does not delete it.

The direct single-store `TenantStore::open` API remains for separate removal.
The obsolete management restore family has two pair `open` callsites in this
base; integration requires the independently owned canonical administration
removal, not an alias. The branch also requires the integration's baseline
fixture/compiler corrections. The separately frozen retained drain-outcome patch
63abded must be integrated; its startup registry selector must retain LocalOperator.
Ordinary catalog preparation error delivery still lacks an actual-recipient error
acknowledgment; cancellation can currently lose that reported failure. That
separate protocol issue is not fixed here.

Standalone administrator recovery and other older offline operator APIs outside
local recovery have not been converted to the retained operator wrapper in this
change. Runtime enrollment of newly configured tenants remains a separate required
production workflow. Startup must not initialize missing tenants to compensate.

## Source evidence

No Cargo, compiler, test, native process or VM was run. Direct Rust 1.97.1 rustfmt
and Git whitespace checks are the only checks. Added regression source covers:

- target file original Created versus Existing replay, missing files and missing
  catalogs, with unchanged rejected bytes;
- target generation cancelled shutdown during a paused catalog provider and the
  exact node cleanup lock after the initializer is joined;
- cancelled local status holding stopped-installation ownership until joined;
- missing/empty file rejection after durable creation dispatch;
- lost file binding cleanup accepting only the original node identity;
- replay resolving fully committed catalogs before restore dispatch;
- incomplete catalogs and dispatched restore rejecting recreation across restart.

Existing complete local recovery and unrelated-file/archive cleanup assertions
remain in place. All new and existing test cases remain unrun on this source.
