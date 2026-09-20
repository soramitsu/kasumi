# Explicit singleton catalog lifecycle

This source change starts from `635e330`. It removes `TenantStore::open`,
`CatalogOpen::CreateIfAbsent`, and the ambiguous single-domain fixture open
and custody helpers. It is a first-release contract, with no compatibility
alias, migration, decoder, or absence-driven retry path. Compilation and Rust
execution remain unrun for this change.

## Production domain boundary

`TenantStore::initialize_catalog` creates only a new singleton catalog;
`TenantStore::open_existing` opens only an installed singleton catalog. Both
accept only `SecurityAudit`, `LiveSignerTrust`, or `TargetJournal`. An explicit
namespace and matching storage purpose remain mandatory. The production entry
points reject fixture capabilities even when fixture features are compiled.

Application, standalone, serving, Node Control, independent authority, and
retirement custody domains use the private paired catalog owners. A public
single-domain call cannot bypass the authenticated application/custody binding.
Fixtures have explicitly named fresh and existing constructors, with separate
clock/access variants, to construct incomplete domains for contract tests.
These helpers are absent from production builds without fixture features.

The four remaining production installation call sites were:

| Installer | Physical creation and provenance | Explicit catalog and higher-level genesis |
| --- | --- | --- |
| `node_provision.rs` | Exclusively created node file with the installed database UUID | New service audit catalog, then audit genesis; its caller writes exact Data or Authority enrollment input and its completion record |
| `standalone.rs::initialize_owned` | Exclusive installation directory and lock, immutable preparation record, new physical database UUID | New service audit catalog and audit genesis, paired Control/application catalogs, policies and credential profiles; installation completion follows drain |
| `signer_runtime.rs` | New verifier file UUID derived from immutable verifier installation/node identity | New signer trust catalog, exact generation-one certificates, then a completion record; previous and partial head adoption branches are deleted |
| `target_journal_installation.rs` | New journal file UUID derived from Control incarnation and physical verifier identity | New independently encrypted journal catalog, then exact Control root/node journal genesis |

Runtime and authority service audit startup, signer verifier startup, target
journal startup, and stopped standalone operator access already selected strict
physical opens. They continue to require strict catalogs and their canonical
higher-level heads. Authority and Control application state is paired storage,
not another singleton creation path. Audit archive roots and watermarks, local
credential families, node enrollment, and local recovery journals are encrypted
records in their existing owned stores; they do not justify creating a missing
catalog during normal startup or recovery.

The initial inventory at `33678ae` found 198 direct old single-domain constructor
calls across 75 Rust files: 37 `open`, 106 `open_fixture`, 53 clocked fixture
opens, and two explicit-access clocked opens. Three of the 37 were the old
paired wrapper already removed before this patch's base. Four were production
singleton installers. The remainder were fixture or test code. There were also
90 references to the formerly ambiguous `with_custody` helper. Migration required
explicit lifecycle selection in fault images, restarts, repeated cached opens,
and shared fixture functions, rather than a mechanical rename alone.

## Ownership and publication

Single-domain preparation now registers an owned `Result<()>` task in the same
NodeStore initializer registry as the paired owner paths. The per-domain owned
open gate remains held through successful handoff or complete abandonment drain.
No node-wide registry lock spans provider calls or per-domain waits.

Fresh initialization rejects a live owner, any raw catalog, and orphan physical
rows before key generation. Publication rechecks catalog/record absence within
the actual durable write transaction. It cannot overwrite a partial or unknown
catalog. An uncertain commit or failure after catalog publication may leave an
incomplete installation; normal startup cannot silently finish higher-level
genesis and a repeated new-catalog operation cannot adopt that state.

Existing preparation never generates or saves a catalog. A cached live owner
must match the raw catalog, storage purpose, and exact serving/lifecycle gate
identities. It keeps its original provider, clock, lease deadline and workers.
An opener observes a completed old shutdown but never starts or takes over
shutdown of another owner's cached handle. Only a new unpublished owner obtains
fresh key decrypts and dormant renewal workers.

The private ticket carries either the prepared owner or its ordinary preparation
error. A successful channel send does not acknowledge ownership or error
observation. Claim checks the current raw catalog and original access before
any publication. New weak slots and worker activation publish synchronously;
borrowed slots and workers remain untouched. A dropped or buffered ticket closes
only new unpublished owners, and an abandoned error reaches the node registry.
The existing cancellation-safe drain retains task outcomes and unreported errors.

Node provisioning, signer store preparation, and target journal installation
retain the actual NodeStore until catalog outcome and initializer drain are both
observed. The signer CLI initializer now owns a detached operation that returns
only its drained unit outcome. Standalone operator/initializer outer ownership
is being completed independently; this patch changes only its creation call.
The caller must retain its node and installation/cleanup ownership through the
initializer drain if it cancels an open.

## Source regressions and verification limits

New tests in `kasumi-store/src/single_catalog/tests.rs` cover:

- `production_singletons_reject_paired_capabilities_before_provider_or_catalog_effects`
- `strict_singleton_creation_rejects_orphan_partial_and_existing_catalogs_without_mutation`
- `existing_singleton_requires_installed_catalog_and_never_repairs_cached_substitution`
- `buffered_singleton_success_publishes_only_on_claim_and_abandonment_preserves_borrowers`
- `borrowed_singleton_keeps_original_provider_clock_and_deadline`
- `buffered_singleton_preparation_errors_require_actual_claim_and_preserve_partial_installation`
- `cancelled_singleton_drain_retains_buffered_preparation_error`
- `cancelling_during_singleton_key_preparation_retains_actual_node_until_provider_drains`

Signer tests now reject repeated initialization, preserve strict reopen of the
completed verifier, reject adoption of a partial verifier, and separately prove
that a corrupt completed head is never reseeded. Existing file-key capability
mismatch, expiry, snapshot/crash, shutdown, audit archive, target journal and
lineage assertions use explicit creation or strict reopen as appropriate. No
assertions were disabled and no tests were newly ignored.

Root independently migrated the engine and Raft fixtures. Those changes include
explicit lifecycle choices for snapshots/fault images, original custody reuse,
and retained bootstrap checks; known file restart paths use strict physical
opens. Their source-review patch was recorded separately as
`/tmp/kasumi-explicit-singleton-engine-raft-fixtures.patch`, SHA-256
`b9d83baf59ed9599b0a144c38545d3b7e314196e3729b1e3f9dac6a83ae96796`.

Rustfmt 1.97.1 parsing/formatting and Git whitespace checks are the only executable
checks authorized for this patch. The workspace, strict Clippy, singleton/store,
signer, engine and Raft tests must run on the final integration. These source
regressions are not evidence of native HA, process crash recovery, filesystem
power-loss durability, capacity, endurance, or completed release acceptance.
Leaf worker drains still suppress some join outcomes as recorded in
`docs/startup-drain-outcomes.md`; this patch does not reinterpret those missing
outcomes as success evidence.
