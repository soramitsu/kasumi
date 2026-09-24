# Five engine integration caller migrations

Target-only, main/master. No actual source edits or Cargo runs. This proposal
owns exactly `backup_checkpoint.rs`, `embedded_audit.rs`, `retirement.rs`,
`lifecycle.rs`, and `replicated.rs`. Root owns common/mod.rs and the other engine
integration files. `manifest.json` records actual, incoming-proposal and final
hashes; the incoming versions were byte-identical to actual source when prepared.

Prerequisites are store metadata revision2, current MemoryCore adapter
9001501726d33c8041c837ffdcda2550131a02993da5bb8d86e6add772382c5d, the engine helper,
root integration common patch ec254c91, engine same-core/codec API migration, and
store synthetic-backend follow-up 2c997182. Apply `callers.patch` against actual
source or copy only its five proposed files into the root combined target layer.
`incoming-followup.patch` is also included for exact target-layer composition.

Every physical scope creates its real NodeAdmission before NodeDisk/ScratchDisk,
uses that exact facade for SecurityAudit/database, and retains the same owners
through reopen. Distinct modeled processes use private sibling roots rather than
placing different cores in the same inferred persistent root. Existing archives
and backup objects share the already admitted owner instead of acquiring unused
extra metadata. Snapshot fixture codecs receive their actual retained scratch
owner. Paused synthetic redb tests use the new admitted backend constructor.

Backup workspace assertions subtract only PhysicalFixture's measured initial
installed disk metadata from real reserved counters; the original maintenance,
snapshot and proposal workspace assertions and payload limits remain. Explicit
old payload configs get their original bookkeeping conversion once before
PhysicalFixture adds only new disk metadata. Default configs keep canonical old
total semantics. No RSS ceiling or workload allowance is enlarged.

The stopped target cold-cache deletion regression now explicitly closes its
actual NodeStore, asserts zero live persistent file handles, deletes externally,
then pauses and reconciles the retained owner before cold reopen. Missing
bootstrap dependencies still reject serving; subsequent publication remains
subject to normal namespace fencing. There is no active-owner census shortcut.

Prepared checks: all 31 existing test entrypoints and Duration expressions are
unchanged, target Rust formatting passes, and git apply --check succeeds.
No typecheck/runtime proof is claimed. Run all-target/all-feature compile and the
five original integration binaries after coherent API integration, then preserve
failures and investigate any actual-owner assertions rather than relaxing them.
