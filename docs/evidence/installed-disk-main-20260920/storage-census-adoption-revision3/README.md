# Fixed storage census and concrete opening/request custody

This is a target-only adoption prerequisite on `/Users/mtakemiya/dev/kasumi` master. It contains a concrete fixed census, mandatory provider wiring, a registered physical opening owner and a closed NodeTables request adapter. It is not the completed NodeDatabase migration or a total memory/RSS bound. No production caller chooses an optional census, legacy format, compatibility mode or fallback.

## Implemented custody

`MemoryCore` includes the census's checked fixed slot allocation in initial bookkeeping, admits that complete base before allocation, allocates the slots, and binds the exact installed trait-object data address before publishing the core. Binding creates no Weak, so existing unpublished `Arc::get_mut` sampler initialization remains valid. `TestDiskMemory` follows the same initial admission order. Its snapshot separately reports fixed `bookkeeping_bytes` and live lease `used_bytes`; the absolute configured maximum applies to their checked sum. Exact-budget fixtures explicitly add the new base while preserving their original resident headroom and denial thresholds.

Each database or writer cell owns a distinct actual resident lease. It retains that lease separately from the actual concrete owner Arc. No Weak or raw Arc to a registered owner escapes the private census. The exact generation prevents a stale identity from acting on a later occupant. Concrete input/owner construction occurs only after reservation and before first dispatch.

The fixed slot stores pending drive, payload-disposal and lease-retirement completions. Every drain metadata acquisition uses try_lock. If metadata is busy after effects, the original owner/result remains installed and a later pass completes bookkeeping; no result is dropped on that path. Original panic payloads use a separate once-initialized mutex, so holding an observation cannot hold census metadata or block another owner draining. Drive panic leaves the original Arc installed. An unexpected shared-owner result is retained in its own fixed field and fences the census. Payload destruction runs after actual Arc uniqueness/unwrapping and outside metadata locks. The slot cannot become vacant until actual payload, Arc backing, lease Box and reservation token retirement have returned. A caught destructor or token panic retains its original payload; a token panic also fences future census registration. No claim is made that arbitrary partially destructed payloads remain intact.

The census drives registrations after the user facade or queued worker disappears. A typed observation facade can borrow the same retained database/request later without constructing an owner or retrying work. Successful physical close does not silently erase an unacknowledged error: concrete owners retain original negative outcomes until explicit report relinquishment, and that relinquishment never overrides uncertain resource settlement.

`RegisteredNodeOpening::prepare` registers the actual effect-free NodeFile and retained vendor opening before NodeFile acquisition, envelope preparation, repair or bootstrap effects. The actual acquired NodeDiskFile is installed before envelope validation. The retained vendor owner preserves its own successive partial memory/backend/bootstrap ownership and original outcomes. One closed NodeTables adapter registers its actual queued request before the serial execution gate, retains a matching actual database reference, installs the actual RetainedWriteTransaction before the body, and records original begin/body/outer/terminal/rollback/disposal outcomes. Body failure takes explicit abort; success takes explicit commit. Close seals new work and uses nonblocking resource access. No raw transaction or arbitrary operation callback is exposed by this primitive.

## Scope still required before production migration

The listed exact backing formula covers census slots, concrete database/request Arcs, prepared NodeFile Arc, path bytes and NodeBackend Box. It deliberately does **not** claim the complete vendor OpeningAdmission proxy/control block, caches, allocator maps, redb transaction/workspace, opaque error/panic backing, or returned application objects. The vendor's internal begin_write partial guard/metadata workspace also remains part of the broader allocation census. Those source-derived typed bounds and their actual lease lifetimes must be added before this can satisfy the release contract.

Existing NodeStore/NodeDatabase and scratch consumers are not switched here. All twelve consumer shapes, actual read lifetimes, scratch RetainedSpool close custody, namespace/domain workloads, ready-header publication, and original-error report transport must be composed as one mandatory adoption. This package introduces no supported alternative fallback for that migration. Managed NodeDisk acquisition/session ownership is a separate dependency; this wrapper does not reconstruct resources lost inside an underlying acquisition implementation.

The two fixed operation outcomes shown here are sufficient to test concrete custody, not a generic proof for streaming namespace replacement, encrypted batches or every callback. A boolean report-release latch is explicit owner-lifetime control; it is not transaction settlement or authorization to retry a failed terminal operation.

## Prepared verification

Eighteen new tests are present. Initial native01 compiled the previous revision: eight census tests passed; four opening tests passed and two failed because an already-disposed transaction incorrectly required an unavailable Closed-database witness. This revision is uncompiled/unrun at its freeze. It fixes that predicate and the independent P1 future-outcome relinquishment finding.

1. Exact provider binding and precharged fixed census.
2. Actual owner retained after facade cancellation; later census-driven destruction before lease credit.
3. Original settlement panic identity and actual owner retention.
4. Payload destructor panic, charge retention and no replay.
5. Byte denial before owner construction.
6. Constructor unwind classification and original payload identity.
7. A held original observation does not block another owner draining.
8. Post-drive metadata contention preserves fixed completion without waiting.
9. Physical opening owner publication before file creation; abandoned prepare has no file effect.
10. Real NodeTables commit and actual disposal, with reports surviving physical close.
11. A real queued worker does not stall close and cancels after sealing.
12. Actual table-type body failure is retained before explicit abort/disposal, without replay.
13. Real commit and abort failures retain actual request/error/transaction after every original facade is dropped; the physical file remains locked.
14. Failed physical opening retains its original error after positive close until explicit report release.
15. Engine provider census identity, capacity, initial charge and base-denial boundary.
16. A real new shutdown error with positive backend release is retained after the initial relinquishment call and all original facades disappear; later explicit report release retires it.
17. Relinquishing a queued request seals it before another facade can run.
18. Relinquishing an active queued worker returns promptly and cannot acknowledge the actual body failure it later produces.

Two uncertain physical fixtures retain their actual provider/census cycle and fixed process-static temporary-directory custody. Tests do not turn thread exit or temporary-file unlink into cleanup evidence.

Target rustfmt returned 0 on all candidate Rust files. The manifest pins every changed baseline/candidate file. git apply --check is read-only. The original native01 attempts, source inventories, failed assertions and post-run test binary are preserved in storage-census-adoption/native-01. This successor has not dispatched Cargo/native tests at freeze, and no actual source was edited.

## Revision 2 corrections

Outcome relinquishment is synchronized by the actual owner state. A busy worker cannot be acknowledged, a queued request is cancelled before acknowledging it, and a database is sealed before acknowledgment. Every new close/abort/disposal entry invalidates an earlier release. A Closed database performs no new close and can relinquish its already-observed original outcomes. An already-recorded positive transaction disposal remains valid after its database witness becomes unavailable; it requires no repeated disposal or reopened database.

The original frozen manifest is ec860ed3dc624fb840100f75fb7681b541ae99004edda7e42ff710883730123b; independent review receipt f9606777a78996f7bdf89ac2117fe7d0189266b25e70718d72543029c7a983f1 documents the P1 finding.

## Revision 3 import correction and qualified runtime

Revision 2 native03 passed all 33 selected tests with a fresh candidate-specific Cargo target directory. The executed store binary listed exactly all eight census and nine opening tests before test dispatch; the engine binary listed exactly all three provider tests. Both actual executables were copied and hashed before execution and checked afterward. All 14 process groups drained; full main/assembly/frozen source inventories were unchanged. Selected dependency artifact hashes, original logs and binaries remain in storage-census-adoption-revision2/native-03. Results SHA256: fc3b5044f40d78d1cfc77932a7235f76111ae675a41c0c34147d44b0bc2e3265.

This revision moves the test-only ReadableDatabase trait import from the production module to its test module, removing the one non-test compilation warning. Every function body and ownership transition is unchanged from the tested revision. Strict lint qualification of this import-only successor remains pending at freeze. The previous native02 reused an old shared-target binary; it is preserved as a stale-artifact qualification failure and provides no revision2 test evidence.
