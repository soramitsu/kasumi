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

Fifteen new tests are present but uncompiled/unrun at the initial freeze:

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

Two uncertain physical fixtures retain their actual provider/census cycle and fixed process-static temporary-directory custody. Tests do not turn thread exit or temporary-file unlink into cleanup evidence.

Target rustfmt returned 0 on all candidate Rust files. The manifest pins every changed baseline/candidate file. git apply --check is read-only. No Cargo or native tests have been dispatched by this agent, and no actual source was edited.
