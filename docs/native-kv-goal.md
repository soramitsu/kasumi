# Native Kasumi key-value engine goal

Status: active. The 2026-09-24 direction replaces the planned redb-backed G02
implementation. Kasumi will own its durable key-value engine in Rust and remove
the redb dependency and vendored fork. This change must preserve the public
encrypted store and Raft storage contracts while replacing the physical format.

## Completion criteria

1. Implement a Kasumi-owned transactional file format with atomic durable
   multi-key and multi-table batches, serialized writers, stable ordered read
   snapshots, crash recovery, corruption rejection, and explicit close custody.
2. Charge persistent and scratch growth and resident work through the installed
   disk and memory owners. Preserve encrypted records, key catalogs, and scratch
   storage without storing plaintext on the persistent backend.
3. Cut over all production and retained-opening/read paths, then remove redb
   from Cargo, vendor inputs, dependency-review scripts, and current operating
   documentation. Retain historical evidence as historical evidence.
4. Pass focused engine failure/restart tests, the store's injected-I/O and
   encryption tests, Raft storage conformance and crash replay, and the complete
   repository gates required by `CONTRIBUTING.md`.
5. Qualify capacity, recovery, and performance against the release ledger. A
   passing unit suite alone does not close the production release goal.

This is the first release, so backward compatibility is forbidden. The new
format must identify itself distinctly and reject every older physical format;
do not add a migration, fallback reader or dual-write path.

## 2026-09-24 implementation checkpoint

- `kasumi-kv` now owns the format, transactional tables, admitted reads and
  writes, retained opening/close custody, and two-stage crash-safe compaction.
  The `redb` Cargo dependency and vendored source are removed. Active database
  filenames use `.kv`; the node envelope rejects the previous format.
- The native crate passes 34 unit and seven crash/recovery integration tests on
  the later source-bound native-read checkpoint, including named-file directory sync and same-host reopen
  after a failed commit sync. Strict native Clippy also passes. The final-core
  all-features store library passes 412 cases (two ignored), and Raft storage
  conformance passes five. The full engine library had 284 passes and three
  obsolete fixture-budget failures; all three adjusted fixtures pass focused.
  The complete workspace gate remains in progress. Source and log hashes are
  in the integration evidence ledger.
- Compaction needs temporary disk headroom equal to the live set and waits for
  active snapshots to drain. Audit maintenance prepays a 128 MiB native KV
  escrow. Only scoped, synchronous preparation and apply work can draw its
  resident leases. A separate 128 MiB and four-slot free reserve excludes
  ordinary operation charges, including retained descendants, while Raft log
  storage uses ordinary Resident admission. Resident saturation can still block
  the asynchronous Raft proposal and archive completion. End-to-end progress
  under that condition, capacity, recovery duration, sustained overwrite
  performance, and final production release gates remain unqualified.

The later 34-unit/7-crash locked offline native KV log and exact source hashes
are recorded in the integration evidence ledger. The combined store checkpoint
passes 417 runnable cases before subsequent admitted-read changes, and its
source is not the final checkout. A read-only parent-sync/close audit identifies
pre-install direct Core/Builder failures that can drop an acquired backend
without explicit native-close custody; the partial pre-acquisition candidate
is held. Production registered-opening adoption and final qualification remain
open.
