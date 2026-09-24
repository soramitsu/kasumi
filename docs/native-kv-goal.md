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
- The native crate passes 44 unit and seven crash/recovery integration tests on
  the current local source, including direct failed-constructor and retry-close
  panic custody, named-file directory sync, final-symlink rejection, and
  same-host reopen after a failed commit sync and strict-create EEXIST rejection.
  Store setup now observes
  database close after a post-open table or Ready failure, with two focused
  regressions passing. The immediately preceding all-features store library
  passes 421 cases (two ignored), the registered-opening overlay passes 424
  (two ignored), and Raft storage conformance passes five. The final combined
  store and strict workspace gates still require reruns after the latest fixes.
  The first full workspace gate on the 39-unit checkpoint passed the authority
  and engine libraries, then exposed an admission fixture that exhausted native
  Raft storage headroom. That fixture now installs the production maintenance
  reserve and passes focused. The complete final-source gate remains open.
- Compaction needs temporary disk headroom equal to the live set and waits for
  active snapshots to drain. Audit maintenance prepays a 128 MiB native KV
  escrow. Only scoped, synchronous preparation and apply work can draw its
  resident leases. A separate 128 MiB and four-slot free reserve excludes
  ordinary operation charges, including retained descendants, while Raft log
  storage uses ordinary Resident admission. Resident saturation can still block
  the asynchronous Raft proposal and archive completion. End-to-end progress
  under that condition, capacity, recovery duration, sustained overwrite
  performance, and final production release gates remain unqualified.

The earlier 34-unit/7-crash locked offline native KV log and exact source hashes
are recorded in the integration evidence ledger. The combined store checkpoint
passes 417 runnable cases before subsequent admitted-read changes, and its
source is not the final checkout. The parent-sync/close audit's four identified
paths now have source fixes: direct Core/Builder failures explicitly close their
backend and retain unproved custody, named-file acquisition binds to a held
parent directory, data and parent descriptors get observed closes, and final
symlinks are rejected. Direct callback panics and post-engine NodeStore setup
failures now retain original outcomes and attempt exact close.

The later six-file production `NodeStore` constructor cutover now adopts one
registered opening from acquisition through table setup and close. Its exact
candidate postimages are present on `master`. Three focused production opening
cases pass. Two additional regressions prove failed file acquisition with no
returned descriptor can close and retire the registered opening without
poisoning disk admission. Scratch tables now explicitly close on last table or
batch drop; a failed bootstrap retains its original error and unproved owner.
Its 13 focused cases pass. Production read/write transactions still escape as
raw handles rather than individually registered census children, except for
the now registered and independently reviewed production catalog point read.
Its focused applied-source tests pass 3/3 with no source drift; derived catalog
allocation accounting remains open. A separately reviewed strict-create
`FileBackend::create_new` removes the old `open` API and its EEXIST adoption
fallback. The later applied store library passes 434 runnable cases, with one
shared-checkout source change during that run. The direct scratch-table builder,
path-only existing-file identity,
direct Core/Builder API boundary, and final-source qualification remain open;
this does not complete G02.
