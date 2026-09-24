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
- After the reviewed failed-owner read fence, native-close witness and repeat
  close-report fixes, the locked offline native crate passes 31 unit and six
  fault/recovery integration tests on the current native source. The immediately
  preceding source passed 412 runnable store library cases (two ignored); its
  full-store successor is running after the repeat close-report fix. The
  five-case Raft storage conformance suite passed on an earlier source and
  needs a final-source rerun. Workspace check, strict lint and complete tests
  remain pending. Source and log hashes are in the integration evidence ledger.
- Compaction needs temporary disk headroom equal to the live set and waits for
  active snapshots to drain. Capacity, recovery duration, sustained overwrite
  performance, and final production release gates remain unqualified.
