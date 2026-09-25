# Acceptance review: engine, storage and release boundaries

Historical review: the 2026-09-05 source used redb. Its findings remain evidence
for that source and do not qualify the current native Kasumi key-value engine.

This review inspected the implementation and tests on 2026-09-05. It records
specific fixes and limits of the evidence, not a production certification.

## Concrete gaps fixed

- The former 1 GiB backup plaintext cap could not contain the default 1 GiB
  document-body quota plus document envelopes, receipts and audits. Retained
  receipt/audit counts could also permit more than the 2 GiB Raft snapshot cap.
  Exact incremental serialized-state accounting now enforces a default 1.5 GiB
  tenant snapshot quota, with a hard ceiling below the format cap. Backup
  plaintext/framing limits were aligned by the storage implementation.
- Key-catalog count limits alone could allow wrapped-key dependencies to outgrow
  the backup header. An exact serialized byte quota now rejects initialization,
  rotation and rewrapping before persistence, and rejects oversized catalogs on
  load. The cap reserves manifest framing even for maximally escaped tenant names.
- Recovery now enforces each document's byte quota. Lowering that quota below a
  retained document is rejected, so accepted limit changes remain recoverable.
- Restore identity metadata is checked against the serialized quota before a new
  bootstrap can be persisted. A nearly full source may require a quota increase
  before backup; required completion-audit failure leaves prepared state suspended.
- Local reads already used the immutable persisted deployment binding to skip a
  distributed barrier. Their health gate now also checks OpenRaft's fatal runtime
  status: snapshot-capture failure cannot leave a stopped Raft core serving local
  data merely because its key lease and last applied generation remain valid.
- The snapshot-transfer test previously assumed the original leader would stay
  leader after healing. A healed voter can advance the term, letting another voter
  legitimately replay retained logs. The test now purges both majority voters
  before healing, so every eligible leader must perform real snapshot transfer.
- The adapter review identified encoding after the engine's result-release gate.
  The parent implementation added a response fence checked after encoding, against
  the original database incarnation, key lease, replica health and policy epoch.
- First-cluster startup previously assumed identical operator bootstrap files.
  Runtime peers now compare the immutable deployment and authenticated initial
  snapshot identity before initialization and on Raft traffic. Restored groups
  use the same check, covering different restored documents under one incarnation.
  This detects configuration divergence; Raft still assumes trusted, non-Byzantine
  replicas.

## Focused evidence

- `tests/snapshot_budget.rs` checks incremental sizes against actual serialization
  after document replacement/deletion, receipt expiry, schema/policy changes,
  suspended state, quota changes and snapshot reconstruction. It verifies durable
  rejected receipts without partial effects, full audit-byte rejection, quota
  recovery, and rejection of oversized recovered documents.
- Key-catalog boundary tests preserve documents and the previous durable catalog
  after oversized key changes, and create a backup at the exact catalog ceiling.
- The restore-budget unit test accepts the source snapshot but rejects added
  identity metadata before bootstrap publication. Existing real backup/restore
  tests cover suspended activation and replicated completion auditing.
- `fatal_snapshot_capture_blocks_even_local_generation_access` uses a real local
  Raft group, a committed write, and an injected backend snapshot-capture failure.
  The key store and applied data remain valid while access correctly fails.
- Existing storage tests inject every modeled snapshot persistence failure and
  recover a complete old or new snapshot; log conformance and commit-fault tests
  check persistent votes, logs and committed cursors. Actual subprocess SIGKILL
  tests recover acknowledged writes and receipts without graceful shutdown.
- Three-node tests cover minority isolation, leader loss, snapshot catch-up,
  replacement, restart and transport backlog shrinking. KMS tests independently
  exercise retained key versions, denial, delayed replies, suspend-aware expiry,
  ciphertext corruption and expiry during synchronization.
- Restore readiness now tests a deliberately isolated apparent leader: the real
  quorum barrier fails and completion leaves the pending marker unchanged. The
  lifecycle fixture waits for quorum and application rather than treating leader
  metrics alone as readiness. Six diagnostic runs did not reproduce the earlier
  intermittent trigger; they do not establish that trigger's exact cause.

## Residual evidence and operating constraints

- SIGKILL and injected `redb` backend failures are useful crash models; they do not
  establish every kernel/filesystem/controller behavior under physical power loss.
  Hardware fault campaigns and sustained mixed failures remain separate evidence.
- Three-node integration tests mostly run processes or listeners on one host.
  Configuration rejects duplicate failure-domain labels, but actual independent
  infrastructure placement still requires operator deployment validation.
- Logical/serialized quotas are deterministic hard bounds. RSS admission remains
  sampled and its workspace reservations are estimates. Staged-index, snapshot,
  backup and recovery allocations can temporarily exceed those estimates; this is
  not an allocator-level physical-memory guarantee. See `admission.md`.
- Serialized quotas intentionally include audit and receipt retention. Operators
  must preserve headroom for required records and restores; exhausting required
  audit storage stops associated operations. Successful read auditing records an
  authorized release, not confirmed client receipt.
- Capacity, latency and recovery claims must use the final binary and disclose
  concurrency, durability and authentication guarantees. The map-sharing
  microbenchmark does not establish end-to-end speedup or comparison with Redis.
