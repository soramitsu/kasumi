# Kasumi Raft adapter

This crate pins OpenRaft **0.9.25** and connects its storage-v2 interfaces to
Kasumi's encrypted, immediately durable redb store. It replicates typed commands;
the engine owns deterministic authorization, validation, receipts, and complete
generation publication.

`RaftGroup::write` returns only after OpenRaft reports quorum persistence and the
local backend finishes applying the command. A canceled or timed-out write has an
unknown outcome. Callers must retain application idempotency keys. Fresh reads
must pass `linearizable_barrier` before capturing a resident generation.

Every group retains its configured membership through restart and network cuts.
`local` initializes a single voter only when the store has never been initialized;
it does not rewrite an existing replicated group into a single voter.

## Persistence and recovery

- Votes, committed cursors, group/node bindings, log headers and retirement seeds
  use a separately keyed control catalog. Application log bodies and snapshots
  use the application catalog. `TenantStorageSet` commits both domains in one
  durable redb transaction; append completion follows its final fsync.
- Log commands use compact binary records with no legacy JSON decoding. An 8 MiB command remains approximately 8 MiB
  before encryption, avoiding JSON byte-array expansion beyond store limits.
- A resident index contains log IDs, not application payloads. Range reads decrypt
  the requested entries. Large appends write contiguous prefixes; truncation
  removes suffixes from the end; purges atomically advance each removed prefix's
  cursor. A crash does not leave a log hole between retained entries.
- Snapshots consist of 4 MiB encrypted chunks and a durable manifest. The new
  manifest and independently keyed exact snapshot coverage replace the old ones
  in one transaction only after every chunk is durable. Durable pending
  and obsolete manifests allow interrupted installation/cleanup to resume safely.
- Remote snapshot metadata and backend content are validated before replacement.
  Backend restoration must validate and atomically publish its complete state.
- Recovery restores the snapshot and replays through the durable committed
  cursor before `RaftGroup::open` returns. A backend materialization failure makes
  the replica unavailable until recovery.

Each backend application receives the actual `LogId`, previous applied position,
membership and command digest. Successful engine retirement returns its actual
retained receipt to the adapter; the exact applied cursor and immutable retirement
boundary then publish atomically in control storage. Ordinary log purges delete
covered application bodies. Only an accepted retirement boundary retains the
remaining source log ciphertext for subsequent custody recovery.

`ControlLog` can reopen committed retirement seeds with only the custody key.
It never opens an application provider or payload decoder. This is local recovery
input, **not** a current administrative proof, a fresh quorum acknowledgement or a
serving lease. See [the custody substrate contract](../../docs/custody-control.md)
for the remaining runtime and unavailable-source recovery boundaries.

The default per-group snapshot transfer limit is 2 GiB, including the envelope.
The engine must account for snapshot construction/validation/transfer memory in
its admission budgets; the adapter's byte cap is not a total resident-memory cap.

## Transport boundary

`RaftTransport` is the network integration point. The production transport must
authenticate peers and authorize their source node, target node, and group before
calling `dispatch_rpc`. The crate does not implement TLS by itself.
`InProcessRouter` delivers requests to actual OpenRaft instances and supports
explicit link partitions for testing. It is suitable only within a trusted process.
Transports report `RpcPayloadTooLarge` when a multi-entry append exceeds their
byte budget. The adapter converts this into OpenRaft's adaptive retry hint, so
backlogged followers catch up through smaller batches rather than retrying an
oversized request indefinitely.

## Verification

Run `cargo test -p kasumi-raft` and
`cargo clippy -p kasumi-raft --all-targets --no-deps -- -D warnings`.

The tests cover the upstream storage conformance suite; actual three-node Raft
elections, minority read/write rejection, healing and complete restart; snapshot
transfer after log compaction; learner promotion and voter replacement; leader
loss; a separate process killed after an acknowledged local write; every injected
storage mutation/fsync failure during append/commit and snapshot installation;
invalid logical snapshots; snapshots above the store's individual-record limit;
and bounded snapshot writes/seeks.

The cluster tests use independent redb files in one process. The fault backend
models power loss by reopening only the last synchronized storage image. These
tests do not replace physical power-loss testing, production mTLS transport tests,
or deployment across independent host failure domains.
