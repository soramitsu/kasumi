# Retiring a former leader's replication streams

Focused review, 2026-11-13, of the sources in Kasumi commit `4fe35fc7`. It
covers two changes to this fork and the Kasumi log-store change they rely on.
It does not cover the rest of the fork, upstream conformance or release
qualification.

## The failure

A leader cut off by a partition appends an entry it cannot commit. When the
partition heals, it sees the new leader's higher vote and steps down. As a
follower it then truncates that entry and appends the new leader's entries.
Before this change, the old leadership's replication streams kept running
after `Command::QuitLeader`. A stream that read the log between the
truncation and the append got Kasumi's refusal for a missing log prefix. A
storage error from any replication stream is fatal, so the node's Raft core
stopped and the node stayed out of service until restarted. Kasumi's
three-node partition test reported it as "raft is shutting down".

## The change

- `openraft/src/core/raft_core.rs`: `Command::QuitLeader` also calls
  `remove_all_replication()`, dropping the core's stream handles. Each
  stream's task owner stays in the bounded replication registry until the
  stream exits.
- `openraft/src/storage_error.rs`: a new
  `Violation::LogReadPrefixUnavailable { start }`.
- `openraft/src/replication/mod.rs`: a storage error from a stream's log read
  ends that stream without failing the core only if all of these hold:
  - the stream's event channel is closed, so the core has dropped it;
  - the error is `StorageError::Defensive` with `LogReadPrefixUnavailable`;
  - its `start` is the start this stream requested.

  Every other storage error stays fatal.
- Kasumi `crates/kasumi-raft/src/storage.rs`, `LogStore::read_entries`: a
  limited (replication) read whose start is no longer retained returns that
  violation. The store decides this from its retained-log inventory, inside the
  same critical section that truncation, purge and append use. An exact read
  of a range outside the inventory still returns an empty vector.

## What was checked

**Ordering.** `ServerStateHandler` emits `QuitLeader` when the server state
leaves `Leader`, in the engine step that changes the vote. `append_entries`
updates the vote before `ensure_log_consecutive` and `append_entries` run.
So `QuitLeader` comes before that step's `DeleteConflictLog` and
`AppendInputEntries`. `RaftCore` runs queued commands in order. Neither
command has an execution condition. A postponed command goes back to the
front of the queue and stops the loop, so no later command can overtake
`QuitLeader`.

**Nothing uses a removed stream.** `Replicate` commands are pushed only by the
leader's replication handler, which requires a leader; any queued before
`QuitLeader` run before it. `ReplicateCommitted` iterates the now empty
stream map. Later responses from a removed stream are ignored: progress
updates require a leader, and higher-vote notices are checked against the
current vote.

**A stream can still be mid-read when its handle is dropped.** Kasumi
serializes reads, truncation, purge and append through one I/O gate. It
updates the retained span inside that gate, so a read sees the log before or
after each mutation, never during one.
- A read between the truncation and the append gets the typed refusal for its
  own start.
- A read before the truncation, or after the new leader's entries are
  appended, returns entries that the stream sends under its old vote. A target
  that has seen the newer vote rejects them. An entry is identified by its log
  id, so this is how a stale stream already behaved, now for a shorter time.

**The exception cannot hide a storage failure.** Only Kasumi's
`read_entries` produces `LogReadPrefixUnavailable`; OpenRaft never
constructs it. These stay fatal:
- I/O, authentication and decoding failures;
- the refusal on a live stream;
- the refusal for a different start;
- errors on the snapshot path.

OpenRaft otherwise treats `Defensive` and `IO` storage errors the same way.
One visible difference: if a live stream ever receives the refusal, Kasumi's
diagnostic class for the stopped core is `storage_defensive` instead of
`storage_io`.

## Behaviour changes to know

- **A departing leader no longer sends events still queued for its streams.**
  When its channel closes, a stream processes the buffered events and exits
  without sending another RPC. Upstream already delays a removed leader's
  step-down until the membership entry that removes it is applied, so its
  commit has usually been broadcast by then. If not, followers learn the
  commit from the next leader's first commit.
- **One case stays fatal, as before the change.** A stream decides it is
  retired from `is_closed()` on its event channel. A snapshot task briefly
  upgrades its weak sender to report its result. If a log read failed at that
  exact moment, the refusal would stay fatal. Within one stream, a snapshot
  transfer and a log read do not overlap.

## Evidence

Run on `4fe35fc7`, macOS arm64, with Kasumi's pinned Rust toolchain, on a
shared host at load 50-600:

| Suite | Result |
| --- | --- |
| OpenRaft unit tests, `-p openraft --features serde,storage-v2 --lib` | 234 passed, including `replication::log_read_error_test` and `update_server_state_test` |
| Upstream integration tests, `-p tests`, all 12 binaries | 126 passed, 0 failed, 2 ignored upstream |
| Kasumi cluster test `partition_rejects_minority_reads_and_writes_and_recovers_after_full_restart` | 5 of 5 alone; passed in a full workspace run |
| Kasumi `limited_read_*` tests | 3 passed |

- The upstream integration tests include `membership::t31_remove_leader`,
  `append_entries::t10_see_higher_vote`, `t11_append_conflicts` and
  `t11_append_inconsistent_log`.
- Before the change, the partition test failed 2 of 25 instrumented runs
  alone, each time with the former leader's core stopped on the refusal.
- Two of the `limited_read_*` tests check the typed refusal after the retained
  end and after a purge. They also check that a revoked custody lease and a
  changed log body stay `StorageError::IO`.

The workspace build writes `target/`, and the upstream integration tests write
`_log/` into their working directory. The dependency verifier rejects any
extra file under `vendor/`, so build outside it and run the test binaries from
a scratch directory:

```sh
export CARGO_TARGET_DIR=/path/outside/vendor/openraft-target
cargo test --manifest-path vendor/openraft-0.9.25/Cargo.toml -p openraft \
  --features serde,storage-v2 --lib --locked --offline
cargo test --manifest-path vendor/openraft-0.9.25/Cargo.toml -p tests \
  --locked --offline --no-run
```

## Not covered

- No test drives a retired stream into the refusal deterministically. The
  cluster test reaches it intermittently, and the predicate has unit tests.
- One reviewer, an AI coding agent that did not write the change. There was
  no second independent review.
- The checkpoint's remaining items still apply: complete fork review,
  upstream feature and platform cohorts, fault injection and release
  qualification.
