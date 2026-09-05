# Replicated read barrier investigation

The first 1-million-document replicated matrix case failed during balanced
traffic, at read operation 8. Its original report and host samples remain in
`benchmarks/results/release-matrix-macos-arm64-20260905-01/`; the failed run is
not converted into a successful measurement.

The failure occurred near the default snapshot threshold of 5,000 Raft entries:
approximately 3,907 load batches, collection/membership entries, 1,000 measured
writes, and 100 writes in the read-heavy phase. The final samples show process
RSS increasing from approximately 12.8 GiB to 20.6 GiB while CPU rose sharply.
This is consistent with snapshot creation, but the run did not capture the
underlying Raft probe error or snapshot event. It is an inference, not a proven
reproduction of that exact failure. Unrelated background CPU/VM activity was
also present and disclosed by the matrix's host-load override.

Review of pinned OpenRaft 0.9.25 established that `ensure_linearizable()` gives
each leadership confirmation round a hard TTL equal to the heartbeat interval,
250 ms in the server profile. Kasumi's network honors OpenRaft's 3/4 soft TTL,
about 187.5 ms. Previously one failed round immediately returned `UNAVAILABLE`,
even though the API allowed five seconds to establish the read barrier.

The shared Raft-group barrier now retries only typed `QuorumNotEnough` failures
within the original five-second deadline. Every attempt performs a fresh quorum
confirmation and waits for the corresponding local application. Ten milliseconds
of backoff prevents immediate network errors from spinning. Term changes,
forwarding, fatal errors and key sealing stop the barrier. No failed attempt
grants permission to read; membership and persistence rules do not change. This
is production barrier behavior included in API latency, not benchmark retries.
Sustained latency above every individual probe TTL can still exhaust the deadline.

The same review found three concrete async-runtime blocking paths during large
snapshots. Builder creation copied the entire captured payload on a Tokio worker;
it now clones an `Arc` and encodes on a blocking worker. Installation now parses
the full snapshot on a blocking worker. Applied-state metadata lookup also waits
for the snapshot's shared lock off the async runtime. Snapshot validation,
durable installation, atomic application and covered-log retention remain in
their original order. Loading a previous full snapshot merely to compare its
metadata remains a possible future memory/performance optimization.

Four real three-node tests verify the read behavior: a direct pinned probe fails
during a finite stall while fresh rounds subsequently succeed; a permanent
partition expires at five seconds without membership reduction; key sealing
interrupts a pending probe; and a higher term prevents stale release. A separate
single-thread runtime test holds the actual snapshot-capture lock and verifies
that an independent timer still runs while metadata lookup waits. The full Raft
suite also passes the existing crash, injected snapshot I/O, recovery, partition,
replacement, and upstream storage conformance tests.

The affected release benchmark must be rerun before claiming improved capacity
or reliability for the million-document workload. The controlled tests establish
the fixed behaviors, not an end-to-end speedup.

## Run04 observation and capacity implications

The retained [run04 replicated report](../benchmarks/results/release-matrix-macos-arm64-20260905-04/replicated-1.json)
records another finite read failure under the disclosed host-load override.
After loading 1,000,000 exact 1 KiB documents, balanced traffic completed 10
operations, then zero-based operation 10 returned `UNAVAILABLE` with
`read quorum unavailable` after 5,001,772 microseconds. The remaining 989
operations were unattempted. Owned reads, shared reads, durable writes,
90/10 traffic, and subsequent indexed-equality queries each completed all 1,000
operations. The later immediate-reopen file-lock failure is a separate
[shutdown issue](shutdown-investigation.md).

A bounded read-only review identifies remaining sources of latency:

- `StateMachine::get_snapshot_builder` holds its applied-state mutex while
  `TenantEngine::snapshot` serializes the complete immutable generation.
  OpenRaft's state-machine worker awaits that capture before spawning the
  snapshot builder, so application can wait behind work proportional to the
  dataset. Moving execution to a blocking worker keeps that serialization off
  Tokio workers but does not remove this ordering delay.
- Snapshot persistence uses bounded 32 MiB batches through the same tenant
  mutation lock and redb write transaction path used by consensus metadata.
  Log-store operations share an I/O gate; pinned OpenRaft directly awaits
  committed-cursor persistence and covered-log purging. These are storage
  throughput and scheduling costs, not evidence of an unbounded wait in this run.
- Key refresh and sealing can acquire a synchronous key-state write lock from
  asynchronous callers, while durable writes hold the corresponding read lock
  through encryption and commit. This can delay a Tokio worker under I/O
  contention. The review did not measure that lock's contribution to this miss.

The relevant source is in [Raft storage](../crates/kasumi-raft/src/storage.rs),
[engine snapshots](../crates/kasumi-engine/src/state.rs), and
[key-store operations](../crates/kasumi-store/src/lib.rs). These are concrete
latency mechanisms; none establishes which mechanism caused the recorded
five-second failure. The common service maps underlying barrier errors to
`read quorum unavailable`, so the result alone cannot distinguish quorum
confirmation delay from waiting for local application.

The [host samples](../benchmarks/results/release-matrix-macos-arm64-20260905-04/host-samples.jsonl)
during this part of the replicated case show harness RSS increasing from about
12.35 GiB to 22.70 GiB, with concurrent background CPU observations of
244.9–336.3% in the 05:29:16–05:29:37 UTC interval. Samples are approximately
five seconds apart. They establish concurrent host activity and resident-memory
growth, but provide no snapshot event, probe trace, lock-duration measurement,
or precise per-request timeline. They do not isolate host contention from
Kasumi's storage and snapshot work.

No five-second success SLA is inferred, and this observation does not show a
stale read, lost acknowledged write, or partial batch. It is a failed-closed
availability observation that must remain visible in capacity results. The
next frozen-source matrix should attempt all 15 configured cases and preserve
finite failed and unattempted measurements, without extending deadlines,
retrying measured requests, or restarting the matrix merely to hide a miss.
Its completion and interpretation remain separate from the focused shutdown
regressions and correctness gates.
