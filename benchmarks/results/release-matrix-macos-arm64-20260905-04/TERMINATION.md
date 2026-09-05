# Run04 termination and retained evidence

This matrix is **failed and incomplete**. It was explicitly interrupted after
the replicated case exposed a shutdown/reopen defect, before new source edits.
The in-progress text case was also stopped. No interrupted workload or missing
case is counted as successful.

[execution.json](execution.json) records the wrapper's start at
2026-09-05 05:16:04.186372 UTC and terminal completion at
2026-09-05 05:35:54.076917 UTC. The driver exited with `-2` (SIGINT), and
[driver.log](driver.log) retains its `KeyboardInterrupt` traceback. The source
SHA256 is identical before and after execution:

```text
c55682adadd4c92e499f8a252a6f8fdb496184b4b0f693fe53a6e49195728f58
```

[matrix.json](matrix.json) remains unmodified with `status: failed`. Its empty
second failure string comes from serializing the interrupted exception; the
wrapper and traceback supply the terminal explanation. The matrix did not
reach the normal `completed_with_failures` end state described in the original
[run notes](RUN_NOTES.md).

| Case | Retained outcome |
| --- | --- |
| Raw, 1 tenant | Passed; 1,000,000 documents and all 1,000 measured lookups. |
| Local, 1 tenant | Passed; all measured workloads and verified clean recovery. |
| Replicated, 1 tenant | Failed. Five workloads completed 1,000 operations each; balanced traffic had 10 successes, one failed read, and 989 unattempted operations. Immediate recovery then failed acquiring the redb file lock. |
| Text, 1 tenant | Interrupted. Loaded all 1,000,000 documents and retained completed base workloads plus English phrase queries. Remaining text work and recovery are not established. |
| Network, 1 tenant; all 100/1,000-tenant cases | Not run. |

The [replicated report](replicated-1.json) records the balanced-read failure at
zero-based operation index 10: `UNAVAILABLE`, `read quorum unavailable`, after
5,001,772 microseconds. Its subsequent indexed-equality workload completed
1,000 operations. The separate reopen error is retained in both the JSON and
[replicated log](replicated-1.log):

```text
opening durable database: Database already open. Cannot acquire lock.
```

The historical `recovering` checkpoint preserved workload results and loaded
RSS, but did not save after-workload RSS/disk/peak before attempting reopen.
Those missing values cannot be reconstructed as direct measurements, and no
shutdown time was measured by this executable.

The [shutdown investigation](../../../docs/shutdown-investigation.md) describes
the subsequent ownership fixes and focused tests. They do not retroactively
pass this case or establish that the separate quorum deadline miss is resolved.

## Partial capacity derivation

The existing `scripts/report_benchmark_capacity.py` was run against this retained
directory to generate [capacity.json](capacity.json) and
[capacity.md](capacity.md). [capacity-generation.json](capacity-generation.json)
records the generator SHA256, command, exit status, output hashes, and unchanged
SHA256 hashes for all 14 pre-existing run files. Raw JSON, logs, matrix metadata,
wrapper source and host samples were not changed.

The derived report contains four observed footprints and 13 issues. Only
`raw-1` and `local-1` have complete results bound to the matrix's result and
executable hashes. Replicated/text partial observations remain visible and are
excluded from qualified tenant-overhead calculations; absent observations stay
null. The host-load override remains disclosed. This partial report supplies
neither a completed release matrix nor an external speed comparison.
