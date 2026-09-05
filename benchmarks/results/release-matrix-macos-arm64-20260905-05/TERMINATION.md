# Run05 termination and retained evidence

This matrix is **failed and incomplete**. It was explicitly stopped after review
confirmed that embedded request denials lacked durable service audit records,
before implementing the common audit layer. This was an audit-contract defect;
the stop was not a retry intended to hide a measured availability failure.

[STOP_REQUEST.json](STOP_REQUEST.json) records SIGINT sent to driver PID 83271
at 2026-09-05 09:33:51.377754 UTC and the reason for stopping.
[execution.json](execution.json) records wrapper PID 83269, start at
2026-09-05 09:17:57.254004 UTC, terminal completion at
2026-09-05 09:33:54.633352 UTC, and driver exit `-2`. Both recorded PIDs were
absent when this evidence was prepared. [driver.log](driver.log) retains the
`KeyboardInterrupt` traceback. The source SHA256 is identical before and after:

```text
fffa308bc84d9ab5d015ec7f7f0c33af9b592d04a49ff0005b5633c4ab58ed33
```

[matrix.json](matrix.json) remains unchanged with `status: failed`. Its empty
failure string represents the interrupted exception; the stop request, wrapper
and traceback supply the explanation. The all-15-case intention in the original
[run notes](RUN_NOTES.md) was not completed.

| Case | Retained outcome |
| --- | --- |
| Raw, 1 tenant | Passed; 1,000,000 exact 1 KiB documents and 1,000 measured lookups. |
| Local, 1 tenant | Passed; all six workloads completed 1,000 operations each, then verified clean recovery. |
| Replicated, 1 tenant | Interrupted after the `recovered` checkpoint. All six workloads completed 1,000 operations each with zero failed or unattempted operations; clean shutdown and verified recovery were measured. Final cleanup and normal case completion were not recorded. |
| Text/network, 1 tenant; all 100/1,000-tenant cases | Not run. |

The [local result](local-1.json) measured shutdown at 0.937569625 seconds and
recovery at 27.809001417 seconds. The [replicated checkpoint](replicated-1.json)
preserves shutdown at 3.427382958 seconds and recovery at 94.249789833 seconds,
plus after-workload RSS of 15,022,112,768 bytes, disk size of 12,884,914,176 bytes
and after-recovery RSS of 26,461,782,016 bytes. Recovery starts after complete
closure and includes reopen, reconstruction/readiness and a verified read per
tenant. Final cleanup is outside those timers. Replicated has no final `cases`
entry or matrix result hash, so its observations remain partial despite these
successful checkpoints. No recovery lock error or failed workload is recorded
in this run; earlier runs retain their separate failures.

## Partial capacity derivation

The existing capacity script generated [capacity.json](capacity.json) and
[capacity.md](capacity.md). [capacity-generation.json](capacity-generation.json)
records the command, script hash, terminal process check, output hashes and
unchanged SHA256 hashes for all 15 pre-existing files. Raw results, logs, matrix,
wrapper, stop request, source manifest and host samples were not modified.

The report contains three observed footprints and 13 issues. Only `raw-1` and
`local-1` are complete and bound to matrix result/executable hashes. Replicated
observations are retained but excluded from qualified tenant-overhead
derivation; absent measurements remain null. This executable's embedded
fixtures predate the mandatory service audit store, so the report retains their
historical zero service-store count rather than inventing its costs. The
shared-host load override remains disclosed. This partial report is not a
complete release matrix, a measurement of the subsequent audit fix, or evidence
for a 50× external speed comparison.

The [embedded audit investigation](../../../docs/embedded-audit-investigation.md)
describes the confirmed gap, changes and focused proof scope. The corrected
source requires new source-bound macOS/Linux gates and complete measurements;
the older source's passing gates are not relabeled as validation of this fix.
