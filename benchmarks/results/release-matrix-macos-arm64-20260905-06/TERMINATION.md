# Run06 terminal failure and retained evidence

This matrix reached all 15 case outcomes and ended **`completed_with_failures`**:
14 cases passed, and `network-1000` failed before server readiness. The run was
not interrupted or retried. Complete performance coverage remains unavailable.

[execution.json](execution.json) records wrapper PID 41576, driver PID 41577,
start at 2026-09-05 10:22:53.242940 UTC, finish at
2026-09-05 12:13:31.563358 UTC and exit 1. Both processes and the final fixture
PIDs 4029, 4030 and 4041 were absent during independent terminal verification.
The recorded source identity is identical before and after execution:

```text
a3205990001d86ea66e4ac457fba29ef634b7b6923dfdaa5d80cf2916d517df2
```

| Cases | Retained outcome |
| --- | --- |
| Raw, local, replicated and text at 1, 100 and 1,000 tenants | All 12 passed with 1,000,000 exact 1 KiB documents per case. Every measured workload completed 1,000 operations. Database cases completed their shutdown and verified recovery measurements. |
| Network at 1 and 100 tenants | Both passed with 1,000,000 exact 1 KiB documents per case. All ten gRPC/MCP workloads per case completed 1,000 operations, and shutdown and verified server recovery completed. |
| Network at 1,000 tenants | Failed during fixture startup. No measurement client workload or document loading ran; server readiness, memory checkpoints, shutdown and recovery were not measured. |

The 14 successful cases contain 89 workload measurements and 89,000 successful
operations, with no failed or unattempted operations within those measurements.
This excludes the ten intended workloads in the failed case: their 10,000
requested samples were never started and are not fabricated as measured
latencies or per-operation errors.

The final [failure result](network-1000.json) contains `cases: []` and:

```text
kasumid exited before readiness: Error: Invalid argument (os error 22)
```

The same error is retained in [network-1000.log](network-1000.log) and
[driver.log](driver.log). The final case elapsed 170.114654064 seconds including
fixture setup; this is not a measured server-open duration. The failure record
has no measurement-client executable hash or completed server fixture metadata.
Its result hash is bound by [matrix.json](matrix.json); the matrix separately
records the executables used to launch the run.

## Evidence verification

The terminal driver generated [capacity.json](capacity.json) and
[capacity.md](capacity.md). Independent read-only verification checked all 15
result hashes against the matrix, the successful client/server executable
bindings, the wrapper/source identity, and exact equality between the retained
capacity JSON and the existing reporter's in-memory derivation. It did not
replace results, logs, capacity files or source manifests, or publish a final
release report.

The capacity report contains 15 entries, of which 14 are complete and identity
verified, 16 qualified overhead estimates, and one issue for `network-1000`.
That failed entry's document/tenant observations, timings and RSS are null.
Its 1,000 data groups, one control group and one service security store describe
the configured topology inferred by the report; they do not establish that those
groups became ready. Its zero derived payload bytes mean absent measured
payload evidence, not an observed empty database. It is excluded from qualified
tenant-overhead derivation.

| Retained artifact | SHA256 |
| --- | --- |
| `execution.json` | `782740f589c7d46bdd0ef653368ee6cb6473e41cc2c3109a871944feb7ac3f9a` |
| `matrix.json` | `ea57faf5f23157b76b9ca4e5190ee123b583905cab8b32512d40fed7ce1a5a5a` |
| `source-manifest.json` | `f4495221b02f346d1cff99b3bdbbdec1d6c5b8e3f4d4460f4631111bd41a6643` |
| `network-1000.json` | `76bcdb1e365f8fd5a7778d071af526eb7cb900276580ff370a3609adae399f3d` |
| `network-1000.log` | `8ef2d26a9d2310f7b85446e4c2e7fb14f27708d0af12b912d68947f4279bba11` |
| `capacity.json` | `f86e76305155dd7ccab7f0330593dd1e77793294944a76511e32b2991eb2561e` |
| `capacity.md` | `9b14bc0049792cf0bec34325afa033fab85fdb134b7e14049171b6fabcc75f8e` |

The [source manifest](source-manifest.json) and matrix preserve every source and
release executable binding. The successful intermediate analyses remain dated
observations: [one-tenant analysis](one-tenant-analysis.md) and
[12-case analysis](completed-cases-analysis.md). Their earlier completion counts
are not rewritten as terminal results.

## Interpretation and next evidence

The [listener investigation](../../../docs/listener-startup-investigation.md)
records a reproduced macOS reset-socket mechanism that matches this error and a
connection-local handling defect in the run's listener. The original syscall
was not logged, so that mechanism is a supported explanation, not a proven trace
of the original failure. No persistence loss or partial batch was demonstrated.
The listener correction needs its own source-bound validation and affected
network measurements; run06 does not validate a later executable.

Heavy unrelated shared-host activity remained present. The
[run notes](RUN_NOTES.md) disclose internal cache cleanup 208.48–245.99 seconds
after the `local-1000` case started, overlapping collection setup and possibly
early loading; exact phase timestamps were not recorded. All 130,488 retained
compiled files and the measured source/binaries were unchanged by that cleanup.
Setup, loading and cache/I/O comparisons retain this qualification.

Peak RSS was sampled at the pre-shutdown checkpoint; recovery can exceed it and
has a separate RSS sample. Shutdown and recovery are separately timed, with
recovery starting after complete closure. Successful-read strict tenant auditing
was disabled, while network authentication lifecycle auditing remained durable.
These shared-host measurements do not establish an intrinsic speedup, an
external 50× comparison, an isolated multi-host deployment result or release
completion. Earlier failed and interrupted runs remain preserved separately.
