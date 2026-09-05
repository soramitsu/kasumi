# Sixth full-scale measurement run

This directory is prepared for measurement; preparation does not launch a
process or establish passed gates. At launch, `execution.json` and `matrix.json`
will record actual status, command, PIDs and executable identities. Their absence
means no execution has been recorded. The wrapper rejects an existing execution
or matrix rather than overwriting or restarting it.

The frozen source SHA256 is
`a3205990001d86ea66e4ac457fba29ef634b7b6923dfdaa5d80cf2916d517df2`.
[source-manifest.json](source-manifest.json) records every participating file.
Per-executable Rust/Cargo fingerprints have a narrower scope and must not be
mistaken for matrix source drift. The archived
[execution-wrapper.py](execution-wrapper.py) must match the executed wrapper.

The wrapper requires fresh passed
[macOS](../macos-validation-20260905-embedded-audit/evidence.json) and
[Linux](../linux-validation-20260905-embedded-audit/evidence.json) gates, each
bound to this source before and after execution. It also requires the fresh
MinIO manifest at `../linux-validation-20260905-embedded-audit/minio-evidence.json`
to record a passed test, exit zero and matching source identities. The
[release build](../macos-validation-20260905-embedded-audit/release-build.json)
must also pass and bind the same source before and after. Shutdown of this
task's validation VM/build activity and adequate disk headroom must precede
launch. The standard locked release build remains in the driver.

The command requests 1,000,000 documents with exact 1,024-byte JSON bodies,
1,000 measured operations per workload, and raw/local/replicated/text/network
cases at 1, 100 and 1,000 tenants: all 15 cases. The driver continues independent
cases after a finite workload or case failure. Measured operations are not
retried; failed attempt latency, unsuccessful operations, unattempted operations
and missing case results remain visible. A terminal `completed_with_failures`
means the case matrix was attempted, not that every operation succeeded. No
five-second success SLA or external 50× speed claim is imposed.

The wrapper is launched in a detached OS session with regular-file stdout/stderr
and `/dev/null` stdin. The driver uses `caffeinate -i` for its lifetime without
changing global power settings. A lost tool handle alone is not a reason to stop
or restart: inspect durable execution status and recorded processes first.
Source, executable and free-disk guards remain enabled. Unrelated host activity
is left running and disclosed through `--allow-host-load`; this is shared macOS
development hardware, not isolated production hardware. A source/integrity or
resource-safety guard failure remains grounds to stop, and must stay recorded.

Each case uses its own process. Fixed workload order, owned-before-shared point
access, sequential clients, native-before-MCP order, retained allocations,
receipts/audit growth and changing text-result cardinalities affect timing.
The common service audit writer/store is now mandatory in embedded and network
fixtures. Store counts and their measured memory/disk/key costs are separate
from tenant/control Raft-group counts; older results are not adjusted to include
these new fixture costs. Strict successful-read auditing remains disabled.

Shutdown has its own timer. Recovery starts after complete closure and includes
reopen/process spawn, reconstruction, key access, readiness and a verified read
per tenant. Final cleanup is outside those timers. After-workload memory/disk,
successful shutdown and verified recovery are checkpointed independently so an
interrupted later stage cannot erase them. These are clean recovery observations,
not power-cut tests or three independent physical failure-domain measurements.

Run05 remains [stopped and incomplete](../release-matrix-macos-arm64-20260905-05/TERMINATION.md).
Its raw/local cases passed; replicated completed all six 1,000-operation
workloads and verified recovery, then was stopped before final cleanup to fix
the [embedded denial-audit gap](../../../docs/embedded-audit-investigation.md).
That interruption and every earlier failure retain their original evidence.
This new directory does not turn prior partial runs into a completed matrix.

## Cache cleanup during the run

After all cases at 1 and 100 tenants passed, free disk headroom was falling on
the shared host. During local-1000 setup and possibly the beginning of its load,
this task removed only the explicitly inventoried Cargo incremental cache directories.
The [cleanup record](artifact-cleanup-incremental/result.json) gives its exact
start/end timestamps and observed free-space change, and confirms unchanged
source and 130,488 retained compiled files. The existing target directories,
compiled dependencies, validated test binaries and all release executables were
preserved. Some future changed-source compilations lose incremental reuse.

This filesystem activity overlapped setup and may have overlapped the beginning
of loading. Its 37.51-second interval began 208.48 seconds after the case started;
recorded open/setup durations total 233.77 seconds, but checkpoints do not carry
individual timestamps. It can affect setup, early-load timing and host I/O/cache
state. Those observations are therefore additionally qualified; no isolated setup cost or causal speed comparison is inferred. The
benchmark's 30 GiB reserve, source guard and executable guard were unchanged.
Earlier [obsolete-artifact cleanup](artifact-cleanup/result.json) finished before
this matrix launched.
