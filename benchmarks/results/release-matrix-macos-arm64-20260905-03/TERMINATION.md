# Retained execution termination

The manifest records raw-1, local-1 and replicated-1 passed. Each database case
loaded all one million exact 1 KiB documents, completed six 1,000-operation
workloads without a failed sample, and completed verified clean recovery.
Replicated recovery took 86.522584667 seconds.

The driver then recorded `[Errno 32] Broken pipe` before launching text-1.
The original tool handle had become unavailable after a task continuation;
authoritative process checks showed the driver still running until it reached
its next progress print. At termination, both driver PID 22958 and benchmark
child PID 26511 were absent, and the manifest was terminal `failed`.

No database workload failed in this run. The rest of the matrix was unattempted.
The partial capacity report is derived from the retained result hashes and does
not imply that the 15-case matrix completed. Run 04 uses the same frozen source
and release binaries, but sends wrapper/driver stdout and stderr to a regular
file, with `/dev/null` stdin and an independent OS session.
