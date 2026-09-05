# Fifth full-scale measurement run

This run measures the shutdown-corrected source after refreshed macOS/Linux
gates. The command requests 1,000,000 exact 1,024-byte JSON documents, 1,000
operations per workload, and all raw/local/replicated/text/network cases at
1, 100 and 1,000 tenants. See `matrix.json` and `execution.json` for actual
progress, terminal status, command arguments and executable identities; this
note alone does not assert that a run has started or finished.

The frozen source SHA-256 is
`fffa308bc84d9ab5d015ec7f7f0c33af9b592d04a49ff0005b5633c4ab58ed33`.
`source-manifest.json` records every file participating in the matrix identity.
Each Rust executable also reports a narrower Cargo/Rust build fingerprint;
those different identity scopes must not be mistaken for source drift.

The archived `execution-wrapper.py` runs in a separate OS session. Standard
output and error point to a regular `driver.log`, and input is `/dev/null`.
The wrapper records its PID, child PID and terminal exit independently of the
initiating tool handle. A missing tool session is not a reason to restart it:
check the recorded processes and durable execution manifest first.

The standard locked release build remains part of the driver command. The
dedicated validation VM and this task's other builds are stopped before
measurements. Unrelated host work is left running and disclosed through
`--allow-host-load`; source, executable and free-disk guards remain enforced.
This is a shared macOS development host, not isolated production hardware.

Every case runs in a separate process. Within a case the fixed workload order,
owned-before-shared accesses, sequential traffic, native-before-MCP order,
receipts/audit growth and changing text-result cardinalities affect timing.
Shutdown is measured separately; recovery starts after complete closure and
includes reconstruction/readiness plus a verified read per tenant. The capacity
report preserves missing values and failed/unattempted operations.

The driver continues independent cases after an individual workload/case
failure. It never retries a measured operation or hides a finite read-quorum
timeout. All 15 cases should be attempted and interpreted; failures are assessed
against the documented guarantees rather than an invented latency SLA. Prior
failed/interrupted runs remain retained with their original source hashes.

Software validation is recorded in
[macOS](../macos-validation-20260905-shutdown/evidence.json) and
[Linux](../linux-validation-20260905-shutdown/evidence.json); each manifest's
terminal status is authoritative. These tests are separate from performance
measurements and do not certify a storage controller under a physical power cut
or three independent physical failure domains.
