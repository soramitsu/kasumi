# Offline standalone diagnostic — frozen 3a8d512

The actual Linux ARM64 diagnostic passed on 2026-09-09, from 03:33:58 to
03:34:06 UTC. It used the existing fixture-free Rust 1.97.1 production binaries
from `3a8d5121e1ddee14ae8a6d938d12152eaa04e417`. The original functional run remains
**failed**. This diagnostic is not final-release acceptance or closure of any
failure from that run or the later integrated source.

The source tree is `44871b6470914c011ad56f374d416b7d0e742efe`; the lockfile SHA-256
is `f42fec1f6e7232b1cd5e9c564cfff56dfec7634f2548eab7eb2096a0d0c17c78`.
The [original build report](../frozen-linux-arm64-3a8d512-terminal-20260908/run/evidence.json)
has SHA-256 `41c9a17334c861ad20c560d6dd3cdd802b67bd307a1806fa1d83f9e6e5980545`.
Its production and network-driver build gates passed with nonempty actual
compiled-feature inventories and no fixture features. The sanitized evidence
binds all three actual executed copies to their build-reported executable hashes.

| Executable | SHA-256 |
| --- | --- |
| kasumid | `340db15a8130289da49ca18c50e6da25ac27a1a3210bbdeed72ec5acba81bc8b` |
| kasumictl | `5488d51495a750e3ec4a22ae4591d8f5a1e313af1e8183a59ce7292ecc75a600` |
| kasumi-bench-capacity | `2bf9528308df725f4f3d343d700934d9dd628b92c6e17f3008552e434fea1975` |

## Observed checks

The runner initialized a clean standalone installation and loaded 129 documents
of 1024 canonical bytes each, totaling 132,096 bytes. Native full-corpus checks
after credential renewal, encrypted restart, stopped-instance local recovery,
and the old-resource rejection all matched SHA-256
`1db24d06974750aa4e4b06b41861316dbd751c674a18a3ec4241614256f8557d`.

All three daemon starts reached protected readiness over installed pinned TLS
1.3 with mTLS. MCP discovery and exact document reads passed before and after
recovery. Backup verification returned the exact completed checkpoint. Local
recovery and its status lookup retained the exact request and published client
profile, reached `finished`, and reported `exclusive_local_installation` fencing.
The original still-unexpired resource credential received an explicit native
`Unauthenticated` response; a final successful corpus read followed that denial.
The pinned runner implements the token-lifetime and installed-profile checks;
private credential contents were not exported for this evidence review.

The container was created and started once, using image
`sha256:abf802c3daf7460f7498869910288b63bf5e138efc28e3c0704bf931b99e1ed4`
in the `kasumi-production-arm64` Lima VM. Its network was `none`, root filesystem
read-only, source/build/runner mounts read-only, and only the owned `/results`
host mount writable. Docker init, two CPUs, 4 GiB memory with no extra swap,
256 MiB `/tmp`, and a 512-process limit were verified in its actual creation
inspection. The three previously exited containers were retained unchanged.

Container `a39fb19f7fd156cc6f34166691e06077362cd5748ca15f46e81af1f3a8283b6f`
finished `exited`, exit code 0, PID 0, and `OOMKilled=false`, with no running,
paused, or restarting state. The exact terminal inspection agrees with the
dispatch receipt. All 15 dispatch client process groups and all 21 native step
process groups recorded successful drain. No forced stop or cleanup error was
recorded. The sole intentional nonzero native step is the verified old-resource
authorization denial. The actual controlling session reported by the parent
was 5456; it was already terminal before this independent evidence-only review.

## Preservation and privacy

`evidence.json` is an allowlisted extraction of public metadata and hashes.
`extract-safe-evidence.py` shows the exact read-only extraction and assertions.
It checks selected original JSON files and log hashes inside the VM and emits
only the selected fields. Source commit/tree/lock and the runner source hash
were also compared to local Git objects. No Kasumi process, container, compiler,
or new functional test was executed during this review.

The private directory
`/opt/kasumi-acceptance/3a8d512-small-standalone-001` remains root-owned mode 0700
and contains real installation keys, tokens, provider configuration, and logs.
Those files, raw Docker inspections, and the full output directory were **not**
copied into this bundle. Only their explicitly selected evidence hashes and
safe fields were exported. Do not copy or publish the original directory
wholesale. Its stopped container and evidence remain available for controlled
operator review; the runner performs no automatic removal or retry.

The final dispatch source, execution plan, mock guard tests, and exact native
runner source are archived here. Before dispatch, five pure mock guard tests
passed under Python 3.12 in 0.018 seconds; they prohibited subprocess creation.
That result is preparation evidence, not another native gate. The preserved
plan describes the historical dispatch and must not be rerun against the
already occupied output directory. `public-files.json` hashes this public bundle.

## Limits

This small diagnostic does not establish 3 GiB capacity, HA membership or
failover, distributed source-unavailable fencing, crash/cancellation recovery,
S3 behavior, archival endurance, wrapping-key/signer/certificate rotation,
revocation, renewal-watcher endurance, administrator recovery, performance, or
the 24-hour soak. It also predates the current integrated APIs, formats,
dependencies, and prepared permanent-prefix/target-resolution work. Final
release gates must use the final source and executable hashes.
