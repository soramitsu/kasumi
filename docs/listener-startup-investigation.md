# Listener startup failure investigation

Run06's final 1,000-tenant network case exited before readiness with
`Invalid argument (os error 22)`. Fourteen other cases passed. The
[terminal record](../benchmarks/results/release-matrix-macos-arm64-20260905-06/TERMINATION.md)
preserves the failed case, all successful measurements and their source identity
`a3205990001d86ea66e4ac457fba29ef634b7b6923dfdaa5d80cf2916d517df2`.
No gRPC/MCP workload or document load ran in the failed case. Its 170.114654064
seconds include fixture preparation; no server-open timing was completed.

## Direct observations

The original server error lacks a syscall or stack trace. A separate controlled
macOS reproduction demonstrates one matching mechanism. The
[reproducer](../benchmarks/results/listener-startup-20260905/reset_reproducer.py)
opens a local TCP listener, connects a client, sets `SO_LINGER` to `{1, 0}` and
closes that client to send a reset before accepting it. It then applies
`TCP_NODELAY` to the accepted socket. The
[actual output](../benchmarks/results/listener-startup-20260905/reset-reproducer.json)
records `EINVAL` / errno 22 for delays of 10, 100 and 500 milliseconds on
macOS 26.6.2 arm64. This small socket experiment does not involve Kasumi,
1,000 tenants, memory pressure, or a key service.

| Reproduction artifact | SHA256 |
| --- | --- |
| `reset_reproducer.py` | `01b47b7ead50f17765853bd8720bf364ba5033b65658eeadfae53bb96e403243` |
| `reset-reproducer.json` | `c52df59e96458ff69e5b99a2eb60e85c5f26babec98e45fe51f0dad7fb032ff3` |
| `tls-before.rs` | `df1adf0a46a36b2fd38459363630fe5fdf9922cf3b823b06d8c025beac2c9151` |

The [archived listener](../benchmarks/results/listener-startup-20260905/tls-before.rs)
matches the run06 source manifest. Its `serve_tls_source` applies
`socket.set_nodelay(true)` in the listener loop, before spawning the connection
task. An error sets the listener outcome to failure and breaks the loop.
`NodeRuntime::serve` treats a required listener's error as a node failure and
drains/shuts down the runtime. This is a concrete availability defect: a
connection-specific socket setup error can stop the service.

## Connection to the original startup failure

The relevant source path is:

1. [NodeRuntime::open](../crates/kasumi-server/src/runtime.rs) binds the MCP,
   native and administrative sockets before opening the encrypted security,
   control and customer tenant stores. Those sockets accept no application
   traffic until runtime startup completes.
2. Runtime startup initializes groups, publishes control metadata, reconciles
   routes and records `NodeStarted` before starting the data listener tasks.
3. The [loopback fixture](../crates/kasumi-bench/src/bin/loopback.rs) repeatedly
   attempts an administrative TLS/gRPC connection while that work is pending.
   A TCP connection can therefore queue before the server starts accepting.
   A client which times out or resets during that interval can leave a stale
   queued connection for later socket configuration.
4. The pre-fix listener promotes a socket's `TCP_NODELAY` error to a fatal
   listener error. The fixture observes the child exit and retains its stderr
   as `kasumid exited before readiness`.

The actual macOS socket result and fatal propagation provide a strong candidate
explanation. They do not prove that this exact syscall failed in the original
process. In particular, the evidence does not establish a 1,000-tenant OS
resource ceiling or exhaustion of memory, file descriptors or threads. A longer
opening phase increases the opportunity for stale queued probes, but no timing
or causal claim about the original reset is measured. The readiness deadline
for 1,000 tenants is 1,300 seconds; the retained error is a child exit, not that
deadline expiring.

## Correction and proof boundary

The narrow correction moves accepted-socket configuration inside its connection
task. A configuration failure closes that socket and attempts the existing
bounded rejected-handshake audit; the listener continues accepting. Connection
permits, TLS/authentication checks and connection draining remain in effect.
An actual listener `accept` failure remains fatal and drains nested owners
before returning. No request deadline or quorum/durability contract is relaxed.

Two focused regressions accompany the correction in
[tls.rs](../crates/kasumi-server/src/tls.rs): an injected socket-setup failure
and a real queued-reset client. Both check rejection audit output, continued
listener availability, a subsequent successful TLS request and bounded clean
shutdown. On macOS the reset test additionally checks actual errno 22. These
tests address connection failure isolation; they do not replace the failed
full-size network measurement.

At this investigation's initial publication, new complete platform gates,
release executable identities and affected network measurements were pending.
The following evidence completes those checks without changing the historical
run06 outcome or claiming to identify its unrecorded syscall.

## Completed correction evidence

The corrected source is
`28aeb80168d3ab02a0eec7bf2a0163a7cb99dbfd74adf596e849de17e1fa3c1d`.
The [source-change record](../benchmarks/results/listener-startup-20260905/source-change.json)
compares complete before/after manifests and identifies only server `tls.rs` as
changed. Fresh [macOS validation](../benchmarks/results/macos-validation-20260905-listener/evidence.json)
and [Linux validation](../benchmarks/results/linux-validation-20260905-listener/evidence.json)
each passed 188 workspace test entries with zero failures, strict all-feature,
all-target Clippy, formatting and six Python driver tests. Each platform also
passed its separately executed actual OpenBao test. The fresh
[MinIO test](../benchmarks/results/linux-validation-20260905-listener/minio-evidence.json)
passed with a macOS client and Linux MinIO container. These source-bound gates
include the injected setup-error and queued-reset listener regressions.

The [network supplement](../benchmarks/results/network-rerun-macos-arm64-20260905-listener/matrix.json)
finished `completed_under_host_load`, and its
[detached wrapper](../benchmarks/results/network-rerun-macos-arm64-20260905-listener/execution.json)
recorded a successful exit. All three cases at 1, 100 and 1,000 tenants completed
loading 1,000,000 exact 1 KiB documents each, all ten native RPC/MCP workloads,
clean server shutdown and verified recovery. Every workload completed 1,000
successful operations, for 30,000 successes with zero failed or unattempted
operations across the supplement.

| Tenants | Shutdown seconds | Verified recovery seconds |
| --- | --- | --- |
| [1](../benchmarks/results/network-rerun-macos-arm64-20260905-listener/network-1.json) | 1.089533167 | 29.221108625 |
| [100](../benchmarks/results/network-rerun-macos-arm64-20260905-listener/network-100.json) | 0.657342500 | 19.265642000 |
| [1,000](../benchmarks/results/network-rerun-macos-arm64-20260905-listener/network-1000.json) | 1.608116750 | 52.016212458 |

The 1,000-tenant case now completed readiness, full loading, measurement and a
fresh server-process recovery. Its retained result SHA256 is
`b4692d7842fb899e5f76852cb81de9c13de21b89af3a4ebe2212c656e23e1828`.
Recovery starts after successful shutdown and includes reconstruction, key
access, readiness and one authenticated native read per tenant. OpenBao and the
issuer remain running. This demonstrates clean recovery under the disclosed
fixture conditions; it is not a power-loss measurement or a general startup SLA.

The [release build](../benchmarks/results/macos-validation-20260905-listener/release-build.json)
produced an engine benchmark executable byte-for-byte identical to run06:
`a1f93ade86ddfe7096bb0afccc9ae72b4f196254657595d4f6409525f0be52b7`.
The [final cohort](../benchmarks/results/release-cohort-macos-arm64-20260905-listener/cohort.json)
therefore selects its twelve successful engine/text cases at their original
`a3205990…` source identity alongside these three corrected network cases. It
preserves per-case result/executable hashes and both full source identities.
The [measured report](../benchmarks/RESULTS.md) contains 15 qualified case results
and 99 workloads; the original failed run06 network case remains retained.

These measurements used a shared macOS host and loopback networking. Durable
authentication and mutation auditing were enabled; strict successful-read
auditing was disabled. The successful rerun establishes the observed corrected
behavior without proving the original error's exact trigger, isolated-host
capacity, a physical multi-host deployment result or an external speed ratio.
