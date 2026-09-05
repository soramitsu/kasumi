# macOS validation evidence

The listener correction passed on frozen source
`28aeb80168d3ab02a0eec7bf2a0163a7cb99dbfd74adf596e849de17e1fa3c1d`:
188 all-feature/all-target workspace test entries, zero failures, strict Clippy,
formatting, six Python tests, and one separately executed real OpenBao test.
The [listener gate manifest](../benchmarks/results/macos-validation-20260905-listener/evidence.json)
records identical before/after source hashes and verified hashes of every log.
Two opt-in service tests were ignored in the workspace command. The separate
[MinIO check](../benchmarks/results/linux-validation-20260905-listener/minio-evidence.json)
also passed using the current macOS binary against the digest-pinned Linux
service; its source and executable hashes remained unchanged.

The two additional regressions cover a real reset queued before listener startup
and a portable injected socket-configuration failure. Both verify the rejection
audit callback and a successful subsequent TLS request. Runtime service-audit
tests separately verify persistence through that callback. The existing genuine
listener-accept failure test still verifies request draining before store release.
See the [listener investigation](listener-startup-investigation.md) and
[exact source change](../benchmarks/results/listener-startup-20260905/source-change.json).
The TLS file is the only source change from the preceding gate; benchmark
measurements remain a separate completion gate.

## Earlier common embedded audit gate

The common embedded audit correction passed on frozen source
`a3205990001d86ea66e4ac457fba29ef634b7b6923dfdaa5d80cf2916d517df2`:
186 all-feature/all-target workspace test entries, zero failures, strict Clippy,
formatting, six Python tests, and one separately executed real OpenBao test.
The [audit gate manifest](../benchmarks/results/macos-validation-20260905-embedded-audit/evidence.json)
records identical before/after source hashes and SHA-256 hashes of every log.
Two opt-in live service tests were ignored in the workspace command; the
[explicit MinIO result](../benchmarks/results/linux-validation-20260905-embedded-audit/minio-evidence.json)
uses the matching macOS test binary against the pinned Linux MinIO container.

The new regressions cover durable denials through every embedded request
boundary, standalone restore checks before database construction, exact-one
records across native/MCP adapters, non-wire audit markers, cancelled queued
writers, duplicate live writer ownership and uncertain persistence outcomes.
See the [audit investigation](embedded-audit-investigation.md). These checks add
to the durability, replication, query and shutdown contracts below. Benchmark
measurements remain a separate completion gate.

## Earlier shutdown gate

The shutdown corrections passed on frozen source
`fffa308bc84d9ab5d015ec7f7f0c33af9b592d04a49ff0005b5633c4ab58ed33`:
177 all-feature/all-target workspace test entries, zero failures, strict Clippy,
formatting, five Python tests, and a separately executed real OpenBao test.
The [shutdown gate manifest](../benchmarks/results/macos-validation-20260905-shutdown/evidence.json)
records identical before/after source hashes and SHA-256 hashes of every log.
The two opt-in service tests remain ignored in the workspace command; OpenBao
was then run explicitly. MinIO evidence is recorded separately.

These checks include storage-owner draining after upstream Raft shutdown,
cancelled/concurrent key-store shutdown, abandoned query output, immediate
database reopen with receipts, and live TLS request draining on normal startup
cleanup and injected listener I/O failure. See the
[shutdown investigation](shutdown-investigation.md) for their scope.

## Earlier barrier and driver gates

After the first matrix exposed a replicated read failure, the updated source
passed 167 workspace test entries, strict all-feature/all-target Clippy,
formatting and both Python driver failure tests. The new
[evidence manifest](../benchmarks/results/macos-validation-20260905-barrier/evidence.json)
binds those results to
`a36dd4e69700ea7e20aec5784106c0034f306d50edfec8939ad2b46ba439a63f`
before and after every command. It includes the snapshot runtime-responsiveness,
fresh-quorum retry, concurrent pagination and lost-adapter-response regressions.

The subsequent benchmark guard correction changes only two Python files:
low disk space now takes precedence over permitted competing host activity,
with a regression covering both conditions at once. The
[targeted supplement](../benchmarks/results/macos-validation-20260905-barrier/python-guard-evidence.json)
records all three Python tests passing on source
`c55682adadd4c92e499f8a252a6f8fdb496184b4b0f693fe53a6e49195728f58`.
The [reconstruction proof](../benchmarks/results/release-matrix-macos-arm64-20260905-02/guard-validation/source-manifest.json)
includes the exact before/after files and hashes of every unchanged source file
and release executable. Replacing only those two files with their recorded prior
bytes reproduces the full gate's source hash. The Rust implementation, dependency
graph and binaries did not change, so their complete gate remains applicable;
the Python supplement validates the changed scope.

## Earlier frozen-source gate

The final frozen-source gate passed on macOS arm64 with Rust/Cargo 1.94.1:

```sh
cargo test --workspace --all-features --all-targets --locked
cargo clippy --workspace --all-features --all-targets --locked -- -D warnings
cargo fmt --all -- --check
```

The workspace test run passed 157 test entries with zero failures. Two live
service tests were explicitly ignored in this command; their separate OpenBao
and MinIO evidence is described in [compatibility](COMPATIBILITY.md). Strict
Clippy and formatting both exited zero.

The source fingerprint before and after every command was
`358b623bee1e6a9189cdec2aeadbe047b4e1499e179386be4613b3684708db44`.
The [evidence manifest](../benchmarks/results/macos-validation-20260905-final/evidence.json)
records command arguments, elapsed times, source identity and each output's
SHA-256 hash. Logs are retained alongside it. The fingerprint uses the benchmark
driver's source identity function, covering Rust, Protobuf, manifests, lockfile
and executable helper scripts; prose and generated results are outside it.

Two earlier full runs failed at the restore fixture's immediate use of a
reported leader. Those outputs are preserved in
[the earlier evidence directory](../benchmarks/results/macos-validation-20260905/).
The original transient trigger was not recorded at the OpenRaft error level.
Six focused diagnostic runs passed, so they do not establish its exact cause.

The corrected fixture checks a real quorum barrier and applied readiness,
reselects leaders for documented unavailable/unknown outcomes, and has a
deterministic isolated-target test. That test records
`QuorumNotEnough { got: {1} }`, verifies that restore completion is refused and
its pending marker is unchanged, then restores connectivity and completes the
restore/activation/read lifecycle. Production consistency and response deadlines
were not weakened to make the fixture pass. Its diagnostic output is retained
with the final evidence.

These are software fault, protocol and integration tests. macOS supports local
development and embedded validation; [Linux validation](validation-linux.md)
is separate. The tests do not certify a storage controller under physical power
loss or a deployment across independent physical failure domains.
