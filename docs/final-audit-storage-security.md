# Final storage, consensus and security acceptance audit

> Historical 2026-09-05 audit. Its source and gate claims do not certify the
> current [native Kasumi KV implementation](native-kv-goal.md).

Updated on 2026-09-05 against inspected source SHA-256
`28aeb80168d3ab02a0eec7bf2a0163a7cb99dbfd74adf596e849de17e1fa3c1d`.
This update changes documentation only. Source, test assertions and retained logs
are the primary evidence; the release checklist is only a navigation aid.

**The embedded denial-audit gap and queued-reset listener failure are fixed, and
both current-source platform gates pass 188 workspace test entries plus the
separate actual OpenBao test. No further
implementation gap was identified in this bounded storage, consensus, security
and backup review.** The actual MinIO fixture also passed with the current macOS
client and a pinned Linux server. The [published release report](../benchmarks/RESULTS.md)
now has complete measurement coverage: 15 selected cases, 99,000 successful
operations and zero failed or unattempted operations. No remaining hard
requirement or required evidence gap was identified within this audit's scope.

## Resolved: queued connection reset could stop the listener

[Run 06](../benchmarks/results/release-matrix-macos-arm64-20260905-06/matrix.json)
passed 14 cases, including local, replicated and indexed-text workloads at 1,000
tenants. The final network-1000 case exited before readiness with macOS
`EINVAL`; it produced no measured operations. The
[OS reproducer](../benchmarks/results/listener-startup-20260905/reset-reproducer.json)
observes that error from `TCP_NODELAY` on a connection reset while queued before
accept. This is a matching reproducible mechanism; the original benchmark did
not record the failing syscall.

[TLS serving](../crates/kasumi-server/src/tls.rs) now configures an accepted socket
inside its bounded connection task. Setup failure closes that socket, attempts a
rejected-handshake audit, and leaves the listener available. A genuine listener
accept error still stops accepting and drains nested connection owners before
returning. The [source comparison](../benchmarks/results/listener-startup-20260905/source-change.json)
and archived before/after files identify `tls.rs` as the only change since
`a3205990…`; storage, consensus, lease, backup and shared-audit code is unchanged.

Both new lifecycle tests pass in the current full platform logs below. One
injects socket-setup failure portably; the other queues a real reset before the
listener starts, observes kernel closure without a sleep, and asserts macOS
errno 22. Each checks the rejected audit callback metadata and a subsequent
successful TLS request. The retained accept-I/O regression still verifies active
request drain and immediate redb reopen.

Those listener tests use a recording callback; they do **not** independently
prove durable audit persistence. The production
[runtime audit adapter](../crates/kasumi-server/src/runtime.rs) maps that callback
to `TransportDenied` and awaits the shared encrypted security writer.
`service_audit_survives_reopen_and_tenant_sealing_and_fails_closed_at_quota` and
the shared-writer/embedded regressions below establish durable persistence,
separate service protection and failure handling independently. Rejected
connections remain closed if recording fails. The
[affected network rerun](../benchmarks/results/network-rerun-macos-arm64-20260905-listener/matrix.json)
now passes all three tenant counts, including complete startup, workloads,
shutdown and recovery at 1,000 tenants. Its measurements and the unchanged engine
cases are combined with explicit provenance in the release evidence below.

## Resolved: embedded denial auditing

The original review of `fffa308bc84d9ab5d015ec7f7f0c33af9b592d04a49ff0005b5633c4ab58ed33`
found correct denial enforcement without durable records for direct embedded
calls. Run 05 was stopped before corrective source edits. The
[investigation](embedded-audit-investigation.md) retains that history and the
benchmark stop record.

[Every Database constructor](../crates/kasumi-engine/src/service.rs) and every
local/replicated open or restore entry in
[bootstrap](../crates/kasumi-engine/src/bootstrap.rs) now requires an explicit
`Arc<SecurityAudit>`. There is no default or no-op sink. Public async request
methods audit `Forbidden`, `Unauthorized` and `Sealed` before returning, including
failures before any Raft proposal. `Database::audit_result` preserves the original
denial if storage fails. Standalone restore uses `restore_access` and
`restore_denial` to record target sealing and policy/tenant authorization denial
before a Database exists; rejected targets remain uninitialized.

The [shared writer](../crates/kasumi-engine/src/security_audit.rs) accepts only the
reserved `__kasumi_security` store and persists closed metadata plus its next
sequence atomically in encrypted immediate-durability transactions. Live opens
of the same `TenantStore` and quota share an inner `AuditWriter`; a conflicting
quota is rejected. Its registry holds weak inner identities, prunes expired
entries on opens, and remains valid while a value clone or detached work owns the
writer. Thus dropping the original outer `Arc` cannot reset a counter, bypass a
failed state or lose a queued job from shutdown accounting.

The network [runtime configuration](../crates/kasumi-server/src/runtime.rs)
rejects duplicate Transit wrapping identities across security, control and all
customer tenants. The [embedded API contract](api.md#embedded-rust) explicitly
requires a separate service wrapping key and authorization, and its example
constructs that provider independently. Generic embedded `KeyProvider` objects
are supplied by the trusted application; the engine does not claim to verify an
arbitrary provider's external key identity. The shared writer does not silently
reuse the customer store or its key. Tests use distinct service/customer keys
and verify the service record remains writable after customer sealing.

[Database, administration and adapter boundaries](../crates/kasumi-server/src/administration.rs)
compose using the error's private, nonserialized audit-attempt marker. A failed
sink is still an attempt, and the original denial remains enforced. The marker
is excluded from wire data, receipts, equality and diagnostic text; it cannot be
set by deserialization. It is not request-ID deduplication: independent denials
with a reused request ID each receive a record. Authentication and
adapter-originated routing/protocol/encoded-release denials stay at their
respective server boundaries. Raw engine primitives and the response fence are
trusted building blocks, not additional authenticated request endpoints.

The writer registers blocking work before spawning. Database shutdown drains its
own denial jobs; the node owner then closes and drains the shared writer before
shutting down the service key store. Canceled callers and canceled shutdown
futures leave ownership tracked. Any audit persistence error fences the shared
sequence until recovery, including an fsync that committed before lease expiry
caused an unknown outcome. Reauthorizing keys or opening another live handle
cannot then overwrite the uncertain record.

| Focused evidence inspected | Direct result |
| --- | --- |
| [Embedded integration tests](../crates/kasumi-engine/tests/embedded_audit.rs), [log](../target/embedded-denial-audit-tests-final.log): 3 passed | Twelve records cover public request boundaries, cross-tenant access and sealing despite a reused request ID; payload/receipt values are absent. Failed audit storage preserves denial. Queued cancellation drains before immediate real-file reopen. Standalone local/replicated restore denials and a sealed target produce three durable records without initializing the denied target. |
| [Writer tests](../crates/kasumi-engine/src/security_audit.rs), [log](../target/security-audit-component-test.log): 3 passed | Concurrent duplicate opens preserve three distinct sequential records through immediate reopen. Queued work retains writer identity after the original outer Arc drops. Canceled/repeated shutdown drains it. Uncertain fsync fences queued, new and duplicate-open writes, and recovery preserves old/new records at distinct sequences. |
| [Adapter tests](../crates/kasumi-server/src/api.rs), [log](../target/server-common-denial-audit-test.log): 14 passed | `embedded_native_and_mcp_denials_have_one_durable_record_per_request` checks exactly one record per denied call. `shared_adapter_release_audits_a_seal_after_response_encoding` withholds encoded reads/mutations and records the denial. Routing, protocol, authentication, precision and receipt cases also pass. |
| [Runtime log](../target/security-audit-runtime-test.log): 14 passed | Local and three-runtime startup, restore, voter replacement, service-audit recovery and distinct wrapping-key configuration regressions passed after extraction. This focused run preceded the final shared-inner registry improvement. |
| [Combined engine/server Clippy log](../target/security-audit-component-clippy.log) | All targets/features, locked dependencies, no dependency linting, warnings denied: passed after the shared-inner writer change. |

These focused logs were produced during the corrective development sequence,
not by one final frozen-source platform command. The fresh source-bound
macOS/Linux gates below now include the final shared-writer, embedded,
standalone-restore and adapter denial regressions. No new tests or builds were
run for this documentation review.

## Requirement-to-primary-evidence coverage

The current [macOS command manifest](../benchmarks/results/macos-validation-20260905-listener/evidence.json)
and [Linux command manifest](../benchmarks/results/linux-validation-20260905-listener/evidence.json)
both retain unchanged before/after source fingerprints, 188 passing workspace
test entries, zero failures, and two opt-in tests ignored by the workspace
command. Both also record strict all-feature/all-target Clippy, formatting, six
Python tests, and one separately executed actual OpenBao test. The actual passing
entries are in the [macOS log](../benchmarks/results/macos-validation-20260905-listener/1-test.log)
and [Linux log](../benchmarks/results/linux-validation-20260905-listener/full-gate.log).
Both manifests bind their results to the inspected `28aeb801…` source. The upstream
storage conformance suite is one entry, not an invented count of its internal
assertions. The earlier 186-entry `-embedded-audit` runs retain their
`a3205990…` identity, and the 177-entry `-shutdown` runs retain `fffa308b…` as
historical evidence. The table maps passing contract tests and inspected
implementation, with explicit limits on what they prove.

| Agreed contract | Implementation and inspected primary evidence | Finding |
| --- | --- | --- |
| Durable redb records, votes and committed cursor; encrypted atomic batches | [Store](../crates/kasumi-store/src/lib.rs) sets `Durability::Immediate` and two-phase commit in initial/catalog/data transactions, syncs created directories, and encrypts records before insertion. [Raft storage](../crates/kasumi-raft/src/storage.rs) awaits persistence before completing append callbacks or vote/commit persistence. [Conformance tests](../crates/kasumi-raft/tests/storage_conformance.rs) reopen votes/logs/committed cursor and test every injected append/commit I/O failure. [Store tests](../crates/kasumi-store/src/tests.rs) recover an entire old/new batch, never a partial batch, and require successful writes to survive. | Covered by implementation and modeled I/O/crash evidence. Honest OS/device flush semantics remain an environmental assumption. |
| Authenticated snapshots durable before covered-log removal; complete recovery before readiness | `persist_snapshot` durably publishes chunk manifest before obsolete cleanup; `install_snapshot` validates before persistence and restores only after it. [Snapshot fault test](../crates/kasumi-raft/src/storage/tests.rs), `snapshot_install_power_loss_at_every_storage_operation_keeps_whole_old_or_new_snapshot`, injects faults at each storage operation and requires acknowledged snapshots to recover as new. `TenantEngine::prepare_snapshot` in [state](../crates/kasumi-engine/src/state.rs) verifies identity, schema, uniqueness, logical accounting and quotas and rebuilds indexes before publication. Pinned OpenRaft's `Raft::new` awaits `StorageHelper::get_initial_state`; the [SIGKILL engine test](../crates/kasumi-engine/tests/contracts.rs) recovers documents, receipts and policy. | Covered. This is fault-model and real process-death evidence, not a physical power-cut claim. |
| Atomic resident generation, command ordering and receipts | [State](../crates/kasumi-engine/src/state.rs) uses ArcSwap publication, persistent document/receipt maps, and staged generation updates. `apply_operation` checks all mutation permissions before principal-scoped receipt lookup; validation/CAS/uniqueness/quotas follow. [Contracts](../crates/kasumi-engine/tests/contracts.rs) assert no partial document/index effects, atomic unique-value swaps, current authorization before replay and replay before changed schema/CAS. [Adapter delivery-loss test](../crates/kasumi-server/src/api.rs) discards fully dispatched committed responses and resolves both interfaces by receipt/retry without reapplying. | Covered. Delivery loss is an outer response interceptor, explicitly not a kernel/TCP fault injection. |
| One group per tenant; explicit one/three voters; separate control; no partition fallback | [Manifest](../crates/kasumi-raft/Cargo.toml) pins `openraft = "=0.9.25"`. [Bootstrap](../crates/kasumi-engine/src/bootstrap.rs) durably binds mode and requires exactly three initial replicated voters. [Control](../crates/kasumi-engine/src/control.rs) validates unique domains and approved node pins; [runtime](../crates/kasumi-server/src/runtime.rs) shares transport/admission/runtime infrastructure and uses a reserved control group. Runtime tests run real three-node pinned mTLS tenant/control groups and replace `[1,2,3]` with `[1,2,4]`; [control tests](../crates/kasumi-engine/tests/control.rs) reject duplicate/shared placement. | Software contract covered; configured domain labels do not prove physical independence. |
| Durable quorum and full local apply before acknowledgment; fresh read barrier | `RaftGroup::write` awaits `client_write`; `StateMachine::apply` calls the backend before advancing applied state. `linearizable_barrier` invokes pinned OpenRaft `ensure_linearizable`, which checks quorum and waits for local applied index. [Partition test](../crates/kasumi-raft/tests/cluster.rs) rejects isolated-leader reads/writes, keeps three voters, heals and reopens all three stores. [Barrier regressions](../crates/kasumi-raft/tests/read_barrier.rs) cover finite delay, full deadline partition, higher term and sealing. | Covered contract tests. The retained full-scale quorum timeouts remain real availability observations; these tests alone do not explain them or establish a latency SLA. |
| Fatal materialization failure fences replica; orderly shutdown cannot retain an untracked store | [Raft storage](../crates/kasumi-raft/src/storage.rs) sets a permanent failure flag on backend application failure. [Conformance test](../crates/kasumi-raft/tests/storage_conformance.rs) refuses subsequent apply until reopen. [Raft shutdown](../crates/kasumi-raft/tests/shutdown.rs), [engine shutdown](../crates/kasumi-engine/tests/shutdown.rs), runtime and TLS tests hold real work/resources through shutdown and immediately reopen redb after release. | Covered by retained regressions and current lifetime implementation. Runtime lifecycle regression exercises the shared startup/serving drain with actual TLS request owners, not every possible full bootstrap failure. |
| TLS 1.3, mTLS services/cluster, verified OAuth context, default-deny RBAC | [TLS](../crates/kasumi-server/src/tls.rs), [authentication](../crates/kasumi-server/src/auth.rs), [cluster](../crates/kasumi-server/src/cluster.rs), [Policy::allows](../crates/kasumi-types/src/lib.rs) and ordered policy operations enforce the contract. [TLS listener](../crates/kasumi-server/tests/tls_listener.rs) and [peer transport](../crates/kasumi-server/tests/cluster_transport.rs) tests reject TLS 1.2, absent/foreign certificates and wrong identity pins. Auth tests reject issuer/audience/expiry/not-before/signature/type errors; [adapter tests](../crates/kasumi-server/src/api.rs) reject cross-tenant, scope and administrative escalation. | Covered. The embedding application remains trusted to authenticate its supplied context. |
| Per-tenant Transit envelope encryption and fresh nonces | [Keys](../crates/kasumi-store/src/keys.rs) implements fresh authenticated Transit decrypt, bounded TLS 1.3 requests, context/reference/version checks and owned zeroizing keys. [Store](../crates/kasumi-store/src/lib.rs) uses independently random 24-byte XChaCha20-Poly1305 nonces and tenant/record-bound AAD. [Store tests](../crates/kasumi-store/src/tests.rs) inspect disk plaintext absence, nonce changes, corruption, record swapping and wrong-tenant failure; runtime rejects shared tenant/control/security wrapping identities. | Covered, including actual OpenBao. Compatibility is not certification of arbitrary Vault configurations. |
| Every replica: 20-second real decrypt refresh, five-second whole probe, 60-second probe-start lease, every historical key | `TenantStore::refresh_lease` probes every catalog entry under one five-second timeout and computes expiry from probe start; an epoch check prevents late success undoing sealing. [Clock](../crates/kasumi-store/src/clock.rs) uses Linux `CLOCK_BOOTTIME` and macOS continuous time. [Tests](../crates/kasumi-store/src/tests.rs) verify start cadence despite latency, historical revocation, delayed response, exact lease boundary, idle watchdog, late success and expiry during fsync. | Covered with deterministic suspend-aware clock tests and actual clock implementation. No claim of a physical suspend campaign is needed. |
| Seal blocks admission/release, cancels work, clears state and owned keys | `TenantStore::seal` closes the epoch before waiting for key locks and clears the owned key map. [Database](../crates/kasumi-engine/src/service.rs) fences admission/release, seals work, clears resident generation/cursors and observes independent expiry. [Response-release tests](../crates/kasumi-engine/tests/response_release.rs) deny encoded output after policy/key changes. | Access, owned-resource behavior and embedded denial records are covered in both current-source full gates. Previously returned plaintext remains outside recall. |
| Durable audits survive compaction; strict successful reads persist before release | Tenant audits are retained in `TenantState` and serialized with snapshots, independently of purged logs. [State](../crates/kasumi-engine/src/state.rs) rejects effects when required audit count/byte capacity is unavailable. `release_event` commits strict read/discovery/receipt audit before final authorization and release, with the read revision and `authorized_release`. [Contracts](../crates/kasumi-engine/tests/contracts.rs) assert revision binding and actual I/O failure withholding results. [SecurityAudit](../crates/kasumi-engine/src/security_audit.rs) persists closed metadata and sequence atomically in the separately wrapped service store; tests reopen it after tenant sealing and enforce quota failure. | Tenant auditing has retained contract evidence; shared embedded/network denial auditing is fixed with the focused proof above. No claim of confirmed client receipt or automatic audit pruning. |
| Encrypted filesystem/S3 backup, integrity and wrapped dependencies; new suspended restore only | [Backup](../crates/kasumi-store/src/backup.rs) authenticates a versioned manifest containing all retained wrappers and an internal snapshot digest. Filesystem writes fsync before create-only publication and directory sync; S3 signs bounded TLS requests and uses create-only writes. [Engine bootstrap](../crates/kasumi-engine/src/bootstrap.rs) requires empty targets/new incarnations and validates/rebuilds before readiness. [Administration](../crates/kasumi-server/src/administration.rs) requires completed suspended targets, terminal source retirement and control CAS before routing replacement. [Local contracts](../crates/kasumi-engine/tests/contracts.rs) and [replicated restore](../crates/kasumi-engine/tests/replicated.rs) verify receipt preservation, fresh identity and quorum completion audit before activation. | Covered. Service durability is bounded by the selected destination's honest guarantees. |
| Actual key/object adapter compatibility | [Actual OpenBao test](../crates/kasumi-store/tests/openbao_live.rs) uses real Transit generation/decrypt/rewrap, wrapping rotation, minimum-version revocation and old/new encrypted backup decryption, then warm-store denial. It passed separately on both current 188-entry platform gates. [Current actual MinIO evidence](../benchmarks/results/linux-validation-20260905-listener/minio-evidence.json) binds the passing encrypted TLS/SigV4/create-only/access-denial test to the unchanged `28aeb801…` client source and binary hash before/after. | MinIO client is macOS aarch64 and server is digest-pinned Linux aarch64; this is current-source adapter evidence, not a Linux-client claim. Actual Vault or arbitrary S3 implementations were not claimed. |

## Release measurement closure

The [cohort manifest](../benchmarks/results/release-cohort-macos-arm64-20260905-listener/cohort.json)
records `completed_under_host_load` and complete coverage of raw, local,
replicated, indexed-text and authenticated network cases at 1, 100 and 1,000
tenants. Each case uses one million documents with exactly 1,024-byte JSON
bodies. Recounting the selected raw results yields 99 workloads of 1,000
successful operations each, with no failed or unattempted operations.

The cohort retains twelve engine measurements under their original
`a3205990…` source and three corrected network measurements under `28aeb801…`.
It is explicitly not a single execution. Reuse is supported by the complete
TLS-only source comparison and the identical rebuilt `kasumi-bench` executable
SHA-256 `a1f93ade86ddfe7096bb0afccc9ae72b4f196254657595d4f6409525f0be52b7`.
The cohort binds the selected result hashes, both original manifests, current
platform gates, release build and renderer identities. This audit verified all
selected result hashes, referenced evidence hashes and the
[derived capacity hash](../benchmarks/results/release-cohort-macos-arm64-20260905-listener/capacity.json).
Earlier failures and source labels remain intact.

[Measured results](../benchmarks/RESULTS.md) report raw lookup, actual embedded
access, native RPC, MCP, local durable writes and replicated durable writes
separately, with throughput, p50/p99, memory, shutdown/recovery and tenant-group
overhead. Shared-host load, single-run sampling, loopback topology, wrapping
provider differences and strict-read-audit settings are disclosed. These
qualified measurements complete the agreed reporting work; they establish
neither a Redis speed ratio nor a production capacity or latency guarantee.

## Evidence boundaries

The agreed software uses deterministic logical quotas for document, metadata,
receipt, audit and snapshot state. Node-local RSS/admission estimates cancel or
reject work before admission, while already committed application remains
mandatory; [admission tests](../crates/kasumi-engine/tests/admission.rs) assert
that distinction. This does not promise an exact allocator-level memory cap.

Production filesystem/controller behavior, independently situated failure
domains, swap/dump settings and externally operated key/object services remain
operator/environmental responsibilities. No new hardware provisioning gate or
latency SLA is inferred from the plan. The retained benchmark failures and
interrupted earlier matrices remain historical evidence alongside the completed
cohort. Their safety regressions, fresh platform validation and the published
measurement report close the software and evidence work covered by this review.
No further missing software behavior or agreed acceptance evidence was
established. Environmental assumptions and the limits of the reported
measurements remain in force.
