# Embedded request denial audit investigation

Historical investigation: these runs and source observations predate the native
Kasumi key-value engine. They do not qualify its recovery or release behavior.

Review during the fifth full-size matrix found a concrete contract gap:
embedded `Database` calls enforced authorization and tenant sealing, but their
denials did not pass through the server-owned service audit writer. Network
adapters recorded these errors, while embedded callers could receive the same
denial without an independent durable record. This did not demonstrate an
authorization bypass, document loss, or stale read; it violated the agreed
auditing contract across interfaces.

Run05 was explicitly interrupted before changing source. Its
[termination record](../benchmarks/results/release-matrix-macos-arm64-20260905-05/TERMINATION.md)
preserves the exact stop reason, unchanged historical source identity and partial
measurements. The historical macOS/Linux gates bound to source `fffa308bc84d9ab5d015ec7f7f0c33af9b592d04a49ff0005b5633c4ab58ed33`
do not validate the subsequent changes described below. Fresh
[macOS](../benchmarks/results/macos-validation-20260905-embedded-audit/evidence.json)
and [Linux](../benchmarks/results/linux-validation-20260905-embedded-audit/evidence.json)
full gates now pass on source
`a3205990001d86ea66e4ac457fba29ef634b7b6923dfdaa5d80cf2916d517df2`,
with 186 workspace test entries and zero failures on each platform, strict
Clippy, formatting and six Python checks. Each platform's actual OpenBao test
also passed; the fresh [MinIO test](../benchmarks/results/linux-validation-20260905-embedded-audit/minio-evidence.json)
passed with a macOS client against a Linux MinIO container. These manifests bind
the corrected source. The complete measurement matrix remains required.

## Shared ownership and denial coverage

[SecurityAudit](../crates/kasumi-engine/src/security_audit.rs) now lives in the
engine layer. Every `Database` constructor and local/replicated bootstrap or
restore entry requires an `Arc<SecurityAudit>` as its final argument. There is
no optional sink or implicit no-op writer. Share one writer per node across its
databases and adapters. Its reserved `__kasumi_security` store is separately
encrypted and must use a wrapping key distinct from tenant customer keys; the
embedding application owns that configuration and lifecycle. Server runtime
reexports the shared types and retains local authentication/transport trait
implementations. Service records remain independent of tenant log compaction
and can be written after a customer tenant is sealed.

Repeated live opens on the same `TenantStore` with the same retention quota
share one sequence, failure state and work fence; a conflicting quota is
rejected. The weak registry tracks the shared inner writer, so a value clone or
detached write job retains that identity after an outer `Arc` is dropped. A
second live handle cannot reset the sequence or bypass its failed state.

The [Database request layer](../crates/kasumi-engine/src/service.rs) records
`FORBIDDEN`/`UNAUTHORIZED` as `access_denied` and `SEALED` as `tenant_sealed`.
Coverage includes owned/shared point access, query, collections, receipt lookup,
mutation, administration, backup, restore completion and maintenance audit.
The public [standalone restore paths](../crates/kasumi-engine/src/bootstrap.rs)
also audit denied authorization and sealed target access before a `Database`
exists. Trusted raw engine primitives are not separate authenticated endpoints;
the host and embedding application remain trusted.

The [error type](../crates/kasumi-types/src/lib.rs) carries a private, nonserialized
`denial_audit_attempted` marker. A nested database, administration or adapter
boundary checks it before attempting the same denial record again. It marks an
attempt, not successful persistence: a failed audit cannot turn a denied request
into access. The marker is excluded from wire values and durable receipts, is
reset by deserialization, and does not alter error equality or diagnostics.
This is per-error composition, **not request-ID deduplication**. Independent
denied requests that reuse a request ID still each require a record.

[Native RPC](../crates/kasumi-server/src/rpc.rs) and
[MCP](../crates/kasumi-server/src/mcp.rs) retain adapter-originated routing,
protocol and predispatch response-fence denials. Authentication lifecycle
auditing remains in [Authenticator](../crates/kasumi-server/src/auth.rs).
Both data adapters use the shared [response release boundary](../crates/kasumi-server/src/api.rs)
after constructing their encoded payload, so a later seal can withhold release
and record its own denial. Already audited database errors do not acquire a
second record. Records contain the closed security metadata fields, excluding
document bodies, query/receipt values and tokens.

## Cancellation, shutdown and uncertain persistence

The common writer registers work before scheduling blocking persistence. Its
registration outlives an abandoned async caller and holds the resources until
the actual write job ends. `Database::shutdown` drains its admitted denial jobs;
the node owner shuts down the shared audit writer after all databases and
listeners stop. Writer shutdown closes admission, drains queued/running jobs,
and shuts down its key store. A canceled shutdown can be awaited again. Caller
handles must still be released before opening the same exclusive node file.

An audit transaction can become durable before a later key-access release check
reports an unknown outcome. The writer now marks its sequence state failed on
any storage write error. Queued and future writes then fail until recovery
reloads the durable sequence, even if key authorization is refreshed. This
prevents uncertain persistence from causing a sequence number to be reused and
an earlier audit event overwritten. Required successful-operation audit failure
continues to block its operation; access denials remain enforced when their
record cannot be persisted.

## Focused evidence and limits

| Evidence | Direct proof |
| --- | --- |
| [Embedded integration tests](../crates/kasumi-engine/tests/embedded_audit.rs), [passing log](../target/embedded-denial-audit-tests-final.log): 3 passed | All listed request boundaries plus cross-tenant and sealed access produce 12 retained records despite one reused request ID; payload fields stay absent. Denial remains enforced with a failed audit sink. Immediate real redb reopen preserves records. Standalone local/replicated restore denials and sealed target access produce three records without initializing the unauthorized target. |
| Embedded cancellation test in the same log | A single-thread runtime and occupied blocking worker deterministically queue a real denial write. Canceling its caller and the first shutdown keeps ownership until the worker is released; subsequent shutdown drains it and immediate reopen preserves the record. |
| [Security writer tests](../crates/kasumi-engine/src/security_audit.rs), [passing log](../target/security-audit-component-test.log): 3 passed | Queued writer/canceled shutdown ownership drains before immediate real-file reopen. Concurrent live opens share sequence state and retain three unique sequential records across real-file reopen; conflicting quotas are rejected, and value clones retain the writer identity. The injected persistence backend advances the lease clock during durable sync, produces an unknown outcome, proves queued/new/duplicate-open writers remain fenced, then recovers sequences 0 and 1 without overwriting the first event. |
| [Server API tests](../crates/kasumi-server/src/api.rs), [passing log](../target/server-common-denial-audit-test.log): 14 passed | Exactly one durable record for each embedded/native/MCP denial; unknown native/MCP tenants, SDK Host rejection and predispatch sealed fences remain recorded. A real database response is encoded, the tenant is explicitly sealed, and the shared release helper denies and records both read and mutation branches. Existing authentication, wire precision, receipt, strict-audit failure and lost-response tests pass. |
| [Server Clippy log](../target/server-common-denial-audit-clippy.log) | All server targets pass with warnings denied. |

The postencoding regression controls the shared adapter boundary directly; it
does not claim a kernel/TCP race or confirmed client receipt. The uncertain-sync
test uses an injected persistence backend and clock, not a physical power cut.
These focused logs establish the named behaviors; the fresh platform manifests
above provide the full gates for the corrected source. They do not establish
production performance or complete the measurement matrix. Historical results are
not adjusted to include the added embedded service-store footprint.
