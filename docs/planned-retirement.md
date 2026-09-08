# Exact planned source retirement

Planned retirement permanently closes one source incarnation against a complete verified backup and an intended fresh target incarnation. The source must still provide authenticated administrative quorum. This does not provide disaster recovery when source quorum is unavailable.

## Request and proof contracts

`RetireSourceRequest` requires `retirement_id`, `expected_source_incarnation`, `target_incarnation`, the exact `FullBackupCheckpoint`, an installed backup `destination` alias, and `not_after_ms`. The checkpoint in the request is an equality expectation. Kasumi reads and verifies its actual encrypted manifest, resident state, archive dependencies and key lineage before preparing retirement.

The ID is scoped to the source incarnation. `request.reference()` returns `RetirementRef { source_incarnation, retirement_id, request_digest }`. The permanent record retains the original authenticated principal. Every subsequent observation requires current source Admin, but can use a newly authorized custodian. A different request under the same ID conflicts. Matching replay returns the original outcome without retiring again, changing the original actor or advancing the retirement policy epoch.

The engine and secure Rust Admin SDK provide:

```rust
// Database takes owned requests and a verified/trusted RequestContext.
retire_source(context, request) -> VerifiedRetirementReceipt
retirement_status(&context, &reference) -> Option<RetirementStatus>
verify_retirement_receipt(context, &reference) -> VerifiedRetirementReceipt
abort_retirement(context, request) -> VerifiedRetirementResolution

// KasumiAdminClient takes a bearer and a borrowed request/reference.
```

Engine and SDK proof types have private constructors and do not implement Deserialize. Serializable receipts/status are observations. They cannot authorize checkpoint refresh or target activation by themselves. The native API routes only through configured tenant/source generations; no request supplies a source URL, credentials for another tenant, or an arbitrary storage path.

`VerifiedRetirementReceipt` exposes the source tenant/incarnation, intended target, original action ID and digest, actual retirement revision/policy epoch, and exact backup checkpoint. It is immutable evidence of a permanent fence, not a serving lease. Fresh readback checks current source Admin and source identity through authorized response handoff.

## Closure against the backup

Retirement checks all application collections. There are no collection, document, field or caller-configurable exclusions. The canonical closure covers:

- Every collection definition, data epoch, document ID/version and full-document hash, including verified cold-document hashes.
- Tenant/incarnation, schema and policy epochs, current policy/limits, suspension/restore origin and logical counters.
- Retained mutation outcomes, staged transaction identities/payloads/terminal outcomes, schema outcomes, archive publication identities, and retained feed state.

Intrinsic audit events, Raft revisions and retirement-attempt bookkeeping are excluded. Thus routine administrative audits after capture do not invalidate the backup. A new rejected business command, stage transition, schema outcome or archive publication does invalidate it, even when no application document changed. Such work must settle before capture, or the operator must produce a new backup and restore the corresponding new target.

The verified backup closure is compared with current state under the serialized leader proposal gate. Its current revision and canonical digest enter the replicated preparation. Replicas deterministically check that exact previous revision and both digests before atomically retaining the outcome and setting the terminal source fence. They never perform backup I/O or evaluate their own wall clocks during apply. Generic administration rejects prepared retirement and stop operations; dedicated service methods provide their verification/admission boundaries.

Canonical hashing streams bodies into SHA-256. Borrowed sort nodes receive a node admission reservation, and blocking workers retain their resources and shutdown registration until actual completion. Complete graph verification retains its existing operation deadline, cancellation and byte limits.

## Resolving a refresh race

A missing retirement status, elapsed fleet grant or lost response does not establish that a delayed retirement cannot commit. `abort_retirement` orders a permanent stop for the full exact request without reading backup objects:

- If retirement already committed, it returns `VerifiedRetirementResolution::Retired` with the original verified receipt. Recovery must preserve that checkpoint and roll forward.
- If an accepted deterministic failure already exists, or the stop wins first, it returns `Stopped(VerifiedRetirementStop)`. The exact identity is permanently unable to retire afterward. Every delayed same-ID preparation resolves to that retained failure.

The stop exposes `tenant()`, `source_incarnation()`, `retirement_id()`, `request_digest()`, `revision()`, `principal()`, `reference()`, `failure()` and `status()`. The stable accepted `status()` can be digested for an independently authenticated orchestration attestation. The reference must match the persisted retirement request. A stop is evidence about that exact attempt; it does not grant a new serving or orchestration lease. A different already-retired source binding prevents stopped-proof publication.

Quorum, authority or response uncertainty produces no stopped proof. Callers must retry the exact stop and resolve its permanent outcome. They must not convert an ordinary error, status absence or a caller-controlled boolean into refresh permission.

## Time, capacity and administrative custody

`not_after_ms` is an inclusive trusted leader execution-admission deadline, sampled after the serialized gate and closure preparation. A committed outcome remains recoverable after that original action deadline. Fresh credential authorization has its separate exclusive expiry and original suspend-aware monotonic fence; cloning, queueing or readback cannot extend it. Expiry before proposal admits no command. An effect whose acknowledgement expires remains committed and returns UnknownOutcome rather than a fabricated rollback.

Permanent outcomes consume required `Limits.max_retirement_bytes` (positive u64,
default 64 MiB) and exact snapshot accounting. There is no lifetime record-count
ceiling. They do not expire or enter application history archives. Before backup
I/O and again before ordered commitment, a new identity reserves its key/value
at full-width future revision/clock/policy fields plus bounded error-outcome
headroom. Only exact terminal bytes remain charged. Required audit and snapshot
capacity must also fit before any fence is published. Increasing the byte budget
allows further identities; reducing it below retained bytes is refused. The
former count field is rejected.

After retirement, all application commands, policy/limits and `Suspend(false)` remain sealed. The independently keyed closed custody reducer can rotate only its current global administrators and separate bounded metadata budgets; see [the custody contract](custody-control.md). It cannot reopen data or modify the original retirement binding. Native recovery can release current-authority retirement proofs without constructing the old application provider. Independent serving-lease authority remains required; this custody path does not issue serving permission.

## Restore and deployment boundaries

Restores retain the exact authenticated source `FullBackupCheckpoint` in `TenantState.restored_from`, independently of the transient pending-restore flag. Completion cannot erase that identity. Local managed activation now requires a fresh source retirement proof whose target and checkpoint exactly match the completed suspended target.

The local Administration activation path requires the exact installed source custody route and managed target to be available to that control process. It can load an already control-authorized replacement generation independently of the retired source's application handle. Native source proofs can be consumed by a remote executor, but these APIs alone do not complete cross-host control-plane activation or unavailable-source recovery. Deployment integration must provide the independently authenticated target/control authority path. External key custody, disaster-recovery capacity, RPO/RTO certification and operator signoff remain separate.

## Verification

[The source-bound verification receipt](evidence/planned-retirement-20260907-b/verification.json) records 262 passing workspace tests, two ignored external-provider tests, strict all-target/all-feature Clippy, formatting and diff checks. All 128 recorded Rust, manifest and protocol inputs remained unchanged during the run. This includes actual encrypted source retirement/stop races and restart, post-checkpoint drift, permanent quota admission, current-custodian recovery, credential expiry/uncertain acknowledgement, pinned-mTLS SDK proofs, and managed three-node restore/retirement activation.

[The earlier failed run](evidence/planned-retirement-20260907-a/verification.json) is retained. It exposed excessive async stack residency in composed administrative work. Two ordinary boxed future boundaries reduced the measured management entry frame from 19,264 to 4,896 bytes and retirement from 8,496 to 1,952 bytes on this verification target; a regression bounds both entry frames to 8 KiB. Cancellation and resource guards remain owned by the same futures. The corrected run passed the original replicated runtime fixture without increasing thread stack size.
