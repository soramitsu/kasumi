# Credential lifetime through execution and response delivery

Every first-release `RequestContext` requires a `RequestAuthorization`. Trusted embedding or installation code explicitly uses `RequestAuthorization::service_identity()`. Native data, administration and MCP callers cannot select that origin through a request body or metadata. Their authenticator constructs credential authorization only after signature, issuer, audience, token profile and scope verification.

The authenticator captures a paired UTC and suspend-aware elapsed-clock observation before key retrieval and signature verification. The verified token's `exp` determines an elapsed deadline anchored to that original observation. Cloning, queueing, an interrupted caller and delayed construction preserve the same deadline. A shared `kasumi-clock` implementation uses Linux `CLOCK_BOOTTIME` or macOS `mach_continuous_time`; machine suspend counts toward expiry. Once a deadline expires or observes elapsed-clock regression, clones cannot revive it.

`kasumi_clock::EpochClock::system()` returns `anyhow::Result<Arc<EpochClock>>`. Native authenticators, ordered execution and trusted embedding callers share that same process-wide instance. Constructing another listener cannot establish a later, lower UTC anchor. The process UTC floor advances with elapsed time even when wall time moves backward. Forward wall-clock observations can advance the floor. Frequent observations retain fractional elapsed time instead of discarding it. Correct UTC at a fresh process start remains an operational prerequisite; the library does not claim to establish trusted time during a powered-off interval. A restart never restores a serialized live credential proof.

## Ordered writes

The database checks the live authorization at initial admission and after the serialized proposal gate, including another check after schema workspace preparation. It captures trusted command time before submitting to Raft. A credential expired while queued is rejected with `Unauthorized` before proposal, with no effect and no accepted operation identity. A fresh credential may submit that same identity.

Replicas apply only the captured trusted admission timestamp and serialized expiry; they do not sample independent wall clocks when applying a committed command. Expiry after valid admission does not undo committed materialization. If the credential expires before acknowledgement, the caller receives `UnknownOutcome` and uses a fresh credential to resolve or replay the original durable operation identity. Denial auditing happens before normalizing that acknowledgement, so uncertainty does not hide the access-denied event.

Serialization retains authorization metadata for deterministic replication, but both serialized service identity and credential metadata deserialize without live authority. They cannot enter a database as a fresh local request. This is a required first-release contract; there is no default, missing-field fallback or restoration of a live proof from old records.

## Reads, backups and native delivery

Current authorization is checked again when releasing reads, receipt lookups, snapshots, history, and administrative backup proofs. Native adapters retain the original context through encoding and perform the final check before handing bytes to the transport. Bytes already handed off cannot be recalled, and this boundary does not assert that the client received them.

Long backup verification withholds its proof if the credential expires. Backup creation can already have published immutable encrypted objects when expiry is detected; it reports `UnknownOutcome` instead of asserting that those artifacts were rolled back. Current RBAC, key access, policy epochs, shutdown and resource admission remain independent required fences.

The opaque backup checkpoint remains immutable evidence rather than renewable authority. Credential deadlines also do not substitute for independent incarnation serving leases. Source-quorum-unavailable disaster recovery remains blocked until the old incarnation's serving authority can be independently fenced; the current restore activation requirement for durable source retirement remains in force.

## Recorded verification

The [full workspace receipt](evidence/credential-lifetime-20260907-b/verification.json) records 245 passing test entries and two external-service tests ignored, plus strict workspace Clippy and formatting checks. The subsequent three-file shared-clock refinement has its own [final receipt](evidence/credential-lifetime-20260907-c/verification.json): 81 affected clock/types/engine/server library tests and strict workspace Clippy, with unchanged source hashes. The earlier failed Clippy attempt remains recorded separately. These are software test results, not external certification or deployment approval.
