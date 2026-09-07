# Credential resources and immutable restore lineage

Every verified native JWT includes a required signed `kasumi_resource`. There is no missing-claim decoder or tenant-wide token fallback:

| Purpose | Required value |
| --- | --- |
| Ordinary data and tenant administration | `{"kind":"database","incarnation":"<database UUID>"}` |
| Installed lifecycle control | `{"kind":"control","incarnation":"<control database UUID>"}` |
| Independent serving authority | `{"kind":"authority","authority_id":"<installed UUID>","partition":0}` |
| Retired source custody | `{"kind":"custody","incarnation":"<source UUID>"}` |

Signature, configured issuer/audience/type, current scopes/policy and the original credential lifetime remain mandatory. A matching UUID cannot widen a credential's purpose. The live proof is retained through routing, queued leader admission, deterministic replicated application and response release. A serialized RequestContext has no live invocation. Trusted embedded callers explicitly choose `RequestAuthorization::service_identity()` or call `from_verified_credential(expiry_ms, &original_clock_observation, resource)` after verification.

An accepted RetireSource invocation can acknowledge its own exact immutable receipt after the source transitions into custody. Its opaque engine proof retains that original live invocation identity and rechecks current custody Admin, original actor, source incarnation, exact receipt and policy epoch. Equal token claims verified again cannot recreate this transition fence. Fresh retirement status/proof/rotation uses Custody-purpose credentials. Expired or revoked acknowledgement after an accepted effect remains UnknownOutcome; it cannot undo the source fence.

Local control storage and explicit local fixtures may install a known initial UUID with `open_local_with_incarnation`; reopening under a different UUID fails. This does not accept production serving-authorized storage or downgrade a replicated tenant. A fixture needing a pre-issued data token sets its actual UUID explicitly. Production serving tenants still require the installed replicated authority configuration.

## Historical data readers

`Database::read_restore_lineage(&context, ReadRestoreLineage { expected_incarnation, collection })` and `KasumiClient::read_restore_lineage(bearer, &request)` return opaque VerifiedRestoreLineage. Current Read permission on that existing collection is sufficient; no schema/Admin privilege is required. The proof exposes source/target incarnation, source revision, resident state commitment and a commitment to the complete verified checkpoint. It exposes no destination, key lineage, backup object identifier or filesystem location.

Every restored genesis appends the exact previously verified FullBackupCheckpoint and its new incarnation to a required immutable chain. Later full backups authenticate that whole chain. Shape validation rejects cross-tenant/discontinuous/repeated incarnations, incorrect final origins and nonincreasing source revisions. The native engine additionally binds the complete restoration identity at genesis, so a later same-incarnation snapshot cannot substitute a shape-valid prefix. Maximums are 1,024 links and 1 MiB; exceeding either fails closed without truncation. Historical application documents and hashes are not rewritten.

Current collection policy, original credential and serving authority are retained through snapshot/audit, native encoding and final quorum/release checks. Strict audit acknowledgement failure withholds a read proof. Historical lineage is not a new credential, permission, membership, session, approval or serving lease; each application consumer must independently authorize its current operation.

## Verification scope and unfinished lifecycle work

Actual encrypted local restore fixtures exercise two full backup/restore hops, immutable row/version preservation, encrypted reopen, stale unexpired native data/Admin rejection, exact purpose rejection and shape-valid snapshot substitution denial. A TLS/mTLS/pinned SDK fixture checks the ordinary Read proof and exact retirement/custody transition. These fixtures do not prove a deployed disaster-recovery target activation.

The source-independent durable target runner, incarnation-wide preparation/serving stop with full drain and local cleanup, and a closed control-authorization commitment/revocation protocol remain required work. In particular, the former healthy Manage restore path reused one source context across source and target. It must be replaced with explicit installed Control authority while retaining the healthy path's independently verified exact source retirement proof. An old database JWT cannot supply that authority. Separate control and target group reads are not an atomic revocation check. No source-quorum override or local-mode fallback is introduced by this checkpoint. External deployment availability, KMS/PKI custody and certification remain external evidence boundaries.
