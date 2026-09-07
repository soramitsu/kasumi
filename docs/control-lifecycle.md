# Closed control commitments and independent epoch stops

The lifecycle control protocol commits the authority for an exact recovery phase before an independent issuer can grant execution time. It does not yet execute target materialization, target initialization/completion/activation, or local generation destruction. Those closed target operations remain required; a signed grant or `StopActivation` response is not evidence that local target work stopped.

## Installed boundaries

The nullable lifecycle state/configuration fields require explicit JSON values; omitted fields are rejected rather than decoded as an old first-release format.

`ControlConfig.lifecycle` selects an explicit `LifecycleRuntimeConfig` containing the permanent installation command UUID, exact `LifecycleInstallation`, and a private PKCS8 signing-key file. It requires replicated startup and the matching fixed control incarnation. The administrative TLS listener registers `NativeLifecycleControl`; startup publishes the exact installation after topology initialization. Followers become ready only after that installation is locally applied. Startup refuses changed or disabled durable installations. A signer cannot sign a supplied DTO: it accepts only an engine-created observation that rechecks a current three-voter quorum, original live credential and current Admin policy before and after signing.

`AuthorityManifest.lifecycle_controls` is a required first-release map of installed control-incarnation UUIDs to Ed25519 public keys. Empty explicitly disables control grants. The manifest, signing keys, maximum grant lifetime, drift bound and partition topology are immutable. A control group pins the complete authority-partition set and its generation; the issuer checks its exact member and the commitment to that complete set. No native request selects a control key or authority endpoint.

`KasumiLifecycleClient` provides execute, observe-intent, observe-change and status methods over installed pinned TLS. `KasumiAuthorityClient` provides execute-lifecycle, read-lifecycle-receipt, acquire-lifecycle and verify-control-stop. Every service enforces its own resource purpose, actual mTLS peer, current authorization and original credential lifetime. Data-purpose credentials cannot invoke Control or Authority operations.

## Permanent identity and finite grants

An intent binds the source incarnation/authority epoch, exact full-backup checkpoint, target incarnation and node principals/certificate hashes, phase and input digest. Ordered control execution derives its finite original credential deadline once. A renewed credential cannot change that retained deadline. Issuer identity excludes fresh observation positions/signatures, but every attempt verifies the signature before looking up a retained result; changed immutable reuse conflicts.

Lifecycle grants additionally bind the original pre-dispatch attempt and process boot. Their elapsed deadline is capped by the immutable issuer maximum and the remaining original Control and actual node credentials. Copies and delayed replies cannot re-anchor time. Clock regression permanently closes that boot. Issuer release repeats current quorum and epoch/target checks. These grants authorize only the named phase; application session and membership checks are independent.

## Revocation and target stops

BeginPolicyChange freezes new commitments and topology publication and pins the exhaustive installed partition set. Each issuer permanently records StopEpoch, defeating a later intent even when no intent had arrived yet. A stop proof requires a complete immutable, drift-adjusted maximum-grant drain under a fresh term/process witness. Restart, leader change, clock regression or eviction of a completed witness conservatively restarts the full wait. Control policy replacement or control retirement completes only with exact signed drain proofs from every pinned partition. Signer/installation replacement and generic authority/schema invalidation cannot bypass the closed transition.

StopTarget separately retains a permanent incarnation-wide tombstone. It defeats missing/prepared target acquisition and late prepare/activation. A prior committed activation remains the winner and requires roll-forward. StopTarget plus its drain proof is necessary for local cleanup; the actual target runner must also close and drain its materialization and storage work before deleting anything.

## Bounds and evidence

Control state is bounded to 1024 issuer partitions, 10,000 permanent intents, 1024 changes and 8 MiB per installed control group, with configurable lower ceilings. Issuer state has its own explicit count/byte limits. An accepted control epoch reserves a permanent stop receipt and bounded bytes; later commands cannot spend that headroom. Completed proof reads do not create mutation identities. History is not silently dropped: exhausted administrative lifetimes require a separately designed migration/archive facility and are not claimed as unlimited tenanted operation.

Tests cover actual encrypted quorum state, exact replay/restart, missing-stop permanence, queued expiry, delayed grants, rollback, current resource/peer binding, and count/byte reservation. The pinned native integration uses distinct three-voter Control and issuer groups. It proves committed signing and the drain-before-policy-completion protocol; its checkpoint input is deliberately an administrative shape fixture, not a fabricated physical backup proof. Physical target execution, deployment availability, external PKI/KMS and hardware clock-rate certification remain separate acceptance boundaries.
