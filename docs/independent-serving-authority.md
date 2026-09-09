# Independent serving authority — first-release substrate

This source implements the independent issuer, signed serving and restore-preparation capabilities, required application-storage fences, and their native/Rust SDK boundaries. It does **not** yet implement a complete durable native target disaster-recovery runner or an incarnation-wide target destruction/rebind fence. Existing healthy restore activation still requires its verified source retirement proof. External availability, key custody, failure-domain independence and hardware clock validation are deployment obligations.

## Installed trust and durable outcomes

`kasumi-authority` owns a separately keyed, explicitly installed three-voter Raft group. It cannot be opened as a local municipality database. The `kasumi-authority` server binary exposes only the independent authority service; its application, custody and security-audit wrapping roots are separate. Bootstrap waits for the installed peer fingerprints and never manufactures a smaller voter set.

The authority configuration requires a durable nonnil `database_id` for each
physical authority node file. Install that configuration and its private parent
directory before running these commands as the authority service account:

```sh
kasumi-authority check-config /etc/kasumi/authority.json
kasumi-authority provision-node /etc/kasumi/authority.json
kasumi-authority serve /etc/kasumi/authority.json
```

`provision-node` is exclusive first enrollment of the file envelope and storage
tables; issuer/security catalog and bootstrap initialization remain separate.
Subsequent starts run only `serve`, retaining the same configured UUID. Missing,
partial, unrelated or differently identified files fail closed. No existing
path is overwritten, and a failed initialization does not authorize automatic
recreation. See [node-file identity and recovery](node-file-envelope.md).

The immutable `AuthorityManifest` fixes its partition map, signing keys, maximum lease interval and `clock_rate_error_ppm`. A tenant hashes to one power-of-two partition. A source database does not host its own serving authority. The installed node client supplies the actual mTLS leaf and a verified finite JWT; body fields cannot substitute a peer certificate or grant capability.

Commands retain an exact request digest and outcome permanently, under current global Admin authorization. `Enroll` registers the initial incarnation and installed node principals/certificates. `Fence` permanently freezes that exact active source epoch. `Activate` requires that exact committed fence plus a private term-scoped complete drain, then atomically advances the active incarnation/epoch and binds the target nodes to the full backup checkpoint. Every previously activated incarnation remains in permanent history and cannot be reactivated. Concurrent candidates cannot both win. Self-revocation or a failed post-acceptance release produces `UnknownOutcome`; a current custodian can recover the exact original receipt.

`StopActivation` stops only its exact original activation identity. A previously accepted activation remains accepted. This stop is **not** target-incarnation quiescence: it does not stop independently registered restore-preparation lease acquisition, and cannot authorize physical target deletion or rebinding.

The point-addressed authority records have explicit tenant, permanent receipt and byte limits. A new source fence reserves one activation receipt and maximum-sized tenant/incarnation completion records. Subsequent commands cannot spend this reserved headroom. The quotas bound an installed authority partition's retained lifetime; there is no silently dropping permanent history, automatic policy expansion or unlimited maintenance claim. Security-audit storage has its own existing hard lifetime bound.

## Time, renewal and response release

A `ServingBoot` owns a process-created boot nonce and suspend-aware elapsed clock. A `LeaseAttempt` samples time before its exact network dispatch and carries a fresh attempt nonce. A response is accepted only if the installed issuer signature matches that exact manifest, tenant, incarnation, epoch, node principal, mTLS certificate, boot, purpose and attempt. No serialized DTO or saved boot ID can create a live capability. Delayed responses and clones preserve the original deadline. Remaining verified JWT lifetime also caps the grant.

Issuer drain is `ceil(max_lease_ms × (1,000,000 + ppm) / (1,000,000 − ppm))`: the fastest allowed issuer must cover the slowest allowed client. The configured bound is a trust premise that operators must validate for their actual suspend-aware clocks. Zero represents exact logical clocks in fixtures. The operator example uses 1000 ppm as an explicit example, not a hardware certification. A different leader term, process restart or elapsed-clock regression resets the complete drain. No caller timestamp or persisted wall-clock deadline shortens it.

A `ServingGate` supports only continuous fresh renewal for its original boot/incarnation/epoch and activation. Renewal installation checks the previous lease's actual deadline, even if no reader observed expiry. A delayed renewal cannot bridge an expired interval. Once closed, all old handles and captured fences remain closed; a separately verified new admission does not revive them. Every data request also retains its independent original JWT and application `Before`/approval deadlines. Legitimate continuous serving renewal does not extend those request deadlines.

## Required storage and engine boundaries

`TenantStore::open(node, tenant, provider, StorageAccess)` and `TenantStorageSet::open(node, tenant, application_provider, custody_provider, StorageAccess)` require an explicit capability. Production application access uses `StorageAccess::serving(Arc<ServingGate>)`. Reserved node-control, service-audit, independent-authority and retirement-custody domains have closed installed purposes. These purposes are authenticated in the key catalog and custody binding, so a serving catalog cannot be reopened as an unfenced control/fixture store. `open_fixture` helpers exist only in the explicit test feature; there is no production compatibility decoder.

Application keys cannot be constructed/unwrapped/refreshed and application ciphertext cannot be read/written without the live installed capability. Engine generation access, serialized proposal admission, ordered application, persistence and final response release repeat the fence. A serving capability cannot open or restore a local data group. Replicated bootstrap must match the signed incarnation before persistence. Prepared restore verifies the signed backup ID and manifest ciphertext before decrypting the backup graph, and compares the full verified checkpoint before creating the target genesis.

Node startup reads independently keyed retirement control first. Retired custody recovery remains available without an application provider. If a nonretired original incarnation cannot acquire current serving authority, startup installs `RecoveringControl`, does not construct the application key provider, and retains node-control storage/listeners. This does not authorize municipality reads or make a nonretired `Stopped` outcome recoverable after its old serving authority expires.

## Restore preparation and remaining target work

`PrepareTarget` binds a fresh target incarnation, next epoch, exact source and checkpoint. Its signed `RestorePreparation` capability permits bounded suspended-target materialization and exact restore completion; it cannot pass the data registry, ordinary data response fence or application mutation admission. After independent `Fence`/drain/`Activate`, the target must acquire a fresh signed `Serving` capability for the same boot, target and checkpoint before promotion. A prepared gate that expired requires a new admission/open; it cannot be renewed into service.

The existing healthy native `ActivateRestore` also requires its current authenticated source retirement proof and exact restored origin. The new independent issuer does not relax that path. A durable native source-unavailable target runner still needs a closed current-control-Admin command identity, restartable preparation/initialization/completion, exact checkpoint binding, installed target routing and uncertain-outcome recovery without selecting a source URL or requiring the lost source quorum. Incarnation-wide target stop and physical deletion/rebind evidence are separate remaining requirements.

## Native and Rust client contracts

`KasumiAuthorityClient::connect(config, AuthorityTrust)` requires the shared TLS1.3/mTLS connector, approved CA and server leaf pins. `discover_lease` observes the exact requested incarnation's epoch under current node credential; the DTO grants no access. The subsequent `acquire_lease(bearer, &LeaseAttempt)` verifies a fresh signed opaque capability against the same actual client certificate. `execute` and `receipt` verify installed signatures and exact requested command identity. `activate` and `recover_activation` additionally return private-constructor `VerifiedActivation` evidence; that evidence is immutable history, not a live serving lease.

`RuntimeConfig.serving_authorities` and each `TenantConfig.serving` are required first-release configuration. Node epochs are discovered from installed authority rather than copied into stale local configuration. `AuthorityRuntimeConfig` separately fixes the issuer voters, signing-key file, native transport, authentication and independent key domains. No request can choose those trust roots, endpoints, credentials, node principal or boot nonce.

## Verification scope

Focused tests cover actual encrypted three-voter authority state, current Admin/self-revocation recovery, concurrent activation and permanent stop, full drain after encrypted restart, permanent incarnation reuse denial, actual authority quorum loss, preparation/serving separation, real TLS/JWT/pin client binding, original-attempt delay and clock rollback/suspend, unobserved-expiry renewal, encrypted queued-effect rejection, late encoded read/committed acknowledgement fencing, backup publication uncertainty and fresh exact receipt recovery. Issuer/storage fixture signatures are explicit where tests isolate the engine; they are not claimed as deployed issuer availability. Final source-bound command logs and exact input hashes are recorded separately in `docs/evidence`.

## Installed endpoint failover and renewal

Each `ServingAuthorityConfig.endpoints` entry maps a partition to a bounded map
of authority member IDs, HTTPS origins and member-specific certificate pins.
`KasumiAuthorityPool` connects only to this installation and never follows a
peer-provided URL. Unreachable members and retryable quorum/transport failures
advance to another installed member under one overall deadline. Every acquisition
reuses the same opaque `LeaseAttempt`, including its original clock anchor.
Command retries first recover the original receipt and check the complete command.
Invalid authorization or cryptographic proof stops that operation.

Runtime renewals schedule from the verified remaining credential lifetime,
including grants shorter than the configured maximum lease duration. Expiry
permanently closes the old gate; a new lease cannot revive captured handles.
The bearer file is reread for each request, including a failover attempt.
