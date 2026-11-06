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

## Online recovery of credentials that expired during an outage

A credential renews itself with its own bearer: `kasumid credential watch` renews at a random point between 50% and 70% of the remaining lifetime, and lifetimes are at most 3600 seconds. When kasumid is unavailable for longer than what remains of a credential's lifetime, the credential expires, and an expired bearer cannot authenticate its own renewal. Before online recovery, the only remedy was the stopped-installation `kasumid recover-existing-credentials`, which costs another full reopen (7 to 11 minutes on the BOI deployment, where all 54 families expired this way).

### What can recover

The administrative `RecoverCredential` method renews a family from its expired credential only when every condition below holds. The listener checks the first five before it reads the request body. The method checks the last two, and the issuer checks the latest-issuance rule again, with revocation and the window, under its writer lock.

1. The connection presented a client certificate signed by the installation's client CA. The administrative listener already requires one, and the method refuses a connection without one. The certificate's SHA-256 is recorded with the recovery.
2. The installation uses the local issuer. Installations with an external OAuth provider refresh credentials with that provider.
3. The presented bearer is the expired access token itself. Its signature (under any retained signer generation), issuer, audience, `typ`, `token_use`, names and family claim are verified exactly as for any request. Only its expiry is treated differently.
4. Its family exists, is unrevoked, and still has exactly the token's principal, tenant, resource and scopes.
5. It has expired, and less than 24 hours ago (`EXPIRED_CREDENTIAL_RECOVERY_WINDOW_SECONDS`, compiled in; no configuration lengthens it). A credential that is still live must renew instead.
6. It is the family's latest issuance. Every creation, renewal and recovery records its issuance in `local-credential-latest-issuances` in the same batch that writes it. A credential that any later issuance superseded is refused, including one superseded by a recovery.
7. The family's resource is still routed: its database's current serving generation, or the Control incarnation with Control administrator authority. Current policy still grants the principal every registered scope. Stopped-installation recovery checks the same two things.

The recovered credential keeps the family's identity, scopes, resource and lifetime. The request names a renewal ID that the watcher saved before dispatch, the same journal that renewal uses. Retrying with that ID replays the original issuance exactly, so a lost reply never issues a second credential. A replay needs the presented credential to still be inside its window, and it needs the renewal ID, which exists only in the 0600 journal and as the issued token's `jti`.

`credential watch` and `credential renew` try ordinary renewal first. If the daemon refuses the bearer as unauthenticated, they present the same bearer for recovery with the same renewal ID. Uncertain transport outcomes are retried as before. A refused recovery is final: the watcher exits with the daemon's reason and the stopped-installation command to run. If a replayed issuance has already expired because its reply was lost, the watcher publishes it, since it is the family's latest, and recovers from it once. `kasumid credential inspect <profile>` prints `online_recovery_until_ms`, the time the window closes. Only the daemon knows whether the profile's credential is still the latest and its family unrevoked.

### Audit

Every path is recorded in the service audit before the caller sees its outcome:

- An unverifiable presentation (no client certificate, external issuer, bad signature or claims) is recorded as `authentication_denied` without any identity, and counted like any refused bearer.
- A verified credential refused at the listener (still live, outside the window, revoked or with changed claims) is recorded as `key_administration` with outcome `denied`, under the family's principal and tenant.
- An accepted presentation is recorded as `key_administration` `started` before any routing or issuance, then `succeeded`, `denied` or `failed` under the same request ID. `started` must be durable, or nothing is issued. `succeeded` must be durable before the new credential is released; if it cannot be written, the credential is withheld and the client's retry replays it.

The credential ledger (`local-credential-events`) gains a `recover` row in the same atomic batch as the issuance. It records the actor, the renewal ID, the recovered issuance and its expiry, and the client certificate's SHA-256. `key_administration` is the kind the stopped-installation recovery uses, so online and offline credential recovery are found the same way. They differ in principal: the family's own principal online, `offline-operator` offline.

### Threat model

What recovery adds is narrow. For at most 24 hours after it expires, a family's latest credential can still do exactly one thing: obtain that family's next credential, over a client-certificate connection, while no later issuance exists. It never authenticates any other request, never changes a family, and never revives a revoked one.

- **A network attacker without an installation client certificate** cannot complete the TLS handshake on the administrative listener. Nothing changes.
- **A holder of an old credential** (from an application's logs, a backup, a core dump) is refused once that credential is superseded. While a watcher runs, each credential is superseded at its next renewal, 30 to 42 minutes after issue. A credential found later is only the latest if renewal stopped right after it was issued.
- **A holder of the latest credential while its family renews normally** gains nothing new. Ordinary renewal never invalidates earlier tokens, so a stolen live credential could already be renewed for as long as its holder keeps renewing, until revocation. Recovery only extends the deadline for that first renewal by 24 hours, and only after the family's own watcher has stopped renewing.
- **A holder of the latest credential during an outage** races the family's watcher when kasumid returns. The watcher retries every 3 to 8 seconds, so it is usually first. Whoever recovers first supersedes the other: the second is refused as superseded, the watcher reports that and exits, and both attempts are audited under the family's identity. This detects the theft rather than preventing it. Revoke and re-create a family whose watcher reports a supersession it did not cause.
- **An attacker who can read the profile directory** already holds the client key, the bearer and the renewal journal. No mechanism that keeps renewal material beside the client resists that, a refresh secret included. Revocation and file ownership (0600, owned by the installation user) are the controls.
- **Replay** of a captured recovery is prevented by TLS 1.3 without early data. A renewal ID replays only its own issuance and grants no new authority.
- **Time** is the process's trusted UTC floor, the same one expiry uses. A clock set forward at process start closes windows early, which fails safe. A clock set backward at process start reopens windows, just as it would un-expire credentials. Correct UTC at a fresh process start remains the existing operational premise.
- **Rolling back to a build without online recovery and forward again** leaves a residual risk. The older build renews without updating the latest-issuance record. Until a family's next renewal under this build, its record can name a credential the older build superseded, and that credential could recover inside its window. After rolling forward, let every watcher renew once (at most 42 minutes) before treating superseded credentials as dead, or revoke families whose old credentials may have leaked.

### Options weighed

- **Proof of possession with the expired credential** (chosen). It needs no new secret and no change to an existing record, request or response format. BOI's existing families become recoverable at their first renewal under the new build. The latest-only rule gives the rotation property a refresh token would give: a copied older credential is useless.
- **A separate long-lived, single-purpose refresh secret** stored 0600 beside the profile. Such a secret is never sent with data requests, which keeps it out of application memory and logs. It would still sit beside the bearer and the client key with the same protection, so the attacker who matters (one who can read the profile directory) gets it too. Binding it to the client certificate would not tell families apart, because standalone profiles share one client certificate. It would need new client files and a renewal response change (older watchers refuse unknown response fields), and no family could recover until each had received one.
- **An online Control-administrator re-issue command** for a list of families. The administrator's own Control credential expires in the same outage, so it cannot be the way out of one, and the command would hand every family's bearer to the administrator. Stopped-installation recovery remains the path when the window has closed.

### Rollout and rollback

Existing rows, profiles, journals and bearer files are read unchanged. The only new storage is the `local-credential-latest-issuances` namespace and the new `recover` ledger rows, which nothing reads back. A family becomes recoverable online once this build issues it a credential (creation, renewal or recovery). With its watcher running, that happens within one renewal interval of the upgrade. Until then, recovery is refused with "no recorded latest issuance" and the stopped-installation recovery applies. Restart the `credential watch` units after upgrading kasumid so that they run the recovering watcher. Older watchers keep renewing as before. A new watcher talking to an older kasumid is told that the daemon does not offer online recovery. Older builds ignore the new namespace; rolling back and forward again carries the residual risk described above.

## Certificate-bound native credentials and the MCP audience

A family's specification may name one client certificate (`client_certificate_sha256`, the lowercase hex SHA-256 of its DER) and an audience (`native`, the default, or `mcp`). The local issuer derives both claims of every token it signs from the family record: `aud` is the installation's native audience or its separate `mcp_audience`, and a bound family's tokens carry `cnf: {"x5t#S256": <base64url SHA-256 of that certificate>}` (RFC 8705). Creation, renewal, online recovery and every replay of an issuance therefore issue them unchanged, and the authenticator requires a token's audience and confirmation to equal its family's record, so a token cannot outlive or widen its family's binding.

The authenticator checks the binding for every request, after the signature: a verified-token cache hit and a success `authenticate_on` only counts are checked as fully as the first. The certificate is the one the connection's TLS handshake verified (`AuthenticatedTlsPeer`), on the native data and administrative listeners, `rpc.rs`'s fallback verification and the protected observation routes alike. A bound token presented with another certificate, with none, or by trusted in-process code is refused, as is a token confirmed any other way than `x5t#S256`. A recovered expired credential must also arrive with its own certificate. When the configuration sets `auth.require_certificate_binding`, an unbound native token is refused on any connection too, and a Control administrator cannot create an unbound native family; trusted in-process callers may still use unbound families they issue for themselves.

MCP takes no client certificate. With `auth.mcp_audience` set, the MCP listener has its own authenticator for that audience: it refuses every native token, bound or not, and the native listeners refuse every MCP token. An MCP family is never bound. Its token cannot reach the administrative listener, so it cannot renew itself; a Control administrator renews it (`kasumid credential renew|watch <mcp-profile> <control-profile>`), and a Control administrator may renew only MCP families besides its own.

A new installation sets both, binds each generated native profile's family to that profile's own client certificate and writes `profiles/mcp.json` with the application's MCP credential. `kasumid credential create <control-profile> <request.json> <output-profile> <certificate.pem> <private-key.pem>` binds a new native credential to the named certificate, which the new profile presents; it never binds to the administrator's own connection.

Binding defends against a copied token used from another client's certificate, including one the CA issued to a different profile. It does not defend against theft of both a token and its certificate's private key; keep each profile's key with its token. Families issued before binding stay unbound, renew unbound indefinitely, and their records keep their exact bytes: both fields are omitted when they hold their defaults, so the exact reader decodes and re-encodes old records identically. An installation from before this change keeps working with them until `kasumid maintenance bind-credentials` (docs/standalone.md) replaces them.

## Recorded verification

The [full workspace receipt](evidence/credential-lifetime-20260907-b/verification.json) records 245 passing test entries and two external-service tests ignored, plus strict workspace Clippy and formatting checks. The subsequent three-file shared-clock refinement has its own [final receipt](evidence/credential-lifetime-20260907-c/verification.json): 81 affected clock/types/engine/server library tests and strict workspace Clippy, with unchanged source hashes. The earlier failed Clippy attempt remains recorded separately. These are software test results, not external certification or deployment approval.
