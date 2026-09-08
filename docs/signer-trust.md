# Installed live signer trust

The local trust component separates historical signature verification from live
generation acceptance. Authority lease, lifecycle lease, receipt, target stop,
and Control epoch stop envelopes now carry the canonical generation-certified
signature. Serving and lifecycle admission require a current encrypted local
verifier owner. Online coordinated signer rotation remains an unfinished release
gate. The current authority leader exposes authenticated local verifier
maintenance with an exact directive committed in authority consensus before local
dispatch. The coordinator must still cover every data/Control verifier and all
issuer generations before declaring a whole rotation complete.

An installation signing root certifies operational Ed25519 keys for an exact
authority, partition, manifest digest, generation and retirement interval. The
root key must differ from every operational key. `HistoricalSigningTrust`
verifies those certificates and retained signatures. Its verification returns
no live gate or administrative permission.

`LiveSignerTrust` accepts exactly the certificate in its current local record.
`SignerGenerationFence` is an additional fence on an existing request or lease;
it supplies no deadline and cannot replace the original lease attempt or
credential clock. Staging a certificate leaves the current generation live.
Activation durably replaces the active certificate, then wakes generation
watchers. Old fences fail permanently for that owner. Historical signatures
continue to verify, including after their generation is retired.

The encrypted adapter uses an independent `LiveSignerTrust` storage purpose
bound to the physical verifier installation and node ID. It must use its own
installed metadata provider. Application restore cannot initialize this
catalog. Initialization requires an absent record and generation one; opening
existing trust always reads its current durable state. Opening the same live
record shares the exact owner and administrator provider.

Each mutation has a permanent operation UUID, expected revision, immutable
`not_after_ms` admission deadline and exact inputs. State, receipt and permanent key-use bindings commit atomically. A key
cannot be reused in another generation or signing domain, including a key from
a stopped staging operation. Restaging the exact same unactivated certificate
is allowed. The tables have bounded individual records and no lifetime record
count ceiling. Their aggregate node storage admission must be supplied during
runtime integration.

`LiveTrustAdministrator` is an installed authorization callback for the current
administrative path. Its adapter must verify the exact credential resource,
current policy and response-release fences. A historical signature or a valid
root certificate does not implement this callback. Authorization executes
outside the live trust mutex so a current Control policy check can itself
consult a generation fence.

Uncertain publication closes the current trust owner. Reopen reads the durable
outcome and replay resolves the original permanent operation. It never assumes
that an activation failed. Retirement uses a private suspend-aware elapsed
witness. Opening a record with unfinished retirement starts a new full interval;
clock regression closes that owner and requires another fresh complete drain.

The remaining coordinator integration must persist every phase identity before
dispatch and use installed current authenticated administrative channels for
data and Control verifiers. It must bind acknowledgements to the physical
verifier, signing domain, operation digest, exact certificate and committed
revision. Historical issuer keys must not authenticate an activation DTO into
this administrative path. Every authorized verifier must acknowledge activation
or be permanently revoked before retirement can complete. The authority must
also close retired issuer generations and finish its complete issuer drain.
Replacement nodes must inherit the required current trust and permanent key
bindings before gaining serving authority.

An immutable operation receipt is not a current trust acknowledgement. Native
adapters must capture `LocalSignerTrustObservation`, include its exact current
record in the authenticated response, and check its revision fence after
encoding alongside the current administrative response fence.

The canonical `SigningDomain`, `SigningGeneration`, `SigningCertificate`, and
`GenerationSignature` wire records live in `kasumi-types`, allowing typed Control
and authority envelopes to share them without a dependency cycle. Crypto remains
in `kasumi-serving`; import `SigningCertificateVerification` for certificate
verification and its authenticated digest. Decoding these records alone grants
no live trust, and this placement adds no alternate or legacy decoder.

`LiveGenerationSigner` binds an installed operational key to this verifier's
exact current durable certificate. A staged key cannot issue, activation fences
old owners, and reopening a closed trust owner never revives its retained
signatures. `sign` returns `LiveGenerationSignature`; the adapter retains it
through encoding and checks it with the original request authorization before
response release. `AuthorityResponseFence` captures the exact immutable signer
owner used by that authority instance and checks it after encoding and the
current quorum barrier. This guard does not renew a lease or authorize a command.
The authority selects one immutable signer for each request before awaited work.
The trusted runtime can explicitly replace its operational key under a current
administrative fence after activation. The replacement must use the exact same
live verifier owner, not a copied store with an equal public identity. Existing
requests retain their old signer and response fences. There is no implicit
key-file watcher or fallback to the installation root. Explicit native reload
uses the installed private descriptor; the distributed rotation coordinator
still needs operational wiring.

## Runtime installation

The authority manifest partition `public_key` is the installation root's public
key. Its private key belongs in separate operator backup and is never loaded by
an authority daemon. The authority configuration requires `operational_signer_file`, an absolute
owner-only JSON descriptor containing an explicit root-certified `certificate`
and an absolute private PKCS#8 `key_file`. The operational key must differ from
the root key. Replace the complete descriptor atomically when preparing a new
key; its certificate must match the key file. The runtime reads one bounded
private descriptor snapshot at startup and on an explicit authenticated reload.

After activating the intended local durable head, use the native client's
`signer_maintenance` with `reload_operational_signer`, its exact
`expected_revision`, `certificate_sha256`, and finite `not_after_ms`. The request
also names the exact physical verifier and independently installed domain. The
mTLS/JWT/current-quorum administrative boundary is required even if the former
operational signer is sealed. The original elapsed deadline fences publication
and response release. Invalid, staged, retired, mismatched, or oversized key
sources leave the previous slot intact. Existing requests always retain their
original signer and cannot be re-signed by a successful reload.

A successful reply's `loaded_certificate` is a current reload observation for
that request, not a permanent completion receipt or a remote activation proof.
Reload does not change the durable trust revision. If its response is uncertain,
repeat the same request while its admission remains valid; a later fresh
administrative invocation must still name the same current durable head. A
restart reads the currently installed descriptor and validates it against the
retained encrypted trust state before admitting any lease.

Each authority and data/Control runtime configures `signer_verifier` with:

- `identity`: immutable `installation_id` and this runtime's `node_id`;
- `database_path`: an absolute path to its separately encrypted metadata file;
- `keys`: its own installed file or Transit key-provider domain.

Every enrolled HA `NodeIdentity`, lifecycle target node and authority member
contains the exact `verifier` identity. Its node ID must agree with the member's
node ID. The authority runtime's `installed_verifiers` map supplies these
identities for its pinned operational peers and must include its own configured
verifier. A serving or lifecycle boot must use that same physical owner; a copied
node ID, principal and TLS certificate cannot substitute another metadata
installation. All partitions attached to one `AuthorityTrust` share one physical
verifier. These durable bindings are prerequisites for the complete activation
roster; they do not themselves acknowledge remote activation or retirement.

Data/Control runtime configuration explicitly sets `signer_verifier: null` only
when no independent authority manifests are installed. The domain set is the
exact union of all installed authority manifest partitions. Configured metadata
and application files and their wrapping domains must differ.

Before first HA startup, write an `InitializeSignerVerifier` JSON input containing
that `verifier` config and the explicit `initial_certificates` for every domain.
Run `kasumid initialize-signer-verifier /absolute/path/input.json`. The initializer
requires generation one, verifies each root certificate, opens exclusive
owner-only storage and publishes a completion record after every head and
permanent key binding is durable. The same exact input may be retried. A partial
initialization can resume only from the exact initial heads; a corrupt or changed
head is never recreated. Ordinary runtime startup requires the completion record
and every current head and does not create missing trust.

`AuthorityTrust::install` supplies historical verification only. The trusted
runtime attaches the complete exact partition set using `with_live_verifiers`.
An incoming lease cannot bootstrap this set. Each verified lease captures an
additional signer-generation fence alongside its original elapsed deadline;
retirement closes retained responses and cannot be bridged by renewing the old
serving instance. Native fixture construction is available only through the
explicit `kasumi-serving/test-utils` feature and uses separate root and
operational keys.

The encrypted regressions cover missing and incomplete installation, exact retry,
corrupt head rejection, exclusive reopening, wrong identity/domain, staged and
retired key refusal, old wire-format rejection, original lease deadline expiry,
and old-owner fencing across restart. The pinned native TLS regression uses
independently encrypted source and receiver verifier state and checks both
receiver admission and authority response-release fencing after activation.
These tests do not certify the remaining distributed activation acknowledgement,
revocation and retirement-drain coordinator.

## Authenticated local maintenance protocol

`KasumiAuthority.SignerMaintenance` and the Rust client `signer_maintenance`
operate on the exact authority member verifier named by the request. The native
listener requires actual mTLS and a verified finite JWT for the exact authority
partition. The current consensus administrator policy authorizes every request.
A request has a fresh observation UUID, immutable physical verifier identity,
installed signing-domain digest and one action: `observe`, `receipt`, or
`administer`. The latter carries the typed stage, stop-stage, activate or
complete-retirement command.

An `AuthorizeSignerTrust` authority maintenance record commits the original
command, verifier, domain, principal and admission bound before any local effect.
This is permission to dispatch that exact effect; completion of that consensus
directive is not proof of local publication. The response separately contains
the local permanent receipt and a current verifier observation. Receivers must
check both against the original request. Root signatures and serialized replies
cannot create the scoped current-quorum authorization used by the local adapter.

Commands waiting for the local metadata slot retain their original deadline.
First admission must fit the original verified credential. A later request can
read an already committed receipt after that bound expires; it cannot rewrite
the operation's deadline or perform an expired first effect. Failed or uncertain
local publication is resolved by its original operation UUID. Closed metadata
owners require reopening from durable state before further operation.

Activation immediately seals the old operational signer and existing leases.
The administrative channel remains available through its independent current
mTLS/JWT/quorum fence, including after that signing key is sealed. It checks
current policy and term again at response release, plus the local observation's
revision after encoding. Local retirement requires the full installed elapsed
drain; restart conservatively starts that interval again. No reply represents a
global drain or claims activation of another verifier.

The current adapter acts on the leader's own verifier. Completing production
rotation still requires durable dispatch and acknowledgements for every other
authority, data and Control verifier, permanent revocation for unavailable
members, coordinated operational-key loading, and the complete issuer drain.
The local API must not be used to declare that this remaining work has happened.

## Replicated issuer signing head

Authority bootstrap configuration requires `initial_signer_certificate`, the
exact generation-one operational certificate. It is part of the immutable
bootstrap binding, separately from the installation root and the replaceable
`operational_signer_file`. An existing authority store rejects a different
bootstrap certificate. Encrypted snapshots retain the current global signing
head and permanent stage/activation receipts; restore verifies their causal
positions and rejects a head that omits or rolls back retained transitions.

Use the native authority client's `signing_maintenance` with an independently
installed `domain_sha256`, fresh `observation_id` and typed `observe`, `receipt`
or `start` action. Replies supply the current `policy_epoch` and
`operational_revision` for a new exact command. `start` accepts
`EnrollSignerVerifier`, `AdmitControlVerifiers`, `StageSignerGeneration` and
`ActivateSignerGeneration`. Stage retains the successor certificate and freezes
the complete enrolled physical verifier table; activation names that exact stage
operation and certificate digest. The original command UUID, expected revisions and finite
`not_after_ms` remain unchanged across retries. This endpoint uses current
mTLS/JWT policy and quorum authorization, so operators can resolve an activation
that has sealed the loaded operational key.

Global activation changes the replicated accepted issuer certificate. Every
lease admission and captured authority response checks that certificate after
its current quorum barrier, in addition to the exact local verifier and original
request authority. A member whose local signer still uses the prior generation
can continue authenticated administrative recovery while its old lease issuance
and responses fail. Restart preserves this fence. Explicit local trust activation
and key reload then install the selected key on each issuer member.

Global retirement remains pending after activation. A local retirement receipt
cannot clear it, and a new global stage is rejected while retirement is pending.
The coordinator still needs current authenticated acknowledgments or permanent
revocations for every entry in the frozen roster, and the full issuer drain
before global retirement can complete. Global stage abort and
retirement completion are not exposed yet. These prerequisites are required
before the release can claim complete distributed signer rotation.

The authority runtime and signer-verifier initialization request require an
explicit `scratch_disk` object: `directory` (absolute private leaf beneath an
existing parent), `max_bytes`, and `min_free_bytes`. Use the same installed
runtime scratch configuration when initializing its separate verifier store.
Runtime opening passes the shared node owner to both stores; it does not create
an independent per-request or per-verifier allowance.

## Physical verifier enrollment and rotation freeze

Before staging, enroll each physical verifier through `EnrollSignerVerifier`.
An enrollment binds the durable installation UUID and node ID to one canonical
HTTPS administrative origin and explicit certificate pins. Credentials stay in
installed local file sources. An endpoint or certificate cannot identify two
physical owners, and an allocated physical identity cannot be overwritten by a
new command, path alias or endpoint change. Enrollment commands retain exact
permanent completion or rejection outcomes and use the original finite deadline.

For every installed lifecycle Control root, `AdmitControlVerifiers` must retain
its exact root, exhaustive issuer partition descriptor and physical Control node
set. Each node must already have an enrolled administrative endpoint. This is an
explicit current-administrator enrollment fact. It is not a remote publication
acknowledgment or a proof that an independently running Control copy has stopped.

Stage checks all authority members, retained tenant incarnations, prepared
targets, committed lifecycle target identities and admitted Control receivers.
Historical identities are retained conservatively, including revoked issuers;
a later retirement coordinator must resolve their exact permanent revocations.
A missing receiver rejects stage. The reducer orders the enrollment records in
an encrypted, disk-admitted table and retains checked 64-bit counts and a digest
in a permanent frozen-roster record atomically with the stage outcome. It never
constructs an unbounded in-memory roster. Snapshots verify both directions of
the command/enrollment/freeze links and the frozen counts and digest; restoring
cannot erase or substitute an already retained physical identity.

The committed stage stops new old-generation serving and lifecycle leases and
fences lease responses waiting for release. It blocks new physical enrollments,
Control admissions, tenant enrollments, target preparations, lifecycle intents
and authority learner admissions. Exact committed replays and fencing/stopping
operations remain available. Activation permits the selected successor signer;
the roster remains frozen throughout pending retirement. No abort operation can
currently undo a committed stage or activation.

`signing_maintenance` also accepts `verifiers` with an
`expected_operational_revision`, optional exact physical `after` identity and a
`limit` of 1–64. The SDK returns bounded typed registrations and an exact next
identity. Every page has a current administrator/quorum response fence. A changed
operational revision rejects continuation instead of silently restarting it.

The next protocol work must bind live Control admission and remote verifier
publication to this registry, persist exact acknowledgments or revocations,
and complete the full issuer drain. Until then, global retirement stays pending;
these enrollment operations do not certify complete distributed rotation.
