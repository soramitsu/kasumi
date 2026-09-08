# Installed live signer trust

The local trust component separates historical signature verification from live
generation acceptance. Authority lease, lifecycle lease, receipt, target stop,
and Control epoch stop envelopes now carry the canonical generation-certified
signature. Serving and lifecycle admission require a current encrypted local
verifier owner. Online coordinated signer rotation remains an unfinished release
gate: the production maintenance callback rejects transitions until the current
authenticated distributed coordinator is installed.

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

Each mutation has a permanent operation UUID, expected revision and exact
inputs. State, receipt and permanent key-use bindings commit atomically. A key
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
Authority instance replacement is required to change its configured operational
key; there is no implicit key-file reload or fallback to the installation root.

## Runtime installation

The authority manifest partition `public_key` is the installation root's public
key. Its private key belongs in separate operator backup and is never loaded by
an authority daemon. The authority configuration uses `operational_signer` with
an explicit root-certified `certificate` and an absolute private PKCS#8
`key_file`. The operational key must differ from the root key.

Each authority and data/Control runtime configures `signer_verifier` with:

- `identity`: immutable `installation_id` and this runtime's `node_id`;
- `database_path`: an absolute path to its separately encrypted metadata file;
- `keys`: its own installed file or Transit key-provider domain.

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
