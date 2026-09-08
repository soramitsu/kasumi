# Local signer trust and the remaining rotation integration

The local trust component separates historical signature verification from live
generation acceptance. It is the persistence and fencing foundation for HA
rotation. The existing authority lease envelopes and runtime coordinator have
not yet been connected to this component; this document does not claim that HA
signer rotation is ready to operate.

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
