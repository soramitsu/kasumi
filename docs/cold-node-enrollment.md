# Explicit cold node enrollment and strict existing genesis

`kasumid provision-node <runtime.json>` and
`kasumi-authority provision-node <authority.json>` now perform explicit local
HA enrollment. They create the configured physical NodeStore identity and
service audit, retain a canonical encrypted enrollment input, install fresh
application/custody pairs, and persist immutable local genesis. These commands
bind no public listeners and do not initialize Raft membership. Repeating the
command cannot adopt an existing or incomplete node file.

The original physical NodeStore and audit owner stay live from exclusive file
creation through enrollment and terminal drain. No close/reopen interval allows
a second owner between audit creation and genesis publication.

The encrypted `node.enrollment` input commits the exact original configuration
and physical database UUID. Its head is incomplete until local provisioning
finishes. A data tenant captures one finite original issuer grant, records the
exact signed grant before key/catalog work, and checks that same verification
through provisioning and drain. The enrollment path starts no grant renewal
worker. An expired/failed attempt cannot be resumed by reacquiring a grant.
Control metadata uses its explicitly installed node authority; it cannot supply
an application serving grant. Restored/retired data generations must use the
recovery protocol rather than first enrollment.

Fresh domain construction uses `TenantStorageSet::initialize_catalogs`, whose
private ticket retains unpublished stores and both open gates through result
handoff. The enrollment task retains each returned pair, database and verifier
until shutdown, and joins registered initializer tasks. Blocking authority
state publication uses the retained owner and `initialize_storage`, which
publishes paired descriptor/local identity/floor/META/Raft identities in one
pristine-state transaction. Lost CLI replies have only a unit result; the
owning task completes actual drain before returning it.

Normal data and authority runtime open require the exact completed enrollment
input, existing audit/catalogs and authenticated stored genesis. Cold data
startup calls `open_existing_replicated` with the configured expected
incarnation and uses its returned original bootstrap for the handshake.
Authority settings contain only current local resource/transport installation;
they no longer carry a substitute genesis. Initial authority membership uses
the authenticated original voters, not the current configured transport pool.
Configured original bootstrap input remains available only to explicit first
enrollment; it does not replace durable membership or policy on restart.

## Remaining boundaries

This is a source checkpoint of explicit local genesis provisioning and strict
cold open calls, not complete startup acceptance. The following remain open:

* General cold startup now has a source-only retained owner and private success
  delivery; its implementation and remaining internal composite-open gap are
  described in [cold-startup-ownership.md](cold-startup-ownership.md).
* Existing borrowed composite storage opens still need their own deferred
  ownership transition; fresh-only initialization does not solve that case.
* HA `publish_control` still initializes reserved schema/topology on absence
  after quorum. Closing that behavior requires explicit replicated initial
  Control publication state or a typed Control genesis seed. It cannot be
  inferred from a missing document or replaced with an offline consensus call.
* Explicit audit initialization still needs complete-domain pristine validation
  beyond the currently recognized audit namespaces.
* Functional credential/provider, crash/cancel, membership and restart evidence
  for this combined caller source has not been run.

## Source checks and proposed gates

Direct Rust 1.97.1 rustfmt and Git whitespace checks passed. No Cargo,
compiler, native process, provider service or listener ran for this checkpoint.
Two source tests under `node_enrollment::tests` cover exact complete input,
incomplete/corrupt/missing records, rejection without logical mutation and
strict metadata reopen. A production-file-keyring regression under
`node_provision::tests` covers exclusive file ownership during provisioning,
rejection of another creator/opener and strict audit/data reopen after drain.
The existing runtime fixture helper now provisions
its local domains explicitly before the first startup.

After the coordinated lane opens, validate the combined dependency graph first,
then run the four fresh catalog handoff tests, these two enrollment tests, the
finite original grant test, the strict authority/bootstrap tests and actual
local/replicated runtime startup/restart fixtures. No source-only result is
functional or release-readiness evidence.
