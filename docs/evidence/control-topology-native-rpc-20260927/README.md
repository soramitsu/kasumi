# Authenticated Control topology native RPC checkpoint — 2026-09-27

The existing installed lifecycle service now exposes strict topology observation
and release RPCs. The native client generates its request identity, binds the
actual mTLS certificate and bearer digest, verifies the installed signer, and
retains a suspend-aware pre-dispatch deadline. Public serialized replies cannot
construct current native observations or renew them. Release uses the remaining
original elapsed lifetime. No tenant-operation or issuer-lease grant is created.

The routing fence requires `Read` scope and the committed `topology` collection
grant throughout its quorum checks. Administration retains its distinct `Admin`
checks. The native integration uses a principal whose only grant is topology
read access; attempting lifecycle installation with it fails.

Actual final results:

- **5/5** full clock tests; remaining-time sampling and shared-copy sealing.
- **67/67** full native client tests, no ignored or filtered cases. Four new
  cases check request/caller/root binding, delayed replies, clones, server time
  drift, shorter server deadlines and elapsed regression.
- **1/1** exact real mTLS/Raft lifecycle integration, **27.45 seconds**. It checks
  exact read/release identity and immutable deadline, a distinct routing grant,
  native-client substitution rejection, and direct wire rejection of another
  certificate or bearer, duplicate authorization and a missing TLS identity.
  This test also retains the existing administrative lifecycle/issuer checks.
- **1/1** exact native engine topology case, **2.82 seconds**, proving actual
  committed route changes invalidate retained observations and releases.

All logs are original. The first client compile failure (a wildcard Result alias)
and administrative-only predecessor are preserved separately. The 16-file source
archive was captured after these source tests, not as full immutable release
provenance. Its only test dependency addition is the already resolved Ring crate
for disposable client-origin signatures. Native TLS keys and tokens are temporary
fixture identities. Its listener handshake audit sink is deliberately simulated;
authentication and engine security audit are real, as documented in the test.

These are local source/native transport results. The consensus fixture uses
separate local storage roots in one process. Dedicated Control-only processes,
remote data-node integration, nine actual processes, physical HA acceptance,
reviewed final-source release and live BPNG deployment remain outstanding.
