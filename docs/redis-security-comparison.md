# Security comparison: standalone Kasumi and Redis 8

This compares the controls a standalone `kasumid` enforces with those of an
open-source Redis 8 server, and lists the concrete weaknesses a review of
Kasumi's code found. Kasumi references are to source as of this document;
Redis statements describe its documented open-source behavior and were not
re-verified in this repository. The performance cost of each Kasumi control is
measured in the [Redis comparison](../benchmarks/REDIS-COMPARISON.md).

## Controls side by side

| Control | Kasumi standalone | Redis 8 (open source) |
| --- | --- | --- |
| Transport encryption | TLS 1.3 only on every listener and outbound client, 0-RTT off (`kasumi-transport/src/lib.rs`). No plaintext listener exists. | Optional. TLS 1.2 and 1.3 by default; the plaintext port stays open unless `port 0`. |
| Client certificates | Required on the native data and administrative listeners, issued by the installation CA. MCP uses server TLS plus a bearer token. | Optional (`tls-auth-clients`, default `yes` once TLS is on). |
| Server identity | Clients pin the server's exact certificate SHA-256 in their profile. | CA verification only; no pinning in the server's protocol. |
| Authentication | Ed25519 access tokens (or an external OAuth issuer with allowlisted asymmetric algorithms), `typ: at+jwt`, exact issuer and audience, zero leeway, lifetime ≤ 1 hour against a suspend-aware clock; revocable credential families checked on every request and again before the response is released. | ACL users with passwords (`AUTH`), checked once per connection. The default user has no password unless configured; no expiry or revocation of a connection that already authenticated. |
| Authorization | Default deny. Scopes in the token must intersect a per-principal, optionally per-collection grant; re-checked during ordered apply and before release. Tenant comes only from the verified token. | ACL command categories and key patterns per user. |
| Tenant isolation | Separate keys, policies, credentials, audit and (replicated) Raft groups per tenant. | Logical databases share one keyspace process; isolation is by ACL key pattern. |
| Encryption at rest | Every record sealed with XChaCha20-Poly1305 under per-tenant data keys wrapped by a file keyring or OpenBao/Vault Transit; record keys are keyed HMACs; backups and spools are encrypted (`kasumi-store/src/lib.rs`). | None. RDB and AOF files are plaintext. |
| Audit | Durable, encrypted, hash-linked service audit of transport accept/deny, every authentication denial, each bearer token's first success on a connection with a count of its later successes, access denials, key, backup and recovery operations, with repeated events that identify no client kept as exact counts per peer and minute; tenant audit of every mutation and, with `strict_read_audit`, every read before release. | No audit log. `ACL LOG` keeps a small in-memory list of recent denials. |
| Idempotency / exactly-once | Every mutation has a durable receipt keyed by its idempotency key. | None; a retried command applies twice. |
| Durability of acknowledged writes | Always flushed before the reply. | Configurable: `appendfsync always`, `everysec` (≤ ~1 s loss) or `no`. |
| Server-side code | None. | Lua and functions; the Lua sandbox has had memory-safety CVEs (for example CVE-2025-49844). |
| Secrets on disk | Secret files must be owner-only, are read without following links into zeroizing buffers; logs use fixed labels only. | `requirepass`/ACL passwords in the config or ACL file. |
| Resource limits | 8 MiB requests, 16 MiB responses, authentication before body reads, memory admission with a high-water mark, per-tenant quotas, 32 HTTP/2 streams and 128 connections per listener, 60 s idle close. | `maxclients` 10000, `timeout 0` (idle clients never closed), `maxmemory` optional. |
| Replication security | Raft peers authenticate with mTLS and certificate pins bound to node IDs. | Replication and cluster-bus TLS optional. |

Kasumi is stricter in every row. What it does not have, and Redis does not
either: no rate limiting of failed authentication, and no signatures or
external anchoring on the audit chain (whoever holds the audit key could
rewrite it).

## What the controls cost

The comparison benchmark runs both servers with TLS 1.3 and client
certificates, so transport cost is matched. The rest is Kasumi-only work:

- **Authentication audit.** The first successful request of each token on a
  TLS connection waits for a durable service-audit record before the request
  proceeds (`kasumi-server/src/auth.rs`, `authenticate_on`). Later requests
  with that token on that connection are verified in full but counted
  instead; one record carries the count when the connection presents another
  token or closes. A refused bearer waits for its own record only when it is
  the first refusal of its minute; later ones are counted (weakness 2).
  Records from concurrent requests share one commit (up to 64). Until
  1a0f7bc5 every successful request waited for its own record: a lone
  client paid one device flush per read, and at roughly 250–300 bytes a
  record, a client polling ten times a second wrote about 250 MB of audit per
  day, the growth behind multi-gigabyte audit archives on read-heavy
  deployments. A client that opens a new connection for every request still
  pays that.
  - An access denial on a counted request names that request's own id, which
    has no success record of its own; its principal and tenant identify it,
    and its connection's recorded success covers its authentication.
  - After any failed audit write, connections stop counting and record every
    success again, so an audit outage refuses their requests as it refuses
    everyone else's. A count that cannot be written when its connection
    closes, or that a crash interrupts, is lost; the token's first success
    is already durable.
- **Token verification.** An Ed25519 signature check and claim decoding per
  request. Since this change a token already verified by the current key set
  skips the signature check; expiry and revocation still run every time.
- **Encryption.** One AEAD seal or open per record and a keyed HMAC per key.
- **Receipts and mutation audit.** Extra bytes in every write's durable commit.
- **Strict read audit.** Each audited read becomes a journal entry and a
  durable commit before release.

## Weaknesses found in Kasumi

Severity assumes the standalone defaults (listeners on loopback) unless noted;
it is higher wherever a listener is reachable from a network.

1. **Fixed: unknown token key IDs re-read the private signer file.** Before
   this change, a request whose token header named any unknown `kid` made the
   local issuer re-read and re-parse every private signing key, with no rate
   limit and no valid signature required. A reload now happens only for a key
   ID that could still appear (never for a malformed one or an older
   generation of a cached signer), and only once per replacement of the
   signer file, so rotated keys are still trusted on first use. A reload that
   finds the same keys keeps the verified tokens. Covered by
   `auth::tests::local_signer_is_reloaded_only_for_an_unknown_kid`.
2. **Fixed: unauthenticated traffic could exhaust audit capacity (was
   medium; high on reachable listeners).** Every failed TLS handshake, every
   TLS accept on the MCP listener (which takes no client certificate), every
   refused token and every request refused before any identity is verified
   (a bad MCP `Origin`, for example) wrote its own durable service-audit
   record, as does the first successful request of each token on a
   connection. The hot log (64 MiB) drains into archive segments that are
   never pruned and stop at `archive_bytes` (64 GiB by default); when that is
   reached, new records are refused and every authentication and TLS accept
   fails closed until an operator raises the budget, so traffic that
   identifies no client could lock out every client. Since this change:
   - In each minute, the first such event of each kind from each peer
     address is recorded as before, for up to 64 addresses; events from
     further addresses share one entry per kind. Every other one is counted,
     and when the minute ends one `events_counted` record per entry carries
     the exact count and the first and last times. A flood therefore writes
     at most about 136 records a minute (under 100 MB a day), however fast it
     arrives and however many addresses it uses. A crash loses counts not yet
     written.
   - These records, counts included, are written only while the hot log
     stays at or below the 75% threshold where archiving starts. Above it
     such an event is only counted, so the last quarter stays free for
     authentications, accepts with a client certificate, node lifecycle and
     administrative records while archives cannot drain.

   `unauthenticated_flood_tests::an_unauthenticated_flood_leaves_room_for_a_valid_token_and_administrative_records`
   floods refused tokens, identity-less refusals, and failed and anonymous
   TLS handshakes from 300 addresses into a 128 KiB hot log that cannot
   drain. It then records a client certificate's accept, authenticates and
   records administration, and checks that the exported records account for
   every event exactly. What remains:
   - Authenticated traffic shares the capacity above the threshold and
     archives are never pruned, so a full archive still ends in a lockout
     once legitimate traffic fills the hot log. Successful requests write one
     record per connection and token plus one count (since 1a0f7bc5), which
     slows that growth; archive export exists (`kasumid audit export`), but
     pruning exported segments while keeping the hash chain verifiable does
     not.
   - Alert before the archive fills: for example when
     `kasumi_service_audit_archive_bytes` passes 80% of
     `kasumi_service_audit_archive_budget_bytes`, or when
     `kasumi_service_audit_hot_bytes` stays above 75% of
     `kasumi_service_audit_hot_budget_bytes` (archives are not draining).
3. **Connection slots can be held during TLS handshakes (medium).** Each
   listener admits 128 connections and holds a slot through a 5 s handshake
   timeout and its audit write, with no per-source cap
   (`kasumi-server/src/tls.rs`, `ListenerLimits`). Recommended: a separate,
   shorter pre-handshake budget and per-source limits.
4. **Bearer tokens are not bound to a client certificate (medium-low).** All
   listeners share one audience, and MCP requires no client certificate, so a
   token copied from a native client works on MCP. Recommended: a distinct
   audience per listener or certificate-bound tokens (RFC 8705).
5. **Client certificates cannot be revoked (low-medium).** There is no CRL
   check and certificate rotation keeps the CA, so an old client certificate
   stays valid until it expires. Recommended: CRL support or a server-side
   allowlist of client certificate pins.
6. **The generated standalone profile is over-privileged (low-medium).** The
   default application credential carries read, write, admin and audit scopes.
   Recommended: separate application and administrator credentials.
7. **Configuration and CA files are read without ownership checks (low).**
   Secret files are checked; trust roots and the authentication configuration
   are not. Recommended: the same owner and no-group/other-write check.

Two lower-severity items affect replicated deployments only. The Raft peer
listener buffers and parses a request body of up to 40 MiB before mapping the
peer certificate to a node (`kasumi-server/src/cluster.rs`), and that memory
is not charged to node admission. The `kasumi-authority` native listener has
no request admission, so a slowly trickled body can hold a connection slot
(`kasumi-server/src/authority_runtime.rs`). Recommended: check the peer pin
before reading the body, and wrap the authority listener in
`RequestAdmission::native`.
