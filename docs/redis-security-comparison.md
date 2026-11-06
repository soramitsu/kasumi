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
| Client certificates | Required on the native data and administrative listeners, issued by the installation CA and, on new installations, listed in a revocable pin allowlist. MCP uses server TLS plus a bearer token. | Optional (`tls-auth-clients`, default `yes` once TLS is on). |
| Server identity | Clients pin the server's exact certificate SHA-256 in their profile. | CA verification only; no pinning in the server's protocol. |
| Token binding | New installations bind each native token to its profile's client certificate (RFC 8705) and give MCP its own audience; a copied token fails from any other certificate and on MCP. | None: `AUTH` passwords work from any connection. |
| Authentication | Ed25519 access tokens (or an external OAuth issuer with allowlisted asymmetric algorithms), `typ: at+jwt`, exact issuer and audience, zero leeway, lifetime ≤ 1 hour against a suspend-aware clock; revocable credential families checked on every request and again before the response is released. After expiry a credential can do one thing, for at most 24 hours: renew its own unrevoked family over a client-certificate connection, if it is that family's latest issuance, audited each time (`docs/credential-lifetime.md`). | ACL users with passwords (`AUTH`), checked once per connection. The default user has no password unless configured; no expiry or revocation of a connection that already authenticated. |
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
   connection. The hot log (64 MiB) drains into archive segments that were
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
   every event exactly.

   Exported archives can now be pruned. `kasumid audit prune` (the
   `SecurityAuditPrune` RPC) retires the archive segments below an index
   once the export covering them matches stored history. It checks the last
   export page's anchors, the pruned roots' chain and the last pruned
   segment, and rechecks the Control credential and policy just before it
   commits. It keeps every root, deletes the objects and frees their bytes
   in `archive_bytes`. One `archive_pruned` record, written in the same
   commit, names the administrator, the range and the digest of the last
   pruned record. A fresh export starts at the first retained record,
   anchored by that digest, so the saved export and the retained chain meet
   verifiably; a cursor into the pruned range fails with `cursor_expired`.
   Records other than the prune's stop 8 KiB short of the hot budget, so the
   prune can record itself when nothing else fits. Deletion runs in chunks
   that each commit their freed bytes, and resumes in maintenance after a
   crash. Tests:
   `security_audit::retention::tests::a_prune_keeps_retained_history_exportable_and_verifiable_across_restart`,
   `..::an_interrupted_deletion_resumes_after_restart`,
   `..::a_prune_records_itself_when_required_records_no_longer_fit` and
   `..::a_prune_refuses_what_its_export_does_not_vouch_for_and_repeats_as_a_no_op`
   (kasumi-engine), and
   `runtime::audit_tests::audit_native_tls_prunes_exported_segments_through_the_cli`
   (kasumi-server).

   A node that already refuses records is now recovered offline. With
   kasumid stopped, `kasumid maintenance export-service-audit` writes the
   export pages and `kasumid maintenance prune-service-audit` prunes with the
   same engine checks. The stopped installation's exclusive operator
   ownership stands in for the Control credential. The prune's record, from
   principal `offline-operator`, uses the reserve. The command then deletes
   the pruned objects and archives the hot log, so the node starts and records
   again. Test:
   `standalone::service_audit::tests::a_full_service_audit_is_exported_and_pruned_offline_and_records_again_on_restart`
   (kasumi-server). What remains:
   - Pruning is operator-driven. Legitimate traffic still fills a fixed
     `archive_bytes` between prunes, so export and prune before it is full.
     Successful requests write one record per connection and token plus one
     count (since 1a0f7bc5), which slows that growth.
   - A node that already refuses records cannot prune online: the CLI's own
     TLS accept and authentication need records first, and kasumid cannot
     record its own start. Recovery means stopping kasumid and running the
     offline commands on the host.
   - S3 archive destinations are not pruned; the request is refused.
   - A Control administrator can remove exported history. The prune is
     recorded, and `security_audit.prune_minimum_age_days` (off by default)
     keeps recent records out of reach of a stolen credential. The operator
     of a stopped installation, who holds its keys anyway, can prune too;
     that prune is recorded and obeys the same floor.
   - Alert before the archive fills: for example when
     `kasumi_service_audit_archive_bytes` passes 80% of
     `kasumi_service_audit_archive_budget_bytes`, or when
     `kasumi_service_audit_hot_bytes` stays above 75% of
     `kasumi_service_audit_hot_budget_bytes` (archives are not draining).
3. **Fixed: one address could hold every connection slot during TLS
   handshakes (was medium).** Each listener admits 128 connections and holds
   a slot through a handshake of up to 5 s and its audit write
   (`kasumi-server/src/tls.rs`, `ListenerLimits`), so one address that
   opened connections and never finished their handshakes could hold every
   slot. Since this change one remote address may have at most 16 handshakes
   in progress (`max_handshakes_per_source`); a further connection from it
   is closed before it takes a slot, and a finished or failed handshake
   frees its claim at once. Loopback clients are exempt. Covered by
   `tls::lifecycle_tests::one_address_cannot_hold_more_than_its_handshakes`.
   What remains: many addresses together can still fill the slots, and the
   handshake timeout is not shorter than before.
4. **Fixed: bearer tokens were not bound to a client certificate (was
   medium-low).** All listeners shared one audience, and MCP requires no
   client certificate, so a token copied from a native client worked on MCP,
   and from any other client certificate the CA issued. A new installation's
   native tokens now carry `cnf.x5t#S256` (RFC 8705), the base64url SHA-256 of
   their profile's client certificate, from the family record, so creation,
   renewal, recovery and replay keep it. The authenticator checks it on every
   request against the certificate the connection's handshake verified,
   including verified-token cache hits and the successes `authenticate_on`
   counts (`kasumi-server/src/auth.rs`, `check_binding`), on the native,
   administrative and observability paths. `auth.require_certificate_binding`
   refuses unbound native tokens, and a Control administrator must name the
   recipient's certificate to create one. MCP has its own audience
   (`auth.mcp_audience`) and authenticator: native tokens are refused there,
   and MCP tokens on the native listeners. MCP families are unbound and
   renewed by a Control administrator. Family records written before binding
   keep their exact bytes and renew unbound. Covered by
   `auth::tests::a_bound_token_is_accepted_only_from_its_own_certificate_on_every_request`,
   `..::a_malformed_or_unknown_confirmation_is_refused`,
   `..::a_binding_installation_refuses_unbound_tokens_on_connections`,
   `local_auth::tests::bound_and_mcp_families_keep_audience_and_binding_through_every_issuance`,
   `..::an_expired_bound_credential_recovers_only_from_its_own_certificate` and
   `..::a_family_written_before_binding_keeps_its_exact_record_and_renews_unbound`,
   and on a served installation by
   `standalone::credential_binding::tests::a_new_installation_binds_native_credentials_and_separates_mcp`.
   What remains: binding does not help against theft of a token together
   with its certificate's private key. An installation from before this
   change keeps unbound tokens, usable on MCP and from any admitted
   certificate, until the operator runs `kasumid maintenance bind-credentials`
   (`..::bind_credentials_rebinds_every_profile_once_and_finishes_after_an_interruption`);
   profiles outside `profiles/` need new bound credentials. External OAuth
   issuers' tokens are bound only if the issuer adds `cnf`; set
   `require_certificate_binding` to refuse those that do not.
5. **Fixed: client certificates could not be revoked (was low-medium).**
   There was no CRL check and certificate rotation keeps the CA, so an old
   client certificate stayed valid until it expired, up to a year. The native
   and administrative listeners now admit a client certificate only when the
   CA issued it and its SHA-256 pin is in a bounded, trusted allowlist file
   (`client_certificate_pins`; `kasumi-transport/src/lib.rs`,
   `AdmittedClientVerifier`, and `kasumi-server/src/client_pins.rs`). The
   WebPKI chain, validity, usage and handshake-signature checks run first and
   unchanged. The file is loaded at startup and by every TLS reload (SIGHUP);
   a missing or malformed file fails startup or refuses the reload, which
   keeps the previous generation, and an empty one admits no one. A new
   installation lists its three generated client certificates;
   `kasumid client-certificate enroll|remove|list` edits the list, and
   certificate rotation admits replacements before it retires what they
   replace. Covered by
   `admitted_client_tests::only_admitted_leaves_of_the_trusted_authority_complete_a_handshake`
   (kasumi-transport) and
   `api::tests::native_listener_admits_only_allowlisted_clients_across_reloads`
   (a removed pin is refused at the next handshake after a reload, and a
   malformed or missing list keeps the previous generation). What remains:
   removal applies to new handshakes; established connections drain within
   the listener's drain limit, so revoke the credential families too. An
   installation from before this change checks the CA only until the
   operator runs `kasumid client-certificate enable` and restarts. Replicated
   peers keep their own membership pins.
6. **Fixed: the generated standalone profile was over-privileged (was
   low-medium).** The default application credential carried read, write,
   admin and audit scopes, so whoever held it could change the tenant's
   policy, schema and backups. A new installation now writes three profiles,
   each with its own credential family, principal and client certificate
   (`kasumi-server/src/standalone.rs`, `initialize_owned`):
   `profiles/default.json` is the `application` principal with read and
   write; `profiles/operator.json` is the tenant `administrator` with read,
   admin and audit (schema activation reads what it asserts) and no document
   write; `profiles/control.json` keeps the Control administrator. The tenant
   policy grants exactly that, so a token's scopes cannot widen either.
   `kasumictl --profile operator.json <administrative command>` administers
   through an installed profile. Administrator recovery issues only the
   administrator grant's own actions, and certificate rotation replaces every
   generated client certificate the installation's profiles use. Covered by
   `standalone::credential_split::tests::a_new_installation_gives_each_profile_only_its_own_authority`
   (the application writes and renews itself but cannot create collections,
   activate schema, read the service audit or administer credentials; the
   operator administers and activates schema with read assertions but cannot
   write). An installation from before this change keeps its single
   credential until the operator runs `kasumid maintenance split-credentials`
   with the daemon stopped, which journals the new families, removes document
   write from the tenant administrator's grant, publishes the split profiles,
   and revokes the old family; a rerun finishes an interrupted split
   (`..::a_pre_split_installation_is_split_once_and_finishes_after_an_interruption`).
   What remains: the profiles sit under one operating-system account unless
   the operator moves the operator and Control files elsewhere, and an
   installation that never runs the migration keeps the old risk.
7. **Fixed: configuration and CA files were read without ownership checks
   (was low).** Secret files were checked; trust roots, the authentication
   configuration and operator request files were not. They are all read
   through `read_bounded` (`kasumi-server/src/runtime.rs`), which now
   refuses a file that another user owns (root may own it) or that its group
   or others may write (`kasumi_store::private_files::read_trusted`). Unlike
   secrets they may stay readable by others and may be reached through a
   symlink; the checks apply to the file actually opened. Covered by
   `private_files::tests::trusted_files_may_be_shared_for_reading_but_not_for_writing`.

Two lower-severity items affected replicated deployments only, and both are
fixed. The Raft peer listener buffered and parsed a request body of up to 40
MiB before mapping the peer certificate to a node
(`kasumi-server/src/cluster.rs`); it now refuses a certificate that no
installed peer uses before reading any of the body
(`maintenance_tests::peer_listener_refuses_an_uninstalled_certificate_before_reading_its_body`).
The `kasumi-authority` native listener had no request admission, so a slowly
trickled body could hold a connection slot
(`kasumi-server/src/authority_runtime.rs`); it now verifies the bearer and
admits the body before decoding, through the same `RequestAdmission::native`
as the data listeners.
