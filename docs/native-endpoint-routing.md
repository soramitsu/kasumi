# Installed native endpoint routing

`KasumiClientPool` accepts a bounded map of installed member IDs to
`KasumiClientConfig`. Each entry supplies an HTTPS origin, approved CA and leaf
certificate pins; every entry uses the same client mTLS identity. Pools never
follow URLs returned by a member. Use
`kasumi_transport::credentials::FileCredentialSource` for a bearer file renewed
by atomic rename. The pool reads current credentials for each dispatch.

Every operation takes one total timeout. Connections, retries and backoff share
that original deadline; gRPC requests receive its remaining duration. A changed
credential does not create a later operation deadline. Permission denials,
conflicts, invalid responses and proof errors stop retries.

`mutate` resends the exact original `MutationBatch`, including its idempotency
key, read set and body. A committed but lost reply resolves through the database's
permanent receipt; a different payload with the same key remains a conflict.
When the total deadline expires, retain the complete original batch to resolve
uncertainty. Never generate a new key solely because a reply was lost.

`query` returns `RoutedQueryPage`; call `next_query_page` with that handle.
`open_snapshot_lease` returns `RoutedSnapshotLease`, which the read/scan/close
methods require. Both handles keep their originating member and cannot be used
with a different pool (pool clones retain that identity). A member outage or
snapshot expiration returns an error instead of restarting a historical read.
The application may explicitly begin a new query after handling that outcome.
An uncertain lease-creation reply is not replayed, since replay could create a
new snapshot. The low-level `KasumiClient` remains available for callers that
manage explicit member selection themselves.

`KasumiAuthorityPool` applies the same installed routing rules to authority
requests. It preserves each original lease attempt, boot identity and clock
anchor across member failover, and checks the complete original administrative
command when resolving a receipt. `ServingAuthorityConfig.endpoints` maps each
partition ID to a member-ID map, with independent leaf pins for each endpoint.

The focused TLS integration tests inject an unavailable response after mutation
commit and verify exact replay, then close the member owning a cursor and lease
and verify that the healthy alternate member is never contacted for historical
pages. These tests exercise routing against one shared test database; they do
not replace the release's multi-process HA endurance gate.
