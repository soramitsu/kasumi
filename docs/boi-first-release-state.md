# BOI Core first-release state contract

BOI Core uses one dedicated Kasumi tenant bound to its independently signed client profile, tenant, incarnation, principal, and credential family. It uses one native Iroha dataspace, is2; these Kasumi collections are application state within BOI Core.

Provision 14 collections before Core starts. The append-only collections use archivable-history retention; mutable collections use operational retention. Every collection enables strict read audit. Native Admin readback must prove their exact definitions, write modes, limits, and policy grants. Missing or foreign collections fail admission; Core does not create or adopt another tenant.

| Collection | Write mode | Contents |
| --- | --- | --- |
| boi_core_owner | append_only | Exactly id=owner, schema boi.core-owner.v1, owner boi-core.is2 |
| boi_core_policy | mutable | Exactly id=policy, schema boi.core-policy.v1, retail policy and state schema version |
| boi_core_uids | append_only | UID entities |
| boi_core_wallets | mutable | Wallet entities |
| boi_core_dynamic_wallet_bindings | mutable | Dynamic wallet bindings |
| boi_core_payments | append_only | Payment entities |
| boi_core_payment_idempotency | append_only | Payment idempotency entities |
| boi_core_ledger_payment_intents | append_only | Ledger payment intents |
| boi_core_ledger_payment_receipts | append_only | Ledger payment receipts |
| boi_core_ledger_payment_claims | mutable | Ledger payment claims |
| boi_core_client_payment_quotes | append_only | Client payment quotes |
| boi_core_client_payment_idempotency | append_only | Client idempotency entities |
| boi_core_client_payment_receipts | append_only | Client payment receipts |
| boi_core_settlements | append_only | Settlement entities |

Entity documents use schema boi.core-entity.v1, owner boi-core.is2, a typed kind and key, and one value. Core validates the reconstructed CentralState on read. Schema validation alone does not authenticate the writer; tenant policy and the bound credential authorize writes.

Startup and each mutation use a coherent native snapshot lease. Core scans all 14 collections in pages of at most 256 rows while retaining one generation; it limits each collection to 10,000 rows and hydrated state to 64 MiB. The lease preserves one incarnation, policy/schema epoch, and collection data epochs across every page. A partial page, changed authority, expired lease, or retained-root budget failure aborts hydration. Core closes the lease and starts again from a new one rather than combining generations. Kasumi's native per-page cap remains 1,000 rows and 8 MiB of encoded result.

An empty tenant may be claimed only by one mutation that proves every collection empty and creates the append-only owner marker and policy document with absent preconditions. An established tenant must have exactly one owner and policy document; a missing marker or foreign state fails closed. Later mutations submit only changed entity documents using exact versions or absent preconditions. Every batch carries a snapshot identity assertion plus all 14 collection epochs. The batch is bounded by 256 operations and 8 MiB. A committed mixed Put/Delete receipt reports each target path at one global revision, and exact replay returns the same receipt.

For an uncertain write, Core resolves the original batch with KasumiClientPool::resolve_mutation and its independently expected MutationReceiptScope. An absent receipt is unknown, not permission to issue another batch. Core checks the result and reads state back after commit. The owner marker cannot be overwritten or deleted through the data API.

Each document is capped at 1 MiB; batch and result limits are at most 8 MiB. Payment-claim expiry remains application state rather than Kasumi TTL. Transitions needing trusted leader time use bounded snapshot time and Before or NotBefore assertions in the same mutation batch.
