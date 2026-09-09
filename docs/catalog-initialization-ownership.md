# Fresh catalog initialization ownership

`TenantStorageSet::initialize_catalogs` is the explicit creation boundary for a
new application/custody catalog pair. It does not adopt partial installation,
replace an existing catalog, or expose custody access to the server. Both live
cache owners and both physical catalog/record prefixes must be absent before
any provider call. The actual catalog publication transaction checks physical
absence again and creates the two catalogs atomically. Binding installation is
a subsequent authenticated transaction; interruption can leave an incomplete
installation, which this API deliberately rejects on another invocation.

The NodeStore registers an initializer task before starting work. That task
holds the custody open gate followed by the application gate. Key generation
and first unwrap retain the caller's original storage capability. Provider
calls keep their existing finite timeouts. The actor owns each blocking disk
publication through completion. New TenantStores stay unpublished; renewal
workers are registered dormant before result delivery.

A private ticket, rather than a store handle, crosses the result channel.
Sending the ticket is not ownership transfer. The receiving future checks both
original accesses, publishes both cache entries, activates the already
registered workers and returns the public pair in one synchronous transition.
There is no await, fallible operation or allocation after the first cache
entry publication. Both open gates remain held through that transition.

If a ticket is rejected, dropped while buffered, or cannot be claimed under
its original access, its actor drains the unpublished stores before releasing
either gate. It never shuts down a committed pair. Cancellation after the
future returns `Ready` has the same semantics as dropping any returned runtime
handle: actual runtime owners must drain their scopes; cache publication is
not undone. No Arc reference-count inference is used.

`NodeStore::drain_initializers` joins actual initializer tasks without stopping
committed/shared stores. Callers must stop new initialization admission before
using it as final node drain. A cancelled drain retains unfinished JoinHandles.
Completed tasks are also joined/reaped on the next admission, so the registry
does not retain a history proportional to lifetime installations.

Existing acquisition now has a separate prepared/borrowed ownership path in
[existing-catalog-ownership.md](existing-catalog-ownership.md). Neither path
supplies full process-wide admission for an arbitrary number of concurrent
catalog requests. Remaining create-or-open APIs still require removal.

## Validation status

Source-only. Direct Rust 1.97.1 rustfmt and Git whitespace checks were run.
No compiler, tests, provider service or native listener was started for this
checkpoint. Proposed focused gate, after explicit lane scheduling:

```
cargo +1.97.1 test --locked -j1 -p kasumi-store --lib storage_domains::catalog_initialization::tests:: -- --test-threads=1
```

Four regression sources cover buffered unclaimed result cleanup, committed
handoff with a concurrent existing opener, rejection of shared/partial/orphan
domains without mutation, and cancellation while a provider is still active.
The normal renewal refactor also requires the existing lease/shutdown store
regressions before integration can claim functional validation.
