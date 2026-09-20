# Synchronous membership invalidation

This uninstalled source patch adds the following direct API; it does not activate
Kasumi's dependency or establish release readiness:

```rust
pub trait MembershipObserver: Debug + Send + Sync + 'static {
    fn membership_changing(&self);
}

pub fn Raft::install_membership_observer(
    &self,
    observer: Arc<dyn MembershipObserver>,
) -> Result<(), MembershipObserverAlreadyInstalled>;
```

The trait and its concrete Error + Send + Sync installation error are exported
at the crate root. A Raft group has one fixed slot. Reinstalling the same Arc is
idempotent; a different observer is rejected. Installation and membership
mutation use the same mutex, including before any observer is installed. The
mutation guard spans callback and actual field updates, so installation cannot
return in the gap between an unobserved mutation starting and its completion.
First installation calls the observer once to invalidate any prior evidence.

The slot is shared by MembershipState clones and by the public Raft handles. It
is not part of the logical membership equality. Recovery builds a new slot along
with MembershipState before the Raft owner is exposed; no live production path
replaces the whole MembershipState after initialization. The current source has
no MembershipState serde implementation. The callback must be bounded,
nonblocking, non-panicking and non-reentrant; atomically incrementing a node-wide
generation is the intended implementation.

Every actual append, effective-log truncation/reversion, committed-membership
change and snapshot update_committed mutation invalidates before the fields
change. Both snapshot paths are covered, including replacement by an older
membership after the snapshot covers the effective log. Ordinary commit
advancement that leaves membership unchanged does not invalidate readiness.
There are no per-request membership scans and no callback helper tasks.

A readiness builder must install the observer before route publication and the
first sweep, then read current membership through the Raft actor, bind the exact
voter set to its committed route, and verify an unchanged generation before
publishing evidence. Metrics can lag the actor and cannot safely recertify a new
generation. The application must handle generation exhaustion by failing closed.

Unit tests use a callback panic to prove that append, commit, truncate and both
snapshot update branches have not changed fields before invalidation. They also
cover shared clone custody, replacement rejection, no-op commits and installation
waiting for an initially empty mutation guard. A real three-node integration test
installs through the public follower API and verifies that remote membership
AppendEntries invalidates before the actor exposes the resulting voter set.

Validation attempt receipts and full source patches are retained in
`../openraft-core-ticker-validation-20260920/`; this hook's Kasumi integration and
readiness qualification remain separate gates.
