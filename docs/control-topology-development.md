# Current Control topology observation

This is an implementation checkpoint, not a deployed topology or release claim.

`kasumi-types::control_topology` owns node, tenant route and versioned topology
records. The engine consumes that single definition. Tenant incarnations are
non-nil canonical UUIDs. Node keys, pins, voter counts and failure domains are
validated before the topology can be applied.

`Database::observe_control_topology` obtains the actual installed Control
quorum and authorization fence. The returned `VerifiedControlTopology` has no
serialized constructor. It retains the original database, quorum, credential
expiry and resource reservation. The signer checks that original before and
after signing. The record binds the request, installed root, authenticated
caller, policy epoch, revision, term, leader, voters and full topology.

Releasing a historical signed read requires a fresh authenticated quorum read
of the same topology. The caller, term, membership, policy and original deadline
must still match. Release cannot extend the deadline. Any committed topology
change invalidates the original retained proof and prevents its signing.

`ControlTrust` validates immutable signatures and release binding. The native
`KasumiLifecycleClient` now owns each actual request and its original
suspend-aware elapsed deadline. `ObserveTopology` and `ReleaseTopology` run over
the existing pinned mTLS listener. The response binds the installed root,
expected principal, actual client certificate and digest of the exact verified
bearer. A release with another credential or certificate rejects. Neither reply
can be deserialized into a current native observation or extend its lifetime.
Network release time is bounded by the original remaining deadline.

Routing reads require the current Control credential's `Read` scope and a
committed policy grant for the `topology` collection. Their retained quorum
fence rechecks that same permission at each release. Administrative lifecycle
operations retain their separate `Admin` requirement. A routing principal needs
no administration grant. Tenant/data permissions and issuer execution leases
remain separate; this observation grants neither.

The scoped native test exercises real in-process Control consensus and an actual
route change. Original results and explicit limits are retained in
[evidence](evidence/control-topology-development-20260927/README.md). Actual
pinned TLS/client acceptance is recorded in the
[native RPC checkpoint](evidence/control-topology-native-rpc-20260927/README.md).
Dedicated Control-only processes, data-node routing integration, recovery
integration and nine-process qualification remain open.
