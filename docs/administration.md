# Runtime administration

`kasumid example-config` emits a credential-free JSON template. Configure a separate TLS 1.3 endpoint for MCP, a TLS 1.3/mTLS native data endpoint, and a TLS 1.3/mTLS administrative endpoint. Every native administrative call additionally requires a signed bearer credential for the selected resource. The verified token selects the tenant and principal; requests cannot override either. Control-group membership administration uses an explicitly authorized token for `__kasumi_control` and remains absent from data/MCP discovery.

`kasumictl example-config` emits a client template. Store one client configuration per node, with its actual administrator certificate, CA, server certificate pin, and private renewable credential file. Keep private-key files readable only by their owner. The CLI never accepts access tokens as command-line arguments.

```
kasumid check-config /etc/kasumi/node.json
# First enrollment of this HA node file only:
kasumid provision-node /etc/kasumi/node.json
kasumid serve /etc/kasumi/node.json
kasumictl --config /etc/kasumi/client-node1.json create-collection collection.json
kasumictl --config /etc/kasumi/client-node1.json suspend
kasumictl --config /etc/kasumi/client-node1.json manage operation.json
```

The server configuration requires a nonnil `database_id` UUID chosen and saved
before file creation. Keep it unchanged for that node file; each new node gets
its own UUID. `example-config` generates a candidate UUID, so save the generated
configuration once instead of regenerating it on restart. The database parent
and configured scratch parent must already exist, with node state owned by the
service account. Run `provision-node` as that account; it exclusively creates the
configured node file and refuses every existing path. It enrolls service audit, application/custody catalogs and immutable local genesis
under the original exclusive file owner. It does not initialize Raft membership;
see [cold node enrollment](cold-node-enrollment.md) for the retained enrollment
identity, finite issuer admission and remaining Control publication boundary.
`serve` opens an existing file with the configured UUID and never creates or
repairs an unrelated file. On restart omit `provision-node`; a failed or uncertain
creation is not permission to remove/recreate its file. See the
[node-file contract](node-file-envelope.md) for partial creation and cleanup.
Standalone installations use `kasumid init --mode standalone` instead.

`manage` accepts the closed `ManagementCommand` JSON enum, rejects unknown fields, and prints exact JSON. Ordinary schema, policy, limits, suspension and resume commands use their corresponding native methods. Management is never exposed as an MCP data tool.

## Routing and outcomes

Each tenant and the control database elect independent leaders. There is no implicit forwarding of bearer tokens or arbitrary client-selected URLs. Configure clients with the approved node-to-endpoint mapping.

`{"operation":"status"}` reports local committed state, the tenant leader node ID and `control_leader`. Status has no caller-selected incarnation. Recovery status belongs to the typed coordinator. Status is an administrative observation, not a fresh point read. Required security auditing precedes release. A missing leader means election or quorum recovery is still necessary.

Native data errors may carry `kasumi-leader-node-id`; MCP tool errors may carry `leader_node_id`. Hints are limited to operator-configured pinned nodes and principals with a current tenant grant. Select the matching configured API endpoint. A node ID does not supply an untrusted redirect destination. `UNKNOWN_OUTCOME` remains explicit: resolve or retry the same idempotency key for mutations. Administrative external effects may also have uncertain outcomes; inspect status or existing artifacts before retrying.

## Backups and keys

Configure destination names in the server JSON, for example:

```json
"backup_destinations": {
  "nightly": {
    "kind": "filesystem",
    "directory": "/var/lib/kasumi/backups",
    "max_bytes": 33554432
  }
}
```

S3 destinations use `kind: "s3"`, an HTTPS `endpoint`, `region`, `bucket`, `prefix`, `max_bytes`, one absolute `credentials_file` path and nullable `ca_certificate`. The private credential file contains one JSON object with `access_key_id`, `secret_access_key`, and nullable `session_token`; all fields are reloaded together for each signed request. The adapter requires TLS 1.3, signs requests with SigV4, and refuses redirects. Filesystem and S3 publication are create-only. The destination byte limit bounds individual encrypted objects. Publication and verification use bounded encrypted chunks and streaming records. Decoded database state and indexes still consume their configured resident capacity; final capacity acceptance must measure those allocations and maintenance workspace together.

```json
{"operation":"backup","destination":"nightly","session_id":"5daa40b0-d0a4-4ad3-bec1-83ed5880e75a"}
```

Persist a newly chosen session UUID before sending the request and reuse it for ambiguous retries. See [durable backup sessions](backup-sessions.md) for status, abort, and cleanup. Run backup on the current tenant leader. The returned UUID identifies an encrypted, authenticated logical backup containing documents, schemas/index definitions, receipts, integrity metadata and wrapped-key dependencies. Backup and restore audit events are durable. Requests cannot choose filesystem paths or S3 URLs.

```json
{"operation":"rotate_data_key"}
{"operation":"rewrap_keys"}
```

These operations act on the addressed replica's encrypted store, with tenant consensus authorization/auditing and separately protected security auditing. They require that replica to be the group leader. They do not rotate the customer Transit wrapping key itself; that remains a Transit operator action. Rewrapping preserves historical backup wrappers, which may still require older wrapping-key versions. Keep those versions decryptable for retained backup/recovery dependencies. Each replica's actual decrypt leases independently enforce revocation.

## Recovery through the installed coordinator

Distributed recovery uses the typed `KasumiRecoveryControl` service and
`kasumid control-recovery` commands. Install the exact source, target voters,
issuer, approved endpoints and trust in `control.lifecycle.recovery` before
starting. The coordinator retains one operation identity and the exact inputs
of every phase before dispatch. Target file identities derive from the durable
Control incarnation, target incarnation and physical verifier; management
requests cannot select paths, open a generation or publish a route.

For planned recovery, suspend the source and create and verify the complete
backup after its final application and policy changes. The installed route uses
independent source application, source custody, target Control and issuer
credentials. For a source-unavailable disaster, explicitly select that fencing
mode; it requires the complete issuer drain and cannot claim source retirement
evidence. Never reuse a source credential to authorize the target.

```sh
kasumid control-recovery start /private/control-profile.json /private/start.json /private/start-attempt.json 5000
kasumid control-recovery status /private/control-profile.json OPERATION_UUID 5000
kasumid control-recovery resume /private/control-profile.json OPERATION_UUID 2 60000
kasumid control-recovery stop /private/control-profile.json OPERATION_UUID /private/stop-attempt.json 5000
```

Persist the original start/stop attempt files and resolve their retained
identities after ambiguous replies. Completion requires actual target quorum
proof, source fencing, the single committed activation winner, confirmation on
every target voter and atomic Control route publication. A committed activation
proceeds forward. A pre-activation stop permits physical cleanup only after its
permanent outcome and issuer drain; failed or uncertain cleanup retains its
owners and evidence. See [Control recovery](control-recovery.md) for exact phase
contracts, configured dispatch and remaining acceptance gaps.

Standalone recovery uses `kasumid local-recovery` while holding exclusive
ownership of the stopped installation. Its permanent stop and active-generation
selection apply to that installation; they do not fence an independently running
copy. Follow the [standalone recovery procedure](standalone.md#local-data-recovery).

The management restore family and its private generation descriptors are removed.
Unknown operations and an `incarnation` field on management status are rejected.
The native source retirement/status/abort/proof operations remain independently
resource-bound custody operations used by planned recovery. See
[planned retirement](planned-retirement.md). An admitted management invocation
borrows one exact serving database for execution and response release. Renewing
a credential or publishing a different route cannot redirect that invocation.

## Adding configured tenants and peers

New replicated control and tenant groups compare their persisted bootstrap
fingerprints over pinned mTLS before initialization. The fingerprint binds the
actual immutable snapshot digest, tenant identity and deployment configuration;
all three initial voters must match. A mismatch refuses startup. Already-initialized
groups can recover with quorum, and every Raft request still carries the fingerprint
and is rejected before persistence/application if the receiving replica differs.
Restored generations use the same fence, including their restored documents and
receipts. Certificate rotation and credential settings are separate from this
immutable logical-state identity.

Roll out the approved configuration to every replica before provisioning. Add the
new tenant with its own Transit wrapping key, initial policy and limits. Replicated
configurations require an identical fresh incarnation and the same three initial
voters, in independent approved failure domains. Configuration may be a superset
of the durable topology: extra tenants remain absent from data RPC/MCP and ordinary
tenant administration, and extra peers do not become learners or voters. Existing
approved pins, endpoints, failure domains and routed tenants must remain present.
The runtime opens bounded empty staged stores; they consume configured RAM and key
leases even while hidden. An existing serving tenant continues operating.

Use an OAuth identity for `__kasumi_control` with current read/write/admin grants
on the separate native admin endpoint. Every command below is supplied through
`kasumictl --config <client.json> manage <command.json>`. Tenant administrator
identities cannot provision, and control approval never grants tenant data access.

If the configured peer pool gained nodes, obtain `control_topology_version` from
`{"operation":"status"}` using the control identity, select the reported control
leader, then submit:

```json
{"operation":"approve_peer_pool","expected_topology_version":7}
```

This CAS adds only configured pinned peers, preserving existing routes and node
identities. It does not perform a membership change. All transport endpoints and
key settings come from node configuration; management requests cannot supply them.

To add a configured tenant named `beta`:

1. On the control leader, issue `{"operation":"approve_tenant","tenant":"beta"}`.
   This durably records an immutable bootstrap fingerprint in the control group.
   Retries retain the same approval; differing policy, limits, incarnation,
   wrapping-key identity or voter pins are rejected.
2. On each required replica, issue `{"operation":"prepare_tenant","tenant":"beta"}`.
   Preparation requires that replica to have applied the committed approval. It
   durably records local readiness after checking the configured bootstrap and
   key access. It does not publish a data route.
3. On the lowest initial voter, issue `{"operation":"initialize_tenant","tenant":"beta"}`.
   Replicated initialization checks all three authenticated peers for identical
   prepared fingerprints. Missing or mismatched preparation refuses initialization.
   Local mode performs the equivalent one-voter readiness check.
4. Obtain a fresh control topology version with control `status`. On the control
   leader, issue `{"operation":"activate_tenant","tenant":"beta","expected_topology_version":7}`.
   All required replicas must have rebuilt state and applied the expected
   non-joint membership. Current control authorization and a topology CAS persist
   the route. Each node then registers the tenant from that committed route.

Activation does not require the tenant and control leaders to be the same node.
A stale topology version fails with a conflict. Inspect status after an uncertain
response and retry the same approved tenant; a matching already-published route
is idempotent. Restart follows committed routes, so staged tenants stay hidden and
activated tenants recover automatically. An immutable-bootstrap mismatch requires
correcting the deployment before approving a fresh tenant/incarnation; the server
never rewrites an already-created replicated bootstrap in place.

## Membership replacement

`replication.peers` is an operator-approved pinned peer pool (3–64 nodes). If it contains more than three nodes, set explicit `initial_voters` to the immutable original three IDs. New learners use that same original bootstrap and distinct node identity. Never edit initial voters to shrink an existing group or recover quorum. The final placement must have exactly three voters across independent failure domains recorded by the control database.

Start the spare with its configured identity and original bootstrap. On the control leader, using a control-tenant administrator token, run `{"operation":"add_learner","node_id":4}`; it waits for catch-up. Once the spare has the committed topology, add it to the tenant group on that tenant's leader using the same command with the tenant token. The peer must exist in both configured pinned transport and approved control metadata.

On the relevant group leader run, for example, `{"operation":"change_membership","voters":[1,2,4]}`. Every proposed voter must already be a known learner/member. OpenRaft performs the membership transition without a one-voter fallback. Then issue `{"operation":"publish_membership","voters":[1,2,4]}` on the control leader only after that node has applied the final non-joint tenant membership. The runtime verifies applied membership and CAS-updates routing. Perform the control group's own replacement independently with its control-tenant token.

Tenant RBAC stays in the tenant group. Control metadata, certificate identities, membership and CLI descriptions do not grant document access. Required audit-storage failure blocks the associated successful operation; access denials remain enforced.

## Validation evidence

The runtime tests exercise TLS Transit, separate audited listeners, local reopen and restored-generation routing, and actual three-node pinned mTLS restore with independent source/target/control leader selection. Local and three-node onboarding fixtures restart with configuration supersets, keep an existing tenant usable, reject unapproved or mismatched preparation, activate through control CAS, and check that control grants never become tenant grants. The three-node fixture also approves a configured spare peer through a topology CAS; pin/domain mismatch tests reject changes to existing identities. They deliberately reject initialization with only one prepared replica. A four-runtime fixture catches up a pinned spare, rejects two-voter membership, and replaces both tenant and control memberships from `[1,2,3]` to `[1,2,4]`. Engine/Raft tests separately exercise partitions and delayed replication. Loopback fixtures do not prove physical failure-domain independence or production network capacity.


Control policy and limits are available only through the native administrative
router with a verified control-tenant administrator. They remain inaccessible to
data RPC/MCP. To rotate the startup/control-route operator, first grant a new
principal read/write/admin in the current control policy, configure
`control.startup_principal` to that already-authorized name, restart/recheck, then
remove the old grant. This selector never grants permissions and does not modify
the immutable original bootstrap policy. Without it, startup uses the first
read/write/admin principal in the original bootstrap policy.
