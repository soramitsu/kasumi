# Explicit standalone tenant enrollment

Standalone installation format 3 requires the immutable node genesis input and a
completed, incarnation-bound ledger row for every original tenant. The initializer
records each actual bootstrap fingerprint after its workers drain, then completes
the ledger before publishing the installation marker. Earlier installation formats
are rejected; there is no migration or catalog-absence bootstrap.

Later configuration entries are templates. Startup reads the independently
encrypted enrollment ledger before opening their keyrings or catalogs. Unrecorded
and incomplete entries stay dormant. A committed route without a completed ledger
row is corruption and fails startup. Stopped wrapping-key rotation and administrator
recovery apply the same rule using the retained strict Control database; they do
not silently skip a damaged routed tenant. Those operations reuse the exact owned
Control handle, and its ordered owner drain closes stores after database workers.

## Stage while the installation is stopped

`kasumid tenant stage /absolute/installation/kasumi.json request.json` requires the
exclusive stopped installation and its canonical configuration path. The request
has five required fields: `operation_id`, `tenant`, `incarnation`, `initial_policy`
and `initial_limits`. This example creates a complete request by copying the
existing tenant's explicit policy and limits for operator review:

```sh
python3 - /absolute/installation/kasumi.json request.json <<'PYTHON'
import json, os, sys, uuid
with open(sys.argv[1], encoding="utf-8") as source:
    installed = json.load(source)
request = {
    "operation_id": str(uuid.uuid4()),
    "tenant": "tenant-b",
    "incarnation": str(uuid.uuid4()),
    "initial_policy": installed["tenants"][0]["initial_policy"],
    "initial_limits": installed["tenants"][0]["initial_limits"],
}
fd = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as output:
    json.dump(request, output, indent=2)
PYTHON
```

Review and edit both policy and limits before running `tenant stage`. The server
validates those supplied objects and adds no policy grants. Reusing an operation
UUID with different input is rejected.

The retained operation records its exact inputs, original configuration digest,
intended configuration bytes and generated private namespace before creating files.
It creates separate application/custody File keyrings beneath
`operator/tenant-stage-<operation_id>/`, verifies their bytes and writes an encrypted
receipt containing their digests. Only then may it atomically publish the new
configuration. The CLI creates no tenant catalogs, routes, credentials or profiles.

Run the same command with the same request to resolve a lost result. A FilesReady
receipt permits exact key verification and configuration publication; an already
published matching configuration resolves an uncertain replacement. Completed
outcomes are permanent historical facts. An interrupted key-creation dispatch
without its completed file receipt becomes permanently Failed. Its files remain
untouched, and a new operation uses another private namespace. No retry adopts
unreceipted files, replaces them, or reruns the original key generation.

`kasumid tenant stage-status /absolute/installation/kasumi.json <operation_id>`
reports `incomplete`, `files_ready`, `completed` or `failed`. It also requires the
installation to be stopped. No staging-file deletion command is installed.

Staging captures one suspend-aware 60-second request deadline before detached work.
Cancellation retains the original installation lock and operation until completion
and worker drain. Once configuration publication commits, the task records its
permanent outcome even if the caller loses its response. A later retry is a new
exclusive operator request resolving the original operation identity.

## Approve, prepare, initialize and activate

Restart the daemon with the updated configuration. The staged tenant stays dormant.
Use the existing mTLS management endpoint with the private Control credential. A
`kasumictl` client configuration takes these values from `profiles/control.json`:

| AdminClientConfig field | Control profile field |
| --- | --- |
| `endpoint` | The selected `administrative_members` entry’s `endpoint` |
| `identity` | `identity` |
| `server_ca` | `server_ca` |
| `server_certificate_pins` | The selected `administrative_members` entry’s `certificate_pins` array |
| `token_file` | `bearer_file` |

Store the client configuration as an owner-only file. For each operation, write the
following JSON to an operation file and run
`kasumictl --config control-admin.json manage operation.json`:

```json
{"operation":"approve_tenant","tenant":"tenant-b"}
```

```json
{"operation":"prepare_tenant","tenant":"tenant-b"}
```

```json
{"operation":"initialize_tenant","tenant":"tenant-b"}
```

Preparation uses the existing installation owner's exact standalone capability,
original administrator context and finite deadline. It records creation once,
initializes and verifies the fresh local bootstrap, drains the new database/stores,
and commits Prepared with its observed fingerprint. Only that permanent outcome
permits a strict existing open. A private recipient handoff publishes the dormant
owner under the same mutex used to close enrollment admission. Abandoned new owners
drain; borrowed resident owners are never shut down by preparation cleanup.

Read the current Control topology version with `{"operation":"status"}` and use
its `control_topology_version` as `expected_topology_version` for activation:

```json
{"operation":"activate_tenant","tenant":"tenant-b","expected_topology_version":1}
```

The value `1` is an example; use the observed current version. A conflicting
topology transition requires another inspection. Activation uses the existing
prepared-state checks and Control compare-and-set. Native and MCP routing appears
only after committed activation is reconciled.

Create application access explicitly with
`kasumid credential create profiles/control.json credential-request.json /absolute/private/tenant-b.json`.
The credential request must name `tenant-b`, its exact staged incarnation through
`resource: {"kind":"database","incarnation":"<staged UUID>"}`, the intended
principal/scopes and lifetime. Use a fresh `family_id`. The existing credential
operation verifies that resource binding and writes the private bearer/profile
files. Renew the profile with the normal credential watcher. The Control bearer
does not become the new tenant's data credential.

## Validation and remaining scope

This checkpoint is source-only. Direct Rust 1.97.1 rustfmt and Git whitespace checks
are the only executed checks. Compiler, Clippy and every test remain unrun.

New regression sources:

- `cancelled_staging_retains_exclusive_owner_until_configuration_and_workers_finish`
- `staging_replay_resolves_lost_configuration_outcome_without_replacing_keys`
- `interrupted_key_creation_never_adopts_files_or_reuses_its_dispatch`
- `unrecorded_standalone_template_never_opens_missing_keyrings_or_catalogs`
- `explicitly_enrolled_standalone_tenant_requires_bound_profile_and_survives_restart`
- `abandoned_fresh_standalone_preparation_drains_without_publication_and_retries_existing_state`

The enrollment fixture uses actual native management, credential-profile creation,
native mutation, MCP reads, restart and explicit wrong-incarnation rejection. It
also removes a routed new-tenant ledger row and requires wrapping rotation and
administrator recovery to fail before keyfile/output mutation. The interrupted
key-creation test models the crash boundary by changing the durable receipt phase;
it is not process-kill evidence. Actual process termination at each phase, expiry
and revocation during local creation, and the final combined release gates remain
required.

No catalog abort/deletion, fresh HA replacement, issuer epoch reinterpretation or
distributed standalone fencing is introduced. Incomplete catalog creation remains
permanently nonresumable until the separately approved exact-ownership abort work
lands. Failed staging namespaces are retained. The typed drain APIs and explicit
replicated Control-genesis work must be preserved when integrating this checkpoint.
