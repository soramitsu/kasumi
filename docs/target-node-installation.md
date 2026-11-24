# Target journal and generation files

Before starting a newly installed target runner, run
`kasumid initialize-target-journal <runtime.json>`. The initializer validates the
installed runtime configuration, exclusively creates the exact journal node
file, installs its independent encrypted catalog and empty canonical journal,
and drains its storage owners before success. Cancellation of the CLI waiter
does not abandon that owned initializer. Existing or incomplete files are never
adopted or reset. The configured parent directory must already exist.

For target-journal key retirement across separate Control and Data nodes, set
`target_recovery.writer_observation_bearer_file` on each target. Issue this
credential for the installed Control incarnation, the target's enrolled node
principal and its `control_tls` client certificate, with the single
`kasumi:read` scope. In the Control policy, grant that principal `read` on
`target_journal_writers`. Control continues to authenticate the initiating
administrator. Each target presents its own credential and signed journal
challenge while that administrator's request is active. If a target credential
is unavailable after the fence commits, restore it at its installed path and
retry the same retirement request.

For distributed recovery with separate Control and target TLS identities, set
`target_recovery.phase_observation_bearer_file` to a credential issued for
the target's enrolled principal, its `control_tls` certificate and the installed
Control incarnation. Grant its single `kasumi:read` scope read access to
`target_recovery_observations` in the Control policy. The original dispatcher
holds the administrator's authorization while the target reads the exact
committed intent, membership evidence or journal writer for that dispatch.
The callback closes when the dispatch returns or its deadline expires. Each
target uses its own certificate and credential. A target with both observation
grants can use the same read-scoped credential for journal retirement and
phase observation.

An operator can inspect a stopped physical target using
`kasumid control-recovery target-deletion-via-control CONTROL_PROFILE OPERATION_UUID PHASE_UUID INCARNATION_UUID NODE_ID TIMEOUT_MS`.
Control reads the original marked StopLocal effect, selects the enrolled target
from that operation's installed route, and checks the returned command and
attempt. The target rereads the phase and signed intent using its own credential.
This point read also works after the original dispatch has ended or the target
has restarted. The direct `target-deletion` command accepts a single pinned
target profile for installations that share an eligible return identity.

Every `target_recovery.tenants[tenant]` template requires its own
`audit_placement`, using the tagged local replica only or nested external choice
in the [tenant audit retention guide](tenant-audit-retention.md). The ordinary
`tenant_audit_placements` map covers Control and exactly the application tenants
in `RuntimeConfig.tenants`. A target-only tenant gets its choice from its template;
adding it to the ordinary map is an unknown extra row and rejects. When a source
and target share a tenant name, their choices remain independent. External
filesystem archives must belong to installed persistent roots and stay outside
the target generation deletion root.

Journal initialization durably binds the complete template-name and placement
roster before any target cache or external archive is opened. Startup requires
the same roster, including before the first materialization. Changing a choice
or adding/removing a template cannot rewrite that installed journal. Credential
contents may refresh at their installed path without changing this configuration
identity. Current journal metadata is format 5; superseded heads reject without a
legacy decoder or migration.

Normal target runtime startup uses existing-only node, tenant catalog and journal
opens. An absent journal head fails even when the namespace is empty or a cached
live owner exists. Explicit `TargetJournal::create_new` and
`TargetJournal::open_existing` replace the former combined constructor directly.
There is no legacy decoder, alias or create-on-missing startup path.

The journal file UUID uses the shared `node_store_ids::target_journal` derivation.
A generation uses `target_generation` with the immutable Control incarnation,
tenant, target incarnation and physical verifier installation identifier. The
shared versioned derivations do not include endpoints, paths, operational
membership, certificates or signing-key generations. Expected IDs never come
from candidate file headers. The full authenticated Control/target origin and
storage purposes are still checked independently; a file UUID grants no serving
or cleanup authority.

Only the exact original Materialize operation can publish a permanent generation
file-creation intent, after its accepted phase and generation binding already
exist. Its checked byte charge and record publish together. Only that first
successful publication returns a create-new operation; every replay returns an
existing-only operation. The opaque file operation retains the original finite
TargetOperation through synchronous I/O and checks it before and after opening.
Errors after durable acceptance remain unknown outcomes, never new identities.

A lost response or crash after intent publication but before file creation leaves
an unresolved original attempt. It cannot recreate a missing file on replay.
An unrelated replacement, including another canonical node with a different UUID,
is rejected without altering that file. Resume, Start, Complete, activation and
activated-serving recovery require an existing file with the causally retained
original creation intent. Only explicit materialization phases may install
application/custody catalogs; later phases require existing catalogs as well.
Journal startup verifies every file intent's exact original Materialize identity,
generation binding, key and byte accounting while visiting bounded records.

Permanent journal stop, issuer stop/drain evidence, closed gates and completed
worker/storage drain precede cleanup. Cleanup claims the exact canonical Prepared
or Ready envelope without opening the KV engine or constructing application keys; it
retains the exclusive descriptor through identity recheck, unlink and parent
synchronization. Only an explicit NotFound filesystem observation establishes
absence; permission, symlink-loop and other I/O failures remain errors, including
at final response release. Empty or torn-before-header files cannot use this guard. Complete
automatic physical cleanup remains open: a future durable owned-empty inode and
namespace protocol must cover pre-header crashes, including the gap between
creating an inode and recording that inode. This checkpoint neither adopts an
unproven orphan nor claims that partial-file recovery is complete.

Source regressions include three `target_journal::open_tests` cases for absent,
corrupt and wrong-identity heads, cached-owner validation, repeated-installation
rejection and exact file/catalog/head reopening after drain. The existing real
issuer-backed permanent-journal test now additionally drops the first creation
operation, verifies that its missing-file replay cannot create, rejects an
unrelated replacement without byte changes, and checks exact retained identity
and accounting through stop and encrypted restart. The target monitor ownership
fixture uses explicit installed IDs across cancellation and reopen. These changes
are source-only until the scheduled combined compiler and functional gates run.

This file framing work does not complete persistent disk admission or operational
journal trust/certificate maintenance, which retain their separate release gates.

The journal owner registry retains a gate while an opener holds its cloned Arc,
including the interval before it acquires the mutex. A deterministic handoff
regression completes a second opener during that interval and requires both to
return the same journal/mutation owner. Fallible generation-root setup now runs
before journal catalog acquisition, so a rejected root cannot leave journal
renewal workers behind. The explicit initializer separately drains the opened
store after either successful or rejected journal installation. These successor
changes are source-only pending the coordinated compiler and functional gates.

### Bind backup read keys during enrollment

Each newly enrolled target backup source supplies a primary `keys` setting,
a `historical_keys` array for older encrypted backups, and a `read_key_binding`
SHA-256. To obtain the digest, put the source's `destination_alias`, `keys` and
`historical_keys` settings in an owner-only JSON file. Run
`kasumid control-recovery source-key-digest <source.json>` and set
`read_key_binding` to its output before initializing the journal.

The journal binds each tenant, source incarnation and destination alias to its
provider roster. Materialization rechecks that roster before opening the
backup. The roster includes file provider identities and Transit key identities
and CA trust. Token refresh can use the configured credential source. A change
in roster or TLS trust fences materialization. Stop and cleanup can reopen the
journal while the source read keys are offline. Deployed journals with an
unbound single source keep their original configuration and read path.
