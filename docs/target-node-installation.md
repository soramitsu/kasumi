# Target journal and generation files

Before starting a newly installed target runner, run
`kasumid initialize-target-journal <runtime.json>`. The initializer validates the
installed runtime configuration, exclusively creates the exact journal node
file, installs its independent encrypted catalog and empty canonical journal,
and drains its storage owners before success. Cancellation of the CLI waiter
does not abandon that owned initializer. Existing or incomplete files are never
adopted or reset. The configured parent directory must already exist.

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
or Ready envelope without opening redb or constructing application keys; it
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
