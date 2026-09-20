# First production release goals

Status: **active; release not accepted**. Established 2026-09-20 from the
[complete approved plan](first-release-plan.md). That plan is the requirement
baseline; this document supplies workstream goals, dependencies and completion
criteria under the existing [release ledger](production-release.md) and
[acceptance checklist](release-checklist.md).

## Release contract

This is Kasumi's first release. **Backward compatibility is forbidden.** Replace
superseded APIs, configuration and storage formats directly. Update supported
callers and writers together; remove compatibility decoders, aliases, migrations
and fallback paths; explicitly reject unsupported inputs. Preserve the document
model and supported Rust, gRPC and MCP interfaces without preserving obsolete
prototype shapes.

Keep Apache-2.0, Rust 1.97.1, owner-only installation files, loopback listener
defaults, TLS 1.3, one-hour local JWTs and fixture-free production builds.

The latest user instruction requires all work in `/Users/mtakemiya/dev/kasumi`
on `master` only. This overrides the original worktree direction in the approved
plan and the stale location in the active goal's stored objective. Do not create
or switch branches or worktrees. Preserve pending source and historical evidence;
transfer prior work into master before resuming edits or builds. Parallel agents
must use disjoint file scopes in this same checkout.

## Tracking and completion

There is one active release objective. G01–G14 are its implementation goals, not
independent release approvals. Every goal remains open until its implementation
is integrated, its required final-source validation passes and its release
artifacts or operating documentation are usable. Record focused progress and
source-bound evidence in the release ledger; never turn a source-only change,
prepared command, historical pass or candidate package into final acceptance.

| Goal | Workstream | Dependencies for completion | Implementation | Final validation | Artifacts/docs |
| --- | --- | --- | --- | --- | --- |
| G01 | Integration, contract and truthful baseline | None | Open | Open | Open |
| G02 | Physical storage ownership and admitted redb | G01 | Open | Open | Open |
| G03 | Streaming generations and bounded resources | G02 | Open | Open | Open |
| G04 | Retained history and audit dependencies | G02, G03 | Open | Open | Open |
| G05 | Durable backup ownership and cleanup | G02, G03 | Open | Open | Open |
| G06 | Historical keys and authoritative retention | G04, G05 | Open | Open | Open |
| G07 | Response fencing and retained task/drain ownership | G01 | Open | Open | Open |
| G08 | Credentials, endpoints and membership maintenance | G06, G07 | Open | Open | Open |
| G09 | Distributed/local recovery and exact deletion | G03–G08 | Open | Open | Open |
| G10 | Protected observability and complete readiness | G04–G09 | Open | Open | Open |
| G11 | Acceptance manifest, infrastructure and dependencies | G01 | Open | Open | Open |
| G12 | Native, installed and HA final qualification | G02–G11 | Open | Open | Open |
| G13 | Capacity, performance and full-duration endurance | G02–G12 | Open | Open | Open |
| G14 | Verified deliverables and release closure | G01–G13 | Open | Open | Open |

Dependencies govern acceptance, not when independent preparation can begin.
Packaging, runner provisioning, dependency tests and evidence tooling can proceed
alongside implementation. Qualification consumes the actual candidate packages
and binaries; G14 verifies their complete evidence before release closure.
G11 delivers the implemented and validated acceptance verifier and manifest
contract; G14 requires the fully populated passing manifest for the final release.

## Workstream outcomes

### G01 — Integration, contract and truthful baseline

- Preserve the approved plan, pending MCP work, independent worktrees and failed
  attempts. Apply the first-release contract to every integration review.
- Correct the latest frozen checkpoint to eight passing gates, one ownership
  gate with five failing fixtures, and 22 later unrun gates. Preserve the prior
  `32825cf` failure as historical evidence and the original `be2667d` run bytes.
- Create private fixture installation directories; leave production permission
  enforcement unchanged. Validate the corrected ownership cases and the retained
  successor cohort on a newly frozen revision with original mandatory cases and
  deadlines. Record exact results, unchanged source and actual process drains.

### G02 — Physical storage ownership and admitted redb

The next storage-accounting slice is specified in
[installed storage admission](installed-storage-admission-plan.md). It remains
unimplemented: share the durable memory governor across runtime facades, charge
retained metadata before allocation, then account for directories and every
affected parent during namespace mutation.

- Require installed `NodeDisk` at every production storage constructor. Account
  for creation, growth, write, sync, shrink, deletion and directory publication
  through the same physical owner, including archives, journals and local backups
  under their configured roots. Remove production admission bypasses.
- Complete redb admission for construction, repair, writes, commit, compaction
  and close. Distinguish pre-publication `CapacityDenied` transaction rollback
  from `OwnerFailed` fencing on uncertain I/O or identity substitution. Reopen
  only after resources drain and a fresh census completes.
- Prepare allocation, bookkeeping, repair metadata and publication before the
  winning commit header. Use immediate durability and two-phase publication,
  fallible explicit close, non-allocating destructor fallback and settlement of
  retained growth after aborts. Test every allocation/publication boundary,
  rollback, interruption and owner failure.

### G03 — Streaming generations and bounded resources

[Custody staging](custody-staging-plan.md) records the unimplemented bounded
transaction writer identified by the failed capacity diagnostic. It depends on
explicit memory admission and retained worker cleanup; the 4,200-command and
8,400-audit workload, durability and original deadlines remain unchanged.

- Replace whole-namespace replacement with generation-addressed typed records
  streamed into unpublished encrypted generations. Authenticate final checked
  64-bit counts, digests and dependencies; atomically publish generation pointers,
  custody bindings and the matching applied position for snapshots, Raft transfer,
  restore and administrative state.
- Reclaim abandoned/superseded generations in bounded transactions after readers
  drain. Share coherent document/ID roots, charge lease metadata and retained
  versions, and explicitly expire pressured leases while preserving their
  snapshot identity until expiry.
- Reserve maintenance separately from foreground work, initially serialize it
  per owner, and use bounded compaction and synchronized shrink without another
  full database copy. Reserve bounded Raft backlog and application workspace;
  committed entries under capacity pressure remain unapplied until recovery.
  Never manufacture a rejection or advance an unapplied position.

### G04 — Retained history and audit dependencies

- Produce encrypted immutable audit segments of at most 8 MiB; start maintenance
  at 75% of the hot budget and drain toward 50%. Persist the exact pending segment
  before publication, verify it before proposing pruning, and require every HA
  replica to durably preserve the dependency before applying that transition.
  Carry dependencies through snapshots and replacement enrollment.
- Keep permanent command identities, receipts, incarnation/lifecycle history and
  session outcomes in encrypted point-addressed tables governed by disk budgets.
- Expose typed audit status/export/verification/capacity through Rust, gRPC and
  CLI with bounded pages and cursors bound to stream, range and snapshot; never
  silently restart pagination. Qualify outages, restarts and lifetime ceilings.

### G05 — Durable backup ownership and cleanup

- Resolve durable session completion and abort, publishing roots only after
  dependency verification. Cleanup must page boundedly and delete exact objects
  or S3 versions only inside aborted namespaces. Repeat passes to catch uploads
  arriving late.
- Preserve completed backups, audit archives and permanent session tombstones;
  qualify completion uncertainty, cancellation, restart and late-upload races.

### G06 — Historical keys and authoritative retention

- Install a historical-key resolver keyed by exact authenticated wrapping
  identities, separate from the writable primary. Reject duplicate/ambiguous
  bindings and trial decryption. Bind historical provider identities into accepted
  recovery inputs; credential refresh cannot redirect accepted recovery.
- Add `ReadKeyRetention(scope, cursor, limit)` with at most 256 entries per page,
  exact key versions and referencing catalogs, sessions, backups, archives and
  recovery records. Missing/unavailable dependencies mean incomplete coverage.
  Retirement requires complete authoritative coverage and a final race-safe check.

### G07 — Response fencing and retained task/drain ownership

[Filesystem job ownership](filesystem-job-ownership-plan.md) records the remaining
unimplemented archive/backup child registry, pre-open disk fence, output-charge
handoff, constructor plumbing and shutdown order. A caller retaining a resource
charge does not by itself retain the actual child outcome.

- Materialize bounded terminal MCP responses under request ownership before the
  final credential/family check. Reject SSE. Withheld responses after mutation
  dispatch yield `UnknownOutcome`, resolved by the original command identity.
  Renewal never extends an existing request deadline.
- Retain actual children and terminal outcomes in a bounded task registry for
  authority commands, lifecycle, signer and membership work across cancellation
  and timeout. Complete and qualify the retained OpenRaft shutdown changes.
- Use one typed drain result across Raft, authority, custody and serving. Preserve
  core, ticker, blocking, network and storage-child outcomes; report drained only
  when actual ownership ends. Test cancellation, child panic and revocation.

### G08 — Credentials, endpoints and membership maintenance

- Qualify installed endpoint pools, renewable credential files, original-deadline
  routing, exact receipt resolution and fresh admission after authority expiry.
  Drain the old serving instance before reopening.
- Complete learner/voter, certificate, signer-generation and endpoint-trust
  maintenance and rotation. Invalid TLS replacements retain the last valid
  configuration and expose failure. Exercise maintenance under load and outages.

### G09 — Distributed/local recovery and exact deletion

- Exercise durable preparation, every target's materialization, initialization,
  source fencing, activation, confirmation and route publication. Preserve
  independently verified source/target authorization, a single activation winner
  and forward progress after committed activation, including absent source quorum.
- Complete cleanup through permanent stop, issuer drain, gate closure,
  worker/storage drain, exact deletion, parent sync and durable evidence. Preserve
  physical generation bindings across path, alias, provider and restart changes.
- Keep standalone recovery exclusive and local. Qualify initialization,
  credentials, operator key backup, rotations and stopped-installation admin
  recovery. Advertise OAuth discovery only for an installed external provider.
  Inject crashes/cancellation at every recovery/deletion phase and sync failures.

### G10 — Protected observability and complete readiness

- Expose protected physical capacity, archive failures/backlog, durable backup
  outcomes, authority health, membership maintenance and distributed recovery
  phases through operational diagnostics and documentation.
- Replace the fixed 128-group readiness ceiling with bounded background probes
  and membership-epoch coverage. Require fresh complete coverage for readiness;
  qualify changes in membership, stale probes and former group ceilings.

### G11 — Acceptance manifest, infrastructure and dependencies

- Add final acceptance verification above candidate packaging. Require every
  gate, exact clean source/tree/lockfile/configuration/patch/binary hashes,
  complete workload samples and drained test processes. Reject missing, failed,
  shortened or mismatched evidence; retain every failed attempt.
- Reserve explicit capacity on the native Linux ARM64 reference deployment and
  provide a native Linux x86-64 runner. Emulation cannot satisfy native acceptance.
  Document shared-host limits and operator durability/failure-domain requirements.
- Qualify memory-safety fixes and every retained dependency patch with upstream
  tests and provenance checks; record explicit remaining-advisory dispositions.

### G12 — Native, installed and HA final qualification

- Freeze a clean source revision and its candidate binaries. On native Linux
  x86-64, Linux ARM64 and macOS ARM64 with Rust 1.97.1 run the complete workspace,
  doctests, strict Clippy, formatting, Python, dependency regressions and
  fixture-free production builds.
- Use those candidates for offline standalone native/MCP lifecycle and actual
  OpenBao/MinIO interoperability: credentials, rotations, revocation, restart,
  backup/restore and administrator recovery.
- Run separate three-member data, Control and authority groups with distinct TLS
  identities. Inject leader loss, partitions, lease-length outages, replacement
  under load and every required recovery/deletion crash and cancellation,
  including absent source quorum. Preserve exact outcomes and process drains.

### G13 — Capacity, performance and full-duration endurance

- Run an incompressible corpus **exceeding 3 GiB** through standalone and HA
  snapshots, compaction, restart, follower replacement, filesystem/S3 backup and
  restore. Record compression, exhaustive integrity, retained-read pressure,
  memory peaks, allocated disk and maintenance workspace. Cross former lifetime
  ceilings and repeatedly test archive outages and delayed-upload cleanup.
- Preserve all 15 million-document cases across raw/local/replicated/text/network
  and 1/100/1,000 tenants; use production providers for production claims and add
  concurrent workloads with complete samples and measured operating limits.
- Run a genuine **86,400-second HA soak** containing credential renewal,
  archival, backup and membership maintenance. Never shorten, substitute or waive
  this gate; retain failures and rerun corrected final candidates as required.

### G14 — Verified deliverables and release closure

- Deliver Linux binaries, macOS ARM64 development binaries, both Linux OCI
  architectures, systemd units, source archives, checksums, dependency and image
  SBOMs, notices, contribution/security guidance and installation, maintenance
  and recovery documentation.
- Smoke-test actual packages and images, verify repeatable assembly and
  independent reproducible builds, and publish measured operating limits with
  source-bound evidence. Final acceptance must bind artifacts to qualified
  binaries and reject any missing gate or identity mismatch.
- Close the active objective only after G01–G14, every required acceptance gate
  and every usable deliverable are complete. Infrastructure gaps or unfinished
  qualification remain open work, never implicit waivers.

## Immediate execution order

1. Finish G01's private-directory fixture correction and frozen successor
   validation. The ledger correction and goal setup do not imply passing tests.
2. Advance G02, G07 and G11 in independent owned scopes. Preserve and reconcile
   pending MCP changes before final source freezes.
3. Build G03, then integrate G04–G06; advance G08–G10 as their prerequisites land.
4. Freeze the combined implementation, qualify G12 and G13, and verify G14 using
   the exact packages/images and complete G11 acceptance manifest.

Initial evidence: [latest failed frozen ownership run](evidence/first-release-be2667d-check-20260919/README.md).
No implementation or qualification goal is marked complete by this planning update.
