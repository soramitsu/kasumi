# Finish Kasumi’s first production release

> Working-location override, 2026-09-20: the latest user instruction requires
> `/Users/mtakemiya/dev/kasumi` on `master` only. This overrides the original
> branch/worktree direction below. The original approved plan is preserved.

## 1. Release contract and integration

Complete the existing integration branch with supported standalone and replicated HA modes, preserving the document model and Rust, gRPC, and MCP interfaces. Replace superseded APIs, configuration, and storage formats directly. Remove compatibility decoders, aliases, migrations, and fallback paths; explicitly reject unsupported formats.

- Continue from `codex/production-convergence-20260919`, preserving pending MCP changes and independently owned worktrees. Integrate finalized changes without overwriting ongoing work.
- Correct the release ledger: the latest frozen run passed eight gates, then failed five ownership fixtures; 22 later gates did not run. Preserve that evidence.
- Fix fixtures by creating private installation directories. Keep production permission checks unchanged.
- Track the following workstreams under the existing release objective. Completion requires implementation, final-source validation, and usable release artifacts.
- Retain the established defaults: Apache-2.0, Rust 1.97.1, owner-only installation files, loopback listeners, TLS 1.3, one-hour local JWTs, and no fixture capabilities in production builds.

## 2. Complete resource-governed storage and streaming publication

- Make installed `NodeDisk` ownership mandatory for every production storage constructor. Route creation, growth, writes, synchronization, shrink, deletion, and directory publication through the same physical owner. Include archives, journals, and local backup storage within their configured accounting roots.
- Keep redb and complete its admitted transaction design across creation, repair, writes, commit, compaction, and close. Install admission at database construction; remove production bypasses.
- Separate recoverable `CapacityDenied` from `OwnerFailed`. Quota denial before publication rolls back the entire transaction. Physical I/O uncertainty or identity substitution fences the owner until its resources drain and reopening completes a fresh census.
- Prepare allocation, bookkeeping, repair metadata, and publication work before writing the winning commit header. Use immediate durability and two-phase publication. Add explicit fallible close; make destructor fallback non-allocating. Settle retained growth after aborted transactions.
- Replace whole-namespace replacement transactions with generation-addressed records. Stream bounded, typed records directly into an unpublished encrypted generation. Authenticate final checked 64-bit counts, digests, and dependencies, then atomically publish generation pointers, custody bindings, and the matching applied position.
- Reclaim abandoned and superseded generations in bounded transactions after readers drain. Apply this publication path to snapshots, Raft transfer, restore, and administrative state.
- Give coherent reads shared document and ID roots. Charge lease metadata and versions retained by concurrent writes. Expire leases explicitly under pressure; preserve their snapshot identity until expiry.
- Reserve maintenance capacity separately from foreground admission. Initially serialize disk maintenance per owner; use bounded compaction steps and synchronized shrink without another complete database copy.
- Reserve bounded Raft backlog and application workspace. A committed entry encountering local capacity pressure remains unapplied until recovery; never manufacture a rejection or advance its applied position.

## 3. Finish retained history, backup ownership, and key dependencies

- Complete audit maintenance with maximum 8 MiB encrypted immutable segments, maintenance beginning at 75% of the hot budget and draining toward 50%.
- Persist the exact pending segment before external publication. Verify publication before proposing pruning. Every HA replica must durably preserve its dependency before applying the pruning transition; snapshot transfer and replacement enrollment must carry those dependencies.
- Keep permanent command identities, receipts, incarnation history, lifecycle records, and session outcomes in encrypted point-addressed tables governed by storage budgets.
- Add typed audit status, export, verification, and capacity operations through Rust, gRPC, and CLI. Use bounded pages and cursors bound to the original stream, range, and snapshot; never silently restart pagination.
- Finish durable backup session completion and abort resolution. Publish roots only after dependency verification. Cleanup enumerates bounded pages and deletes exact objects or S3 versions exclusively within aborted namespaces; repeated passes catch late uploads.
- Preserve completed backups, audit archives, and permanent session tombstones.
- Add an installed historical-key resolver keyed by exact authenticated wrapping identities. Keep it separate from the writable primary provider; reject duplicate or ambiguous bindings and prohibit trial-decryption fallback.
- Bind historical provider identities into accepted recovery inputs. Credential refresh may replace secrets without redirecting an accepted recovery.
- Add paginated `ReadKeyRetention(scope, cursor, limit)` with at most 256 entries per page. Report exact key versions and referencing catalogs, sessions, backups, archives, and recovery records. Missing or unavailable dependencies make coverage incomplete. Retirement requires complete authoritative coverage and a final race-safe dependency check.

## 4. Close runtime ownership, security, and recovery gaps

- Finish MCP response fencing by materializing the bounded terminal response under request ownership before the final credential and family check. Reject SSE. A withheld response after mutation dispatch returns `UnknownOutcome`, resolved through the original command identity. Renewal never extends an existing request’s deadline.
- Add a bounded retained task registry for authority commands, lifecycle work, signer maintenance, and membership operations. Cancellation or timeout must retain the actual child and its terminal outcome.
- Complete and qualify the retained OpenRaft shutdown changes. Use one typed drain result across Raft, authority, custody, and serving adapters. Preserve core, ticker, blocking, network, and storage-child outcomes; report drained only after actual ownership ends.
- Qualify existing endpoint pools, renewable credential files, original-deadline routing, exact receipt resolution, and fresh admission after authority expiry. Drain the old serving instance before reopening.
- Complete maintenance and rotation across learners, voters, certificates, signer generations, and endpoint trust. Invalid TLS replacements retain the previous valid configuration and expose failure.
- Exercise the existing durable recovery coordinator through preparation, every target’s materialization, initialization, source fencing, activation, confirmation, and route publication. Preserve independently verified source and target authorization and the single activation winner; committed activation proceeds forward.
- Complete cleanup through permanent stop, issuer drain, gate closure, worker/storage drain, exact deletion, parent synchronization, and durable evidence. Preserve physical generation bindings across path, alias, provider, and restart changes.
- Keep standalone recovery exclusive and local. Validate initialization, credential lifecycle, operator key backup, rotations, and stopped-installation administrator recovery. Advertise OAuth discovery only for an installed external authorization provider.
- Complete protected observability for physical capacity, archive failures/backlog, durable backup outcomes, authority health, membership maintenance, and distributed recovery phases. Replace the fixed 128-group readiness ceiling with bounded background probes and membership-epoch coverage; readiness requires fresh complete coverage.

## 5. Final qualification and release artifacts

Run focused regressions during implementation, then freeze a clean source revision and qualify its exact binaries.

- **Correctness:** test every allocation/publication boundary, transaction rollback, owner failure, interrupted repair/close/compaction, generation publication, pinned-reader reclamation, cancellation, child panic, response revocation, and cleanup synchronization failure.
- **Native platforms:** run the complete workspace, doctests, strict Clippy, formatting, Python checks, dependency regressions, and fixture-free production builds on Linux x86-64, Linux ARM64, and macOS ARM64 using Rust 1.97.1.
- **Dependencies:** qualify the memory-safety fixes and all retained patches against their upstream tests and provenance checks. Record explicit dispositions for remaining advisories.
- **Installed operation:** test offline standalone native/MCP access and real OpenBao/MinIO interoperability using candidate binaries. Exercise credentials, rotations, revocation, restart, backup, restore, and administrator recovery.
- **HA and recovery:** run separate three-member data, Control, and authority groups with distinct TLS identities. Inject leader loss, partitions, lease-length outages, replacement under load, and crashes/cancellation at every recovery and deletion phase, including absent source quorum.
- **Capacity and retention:** run an incompressible corpus exceeding 3 GiB through standalone and HA snapshots, compaction, restart, follower replacement, filesystem/S3 backup, and restore. Record compression measurements, exhaustive integrity checks, retained-read pressure, memory peaks, disk allocation, and maintenance workspace. Cross former lifetime ceilings and repeatedly test archive outages and delayed-upload cleanup.
- **Performance and endurance:** preserve all 15 million-document cases across raw/local/replicated/text/network and 1/100/1,000 tenants. Use production providers for production claims. Add concurrent workloads and a genuine 86,400-second HA soak containing credential renewal, archival, backup, and membership maintenance.
- **Infrastructure:** use the native Linux ARM64 reference deployment for software acceptance with explicitly reserved capacity. A native Linux x86-64 runner remains required; emulation cannot satisfy that gate. Document shared-host test limitations and operator durability/failure-domain requirements.
- **Release verification:** add a final acceptance manifest above candidate packaging. Require every gate, exact source/tree/lockfile/configuration/patch/binary hashes, complete workload samples, and drained test processes. Reject missing, failed, shortened, or mismatched evidence; preserve failed attempts.
- **Deliverables:** produce Linux binaries, macOS ARM64 development binaries, both Linux OCI architectures, systemd units, source archives, checksums, dependency and image SBOMs, notices, contribution/security guidance, and installation/maintenance/recovery documentation. Smoke-test the actual packages and images; verify repeatable assembly and independent reproducible builds.

The release objective closes only when every required gate passes and the verified artifacts and measured operating limits are available.
