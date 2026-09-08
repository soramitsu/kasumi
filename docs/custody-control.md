# Independently encrypted retirement recovery substrate

The first-release storage contract installs two encryption domains for each
application database incarnation. `TenantStorageSet` contains the application
store and the fixed `kasumi.custody/{application tenant}` catalog. Both belong to
one `NodeStore`, with independent wrapping policies, keys and UUID catalog
identities. The immutable binding is encrypted under the custody key. There is
no same-key default, optional custody provider or reader for old development
catalogs/log formats. The custody prefix is reserved and cannot be installed as
an application tenant, preventing an application/control namespace collision.

Normal engine open, local and replicated execution, and all restore entry points
take `Arc<TenantStorageSet>`. Production startup supplies both explicit Transit
providers through `keys` and `custody_keys`; control databases have the same
requirement. Existing Rust embeddings create the set before calling an engine
opener. A raw `TenantStore` remains suitable for independently keyed security
audit or storage-level use, but it cannot open a serving engine.

## Durable execution linkage

Raft application bytes stay in application storage. The separately encrypted
control catalog contains votes, committed and purged cursors, group/node identity,
log headers, exact applied positions and closed retirement seeds. A normal log
header contains only an actual log identity and digests. Retirement seeds contain
the exact prepared request, verified checkpoint/closure observation, original
principal, captured authorization, admission time, scopes and bounded source
policy/accounting metadata. They cannot carry arbitrary documents or operations.
Their canonical command is reconstructed and its digest checked on decode.

The append transaction publishes an application's ciphertext, its header and any
retirement seed atomically, before acknowledging durable append. Commitment
remains a distinct durable Raft operation. A seed without commitment is never
returned by the recovery reader. Truncation deletes the whole uncommitted suffix;
normal overwrite explicitly clears stale seeds. The seed records the installed
bootstrap digest and catalog binding, preventing substitution across incarnations.

The state-machine adapter supplies the actual `LogId`, previous applied position,
membership and command digest. The engine recomputes retirement seed metadata
against its current ordered generation before executing. Ordinary application replay validates the actual retained successful retirement
receipt before producing an accepted boundary. The adapter
validates that receipt against the durable seed and writes the boundary together
with its exact applied position. Interrupted projection publication can therefore
be distinguished from a completed applied retirement.

Snapshot bodies and chunks remain encrypted in the application domain. The final
snapshot manifest and its exact control coverage publish atomically after all
chunks. Recovery checks content digest, snapshot identity and membership coverage
before restoring the application backend. Ordinary purge deletes application log
bodies and control headers together. After an accepted retirement boundary, purge
retains the remaining source ciphertext and permanent retirement seeds; it does
not retroactively restore previously compacted log bodies.

## Metadata-only recovery boundary

`CustodyStore::open` needs only the custody provider and checks the installed
application catalog's wrapped identity. `ControlLog` reads a locally committed
retirement seed without constructing an application provider, unwrapping its keys,
opening an engine or decoding payload. A crash after commit but before applied projection preserves enough closed
metadata for deterministic recovery. Before proposing a potentially successful
retirement, the leader reserves its exact permanent receipt/audit completion
headroom against the captured source accounting. Every replica checks the same
reservation. A locally committed exact seed can finish only when that positive
outcome is forced by the closed captured state and the actual apply predecessor
and membership remain independently available. Exhausted capacity, a failed or
expired attempt, an uncommitted seed, or an already-applied cursor without its
atomic accepted boundary cannot be promoted.

`CommittedRetirementSeed` establishes local durable log coverage. It cannot mint
`VerifiedRetirementReceipt`, authorize a payload operation, establish a fresh
quorum or enable an incarnation. The closed service described below adds fresh
current-quorum and current-Admin proof release. Independent serving-lease and
source-quorum-unavailable fencing remain separate required protocols.

The metadata-only reader also covers a replica that learns accepted retirement
solely through a full Raft snapshot. The backend returns application bytes and
closed retired metadata from one generation. The portable snapshot capsule binds
the exact prepared command seed, original applied position/receipt and bootstrap
to that image, including the Admin set and policy epoch **as of its capture**.
The receiving backend validates the complete image and returns its independently
derived closed metadata for exact comparison before publication. The receiver
rebinds the seed to its own installed custody catalog; source key identities are
never copied as receiver authority.

After bounded chunk staging, the final application manifest, snapshot coverage,
closed capsule, permanent accepted boundary and explicit snapshot applied cursor
publish in one encrypted cross-domain transaction. Snapshot publication and log
cleanup share the same per-store control gate; application apply also holds this
gate when publishing its accepted cursor. An older capture cannot regress a newer
accepted cursor. The snapshot cursor contains image/coverage digests and Raft
metadata, with no invented command digest.

Committed snapshot coverage stays separate from the raw committed-log cursor.
A crash before physical log purge therefore retains exact local custody recovery
input without claiming the receiver possesses the original source log. Beneath a
committed snapshot, only its exact accepted seed can be returned. A conflicting
uncommitted local seed is superseded, subsequent physical suffix cleanup preserves
the accepted seed. Physical log repair beneath snapshot coverage remains legal,
but cannot substitute the exact accepted retirement entry or promote a new
candidate into accepted custody. Equal index but different term identities fail
closed. Missing or substituted capsules,
backend policy/receipt differences, stale projection digests and mismatched local
bootstrap bindings reject installation or recovery.

Application serialization can reorder equivalent persistent maps after a restart.
Every published image keeps its own exact byte digest; two independently validated
encodings at the same applied position must retain identical complete custody
metadata and membership. A builder recapturing that position reuses the current
image only after checking its application and custody coverage together. Replacing
the Admin set or policy epoch in both the incoming image and capsule still fails
against the already published custody identity.

## Closed runtime and current administrative custody

`InstalledRetirementSource` has explicit `Serving(Arc<Database>)`,
`RetiredCustody(Arc<RetiredCustody>)` and `RecoveringControl` routes. Source identity
comes from installed storage, never a request URL, provider, path or credential.
The native runtime opens the custody catalog first. An accepted retired source
starts only the closed state machine; it does not construct an application key
provider, request its credential, decrypt municipal logs or materialize documents.
Ambiguous recovery remains `RecoveringControl`, with no normal/local fallback.

Warm retirement drains and seals the application database, publishing the closed
transition before discarding its handle. The existing Raft group, node ID, votes
and membership reopen with the independently keyed custody store. Blank entries,
membership and the typed custody command are the only closed log payloads. A
normal replica receiving a validated closed snapshot evicts its application
backend before publishing it and requires the same closed-runtime handoff.

Closed snapshots have no application body. Their authenticated capsule contains
the original immutable retirement binding plus the current complete custody
state, exact committed/applied position and membership. Same-position replacement
must equal actual current state for both entry and snapshot cursors. Reformatting
an equivalent image is permitted; changing administrators, retained commands or
audit at the same position is rejected. The required
`StateMachineBackend::close_application` method makes receiver eviction explicit.

`RetiredCustody` provides `status`, `execute`, `retirement_status` and
`verify_retirement_receipt`; the secure `KasumiAdminClient` exposes
`read_custody(bearer, &RetirementRef)` and
`execute_custody(bearer, &CustodyRequest)` alongside existing private retirement
proof methods. A verified credential still selects the tenant; its original
suspend-aware expiry survives cloning, queueing and encoded response release.
Serialized contexts cannot become new live service or credential authority.

The deterministic reducer accepts only `ReplaceAdministrators` and `SetLimits`. It requires current global custody Admin,
exact retirement reference, permanent full-request identity, expected custody
policy epoch and inclusive action deadline. Original receipt principal and result
remain immutable on replay, but current authority is checked for every attempt.
A successful self-revocation or expired acknowledgement returns `UnknownOutcome`;
a newly authorized custodian resolves the exact identity. Application policy,
limits, collections and original retirement binding are permanently frozen.

Custody has an independent `CustodyLimits.max_state_bytes` durable budget,
initially 64 MiB, expressed as a checked 64-bit count. It accounts for canonical
policy, permanent receipts and audit records. There is no fixed lifetime command
or audit count ceiling. Every accepted mutation and exact replay adds a bounded
custody audit record; policy and limit changes include their own permanent records
before publication. A current custodian can raise an exhausted byte budget with
`SetLimits`, preserving every existing identity and exact outcome. Limits that
cannot be represented safely by storage/staging arithmetic are rejected.

Receipts and audit entries live in encrypted point-addressed tables. Snapshot
metadata contains a bounded policy head and history digest; typed records stream
through encrypted indexes and closed snapshots publish chunks atomically with
the applied position. Runtime custody transfer uses the installed tenant's
`initial_limits.max_snapshot_bytes` (Control uses its own matching setting).
Embedded callers supply `CustodyRaftConfig` with an explicit `RaftLimits` budget.
Configured disk capacity must cover retained state and snapshot maintenance.
Per-file staging maxima are checked, but shared node temporary-disk admission
remains unfinished and is not certified by these focused tests.

Proof and status observations do not create permanent mutation identities or
consume the custody mutation budget. Their exact source/reference/revision and
custody policy epoch are recorded in the separately keyed durable node security
audit. That writer retains its own explicit operational capacity and fails closed
if it cannot persist; its configured capacity can be raised through its installed
lifecycle without municipal key access. Both read and mutation release repeat the
existing quorum barrier after audit completion, then enforce the original live
credential and current policy fence. A stalled audit cannot release authority
from a now-isolated old leader. Closed snapshots enforce their installed transfer byte budget. Bounded storage reads
reject excessive ciphertext before plaintext allocation, and sequential control
recovery has finite identity/header work budgets.

Closed proof release requires the same existing source quorum, including a fresh
current-term quorum barrier. A retained old leader or snapshot-only learner cannot
substitute local state for that authority. Service work retains its byte reservation
and shutdown registration through actual completion even if a caller disappears.
Key access, live credential, current Admin and policy epoch are checked through
final native encoding; no wire-decoded observation can construct a private proof.

A nonretired `Stopped` outcome continues to require ordinary source serving and
current administrative authority for fresh proof recovery. It cannot enter closed
retired custody or authorize payload materialization after a serving lease expires.
A successful `Retired` outcome alone enters the closed route. Independently
available serving leases, unavailable-source fencing and cross-host target
activation remain required; this tranche creates none of those authorities.

## Verification scope

The current tranche adds actual encrypted source/restart, revoked application-key
and credential-unavailable native startup, secure pinned-mTLS SDK rotation,
three-voter quorum isolation, deterministic capacity and same-position snapshot
substitution tests. [The final source-bound receipt](evidence/custody-rotation-20260907-b/verification.json)
records 319 passing tests, two ignored opt-in external-provider tests and all strict
gates passing against 152 unchanged inputs. The earlier failed candidate remains
under `custody-rotation-20260907-a`; its results describe only its own inputs.
