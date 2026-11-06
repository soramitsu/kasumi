# Protected node observations

The data-node daemon serves `GET /health`, `GET /ready`, `GET /metrics`,
`GET /recovery/{operation_id}` and `POST /maintenance/compaction` on its private
administrative listener (loopback port 9445 in a fresh standalone install).
All five require TLS 1.3, an installed client certificate, and a current Control
administrator bearer credential. Application administrator credentials cannot
scrape these routes. There is no anonymous health endpoint.

`/health`, `/ready`, and exact recovery status return JSON; `/metrics` returns
Prometheus text. Responses are at most 1 MiB and carry `Cache-Control: no-store`.
Each request uses one pre-reserved observation workspace (see *Admission* below)
and retains its original credential deadline and Control policy fence through
encoding and release. Renewal cannot extend that deadline. A revocation, policy
change, lifecycle transition, or closure of an observed store can withhold the
whole result. For `/health` and `/ready`, membership changes, expiry or
invalidation of the original readiness coverage, and persistent-disk admission
ceasing to be ready also withhold the result. `/metrics` is a point sample: it
reports those readiness inputs as gauges and is not withheld when they change
between observation and release. Authentication and authorization failures are
audited.

Failure responses carry no node state. A caller without a client certificate or
a valid bearer, and every 401 other than the one below, gets the generic text
body `protected node observation unavailable`. A 401 caused by the bearer
credential's own expiry (its signature verified, its `exp` passed) carries
`WWW-Authenticate: Bearer error="invalid_token", error_description="the access token expired"`
and the JSON body `{"error":"credential_expired","detail":"the access token expired"}`;
expiry is not secret, since the caller holds the token. Any other failure for an
authenticated caller is JSON naming one coarse reason class,
`{"error":"protected node observation unavailable","reason":"<class>"}`:

| `reason` | Status | Meaning |
| --- | --- | --- |
| `admission` | 503 | No observation workspace: the dedicated slot was busy for 2 s and the shared pool refused too. |
| `control_quorum` | 503 | Control authorization, its quorum barrier, response fence or membership epoch is unavailable. |
| `audit_unavailable` | 503 | The durable service audit store refused the request's record or became inaccessible. |
| `store_closed` | 503 | A store observed as available closed before the result was released. |
| `coverage_stale` | 503 | `/health` or `/ready` coverage changed or expired before release. |
| `disk_unready` | 503 | `/health` or `/ready` persistent-disk admission stopped being ready before release. |
| `lifecycle` | 503 | The node left the serving state the result described. |
| `forbidden` | 403 | The credential is not a current Control administrator. |
| `invalid_request` | 400 | Recovery status only: the path is not a canonical UUID. |
| `not_found` | 404 | Recovery status only: no such durable operation. |
| `response_limit` | 503 | The encoded result exceeds 1 MiB. |
| `unclassified` | 503 | Anything else. |

`/health` reports whether startup completed and the daemon is serving. `/ready`
additionally requires an accessible service audit store without persistence
failure, usable unpressured node admission, ready persistent-disk admission, no
pending standalone recovery, and complete, fresh coverage of every locally
hosted group at the current membership epoch. A completed probe reporting a
negative group state, unavailable quorum, or expired HA serving lease updates
diagnostics without by itself making the node unready. The healthy-group count
is diagnostic. `/ready` returns 503 when coverage or the node's own service
conditions do not hold. A listening socket or remembered leader alone does not
establish readiness. Draining begins before listeners and workers stop.

`GET /recovery/{operation_id}` takes a canonical hyphenated UUID and returns only
the exact durable Control operation's
UUID, phase, updated revision, pending-phase flag, and terminal flag. It is a
point-addressed read, not an enumeration or phase-count metric. With an
available three-voter Control quorum, a valid but unknown UUID returns 404
(`not_found`). An invalid UUID returns 400 (`invalid_request`) after
authorization; unavailable quorum or release authority returns 503
(`control_quorum`). The result is the verified
phase at its reported revision and may be superseded by a later transition.
The route does not reveal the recovery request, target placement, or dispatch
inputs. The protected 1 MiB response limit and original release checks apply.

Control administrator authorization itself requires a current Control quorum
barrier. If that cannot be established, all protected endpoints return 503
(`control_quorum`); they do not release counters using an old policy. On HA
nodes this means a Control follower cannot serve these protected observations
until it can satisfy that administrative authorization. Treat a failed scrape as
unavailable monitoring, not as zero load or an empty database, and use its
`reason` to decide whether the node itself is in trouble.

*Admission.* When the administration manager starts it reserves one observation
slot of 4 MiB from node admission and keeps it as a resident charge. A scrape
holds that slot instead of reserving from the shared request pool, so neither
memory pressure (the RSS high-water) nor exhausted operation slots or bytes can
refuse it. A second concurrent observation tries the shared pool as before and
otherwise waits up to 2 s for the slot, then returns 503 (`admission`). Each
observation is bounded by the 1 MiB response limit, so one slot bounds the
permanent charge. The authentication record that every protected request
writes to the service audit store is part of the protected boundary and still
needs storage admission: a full disk or RSS pressure that refuses that write
returns 503 (`audit_unavailable`). A scrape never waits on a database's
maintenance: storage figures are copies the node workers publish (below).

A retained background worker probes every locally assigned group, including
Control, sequentially with a one-second diagnostic deadline per group. There is
no group-count cutoff. A negative local-state probe retains the actual installed
runtime handle; a missing handle makes coverage unavailable and cannot produce a
fabricated completed probe. The worker retains one separately admitted Control topology document and
one selected group at a time. Its fixed coverage metadata is charged to node
admission; the document and bounded probe workspace have a separate lifetime
charge. The existing serving task inventory owns and joins the worker during
drain. Individual probes are awaited inline and do not spawn detached tasks. One fixed
probe slot holds the actual Raft query and a separate 128 KiB admission charge.
After a diagnostic timeout the cache becomes unavailable and the same query stays
in that slot; a successor cannot add another message behind a stalled actor.
Serving stop transfers observation to drain without dropping the query. The
runtime first drains the selected tenant and Control Raft cores, then observes
the retained query and releases its charge. A caught panic or fatal probe error
keeps its original payload and charge until that shutdown boundary.

A complete sweep is fresh for at most 30 seconds measured from its first probe.
HA serving-lease expiry does not clip that coverage deadline. A sweep taking
longer than 30 seconds cannot establish readiness. The previous complete sweep
remains available during a refresh at the same membership epoch, including
completed negative group probes. Unavailable observations, diagnostic timeouts,
fatal probe failures, and membership changes invalidate coverage. Partial,
stale, unavailable, or membership-invalidated coverage never establishes
readiness. A later sweep or lease renewal cannot extend an already encoded
response's original deadline.

The membership epoch covers the Control topology document, installed route
mutations, and actual Raft effective membership changes. A synchronous observer in
OpenRaft invalidates it before membership append, commit, truncation, and snapshot
changes, including changes not yet published in Control. After each quorum
barrier, an actor-ordered membership observation checks that membership is applied,
nonjoint, contains this node, and agrees with the tenant's committed voters.
The quorum and membership-check results describe group health; a completed
negative result does not by itself invalidate fresh current-epoch coverage.
Release checks the original epoch and coverage token in constant time without a
whole-topology scan or a lagging metrics watch.

Each sweep records its roster: Control and every locally hosted group of the
committed topology, at most 128 (the detail limit; it does not limit readiness
coverage). The roster and each rostered group's newest completed probe survive
coverage invalidation and are replaced only by the next sweep's enumeration, so
every scrape lists every configured group whatever state coverage, stores or
maintenance are in. Scrapes obtain fresh storage, capacity, retention and
serving-authority details for the rostered groups. A group whose store is
closed or unavailable reports `store_available` 0 and the figures last observed
from its store (same incarnation) in this process, with
`figures_age_seconds` (`kasumi_local_group_figures_age_seconds`, 0 when this
sample observed them); a group never observed reports them as unknown. Quorum is
the group's newest completed probe, with `probe_age_seconds`. JSON's
`readiness_coverage` reports expected, examined and healthy group counts,
completeness, freshness, the age of the oldest probe, and the detail limit.
These are bounded local samples, not a distributed snapshot or an authorization
lease. The Control authorization barrier retains its separate five-second
ceiling. Scrapes do not serialize tenant data. The pending-standalone-recovery
flag is read by the readiness worker after each sweep, not by the scrape.

Available metrics include:

- `kasumi_ready`, lifecycle, `kasumi_readiness_coverage_complete`,
  `kasumi_readiness_coverage_fresh`, `kasumi_readiness_groups_expected`,
  `kasumi_readiness_groups_examined`, `kasumi_readiness_groups_healthy`,
  `kasumi_readiness_oldest_probe_age_seconds`, `kasumi_local_group_detail_limit`,
  and `kasumi_local_group_details`. Per group, `kasumi_local_group_quorum` is the
  newest completed probe and `kasumi_local_group_probe_age_seconds` its age.
  Replicated nodes export `kasumi_local_group_authority_remaining_seconds` for
  every group; it is known only where an admitted HA lease of an available
  store supplies it.
- Node admission reservations and operations, the effective (resolved) memory
  high-water `kasumi_admission_high_water_bytes`, the low mark, sample
  usability, and RSS/pressure. `kasumi_admission_memory_used_bytes` is resident
  memory plus reserved bytes, the sum admission compares with the high-water, and
  `kasumi_admission_memory_headroom_bytes` is the high-water less that use: an
  operation of `n` bytes is admitted only while use plus `n` stays below the
  high-water (and the sample is usable and unpressured). JSON reports the same as
  `memory_admission`. Use, RSS and pressure are unknown while the memory sample is
  unusable; do not interpret an unusable sample as current memory use.
- Service-audit hot/archive bytes and budgets, sequence and pruning positions,
  segment count, draining state, persistence failure, maintenance failures, and
  policy-due archive backlog bytes. Archives shrink only when an operator
  prunes exported segments ([`kasumid audit prune`](standalone.md#pruning-exported-archives)),
  so alert before `kasumi_service_audit_archive_bytes` reaches
  `kasumi_service_audit_archive_budget_bytes`: a full archive stops the hot log
  from draining, and a full hot log fails every request that needs a record
  with `audit_unavailable`. If online export or pruning already fails, stop the
  daemon and use the [offline service-audit recovery commands](standalone.md#recovering-a-node-whose-audit-refuses-records)
  to export and prune before restarting.
- Per-group tenant-audit hot/archive bytes and budgets, sequence/pruning positions,
  segment counts, draining state, policy-due archive backlog bytes, and
  archive-worker failure/committed-segment counters where the original store
  remains available and an automatic worker was installed.
- Per-group logical document bytes/counts and configured logical/snapshot disk
  budgets. These are not measurements of filesystem free space or physical file
  allocation. Audit bytes above the 50% drain target describe retained volume,
  not a count of scheduled or running maintenance jobs. Archive backlog bytes
  are hot bytes above that target only when policy has reached the 75% start
  threshold or is continuing a drain. They are not a worker queue length.
- The scraping credential's verified absolute expiry timestamp. No token,
  credential-family identity, key reference, document, or raw provider error is a
  metric label or JSON diagnostic field.
- Per-process native backup request inflight counts and returned-ok,
  returned-denied, returned-error, and cancelled counters, separated by create,
  verify, status, abort, and cleanup. These count adapter invocations, not durable
  backup outcomes. An error or cancellation may follow committed work; resolve the
  original session with `kasumid backup status`. Counters reset with the process
  and do not measure workers that continue after their request is cancelled.
- A point-addressed pending-recovery observation for standalone installations.
  Pending stopped-instance recovery prevents normal startup; this does not attest
  that another independent source copy or any distributed source is fenced.

Health and readiness JSON include
`admission.resident_reserved_bytes_by_origin`, whose six fixed counters sum to
`admission.resident_reserved_bytes` in the same locked ledger sample.
`ordinary_operation` counts retained operation grants; `other_ordinary` counts
other resident grants, including native installed work; `audit_maintenance`
counts maintenance grants; `scoped_application_source` counts source grants
acquired in maintenance scope; `native_cache` counts native cache grants; and
`document_source` counts selected-source metadata and logical document backing.
Active operations and bookkeeping are excluded. These values measure reserved
capacity, including unused headroom, rather than RSS, decoded data size, or actual
cache occupancy. A grant keeps its original category when retained or resized
and leaves the counters when released. The breakdown is JSON-only.

A 200 response always carries every family, and every per-group family for
every rostered group. Unknown values are `NaN` in Prometheus, so the series
stays present, and `null` in JSON: a filesystem or memory sample that failed, a
group never observed in this process, a store whose node worker has not
published yet. Tenant archive-worker counters are local to the current database
instance and reset on restart or replacement; they are unknown (`NaN`/`null`)
for a store without an installed worker. The per-group detail limit remains 128,
so these tenant fields are not whole-node totals above that count. Within a
response every family is one contiguous group introduced by its `# TYPE` line. Durable backup-session totals, authority
daemon metrics, distributed recovery-coordinator phases, and peer-maintenance
counters are not yet instrumented here. Their absence is not a zero value.

Example local scrape using Prometheus's documented
[authorization and TLS settings](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#http_config):

```yaml
scrape_configs:
  - job_name: kasumi
    scheme: https
    metrics_path: /metrics
    scrape_interval: 30s
    scrape_timeout: 12s
    follow_redirects: false
    proxy_from_environment: false
    static_configs:
      - targets: [localhost:9445]
    authorization:
      type: Bearer
      credentials_file: /var/lib/kasumi/profiles/control.token
    tls_config:
      ca_file: /var/lib/kasumi/tls/ca.pem
      cert_file: /var/lib/kasumi/profiles/control-client.pem
      key_file: /var/lib/kasumi/profiles/control-client-key.pem
      server_name: localhost
      min_version: TLS13
      max_version: TLS13
```

The scraper must run under an operator-controlled identity permitted to read these
private files. Keep the selected profile's credential watcher running and update
the scraper's trust and certificate files during explicit rotation. A dedicated
credential family can be revoked independently, but it still requires current
Control administrator policy. A copied profile does not renew itself.

Both `kasumid` and `kasumi-authority` install JSON diagnostics on stderr. Command
results remain on stdout. Production logging includes `kasumi_server` operational
events at INFO and above and `kasumi_engine`, `kasumi_raft` and `kasumi_store`
events at WARN and above. It suppresses span fields, and disables dependency and
DEBUG/TRACE events that can contain command bodies. Kasumi crates log only fixed
labels and drain component names at WARN, never error chains. OpenRaft stays
disabled because its fatal and storage errors format arbitrary error chains; its
failures appear through the fixed classes below. `RUST_LOG` does not expand
this logging policy. Provider errors are represented by static operational events;
use the protected audit/maintenance interfaces for exact outcomes. Persist and
rotate daemon logs using the host's service manager.

The serving reconciliation loop checks for control-plane closure every 250 ms
and runs a pass every 250 ms while passes succeed. After a pass fails, the
loop waits 0.5 s, 1 s, 2 s, 4 s and then 5 s before each next pass, and the
first clean pass resets the wait. It logs an unavailability when it starts
(`serving_reconciliation_unavailable`), when the failing steps change, every
ten minutes while it lasts (`serving_reconciliation_still_unavailable`) and
when it ends (`serving_reconciliation_recovered`), with the count of failed
passes and the first and last failure. It does not log every failed pass.
The readiness probe still sweeps every second, and logs its failures the same
way: `readiness_probe_failed` when sweeps start failing or their classes
change, `readiness_probe_still_failing` every ten minutes, and
`readiness_probe_recovered` at the next complete sweep. A sweep cut short by
shutdown is not counted.

An installed original tenant whose serving instance closes is drained and then
freshly admitted by the next reconciliation pass. A fresh admission that fails
is retried on the loop's backoff. Only an owner whose drain is
`Retained` keeps the tenant closed. A drain that completed with recorded issues
is still complete. Its issues are logged once as component names, and the stale
generation leaves the registry. While fresh admission is pending, a live
credential bound to that exact incarnation receives `Unavailable` (retry the
same request). Unknown tenants and other credentials still receive `Forbidden`.

The node control plane has no such in-process fresh admission. When it closes
(any `closure_cause` below other than `shutting_down`), the reconciliation loop
logs `control_plane_closed` at ERROR and the daemon drains and exits non-zero,
so its service manager reopens it (`deploy/kasumi.service` restarts on
failure). Run every `kasumid serve` under a restarting supervisor: a daemon that
stays down outlives its issued credentials. Their watchers recover them online
for 24 hours after they expire; after that, they need
`recover-existing-credentials`.

Key-access leases are measured on a clock that keeps running while the host
is suspended. A host that sleeps longer than a lease's remaining 40 to 60
seconds wakes with every store sealed, so the control plane closes with
`closure_cause` `key_lease_sealed` and `key_lease_class` `lease_expired`, and
the daemon exits for its supervisor to reopen it. Do not let a host that runs
`kasumid` sleep, including a laptop with its lid closed.

Each event carries only fixed classes:

| `event` | Fields |
| --- | --- |
| `original_tenant_closed` | `closure_cause`: `shutting_down`, `proposal_work_closed`, `key_lease_sealed`, `snapshot_buffer_failed`, `ownership_lost`, `raft_core_failed`, `state_machine_failed`, `engine_sealed`, `target_activation_incomplete`, `restore_preparation`, `unclassified`; `key_lease_class`: `provider_error`, `provider_timeout`, `completed_after_expiry`, `generation_changed`, `access_revoked`, `refresh_admission`, `lease_expired`, `none` |
| `original_tenant_drain_completed_with_issues` | `components`: drain component names |
| `original_tenant_recovery_failed` (message `original tenant remains closed pending fresh admission`) | `recover_stage`: `enrollment_mismatch`, `previous_lease_retained`, `previous_detach`, `previous_shutdown_retained`, `custody_open`, `access_lease`, `key_provider`, `storage_open`, `admission_reserve`, `engine_open`, `route_register`, `setup_route_changed`, `publish`, `initialize`, `unclassified`; `closure_cause` |
| `original_tenant_reopened` | `closure_cause`, `key_lease_class`, `drained_with_issues`, `failed_attempts` |
| `control_plane_closed` (ERROR, message `control plane closed; daemon stopping for restart`) | `closure_cause` (as for `original_tenant_closed`), `key_lease_class` |
| `serving_reconciliation_unavailable` (WARN, message `serving reconciliation unavailable; will retry`) | `failed_steps`: `management_gate`, `retired_generations`, `control_topology`, `original_recovery`, `generation_registry`, `route_install`, `unclassified`; `failure_classes`: the typed cause classes `daemon_failed` reports (for example `key_access_denied`, `sealed`, `resource_exhausted`, `io_storage_full`), the `recover_stage` of a failed fresh admission, or `unclassified`; `failed_passes`; `retry_after_ms` |
| `serving_reconciliation_still_unavailable` (WARN) | `failed_steps`, `failure_classes` seen since the previous report, `failed_passes`, `first_failure`, `last_failure` (RFC 3339 UTC). Also logged once when the loop stops during an unavailability |
| `serving_reconciliation_recovered` (INFO) | `failed_steps`, `failed_passes`, `first_failure`, `last_failure` |
| `readiness_probe_failed` (WARN, message `complete readiness coverage unavailable`) | `readiness_error_class`: `control_unavailable`, `epoch_unavailable`, `epoch_changed`, `admission_reserve`, `memory_pressure`, `route_invalid`, `generation_unavailable`, `probe_admission`, `actor_probe_failed`, `probe_deadline`, `unclassified`; `control_closure_cause`: a `closure_cause`, or `none`; `failed_sweeps` |
| `readiness_probe_still_failing` (WARN) | `readiness_error_class`, `control_closure_cause`, `failed_sweeps`, `first_failure`, `last_failure` (RFC 3339 UTC). Also logged once when the probe stops during a failure |
| `readiness_probe_recovered` (INFO) | the last failure's `readiness_error_class` and `control_closure_cause`, `failed_sweeps`, `first_failure`, `last_failure` |

A consensus write that commits and then loses group access before its result
is released returns `UnknownOutcome`. It no longer fails the proposal child, so
it does not close the proposal registry. The lost access still closes the tenant
through its own gate. Daemon shutdown does not report a failure again when a
superseded owner's complete drain was already logged.

Persistent and scratch storage observations are available only through the same
protected routes. They are node-wide and exported once, without a tenant label.
Health JSON includes `persistent_disk`, with its owner phase,
charged extents, pending growth, file counts, maintenance reserve, current
filesystem observation, `capacity_refusals` and `last_capacity_refusal`.
Prometheus exposes `kasumi_persistent_disk_admission_ready`,
`kasumi_persistent_disk_max_bytes`, `kasumi_persistent_disk_maintenance_reserve_bytes`,
`kasumi_persistent_disk_charged_bytes`, `kasumi_persistent_disk_pending_bytes`
(this owner's promises on all its filesystems),
`kasumi_persistent_disk_files`, `kasumi_persistent_disk_open_files`,
`kasumi_persistent_disk_filesystem_pending_bytes` (every owner's promises on the
filesystem), `kasumi_persistent_disk_filesystem_min_free_bytes`,
`kasumi_persistent_disk_filesystem_available_bytes` (the `f_bavail` sample),
`kasumi_persistent_disk_headroom_bytes` and
`kasumi_persistent_disk_filesystem_device`, plus the
`kasumi_persistent_disk_filesystem_total_bytes` and
`kasumi_persistent_disk_filesystem_used_bytes` physical-utilization samples.
Total counts all filesystem blocks and used counts blocks not free according to
`fstatvfs`; these values include other processes and are not node-owned charges.

Each persistent root is on one filesystem, and each filesystem keeps its own
promises and `min_free_bytes` floor; the extent budget and namespace limits stay
one owner total. The unlabelled `kasumi_persistent_disk_filesystem_*` gauges,
`kasumi_persistent_disk_headroom_bytes` and the scalar JSON `filesystem_*`
fields describe the filesystem with the least headroom, whose device number is
`kasumi_persistent_disk_filesystem_device` (JSON `filesystem_device`). Every
filesystem holding a root also has its own series, labelled
`{filesystem="<device>"}`: `kasumi_persistent_filesystem_available_bytes`,
`kasumi_persistent_filesystem_pending_bytes` (every owner's promises on it),
`kasumi_persistent_filesystem_owner_pending_bytes` (this owner's),
`kasumi_persistent_filesystem_min_free_bytes`,
`kasumi_persistent_filesystem_headroom_bytes` and
`kasumi_persistent_filesystem_admission_ready`. A node with one filesystem
exports one series of each. When the roots span several filesystems, health
JSON adds `persistent_disk.filesystems`, one entry per filesystem with its
device, its root labels (which map device numbers to roots), pending bytes (all
owners and this owner), floor, available bytes, `headroom_bytes`, total and used
bytes and admission readiness.

Headroom is exactly the margin the floor check compares a reservation in one of
that filesystem's roots with, from one locked sample of its three inputs:
available less pending less min-free. A reservation of `n` bytes passes the
floor exactly when `n` is at most its filesystem's headroom; headroom is
negative once the floor is overdrawn. Readiness requires an open owner, usable
admission on every filesystem and sufficient sampled free space on the tightest
one for its pending growth and minimum-free reservation, so it covers every
filesystem. Its response fence rechecks that requirement immediately before
releasing a ready observation.

Every persistent capacity refusal names the check that refused and the figures
it compared; nothing identifies a path, tenant or key. The checks are
`persistent_directory_entries` (children of the transaction's directory,
counting other batches' reserved children, against the directory policy),
`persistent_files` (`max_persistent_files`), `persistent_open_files`
(`max_open_files`, counting reserved descriptors), `persistent_extent` (charged
extents against `max_bytes`, foreground work leaving the maintenance reserve)
and `persistent_filesystem_floor`, which is per filesystem: its refusal names
the device of the filesystem whose floor refused (`filesystem`). The counter
`kasumi_persistent_disk_capacity_refusals_total{check="..."}` counts each since
the owner opened; `last_capacity_refusal` in JSON holds the latest refusal's
`requested`, `in_use` and `limit` (for the floor: available, pending, `min_free`
and `filesystem`). A refused segment-transaction reservation also logs the check
and figures on stderr, for example
`Kasumi transaction reserve failed: stage=disk_space_reservation io=StorageFull check=persistent_filesystem_floor filesystem=2049 requested=67133440 available=7516192768 pending=7381975040 min_free=268435456 headroom=-134217728`,
and a refused growth during a transaction write logs the owner's latest refusal
as `last_refusal: check=...`. The scratch owner does the same for
`scratch_extent`, `scratch_files` and `scratch_filesystem_floor` on its single
filesystem
(`Kasumi scratch transaction reserve failed: ... check=scratch_filesystem_floor ...`).

Health JSON includes `scratch_disk`, including its configured per-table
`native_cache_bytes` ceiling, `capacity_refusals` and `last_capacity_refusal`;
Prometheus exposes
`kasumi_scratch_disk_max_bytes`, `kasumi_scratch_disk_min_free_bytes` (its
configured floor), `kasumi_scratch_disk_native_cache_bytes`,
`kasumi_scratch_disk_charged_bytes`, `kasumi_scratch_disk_live_files`,
`kasumi_scratch_disk_filesystem_pending_bytes`,
`kasumi_scratch_disk_filesystem_min_free_bytes` (the floor its checks keep: the
largest of every owner's on that filesystem),
`kasumi_scratch_disk_filesystem_available_bytes`,
`kasumi_scratch_disk_headroom_bytes` (the scratch floor check's margin, as for
the persistent disk), `kasumi_scratch_disk_capacity_refusals_total{check="..."}`,
plus the `kasumi_scratch_disk_filesystem_total_bytes` and
`kasumi_scratch_disk_filesystem_used_bytes` physical-utilization samples. If
persistent and scratch directories share a filesystem, these samples overlap
and must not be summed. Charged bytes include
rounded encrypted spool extents and staging tables retained by active images or
workers. Filesystem pending bytes include promises by persistent and scratch
owners on the same filesystem in this process; their installed extent limits
remain separate.

Storage maintenance is reported per node database (`node.kv`): the node's
shared database once, and, for a group served from a standalone generation's own
database, that database under the group. Health JSON has a top-level `storage`
object for the shared database; each group has `storage_dedicated` and, when it
is true, its own `storage` object (`null` otherwise). Each node database's
worker runs one bounded maintenance step per iteration and then copies the
database's status, which the database's maintenance owner publishes at the end
of every step (including the inline steps writes run), policy change and
compaction request. Reading the status never enters the database's state lock,
and scrapes read the worker's copy, so an observation never waits for a running
step, a commit or their I/O. `status_age_seconds` is the age of that copy; it
grows only if the worker stops. `measured` reports whether the last completed
census of the retained segment (`.kvseg`) and directory arena (`.kvdir`) files
is still current: a compaction cycle clears it until it measures again.
`segment_files`, `segment_bytes`, `arena_files` and `arena_bytes` are that
census's result, kept with `census_age_seconds` while a cycle runs (`null`
before the first census in this process lifetime), and can lag files created
since. `garbage_files` counts files recorded for unlink. `compaction_phase` is
`idle`, `evacuating`, `reclaiming` or `packing`, with `compaction_cycle`,
`compaction_requested`, the baseline measured when the last cycle finished
reclaiming (`compaction_baseline_bytes`/`_files`) and the thresholds that begin
the next one (`compaction_trigger_bytes`/`_files`). `snapshot_retained_files`
and `snapshot_retained_bytes` are old files the last completed reclamation kept
only for pinned snapshots. The `_total` fields count reclaimed files and bytes,
relocated value bytes, invalidated reclamation cohorts and capacity or rejected
maintenance deferrals since the store opened; `last_deferral` is `capacity` or
`rejected` while maintenance is backing off.

Prometheus exposes the shared database as `kasumi_storage_*` without a tenant
label, and a dedicated database as `kasumi_local_group_storage_*` labeled
`{tenant="..."}`; `kasumi_local_group_storage_dedicated{tenant="..."}` (1 or 0)
says which applies to each group. Node-wide figures are never repeated under
tenant labels. The families are `measured`, `segment_files`, `segment_bytes`,
`arena_files`, `arena_bytes`, `census_age_seconds`, `status_age_seconds`,
`garbage_files`, `compaction_phase{phase="..."}` (1 for the current phase, 0 for
the other three), `compaction_cycle`, `compaction_requested`,
`compaction_baseline_bytes`, `compaction_trigger_bytes`,
`snapshot_retained_files`, `snapshot_retained_bytes`,
`evacuation_surveyed_segments`, `evacuation_kept_segments`,
`evacuation_kept_garbage_bytes`, `deferred{class="capacity"|"rejected"}` (1 while
the last step deferred with that class), and the counters
`reclaimed_files_total`, `reclaimed_bytes_total`, `relocated_bytes_total`,
`evacuation_survey_fallbacks_total`, `reclaim_invalidations_total` and
`maintenance_deferrals_total{class="capacity"|"rejected"}`. Counters restart
from zero when the store reopens. Retained bytes normally oscillate between the
baseline and the trigger; growth past the trigger while the phase stays
`evacuating` and capacity deferrals rise means the volume lacks the headroom a
cycle needs to copy before it can free files (compare
`kasumi_persistent_disk_headroom_bytes`). These are node-local file
observations; the `kasumi_persistent_disk_*` gauges still report the node-wide
charged extents.

`POST /maintenance/compaction` asks every node database this runtime owns (the
shared one and each active standalone generation's) to begin a compaction
cycle at its next maintenance step, below the growth thresholds, and clears a
capacity or rejected deferral's backoff (the rejected backoff otherwise lasts
65,536 steps, hours, until a restart). A database that has nothing older than
its newest files starts no cycle. The route has the same mTLS and Control
administrator boundary as `/metrics`, ignores its request body, and is audited
as an `administration` security event (`started`, then `succeeded`, or `failed`
when a database refused). The JSON response lists each database (`node` for the
shared one, else the tenant whose generation owns it) and whether it accepted:
`{"accepted":1,"refused":0,"databases":[{"database":"node","accepted":true}]}`.
A database refuses when it is closed or its owner failed.

Each available tenant's protected capacity observation includes exact retained
`schema_activation_bytes` and `retirement_bytes` and their configurable byte
budgets. Prometheus exposes the same fields as
`kasumi_local_group_schema_activation_bytes`,
`kasumi_local_group_schema_activation_budget_bytes`,
`kasumi_local_group_retirement_bytes`, and
`kasumi_local_group_retirement_budget_bytes`, labeled by tenant. These are
permanent key/value accounting charges, not physical storage size or free RAM.
New identities also need bounded error-outcome admission headroom; increasing a
permanent budget does not waive snapshot, node memory, disk or audit admission.
