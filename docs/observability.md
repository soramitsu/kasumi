# Protected node observations

The data-node daemon serves `GET /health`, `GET /ready`, `GET /metrics`, and
`GET /recovery/{operation_id}` on its private administrative listener (loopback
port 9445 in a fresh standalone install).
All four require TLS 1.3, an installed client certificate, and a current Control
administrator bearer credential. Application administrator credentials cannot
scrape these routes. There is no anonymous health endpoint.

`/health`, `/ready`, and exact recovery status return JSON; `/metrics` returns
Prometheus text. Responses are at most 1 MiB and carry `Cache-Control: no-store`. Each request reserves bounded
node workspace and retains its original credential deadline and Control policy
fence through encoding and release. Renewal cannot extend that deadline. A
revocation, policy change, lifecycle transition, or closure of an observed store
can withhold the whole result. For `/health`, `/ready`, and `/metrics`,
membership changes or expiry/invalidation of the original readiness coverage
also withhold the result. Authentication and authorization failures are audited. Failure responses contain no diagnostic state.

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
available three-voter Control quorum, a valid but unknown UUID returns a generic
404. An invalid UUID returns a generic 400 after authorization; unavailable
quorum or release authority returns 503. The result is the verified
phase at its reported revision and may be superseded by a later transition.
The route does not reveal the recovery request, target placement, or dispatch
inputs. The protected 1 MiB response limit and original release checks apply.

Control administrator authorization itself requires a current Control quorum
barrier. If that cannot be established, all protected endpoints return a generic
503; they do not release counters using an old policy. On HA nodes this means a
Control
follower cannot serve these protected observations until it can satisfy that
administrative authorization. Treat a failed scrape as unavailable monitoring,
not as zero load or an empty database. Admission pressure can likewise prevent a
scrape from reserving its workspace and return 503.

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

Scrapes consume this cache and obtain fresh storage, capacity, retention and
serving-authority details for at most 128 groups. The diagnostic limit does not
limit readiness coverage. JSON's `readiness_coverage` reports expected, examined
and healthy group counts, completeness, freshness, the age of the oldest probe,
and the detail limit. Quorum details from partial or stale sweeps are unavailable;
their remembered identities can still supply fresh storage diagnostics. These
are bounded local samples, not a distributed snapshot or an authorization lease.
The Control authorization barrier retains its separate five-second ceiling.
Scrapes do not serialize tenant data.

Available metrics include:

- `kasumi_ready`, lifecycle, `kasumi_readiness_coverage_complete`,
  `kasumi_readiness_coverage_fresh`, `kasumi_readiness_groups_expected`,
  `kasumi_readiness_groups_examined`, `kasumi_readiness_groups_healthy`,
  `kasumi_readiness_oldest_probe_age_seconds`, `kasumi_local_group_detail_limit`,
  and `kasumi_local_group_details`. Per-group quorum values describe fresh cached
  probes; serving-authority remaining seconds appear only where an admitted HA
  lease supplies them.
- Node admission reservations and operations, configured high/low memory marks,
  sample usability, and RSS/pressure when the memory sample is usable. JSON keeps
  the `sample_usable` flag alongside the last sample; do not interpret an unusable
  sample as current memory use.
- Service-audit hot/archive bytes and budgets, sequence and pruning positions,
  segment count, draining state, persistence failure, maintenance failures, and
  policy-due archive backlog bytes.
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

Unavailable values are omitted from Prometheus and represented as `null` in JSON.
Tenant archive-worker counters are local to the current database instance and reset
on restart or replacement. A live store can have due backlog without an installed
worker; its worker counters are then `null` in JSON and absent from Prometheus.
The per-group detail limit remains 128, so these tenant fields are not
whole-node totals above that count. Durable backup-session totals, authority
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
      cert_file: /var/lib/kasumi/profiles/client.pem
      key_file: /var/lib/kasumi/profiles/client-key.pem
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

An installed original tenant whose serving instance closes is drained and then
freshly admitted by the 250 ms reconciliation loop. Only an owner whose drain is
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
stays down outlives its issued credentials, which then need
`recover-existing-credentials`.
Each event carries only fixed classes:

| `event` | Fields |
| --- | --- |
| `original_tenant_closed` | `closure_cause`: `shutting_down`, `proposal_work_closed`, `key_lease_sealed`, `snapshot_buffer_failed`, `ownership_lost`, `raft_core_failed`, `state_machine_failed`, `engine_sealed`, `target_activation_incomplete`, `restore_preparation`, `unclassified`; `key_lease_class`: `provider_error`, `provider_timeout`, `completed_after_expiry`, `generation_changed`, `access_revoked`, `refresh_admission`, `lease_expired`, `none` |
| `original_tenant_drain_completed_with_issues` | `components`: drain component names |
| `original_tenant_recovery_failed` (message `original tenant remains closed pending fresh admission`) | `recover_stage`: `enrollment_mismatch`, `previous_lease_retained`, `previous_detach`, `previous_shutdown_retained`, `custody_open`, `access_lease`, `key_provider`, `storage_open`, `admission_reserve`, `engine_open`, `route_register`, `setup_route_changed`, `publish`, `initialize`, `unclassified`; `closure_cause` |
| `original_tenant_reopened` | `closure_cause`, `key_lease_class`, `drained_with_issues`, `failed_attempts` |
| `control_plane_closed` (ERROR, message `control plane closed; daemon stopping for restart`) | `closure_cause` (as for `original_tenant_closed`), `key_lease_class` |
| `readiness_probe_failed` | `readiness_error_class`: `control_unavailable`, `epoch_unavailable`, `epoch_changed`, `stopped`, `admission_reserve`, `memory_pressure`, `route_invalid`, `generation_unavailable`, `probe_admission`, `actor_probe_failed`, `probe_deadline`, `unclassified`; `control_closure_cause`: a `closure_cause`, or `none` |

A consensus write that commits and then loses group access before its result
is released returns `UnknownOutcome`. It no longer fails the proposal child, so
it does not close the proposal registry. The lost access still closes the tenant
through its own gate. Daemon shutdown does not report a failure again when a
superseded owner's complete drain was already logged.

Persistent and scratch storage observations are available only through the same
protected routes. Health JSON includes `persistent_disk`, with its owner phase,
charged extents, pending growth, file counts, maintenance reserve and current
filesystem observation. Prometheus exposes `kasumi_persistent_disk_admission_ready`,
`kasumi_persistent_disk_max_bytes`, `kasumi_persistent_disk_maintenance_reserve_bytes`,
`kasumi_persistent_disk_charged_bytes`, `kasumi_persistent_disk_pending_bytes`,
`kasumi_persistent_disk_files`, `kasumi_persistent_disk_open_files`,
`kasumi_persistent_disk_filesystem_pending_bytes`,
`kasumi_persistent_disk_filesystem_min_free_bytes`, and the optional fresh
`kasumi_persistent_disk_filesystem_available_bytes` sample, plus optional
`kasumi_persistent_disk_filesystem_total_bytes` and
`kasumi_persistent_disk_filesystem_used_bytes` physical-utilization samples.
Total counts all filesystem blocks and used counts blocks not free according to
`fstatvfs`; these values include other processes and are not node-owned charges.
Readiness requires an
open owner, usable filesystem admission and sufficient sampled free space for the
shared pending growth and minimum-free reservation. Its response fence rechecks
that requirement immediately before releasing a ready observation.

Health JSON includes `scratch_disk`, including its configured per-table
`native_cache_bytes` ceiling; Prometheus exposes
`kasumi_scratch_disk_max_bytes`, `kasumi_scratch_disk_min_free_bytes`,
`kasumi_scratch_disk_native_cache_bytes`,
`kasumi_scratch_disk_charged_bytes`, `kasumi_scratch_disk_live_files`,
`kasumi_scratch_disk_filesystem_pending_bytes`, and the optional fresh
`kasumi_scratch_disk_filesystem_available_bytes` sample, plus optional
`kasumi_scratch_disk_filesystem_total_bytes` and
`kasumi_scratch_disk_filesystem_used_bytes` physical-utilization samples. If
persistent and scratch directories share a filesystem, these samples overlap
and must not be summed. Charged bytes include
rounded encrypted spool extents and staging tables retained by active images or
workers. Filesystem pending bytes include promises by persistent and scratch
owners on the same filesystem in this process; their installed extent limits
remain separate.

Each available group's health entry includes a `storage` object describing its
`node.kv` group files and persisted maintenance cycle, or `null` when the
store is unavailable. `measured` reports whether a census of the retained
segment (`.kvseg`) and directory arena (`.kvdir`) files completed in the
current process lifetime; `segment_files`, `segment_bytes`, `arena_files` and
`arena_bytes` are that census's result (`null` before it completes) and can lag
files created since. `garbage_files` counts files recorded for unlink.
`compaction_phase` is `idle`, `evacuating`, `reclaiming` or `packing`, with
`compaction_cycle`, the baseline measured when the last cycle finished
reclaiming (`compaction_baseline_bytes`/`_files`) and the thresholds that begin
the next one (`compaction_trigger_bytes`/`_files`). `snapshot_retained_files`
and `snapshot_retained_bytes` are old files the last completed reclamation kept
only for pinned snapshots. The `_total` fields count reclaimed files and bytes,
relocated value bytes, invalidated reclamation cohorts and capacity or rejected
maintenance deferrals since the store opened; `last_deferral` is `capacity` or
`rejected` while maintenance is backing off.

Prometheus exposes the same per tenant, labeled `{tenant="..."}`:
`kasumi_local_group_storage_measured`, `kasumi_local_group_storage_segment_files`,
`kasumi_local_group_storage_segment_bytes`, `kasumi_local_group_storage_arena_files`
and `kasumi_local_group_storage_arena_bytes` (the last four only once measured),
`kasumi_local_group_storage_garbage_files`,
`kasumi_local_group_storage_compaction_phase{phase="..."}` (1 for the current
phase, 0 for the other three), `kasumi_local_group_storage_compaction_cycle`,
`kasumi_local_group_storage_compaction_baseline_bytes`,
`kasumi_local_group_storage_compaction_trigger_bytes`,
`kasumi_local_group_storage_snapshot_retained_bytes`, and the counters
`kasumi_local_group_storage_reclaimed_files_total`,
`kasumi_local_group_storage_reclaimed_bytes_total`,
`kasumi_local_group_storage_relocated_bytes_total`,
`kasumi_local_group_storage_reclaim_invalidations_total` and
`kasumi_local_group_storage_maintenance_deferrals_total{class="capacity"|"rejected"}`.
Counters restart from zero when the store reopens. Retained bytes normally
oscillate between the baseline and the trigger; growth past the trigger while
the phase stays `evacuating` and capacity deferrals rise means the volume lacks
the headroom a cycle needs to copy before it can free files. These are
node-local file observations; the `kasumi_persistent_disk_*` gauges still
report the node-wide charged extents.

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
