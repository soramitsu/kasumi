# Protected node observations

The data-node daemon serves `GET /health`, `GET /ready`, and `GET /metrics` on its
private administrative listener (loopback port 9445 in a fresh standalone install).
All three require TLS 1.3, an installed client certificate, and a current Control
administrator bearer credential. Application administrator credentials cannot
scrape these routes. There is no anonymous health endpoint.

`/health` and `/ready` return JSON; `/metrics` returns Prometheus text. Responses
are at most 1 MiB and carry `Cache-Control: no-store`. Each request reserves bounded
node workspace and retains its original credential deadline and Control policy
fence through encoding and release. Renewal cannot extend that deadline. A
revocation, policy change, lifecycle transition, or closure of an observed store
can withhold the whole result. Membership changes or expiry/invalidation of the
original readiness coverage also withhold the result. Authentication and authorization failures are
audited. Failure responses contain no diagnostic state.

`/health` reports whether startup completed and the daemon is serving. `/ready`
additionally requires an accessible service audit store, usable unpressured node
admission, complete, fresh coverage of every locally assigned group, fresh diagnostic
store/serving-authority observations, and a successful quorum barrier for each
group in the completed sweep. It returns 503
when these conditions do not hold. A listening socket or remembered leader alone
does not establish readiness. Draining begins before listeners and workers stop.

Control administrator authorization itself requires a current Control quorum
barrier. If that cannot be established, all three endpoints return a generic 503;
they do not release counters using an old policy. On HA nodes this means a Control
follower cannot serve these protected observations until it can satisfy that
administrative authorization. Treat a failed scrape as unavailable monitoring,
not as zero load or an empty database. Admission pressure can likewise prevent a
scrape from reserving its workspace and return 503.

A retained background worker probes every locally assigned group, including
Control, sequentially with a one-second diagnostic deadline per group. There is
no group-count cutoff. The worker retains one separately admitted Control topology document and
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

A complete sweep is fresh for at most 30 seconds measured from its first probe,
clipped by the earliest HA serving-lease expiry observed anywhere in the sweep.
A sweep taking longer than that cannot establish readiness. The previous complete
sweep remains available during a refresh at the same membership epoch; any newly
observed failure immediately invalidates it. Partial, stale, unavailable, or
membership-invalidated coverage never establishes readiness. A later sweep or
lease renewal cannot extend an already encoded response's original deadline.

The membership epoch covers the Control topology document, installed route
mutations, and actual Raft effective membership changes. A synchronous observer in
OpenRaft invalidates it before membership append, commit, truncation, and snapshot
changes, including changes not yet published in Control. After each quorum
barrier, an actor-ordered membership observation checks that membership is applied,
nonjoint, contains this node, and agrees with the tenant's committed voters.
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
  segment count, draining state, persistence failure, and maintenance failures.
- Per-group tenant-audit hot/archive bytes and budgets, sequence/pruning positions,
  segment counts, and draining state where the original store remains available.
- Per-group logical document bytes/counts and configured logical/snapshot disk
  budgets. These are not measurements of filesystem free space or physical file
  allocation. Audit bytes above the 50% drain target describe retained volume,
  not a count of scheduled or running maintenance jobs.
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

Unavailable values are omitted from Prometheus and represented as `null` in JSON.
Tenant archive-worker failure counters, durable backup-session totals, authority
daemon metrics, distributed recovery-coordinator phases, and peer-maintenance
counters and physical disk utilization are not yet instrumented here. Their
absence is not a zero value. Tenant
retention positions alone do not establish that automatic archival maintenance is
enabled; consult the final release checklist and archive status.

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
events at INFO and above, suppresses span fields, and disables dependency and
DEBUG/TRACE events that can contain command bodies. `RUST_LOG` does not expand
this logging policy. Provider errors are represented by static operational events;
use the protected audit/maintenance interfaces for exact outcomes. Persist and
rotate daemon logs using the host's service manager.

Persistent and scratch storage observations are available only through the same
protected routes. Health JSON includes `persistent_disk`, with its owner phase,
charged extents, pending growth, file counts, maintenance reserve and current
filesystem observation. Prometheus exposes `kasumi_persistent_disk_admission_ready`,
`kasumi_persistent_disk_max_bytes`, `kasumi_persistent_disk_maintenance_reserve_bytes`,
`kasumi_persistent_disk_charged_bytes`, `kasumi_persistent_disk_pending_bytes`,
`kasumi_persistent_disk_files`, `kasumi_persistent_disk_open_files`,
`kasumi_persistent_disk_filesystem_pending_bytes`,
`kasumi_persistent_disk_filesystem_min_free_bytes`, and the optional fresh
`kasumi_persistent_disk_filesystem_available_bytes` sample. Readiness requires an
open owner, usable filesystem admission and sufficient sampled free space for the
shared pending growth and minimum-free reservation. Its response fence rechecks
that requirement immediately before releasing a ready observation.

 Health JSON includes `scratch_disk`; Prometheus exposes
`kasumi_scratch_disk_max_bytes`, `kasumi_scratch_disk_min_free_bytes`,
`kasumi_scratch_disk_charged_bytes`, `kasumi_scratch_disk_live_files`,
`kasumi_scratch_disk_filesystem_pending_bytes`, and the optional fresh
`kasumi_scratch_disk_filesystem_available_bytes` sample. Charged bytes include
rounded encrypted spool extents and staging tables retained by active images or
workers. Filesystem pending bytes include promises by persistent and scratch
owners on the same filesystem in this process; their installed extent limits
remain separate.

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
