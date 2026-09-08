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
can withhold the whole result. Authentication and authorization failures are
audited. Failure responses contain no diagnostic state.

`/health` reports whether startup completed and the daemon is serving. `/ready`
additionally requires an accessible service audit store, usable unpressured node
admission, complete local-group coverage, current store/serving authority, and a
successful fresh quorum barrier for every examined local group. It returns 503
when these conditions do not hold. A listening socket or remembered leader alone
does not establish readiness. Draining begins before listeners and workers stop.

Control administrator authorization itself requires a current Control quorum
barrier. If that cannot be established, all three endpoints return a generic 503;
they do not release counters using an old policy. On HA nodes this means a Control
follower cannot serve these protected observations until it can satisfy that
administrative authorization. Treat a failed scrape as unavailable monitoring,
not as zero load or an empty database. Admission pressure can likewise prevent a
scrape from reserving its workspace and return 503.

Each successful scrape examines up to 128 local groups, including Control, with a
three-second total quorum-probe budget and a one-second per-group ceiling. The
Control authorization barrier has its separate five-second ceiling. Unexamined
groups are counted explicitly; timed-out/unperformed probes never establish
readiness. At present, an installation with more than 128 locally assigned groups
cannot pass this node-wide readiness check. Group samples are local observations
collected during the request, not a consistent distributed snapshot. The Control
topology is read from a shared document root; individual routes and observation
rows are bounded, and scrapes do not serialize tenant data.

Available metrics include:

- `kasumi_ready`, lifecycle, examined/unexamined local groups, and actual quorum
  probe outcomes; per-group serving-authority remaining seconds only where an
  admitted HA lease supplies them.
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

Scratch storage observations are available only through the same protected
routes. Health JSON includes `scratch_disk`; Prometheus exposes
`kasumi_scratch_disk_max_bytes`, `kasumi_scratch_disk_min_free_bytes`,
`kasumi_scratch_disk_charged_bytes`, `kasumi_scratch_disk_live_files`,
`kasumi_scratch_disk_filesystem_pending_bytes`, and the optional fresh
`kasumi_scratch_disk_filesystem_available_bytes` sample. Charged bytes include
rounded encrypted spool extents and staging tables retained by active images or
workers. Filesystem pending bytes include promises by other scratch owners on
the same filesystem in this process. Persistent database/WAL/index and archive
capacity is outside this temporary-workspace governor.

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
