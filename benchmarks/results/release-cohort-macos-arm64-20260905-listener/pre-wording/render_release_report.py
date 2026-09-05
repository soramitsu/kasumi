#!/usr/bin/env python3
"""Render recorded measurements as prose/tables; never run a workload."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re

tooling = Path(__file__).resolve().parent
root = next(parent for parent in tooling.parents
            if (parent / 'scripts/run_benchmark_matrix.py').is_file())
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--matrix', type=Path, default=root / 'benchmarks/results/release-matrix-macos-arm64-20260905-06')
parser.add_argument('--output', type=Path, default=root / 'benchmarks/RESULTS.md')
parser.add_argument('--network-cohort', type=Path,
                    help='Verify and combine twelve run06 engine cases with this terminal network supplement.')
parser.add_argument('--cohort-manifest', type=Path)
parser.add_argument('--cohort-capacity', type=Path)
options = parser.parse_args()
directory = options.matrix
cohort = None
if options.network_cohort:
    if not options.cohort_manifest or not options.cohort_capacity:
        raise SystemExit('Cohort rendering requires separate --cohort-manifest and --cohort-capacity outputs.')
    if options.cohort_manifest.exists() or options.cohort_capacity.exists():
        raise SystemExit('Preserve the existing cohort artifacts; choose fresh output paths.')
    from release_cohort import load_cohort
    cohort = load_cohort(old=directory, network=options.network_cohort)
    matrix, capacity = cohort['matrix'], cohort['capacity']
else:
    matrix = json.loads((directory / 'matrix.json').read_text())
    capacity = json.loads((directory / 'capacity.json').read_text())
prefix = Path(os.path.relpath(directory.resolve(), root / 'benchmarks')).as_posix()

def artifact_link(path):
    return Path(os.path.relpath(path.resolve(), root / 'benchmarks')).as_posix()

def case_path(name):
    origin = cohort['origins'][name] if cohort else directory
    return origin / f'{name}.json'

def observed_tenants(entry):
    return entry['tenants'] if entry['tenants'] is not None else f"{entry['id'].rsplit('-', 1)[1]} configured; unobserved"
counts = [int(value) for value in matrix['options']['tenants'].split(',')]
if (capacity.get('source_sha256') != matrix['source_sha256'] or
        capacity.get('matrix_status') != matrix['status'] or
        capacity.get('configured_documents') != matrix['options']['documents'] or
        capacity.get('configured_tenants') != counts):
    raise SystemExit('Capacity data does not match the current matrix; regenerate capacity.json before rendering.')
expected_cases = [f'{mode}-{tenants}' for tenants in counts
                  for mode in ('raw', 'local', 'replicated', 'text', 'network')]
recorded_cases = {case['name']: case for case in matrix.get('cases', [])}
terminal_complete = matrix['status'] in ('completed', 'completed_under_host_load',
                                        'completed_with_failures')
all_cases_attempted = (len(recorded_cases) == len(matrix.get('cases', [])) and
                       set(recorded_cases) == set(expected_cases))

def number(value):
    if value is None:
        return '—'
    if abs(value) >= 1000:
        return format(value, ',.0f')
    precision = 9 if 0 < abs(value) < 0.001 else 3
    return format(value, f'.{precision}f').rstrip('0').rstrip('.') or '0'

def size(value):
    return '—' if value is None else f'{value / 2**30:.3f}'

def table(headers, rows):
    return ['| ' + ' | '.join(headers) + ' |',
            '| ' + ' | '.join('---' for _ in headers) + ' |',
            *['| ' + ' | '.join(map(str, row)) + ' |' for row in rows], '']

def setup_interference(directory, prefix):
    record = directory / 'artifact-cleanup-incremental/result.json'
    if not record.exists():
        return []
    cleanup = json.loads(record.read_text())
    start = datetime.fromtimestamp(cleanup['started_unix_seconds'], timezone.utc).isoformat()
    finish = datetime.fromtimestamp(cleanup['finished_unix_seconds'], timezone.utc).isoformat()
    return [
        '### Filesystem activity during setup', '',
        f"The [incremental-cache cleanup record]({prefix}/artifact-cleanup-incremental/result.json) "
        f"records filesystem activity from {start} through {finish}, while local-1000 "
        'was in progress. Inventoried Cargo incremental caches were removed; the record '
        f"preserves unchanged source and {cleanup['retained_compiled_files']:,} retained compiled files. This overlapped "
        'collection setup and may have extended into initial loading based on the '
        'case start and recorded phase durations; phase checkpoints have no exact timestamps. '
        'Setup/load timing and subsequent host I/O/cache state are additionally qualified. '
        'No isolated setup cost or causal performance improvement is inferred. '
        f"[Run notes]({prefix}/RUN_NOTES.md) retain the cleanup scope and tradeoff.", '',
    ]

lines = [
    '# Kasumi v1 measured results', '',
    f"Recorded matrix outcome: **`{matrix['status']}`**. "
    'These are measurements on a shared macOS development host. '
    'They do not establish a production capacity limit, launch SLA, or Redis speed ratio.', '',
    f"The [matrix manifest]({prefix}/matrix.json), [derived capacity data]({prefix}/capacity.json) "
    f"and [host samples]({prefix}/host-samples.jsonl) preserve commands, source and executable "
    'identities, result hashes, failures and background activity. '
    f"[Run notes]({prefix}/RUN_NOTES.md) explain the identity scopes and workload order.", '',
    '## Dataset and guarantees', '',
    'Each configured case targets 1,000,000 documents whose serialized JSON bodies are exactly 1,024 bytes: '
    '1,024,000,000 logical payload bytes, distributed across 1, 100 or 1,000 tenants. '
    'Replicated cases hold three copies of that logical dataset. Each mode/count runs in '
    'its own process. Every measured workload requests 1,000 sequential operations. '
    'Incomplete loads and unattempted cases are not counted as full-size observations.', '',
    'The host is macOS arm64 with 16 logical CPUs and 128 GiB RAM; Rust/Cargo 1.94.1, '
    'locked dependencies, thin LTO and one release code-generation unit. Unrelated host '
    'work remained running. The dedicated Linux validation VM and this task’s builds '
    'were stopped before measurements. Permitted host load stays visible in the evidence.', '',
    f"The matrix source SHA-256 is `{matrix['source_sha256']}`. "
    'The narrower Rust/Cargo source hash in individual reports has a different documented '
    'scope. Their preliminary-development labels are retained: frozen provenance does '
    'not establish repeatability or isolated hardware ownership.', '',
    'Raw map reads borrow a body without authorization, body cloning or durability. Embedded reads use '
    'the actual shared authorization and consistency layer. Local writes persist through '
    'encrypted redb with immediate durability and two-phase commit. Replicated reads '
    'require a fresh quorum barrier; writes require quorum persistence and complete '
    'local application. The three voters have separate redb files in one process; '
    'physical failure domains and remote-network latency are not measured.', '',
    'Native RPC uses real TLS 1.3, mTLS and OAuth; MCP uses TLS 1.3 and OAuth with protocol '
    '2026-07-28. Both target a separate production server process with one voter per '
    'tenant, actual OpenBao Transit, and durable authentication and mutation audits. '
    'Strict tenant successful-read auditing is disabled, while network authentication '
    'events remain durable for successful reads and are included in request latency. Local/replicated '
    'in-process cases use the explicit test wrapping provider with real encryption; '
    'Transit latency is excluded from those cases.', '',
    '## Latency and throughput', '',
    'All latency columns use **microseconds**; displayed values are rounded. Throughput is completed successes divided '
    'by the entire workload interval, including any failed-attempt delay. Success '
    'percentiles exclude failed attempts; failures and unattempted operations are shown '
    'separately. A workload stops at its first failure, with no hidden client retry. '
    'At 1,000 samples, p99 has roughly ten tail observations. There is one run per '
    'case, with no confidence interval or saturation claim. Mixed-workload percentiles '
    'combine reads and writes. In a 50/50 mix, the median lies near the boundary '
    'between their latency distributions; use the dedicated write row for write latency.', '',
]

if cohort:
    network_prefix = artifact_link(cohort['network'])
    provenance = [
        '# Kasumi v1 measured results', '',
        f"Recorded cohort outcome: **`{matrix['status']}`**. Full measurement coverage: "
        f"**{'yes' if cohort['manifest']['measurement_coverage_complete'] else 'no'}**. "
        'This report selects twelve unchanged engine measurements and three later network case outcomes. '
        'It is not a single execution or a relabeling of old results as corrected-source measurements. '
        'Shared-host observations do not establish production capacity, a launch SLA or a Redis speed ratio.', '',
        f"The [cohort manifest]({artifact_link(options.cohort_manifest)}) binds every selected origin, "
        f"and the [derived capacity view]({artifact_link(options.cohort_capacity)}) retains those origins. "
        f"The original [run06 manifest]({prefix}/matrix.json), [host samples]({prefix}/host-samples.jsonl) "
        f"and [run notes]({prefix}/RUN_NOTES.md), and the network supplement's "
        f"[manifest]({network_prefix}/matrix.json), [host samples]({network_prefix}/host-samples.jsonl) "
        f"and [run notes]({network_prefix}/RUN_NOTES.md) remain separate records.", '',
        '## Cohort provenance', '',
        'The twelve raw/local/replicated/text cases retain source '
        f"`{cohort['manifest']['source_identities'][0]}`. Network cases use corrected source "
        f"`{cohort['manifest']['source_identities'][1]}`. "
        'The complete [source-change proof](results/listener-startup-20260905/source-change.json) '
        'contains exactly one changed file, server `tls.rs`; dependencies and engine/benchmark sources are unchanged. '
        'Reuse additionally requires the new release build to produce the exact previously measured '
        f"`kasumi-bench` SHA256 `{cohort['manifest']['reused_engine_executable_sha256']}`. "
        'Network client, fixture launcher and server identities are bound to their new release build. '
        'All raw hashes, original source labels and the unsuccessful earlier network case are preserved.', '',
    ]
    provenance += table(['Case', 'Origin', 'Recorded outcome'],
                        [[f"[{entry['case']}]({artifact_link(case_path(entry['case']))})",
                          'run06 / a3205990' if not entry['case'].startswith('network-') else 'network supplement / 28aeb801',
                          entry['status']] for entry in cohort['manifest']['selected_cases']])
    # Replace only the single-execution introduction, retaining shared protocol definitions.
    lines = provenance + lines[6:]
    lines = [line for line in lines if not line.startswith('The matrix source SHA-256 is ')]

titles = {
    'raw_hashmap': 'Raw map access',
    'embedded_access': 'Embedded reads and structured queries',
    'local_durable_writes': 'Local durable writes and mixed traffic',
    'replicated_durable_access': 'Replicated access',
    'authenticated_grpc': 'Authenticated native RPC',
    'authenticated_mcp': 'Authenticated MCP',
}
headers = ['Tenants', 'Workload', 'Success / failed / unattempted', 'p50 µs', 'p99 µs', 'Successes/s']

def measurement_row(tenants, measurement):
    latency = measurement.get('latency') or {}
    counts = ' / '.join(str(measurement.get(key, '—')) for key in
                        ('successful_operations', 'failed_operations', 'unattempted_operations'))
    return [tenants, f"`{measurement['name']}`", counts,
            number(latency.get('p50_microseconds')),
            number(latency.get('p99_microseconds')),
            number(latency.get('throughput_ops_per_second'))]

for layer, title in titles.items():
    rows = [measurement_row(entry['tenants'], measurement)
            for entry in capacity['layers'] if entry['layer'] == layer
            for measurement in entry['measurements']]
    lines += [f'### {title}', '']
    lines += table(headers, rows) if rows else ['Not measured.', '']

lines += setup_interference(directory, prefix)

lines += ['### English and Japanese indexed text', '',
          'Text cases include one numeric index and two text indexes per tenant. '
          'Writes change indexed text and include Tantivy commit/reload before acknowledgment. '
          'Queries consume all historical pages before the next operation. At 1/100/1,000 '
          'tenants, the fixture-derived result sizes are 1,000/10/1 rows for phrase, fuzzy '
          'and Japanese terms, and 10,000/100/10 for English prefix. Structured equality '
          'expects one row. These cardinalities follow from fixture definitions; timed '
          'reports do not emit or assert observed row/page counts. Text latency changes '
          'include this changing result work, not a fixed-cardinality speed comparison.', '']
rows = [measurement_row(entry['tenants'], measurement)
        for entry in capacity['supplemental_workloads']
        for measurement in entry['measurements']]
lines += table(headers, rows) if rows else ['Not measured.', '']

lines += ['## Memory and recovery', '',
          'Memory columns are whole-process **GiB**. Local, text and replicated RSS '
          'include the driver and all resident voters. Network RSS is the server only; '
          'OpenBao, issuer and client remain visible separately in host samples. Native '
          'and MCP share one footprint and must not be added together.', '']
lines += table(['Deployment', 'Tenants', 'Configured data voter groups', 'Control groups', 'Service audit stores', 'Qualified observation'],
               [[entry['deployment'], observed_tenants(entry), entry['resident_data_raft_groups'],
                 entry['resident_control_raft_groups'], entry.get('service_security_store_count', '—'),
                 'yes' if entry['completed_and_identity_verified'] else 'no']
                for entry in capacity['footprints']])
lines += ['Service audit stores share a writer per node and are counted separately from '
          'Raft groups. Their footprint is included when that fixture provides the store; '
          'historical fixtures retain their original counts. For failed startup entries, '
          'configured topology does not establish ready groups, and absent RSS/payload observations '
          'must not be interpreted as an observed empty database.', '']
lines += table(['Deployment', 'Tenants', 'Empty maps/groups GiB', 'Empty indexes GiB',
                'Loaded GiB', 'After work GiB', 'Pre-shutdown sampled peak GiB', 'After recovery GiB'],
               [[entry['deployment'], observed_tenants(entry),
                 *[size(entry[key]) for key in ('empty_groups_rss_bytes', 'empty_indexes_rss_bytes',
                   'loaded_rss_bytes', 'after_workload_rss_bytes', 'process_lifetime_peak_rss_bytes', 'after_recovery_rss_bytes')]]
                for entry in capacity['footprints']])
lines += table(['Deployment', 'Tenants', 'Open s', 'Index setup s', 'Load s', 'Shutdown s', 'Clean recovery s',
                'Loaded RSS / resident payload bytes'],
               [[entry['deployment'], observed_tenants(entry),
                 *[number(entry.get(key)) for key in ('open_seconds', 'collection_setup_seconds',
                   'load_seconds', 'clean_shutdown_seconds', 'clean_recovery_seconds', 'loaded_rss_per_resident_payload_byte')]]
                for entry in capacity['footprints']])
lines += ['Shutdown drains database-owned work and releases storage. Recovery starts '
          'after completed shutdown and measures reopening with one verified read per tenant, including '
          'index reconstruction and readiness. Network recovery restarts the actual server '
          'while OpenBao and the issuer stay running. Crash and I/O-failure correctness '
          'have separate acceptance tests. In database case files, peak_rss_bytes is the '
          'OS process peak sampled after workloads and before shutdown; it is not refreshed '
          'after recovery and is not the final whole-run peak. The separately reported '
          'after-recovery RSS can exceed it. Raw cases sample their peak after lookups; '
          'network fixtures do not report a server lifetime peak. RSS snapshots and five-second sampling can '
          'miss short peaks; these figures are not heap-object sizes or maximum safe capacity.', '',
          '### Incremental tenant overhead', '',
          'These estimates divide the RSS difference from an independent one-tenant '
          'process by the added tenant count. They include runtime, policies, keys, '
          'audits, schemas and allocator effects, not isolated Raft allocations. '
          'Only completed cases with verified identities contribute. Negative estimates '
          'are retained as measurement noise, not described as memory savings.', '']
if capacity['tenant_overhead_estimates']:
    lines += table(['Deployment', 'Tenants', 'Stage', 'MiB/additional tenant', 'MiB/additional resident voter'],
                   [[entry['deployment'], entry['tenant_count'], entry['stage'].removesuffix('_rss_bytes'),
                     number(entry['additional_tenant_rss_bytes'] / 2**20),
                     number(None if entry['additional_resident_voter_rss_bytes'] is None else
                            entry['additional_resident_voter_rss_bytes'] / 2**20)]
                    for entry in capacity['tenant_overhead_estimates']])
else:
    lines += ['No qualified tenant-overhead estimates are available in this matrix.', '']

lines += ['## Failures, retained runs and interpretation', '',
          f"The {'cohort' if cohort else 'matrix'} manifest records {len(recorded_cases)} of {len(expected_cases)} expected case outcomes. "
          f"Terminal case coverage: **{'yes' if terminal_complete and all_cases_attempted else 'no'}**. "
          'Completion with failures means the configured cases finished being attempted; '
          'it does not make failed or unattempted operations successful.', '']
lines += table(['Case', 'Recorded outcome', 'Exit code'],
               [[f'[{name}]({artifact_link(case_path(name))})' if case_path(name).exists() else name,
                 recorded_cases.get(name, {}).get('status', 'no terminal outcome recorded'),
                 recorded_cases.get(name, {}).get('exit_code', '—')]
                for name in expected_cases])
failed_attempts = []
for entry in capacity['layers'] + capacity['supplemental_workloads']:
    layer = entry.get('layer', entry.get('workload'))
    for measurement in entry['measurements']:
        for attempt in measurement.get('failed_attempts', []):
            message = str(attempt.get('message', '')).replace('|', '&#124;').replace('\n', '<br>')
            failed_attempts.append([layer, entry['tenants'], f"`{measurement['name']}`",
                                    attempt.get('operation_index', '—'),
                                    attempt.get('error_code') or 'unclassified',
                                    number(attempt.get('elapsed_microseconds')), message])
if failed_attempts:
    lines += ['Measured failed attempts are listed below; operation indices are zero-based. '
              'Their latency does not enter success percentiles. Setup, recovery, cleanup '
              'or interrupted-case errors remain in the case reports/logs and summaries.', '']
    lines += table(['Layer', 'Tenants', 'Workload', 'Operation index', 'Error', 'Failed latency µs', 'Message'],
                   failed_attempts)
case_errors = []
for name in expected_cases:
    path = case_path(name)
    if not path.exists():
        continue
    source = json.loads(path.read_text())
    errors = list(source.get('failures', []))
    if source.get('fixture_error'):
        errors.append(source['fixture_error'])
    for error in errors:
        case_errors.append(f"- `{name}`: {str(error).replace(chr(10), ' ')}")
if case_errors:
    lines += ['Case-reported errors, including setup/recovery/cleanup:', '', *case_errors, '']
lines += [f"- {failure}" if str(failure).strip() else
          f'- The driver recorded an empty failure message; see [execution status]({prefix}/execution.json) and [driver log]({prefix}/driver.log).'
          for failure in matrix.get('failures', [])]
lines += [f"- {issue}" for issue in capacity['issues']]
lines += ['']
if (terminal_complete and all_cases_attempted and
        all(case.get('status') == 'passed' for case in recorded_cases.values()) and
        not matrix.get('failures') and not capacity['issues']):
    lines += [f"All selected cases in this {'cohort' if cohort else 'matrix'} completed and matched their recorded result/executable identities.", '']
lines += [
    'The [first matrix](results/release-matrix-macos-arm64-20260905-01/matrix.json) '
    'failed at a replicated balanced-workload read. The '
    '[investigation](../docs/read-barrier-investigation.md) separates that observed '
    'failure from the controlled regressions proving snapshot scheduling and bounded '
    'fresh-quorum retry fixes. The '
    '[second matrix](results/release-matrix-macos-arm64-20260905-02/matrix.json) '
    'was interrupted to correct a disk-guard precedence bug; its completed raw case '
    'and partial local load are retained. The '
    '[third matrix](results/release-matrix-macos-arm64-20260905-03/matrix.json) '
    'passed the raw/local/replicated one-tenant cases and then stopped with a '
    'broken driver output pipe. The '
    '[fourth matrix](results/release-matrix-macos-arm64-20260905-04/TERMINATION.md) '
    'retained a separate five-second replicated read-quorum timeout and a redb '
    'reopen failure, then was explicitly stopped. The '
    '[shutdown investigation](../docs/shutdown-investigation.md) documents worker '
    'lifetime fixes and their controlled regressions; it does not claim the '
    'quorum timeout was caused by that defect. The '
    '[fifth matrix](results/release-matrix-macos-arm64-20260905-05/TERMINATION.md) '
    'passed raw/local; its replicated case completed all six 1,000-operation workloads '
    'and verified recovery, then was explicitly interrupted before final cleanup '
    'to correct missing embedded denial audits. The '
    '[audit investigation](../docs/embedded-audit-investigation.md) records that '
    'contract gap and its focused corrections. Subsequent runs log to regular '
    'files independently of the initiating tool session. Incomplete runs are not substituted '
    'for a completed matrix.', '',
    'The [sixth matrix](results/release-matrix-macos-arm64-20260905-06/TERMINATION.md) '
    'completed fourteen cases, then its 1,000-tenant network fixture exited before readiness '
    'with `Invalid argument (os error 22)`. No network-1000 workload or document load ran. '
    'The [listener investigation](../docs/listener-startup-investigation.md) distinguishes '
    'the reproduced macOS reset-socket mechanism and connection-isolation correction '
    'from the inferred original syscall. The original failure is retained even if a '
    'later corrected network case succeeds. A configured 1,000-group entry in its partial '
    'capacity report does not prove those groups became ready.', '',
    'Owned embedded reads precede shared reads over the same deterministic IDs. '
    'Owned calls return a document clone; shared calls return a retained immutable '
    'handle. Raw borrowing and these authenticated return paths have different '
    'contracts and cache state, so their ratio does not isolate the copying cost. '
    'Raw maps run in another process. Native RPC precedes MCP on the same server '
    'with a warmup read per credential. Cache state, retained allocations, receipts '
    'and audit growth therefore differ across these paths. Comparing their numerical '
    'ratios does not isolate one implementation cost or justify a Redis multiplier.', '',
    'Leave headroom for snapshots, staged indexes, search writers, cursor results, '
    'receipts, audits and recovery. Repeat on the selected Linux deployment with '
    'concurrent clients and sustained pressure before setting operational capacity '
    'policy. The [benchmark protocol](README.md), [capacity definitions](CAPACITY.md) '
    'and [acceptance checklist](../docs/release-checklist.md) identify reproducible '
    'commands and the limits of these observations.', '',
]
def output_link(match):
    destination = match.group(1)
    if '://' in destination or destination.startswith('#'):
        return match.group(0)
    path = (root / 'benchmarks' / destination).resolve()
    relative = Path(os.path.relpath(path, options.output.resolve().parent)).as_posix()
    return f']({relative})'

if cohort:
    import hashlib
    capacity_body = json.dumps(capacity, indent=2) + '\n'
    manifest = dict(cohort['manifest'],
                    derived_capacity={'path': str(options.cohort_capacity.resolve().relative_to(root)),
                                      'sha256': hashlib.sha256(capacity_body.encode()).hexdigest()},
                    renderers=[{'path': str(path.resolve().relative_to(root)),
                                'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
                               for path in (Path(__file__), tooling / 'release_cohort.py',
                                            tooling / 'render_completed_release_report.py')])
    options.cohort_capacity.write_text(capacity_body)
    options.cohort_manifest.write_text(json.dumps(manifest, indent=2) + '\n')
options.output.write_text(re.sub(r'\]\(([^)]+)\)', output_link, '\n'.join(lines)))
print(options.output)
