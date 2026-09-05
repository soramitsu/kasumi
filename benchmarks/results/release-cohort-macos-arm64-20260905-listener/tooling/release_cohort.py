#!/usr/bin/env python3
"""Read-only provenance checks and a derived view of two recorded cohorts.

Never change, copy, relabel or fabricate raw measurement files. The optional
manifest is a separate derivation whose origins retain their source identities.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
ROOT = next(parent for parent in TOOLS.parents
            if (parent / 'scripts/run_benchmark_matrix.py').is_file())
OLD = ROOT / 'benchmarks/results/release-matrix-macos-arm64-20260905-06'
NETWORK = ROOT / 'benchmarks/results/network-rerun-macos-arm64-20260905-listener'
PROOF = ROOT / 'benchmarks/results/listener-startup-20260905/source-change.json'
BUILD = ROOT / 'benchmarks/results/macos-validation-20260905-listener/release-build.json'
OLD_SOURCE = 'a3205990001d86ea66e4ac457fba29ef634b7b6923dfdaa5d80cf2916d517df2'
NEW_SOURCE = '28aeb80168d3ab02a0eec7bf2a0163a7cb99dbfd74adf596e849de17e1fa3c1d'
BENCH = 'a1f93ade86ddfe7096bb0afccc9ae72b4f196254657595d4f6409525f0be52b7'
COUNTS = (1, 100, 1000)
MODES = ('raw', 'local', 'replicated', 'text', 'network')
NAMES = [f'{mode}-{count}' for count in COUNTS for mode in MODES]
ENGINE_NAMES = {name for name in NAMES if not name.startswith('network-')}
NETWORK_NAMES = set(NAMES) - ENGINE_NAMES


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def relative(path):
    return str(path.resolve().relative_to(ROOT))


def binding(path):
    return {'path': relative(path), 'sha256': sha(path)}


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def verify_samples(result, name, passed):
    measurements = [row for case in result.get('cases', [])
                    for row in case.get('measurements', [])]
    for row in measurements:
        counts = [row.get(key) for key in ('successful_operations', 'failed_operations',
                                          'unattempted_operations')]
        require(row.get('requested_operations') == 1000
                and all(isinstance(count, int) and count >= 0 for count in counts)
                and sum(counts) == 1000
                and row.get('attempted_operations') == counts[0] + counts[1],
                f'Inconsistent requested/attempted/result sample counts: {name}')
        if passed:
            require(counts == [1000, 0, 0], f'Passed case has incomplete samples: {name}')
    if not passed:
        return
    mode = name.split('-', 1)[0]
    require(len(measurements) == {'raw': 1, 'local': 6, 'replicated': 6,
                                  'text': 10, 'network': 10}[mode],
            f'Passed case has the wrong workload count: {name}')
    if mode == 'network':
        cases = result['cases']
        require(len(cases) == 2 and {case.get('protocol') for case in cases} == {'grpc', 'mcp'},
                f'Both distinct network protocols must be present: {name}')
        expected_names = {'authenticated_point_get', 'durable_single_document_write',
                          'read_heavy_90_read_10_write', 'balanced_50_read_50_write',
                          'authenticated_query_complete_pages'}
        require(all(len(case['measurements']) == 5
                    and {row['name'] for row in case['measurements']} == expected_names
                    for case in cases), f'Network workload set mismatch: {name}')
        require(result['fixture'].get('payload_bytes_each') == 1024,
                f'Network payload size differs from the exact 1 KiB protocol: {name}')
    else:
        require(len(result['cases']) == 1 and result['cases'][0].get('payload_bytes') == 1_024_000_000,
                f'Engine payload size differs from the exact 1 KiB protocol: {name}')


def verify_reuse(old=OLD, proof_path=PROOF, build_path=BUILD):
    proof, build = read(proof_path), read(build_path)
    manifest = read(old / 'source-manifest.json')
    require(proof['source_sha256_before'] == manifest['source_sha256'] == OLD_SOURCE
            and proof['source_sha256_after'] == NEW_SOURCE, 'Unexpected source cohort identities.')
    before, after = proof['files_before'], proof['files_after']
    require(before == manifest['files'] and set(before) == set(after),
            'The source-change proof must bind the complete archived source manifest.')
    changed = sorted(name for name in before if before[name] != after[name])
    require(changed == proof['changed_files'] == ['crates/kasumi-server/src/tls.rs'],
            'Reuse requires exactly the TLS source change, with no other source/dependency changes.')
    require(build.get('status') == 'passed' and build.get('exit_code') == 0
            and build.get('finished_unix_seconds') is not None,
            'The new release build has not passed and terminated.')
    require(build.get('source_sha256_before') == build.get('source_sha256_after') == NEW_SOURCE,
            'Release build does not bind the corrected frozen source.')
    require(build.get('executable_sha256', {}).get('kasumi-bench') == BENCH,
            'Engine executable changed; the twelve prior measurements cannot be reused.')
    require(sha(build_path.parent / build['log']) == build['log_sha256'],
            'Release build log identity mismatch.')
    return proof, build


def terminal_network(directory, build):
    matrix, execution = read(directory / 'matrix.json'), read(directory / 'execution.json')
    options = matrix['options']
    require(options['documents'] == 1_000_000 and options['operations'] == 1000
            and options['tenants'] == '1,100,1000' and options['skip_build'] is True,
            'The network supplement has different parameters or permits an in-run build.')
    require(matrix['status'] in ('completed', 'completed_under_host_load', 'completed_with_failures'),
            'The network supplement has not reached terminal completion.')
    cases = {case['name']: case for case in matrix['cases']}
    require(len(matrix['cases']) == len(cases) == 3 and set(cases) == NETWORK_NAMES,
            'The network supplement must contain exactly three distinct terminal network cases.')
    for case in cases.values():
        require(case['status'] in ('passed', 'failed') and isinstance(case.get('exit_code'), int)
                and (case['status'] == 'passed') == (case['exit_code'] == 0),
                f"Nonterminal or contradictory case: {case['name']}")
    failed = any(case['status'] == 'failed' for case in cases.values())
    require(bool(matrix.get('failures')) == failed
            and (matrix['status'] == 'completed_with_failures') == failed,
            'The network supplement failure summaries disagree.')
    require(execution.get('status') == ('failed' if failed else 'passed')
            and execution.get('exit_code') == (1 if failed else 0)
            and execution.get('finished_unix_seconds') is not None,
            'The network wrapper has not recorded its matching terminal exit.')
    require(matrix['source_sha256'] == execution.get('source_sha256_before')
            == execution.get('source_sha256_after') == NEW_SOURCE,
            'The network execution is not bound to unchanged corrected source.')
    expected_binaries = {'target/release/' + key: value
                         for key, value in build['executable_sha256'].items()}
    require(matrix['executable_sha256'] == expected_binaries,
            'Network executable identities differ from the verified release build.')
    require(sha(directory / execution['log']) == execution['log_sha256'],
            'Network driver log identity mismatch.')
    require(sha(directory / execution['wrapper_source']) == execution['wrapper_sha256'],
            'Network wrapper source identity mismatch.')
    for name, case in cases.items():
        path = directory / f'{name}.json'
        if not path.exists():
            require(case['status'] == 'failed' and case.get('result_sha256') is None,
                    f'Missing result for successful case: {name}')
            continue
        require(sha(path) == case['result_sha256'], f'Network result hash mismatch: {name}')
        result = read(path)
        verify_samples(result, name, case['status'] == 'passed')
        if result.get('executable_sha256') is not None or case['status'] == 'passed':
            require(result.get('executable_sha256') == build['executable_sha256']['kasumi-bench-network'],
                    f'Network measurement client identity mismatch: {name}')
        fixture = result.get('fixture', {})
        if fixture.get('server_executable_sha256') is not None or case['status'] == 'passed':
            require(fixture.get('server_executable_sha256') == build['executable_sha256']['kasumid'],
                    f'Network server identity mismatch: {name}')
    return matrix, execution


def verify_network_gates(directory, execution, build_path):
    require((directory / execution['release_build']).resolve() == build_path.resolve(),
            'Network wrapper references a different release build.')
    paths = [directory / value for value in execution['validation']]
    require(len(paths) == 2 and len({path.resolve() for path in paths}) == 2,
            'Both fresh platform gate records are required.')
    for path in paths:
        gate = read(path)
        require(gate['status'] == 'passed' and gate['source_sha256_before']
                == gate['source_sha256_after'] == NEW_SOURCE,
                f'Platform gate is incomplete or has a different source: {path}')
    minio_path = directory / execution['minio_validation']
    minio = read(minio_path)
    require(minio['status'] == 'passed' and minio['exit_code'] == 0
            and minio['client_source_sha256'] == minio['source_sha256_after'] == NEW_SOURCE,
            'The fresh MinIO gate is incomplete or unbound.')
    return paths + [minio_path]


def load_cohort(old=OLD, network=NETWORK, proof_path=PROOF, build_path=BUILD):
    proof, build = verify_reuse(old, proof_path, build_path)
    old_guard = module('old_matrix_guard', TOOLS / 'render_completed_release_report.py')
    old_matrix = old_guard.validate(old)
    require(old_matrix['source_sha256'] == OLD_SOURCE
            and old_matrix['executable_sha256']['target/release/kasumi-bench'] == BENCH,
            'The prior matrix has a different source or engine executable.')
    new_matrix, new_execution = terminal_network(network, build)
    new_source = read(network / 'source-manifest.json')
    require(new_source['source_sha256'] == NEW_SOURCE and new_source['files'] == proof['files_after'],
            'Network source manifest does not match the TLS-only correction proof.')
    gates = verify_network_gates(network, new_execution, build_path)
    reporter = module('cohort_capacity', ROOT / 'scripts/report_benchmark_capacity.py')
    old_capacity, new_capacity = read(old / 'capacity.json'), read(network / 'capacity.json')
    require(sha(ROOT / 'scripts/report_benchmark_capacity.py') ==
            proof['files_after']['scripts/report_benchmark_capacity.py'],
            'Capacity derivation source differs from the frozen cohort proof.')
    require(new_capacity == reporter.report(network),
            'Network capacity is absent, stale or altered; derive it after terminal execution.')
    cases, origins, selected, footprints, layers, supplements, overhead, issues = [], {}, [], [], [], [], [], []
    for directory, matrix, capacity, names in (
            (old, old_matrix, old_capacity, ENGINE_NAMES),
            (network, new_matrix, new_capacity, NETWORK_NAMES)):
        relevant = {case['name']: case for case in matrix['cases'] if case['name'] in names}
        require(set(relevant) == names, 'A selected case is missing.')
        if directory == old:
            require(all(case['status'] == 'passed' for case in relevant.values()),
                    'Only the twelve successful prior engine cases may be reused.')
        qualified = {entry['id']: entry['completed_and_identity_verified']
                     for entry in capacity['footprints']}
        for name, case in relevant.items():
            if case['status'] == 'passed':
                require(qualified.get(name) is True, f'Successful case lacks qualified identity: {name}')
                verify_samples(read(directory / f'{name}.json'), name, True)
            origin = {'case': name, 'directory': relative(directory),
                      'source_sha256': matrix['source_sha256'],
                      'status': case['status'], 'exit_code': case['exit_code'],
                      'result_sha256': case.get('result_sha256'),
                      'executable_sha256': matrix['executable_sha256']}
            origins[name] = directory
            selected.append(origin)
            cases.append(copy.deepcopy(case))
        for entry in capacity['footprints']:
            if entry['id'] in names:
                row = copy.deepcopy(entry)
                row.update(origin_directory=relative(directory), origin_source_sha256=matrix['source_sha256'])
                footprints.append(row)
        layers += [copy.deepcopy(row) for row in capacity['layers'] if row['footprint_id'] in names]
        supplements += [copy.deepcopy(row) for row in capacity['supplemental_workloads'] if row['footprint_id'] in names]
        overhead += [copy.deepcopy(row) for row in capacity['tenant_overhead_estimates']
                     if f"{row['deployment']}-{row['tenant_count']}" in names]
        issues += [issue for issue in capacity['issues'] if issue.split(':', 1)[0] in names]
    require(set(origins) == set(NAMES) and len(cases) == len(origins) == 15,
            'The cohort must select exactly one origin for each of fifteen cases.')
    passed = sum(case['status'] == 'passed' for case in cases)
    status = 'completed_with_failures' if passed < 15 else 'completed_under_host_load'
    paths = [old / name for name in ('matrix.json', 'execution.json', 'capacity.json', 'source-manifest.json', 'RUN_NOTES.md', 'host-samples.jsonl')]
    paths += [network / name for name in ('matrix.json', 'execution.json', 'capacity.json', 'source-manifest.json', 'RUN_NOTES.md', 'host-samples.jsonl')]
    paths += [proof_path, build_path, *gates]
    manifest = {
        'format': 'kasumi-measurement-cohort-v1', 'status': status,
        'artifact_path_base': 'repository root',
        'measurement_coverage_complete': passed == 15 and not issues,
        'single_execution': False, 'current_source_sha256': NEW_SOURCE,
        'source_sha256': None, 'source_identities': [OLD_SOURCE, NEW_SOURCE],
        'documents_per_case': 1_000_000, 'tenant_counts': list(COUNTS),
        'operations_per_workload': 1000, 'reused_engine_executable_sha256': BENCH,
        'reuse_rule': 'Exactly matching engine executable and complete source manifests differing only in server tls.rs. Raw origins remain unchanged.',
        'selected_cases': sorted(selected, key=lambda case: NAMES.index(case['case'])),
        'excluded_prior_network_cases': [dict(case, origin_directory=relative(old),
                                             source_sha256=OLD_SOURCE)
                                         for case in old_matrix['cases'] if case['name'] in NETWORK_NAMES],
        'evidence': [binding(path) for path in paths],
        'source_host_qualification': {relative(old): {
            'passed_quietness_screening': old_matrix['passed_quietness_screening'],
            'host_load_violation_counts': old_matrix['host_load_violation_counts']},
            relative(network): {
            'passed_quietness_screening': new_matrix['passed_quietness_screening'],
            'host_load_violation_counts': new_matrix['host_load_violation_counts']}},
    }
    combined = {
        'format': 'kasumi-cohort-capacity-v1', 'matrix_status': status, 'source_sha256': None,
        'configured_documents': 1_000_000, 'configured_tenants': list(COUNTS),
        'footprints': sorted(footprints, key=lambda row: NAMES.index(row['id'])),
        'layers': layers, 'supplemental_workloads': supplements,
        'tenant_overhead_estimates': overhead, 'issues': issues,
        'limits': old_capacity['limits'] + ['This is a derived two-cohort view; consult each footprint origin. No raw source identity is relabeled.'],
    }
    view = {'status': status, 'source_sha256': None,
            'options': {'tenants': '1,100,1000', 'documents': 1_000_000, 'operations': 1000},
            'cases': sorted(cases, key=lambda case: NAMES.index(case['name'])),
            'failures': new_matrix['failures']}
    return {'matrix': view, 'capacity': combined, 'manifest': manifest,
            'origins': origins, 'old': old, 'network': network}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--old', type=Path, default=OLD)
    parser.add_argument('--network', type=Path, default=NETWORK)
    parser.add_argument('--proof', type=Path, default=PROOF)
    parser.add_argument('--build', type=Path, default=BUILD)
    parser.add_argument('--check-reuse', action='store_true')
    options = parser.parse_args()
    try:
        if options.check_reuse:
            verify_reuse(options.old, options.proof, options.build)
            result = {'status': 'reuse_identity_verified', 'engine_cases_eligible': 12,
                      'network_completion_checked': False, 'rendered': False}
        else:
            cohort = load_cohort(options.old, options.network, options.proof, options.build)
            result = {'status': 'cohort_verified', 'measurement_coverage_complete':
                      cohort['manifest']['measurement_coverage_complete'], 'rendered': False}
    except (ValueError, KeyError, FileNotFoundError, json.JSONDecodeError) as error:
        raise SystemExit(f'Cohort rendering blocked: {error}') from error
    print(json.dumps(result))


if __name__ == '__main__':
    main()
