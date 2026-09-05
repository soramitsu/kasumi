#!/usr/bin/env python3
"""Validate terminal matrix evidence, then invoke the existing prose renderer."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys


TOOLS = Path(__file__).resolve().parent
ROOT = next(parent for parent in TOOLS.parents
            if (parent / 'scripts/run_benchmark_matrix.py').is_file())


def require(condition, message):
    if not condition:
        raise ValueError(message)


def terminal_metadata(matrix, execution):
    counts = [int(value) for value in matrix['options']['tenants'].split(',')]
    require(counts == [1, 100, 1000] and matrix['options']['documents'] == 1_000_000
            and matrix['options']['operations'] == 1000,
            'Final report requires the configured one-million-document 1/100/1000-tenant matrix.')
    require(matrix['status'] in ('completed', 'completed_under_host_load', 'completed_with_failures'),
            'Matrix is not terminal; final report must wait.')
    expected = {f'{mode}-{count}' for count in counts
                for mode in ('raw', 'local', 'replicated', 'text', 'network')}
    cases = {case['name']: case for case in matrix['cases']}
    require(len(cases) == len(matrix['cases']) == 15 and set(cases) == expected,
            'All 15 distinct cases must have terminal outcomes before final rendering.')
    for case in cases.values():
        require(case['status'] in ('passed', 'failed') and isinstance(case.get('exit_code'), int),
                f"Nonterminal case: {case['name']}")
        require((case['status'] == 'passed') == (case['exit_code'] == 0),
                f"Case exit/status mismatch: {case['name']}")
    failed = matrix['status'] == 'completed_with_failures'
    require(bool(matrix.get('failures')) == failed and
            any(case['status'] == 'failed' for case in cases.values()) == failed,
            'Matrix failure summary must agree with its case outcomes.')
    require(execution.get('status') == ('failed' if failed else 'passed') and
            execution.get('exit_code') == (1 if failed else 0) and
            execution.get('finished_unix_seconds') is not None,
            'Detached wrapper has not recorded the matching terminal exit.')
    require(execution.get('source_sha256_before') == execution.get('source_sha256_after')
            == matrix['source_sha256'], 'Execution source changed or is unbound.')
    return cases


def validate(directory):
    matrix = json.loads((directory / 'matrix.json').read_text())
    execution = json.loads((directory / 'execution.json').read_text())
    cases = terminal_metadata(matrix, execution)
    # No capacity file is read or derived until the complete execution is terminal.
    capacity = json.loads((directory / 'capacity.json').read_text())
    for name, case in cases.items():
        path = directory / f'{name}.json'
        if not path.exists():
            require(case['status'] == 'failed' and case.get('result_sha256') is None,
                    f'Missing result for a successful case: {name}')
            continue
        body = path.read_bytes()
        require(hashlib.sha256(body).hexdigest() == case.get('result_sha256'),
                f'Result hash mismatch: {name}')
        result = json.loads(body)
        binary = 'kasumi-bench-network' if name.startswith('network-') else 'kasumi-bench'
        # A failed loopback fixture may exit before the measurement client starts.
        # Preserve that matrix-bound error without claiming a measured client identity.
        if result.get('executable_sha256') is not None or case['status'] == 'passed':
            require(result.get('executable_sha256') == matrix['executable_sha256']['target/release/' + binary],
                    f'Client executable mismatch: {name}')
        if name.startswith('network-') and case['status'] == 'passed':
            require(result.get('fixture', {}).get('server_executable_sha256') ==
                    matrix['executable_sha256']['target/release/kasumid'],
                    f'Server executable mismatch: {name}')
    spec = importlib.util.spec_from_file_location('capacity_report', ROOT / 'scripts/report_benchmark_capacity.py')
    reporter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reporter)
    require(capacity == reporter.report(directory),
            'Derived capacity is stale or altered; regenerate it from terminal raw evidence.')
    qualified = {item['id']: item['completed_and_identity_verified'] for item in capacity['footprints']}
    for name, case in cases.items():
        if case['status'] == 'passed':
            require(qualified.get(name) is True, f'Successful case lacks qualified capacity identity: {name}')
    return matrix


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--matrix', type=Path, default=ROOT / 'benchmarks/results/release-matrix-macos-arm64-20260905-06')
    parser.add_argument('--output', type=Path, default=ROOT / 'benchmarks/RESULTS.md')
    parser.add_argument('--check-only', action='store_true')
    options = parser.parse_args()
    try:
        matrix = validate(options.matrix)
    except (ValueError, KeyError, FileNotFoundError, json.JSONDecodeError) as error:
        raise SystemExit(f'Final rendering blocked: {error}') from error
    if options.check_only:
        print(json.dumps({'status': 'validated', 'matrix_status': matrix['status'],
                          'source_sha256': matrix['source_sha256'], 'cases': 15, 'rendered': False}))
        return
    subprocess.run([sys.executable, str(TOOLS / 'render_release_report.py'),
                    '--matrix', str(options.matrix), '--output', str(options.output)], check=True)


if __name__ == '__main__':
    main()
