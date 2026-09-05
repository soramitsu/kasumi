#!/usr/bin/env python3
"""Small provenance tests; synthetic network files exist only in a deleted target fixture.

These tests run no database or benchmark and create no release evidence.
"""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import release_cohort as cohort


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


class CohortChecks(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='synthetic-cohort-test-', dir=cohort.ROOT / 'target')
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.proof, self.build = cohort.verify_reuse()
        matrix = copy.deepcopy(cohort.read(cohort.OLD / 'matrix.json'))
        matrix.update(status='completed_under_host_load', source_sha256=cohort.NEW_SOURCE,
                      failures=[], cases=[], executable_sha256={
                          'target/release/' + name: value for name, value in self.build['executable_sha256'].items()})
        matrix['options'].update(skip_build=True, output_directory=str(self.directory))
        for count in cohort.COUNTS:
            name = f'network-{count}'
            # Reuse fixture shapes as synthetic inputs, never as actual later measurements.
            result = copy.deepcopy(cohort.read(cohort.OLD / 'network-1.json'))
            result['fixture'].update(tenants=count, server_executable_sha256=self.build['executable_sha256']['kasumid'])
            result['executable_sha256'] = self.build['executable_sha256']['kasumi-bench-network']
            write(self.directory / f'{name}.json', result)
            matrix['cases'].append({'name': name, 'status': 'passed', 'exit_code': 0,
                                    'result_sha256': cohort.sha(self.directory / f'{name}.json')})
        write(self.directory / 'matrix.json', matrix)
        write(self.directory / 'source-manifest.json', {'source_sha256': cohort.NEW_SOURCE, 'files': self.proof['files_after']})
        (self.directory / 'driver.log').write_text('Synthetic test log; not benchmark evidence.\n')
        (self.directory / 'execution-wrapper.py').write_text('# Synthetic test source only.\n')
        gate = {'status': 'passed', 'source_sha256_before': cohort.NEW_SOURCE,
                'source_sha256_after': cohort.NEW_SOURCE}
        write(self.directory / 'mac-gate.json', gate)
        write(self.directory / 'linux-gate.json', gate)
        write(self.directory / 'minio.json', dict(gate, exit_code=0, client_source_sha256=cohort.NEW_SOURCE))
        execution = dict(gate, exit_code=0, finished_unix_seconds=1,
                         log='driver.log', log_sha256=cohort.sha(self.directory / 'driver.log'),
                         wrapper_source='execution-wrapper.py', wrapper_sha256=cohort.sha(self.directory / 'execution-wrapper.py'),
                         validation=['mac-gate.json', 'linux-gate.json'], minio_validation='minio.json',
                         release_build=os.path.relpath(cohort.BUILD, self.directory))
        write(self.directory / 'execution.json', execution)
        self.reporter = cohort.module('synthetic_capacity', cohort.ROOT / 'scripts/report_benchmark_capacity.py')
        write(self.directory / 'capacity.json', self.reporter.report(self.directory))
        (self.directory / 'RUN_NOTES.md').write_text('Synthetic test only; deleted after test.\n')
        (self.directory / 'host-samples.jsonl').write_text('')

    def test_valid_synthetic_merge_retains_distinct_origins(self):
        value = cohort.load_cohort(network=self.directory)
        self.assertTrue(value['manifest']['measurement_coverage_complete'])
        self.assertIsNone(value['manifest']['source_sha256'])
        self.assertEqual(len(value['capacity']['footprints']), 15)
        self.assertEqual(len(value['capacity']['tenant_overhead_estimates']), 18)
        self.assertEqual(len(value['manifest']['excluded_prior_network_cases']), 3)
        for case in value['manifest']['selected_cases']:
            self.assertEqual(case['source_sha256'], cohort.NEW_SOURCE if case['case'].startswith('network-') else cohort.OLD_SOURCE)

    def test_startup_failure_stays_unqualified_with_no_measurements(self):
        write(self.directory / 'network-1000.json', {'cases': [], 'fixture_error': 'synthetic startup failure'})
        matrix = cohort.read(self.directory / 'matrix.json')
        matrix.update(status='completed_with_failures', failures=['synthetic startup failure'])
        matrix['cases'][-1].update(status='failed', exit_code=1, result_sha256=cohort.sha(self.directory / 'network-1000.json'))
        write(self.directory / 'matrix.json', matrix)
        execution = cohort.read(self.directory / 'execution.json')
        execution.update(status='failed', exit_code=1)
        write(self.directory / 'execution.json', execution)
        write(self.directory / 'capacity.json', self.reporter.report(self.directory))
        value = cohort.load_cohort(network=self.directory)
        self.assertFalse(value['manifest']['measurement_coverage_complete'])
        footprint = next(row for row in value['capacity']['footprints'] if row['id'] == 'network-1000')
        self.assertFalse(footprint['completed_and_identity_verified'])
        self.assertIsNone(footprint['tenants'])
        self.assertEqual(footprint['resident_data_raft_groups'], 1000)
        self.assertEqual(len(value['capacity']['issues']), 1)

    def test_altered_result_hash_blocks(self):
        path = self.directory / 'network-100.json'
        path.write_text(path.read_text() + '\n')
        with self.assertRaisesRegex(ValueError, 'result hash mismatch'):
            cohort.load_cohort(network=self.directory)

    def test_altered_capacity_blocks(self):
        value = cohort.read(self.directory / 'capacity.json')
        value['footprints'][0]['clean_shutdown_seconds'] = 0
        write(self.directory / 'capacity.json', value)
        with self.assertRaisesRegex(ValueError, 'capacity is absent, stale or altered'):
            cohort.load_cohort(network=self.directory)

    def test_running_or_missing_case_blocks(self):
        matrix = cohort.read(self.directory / 'matrix.json')
        matrix['status'] = 'running'
        write(self.directory / 'matrix.json', matrix)
        with self.assertRaisesRegex(ValueError, 'terminal completion'):
            cohort.load_cohort(network=self.directory)
        matrix['status'] = 'completed_under_host_load'
        matrix['cases'].pop()
        write(self.directory / 'matrix.json', matrix)
        with self.assertRaisesRegex(ValueError, 'exactly three'):
            cohort.load_cohort(network=self.directory)

    def test_changed_engine_binary_or_extra_source_change_blocks(self):
        with patch.object(cohort, 'read', side_effect=lambda path: dict(self.build, executable_sha256={'kasumi-bench': 'changed'})
                          if path == cohort.BUILD else json.loads(path.read_text())):
            with self.assertRaisesRegex(ValueError, 'Engine executable changed'):
                cohort.verify_reuse()
        altered = copy.deepcopy(self.proof)
        altered['files_after']['Cargo.lock'] = 'changed'
        with patch.object(cohort, 'read', side_effect=lambda path: altered if path == cohort.PROOF else json.loads(path.read_text())):
            with self.assertRaisesRegex(ValueError, 'exactly the TLS source change'):
                cohort.verify_reuse()

    def test_workload_count_and_protocol_mismatch_blocks(self):
        result = cohort.read(self.directory / 'network-1.json')
        result['cases'][0]['measurements'][0]['successful_operations'] = 999
        with self.assertRaisesRegex(ValueError, 'sample counts'):
            cohort.verify_samples(result, 'network-1', True)
        result = cohort.read(self.directory / 'network-1.json')
        result['cases'][1]['protocol'] = 'grpc'
        with self.assertRaisesRegex(ValueError, 'distinct network protocols'):
            cohort.verify_samples(result, 'network-1', True)

    def test_renderer_links_origins_and_preserves_historical_failure(self):
        output = self.directory / 'synthetic-report.md'
        command = [sys.executable, str(cohort.TOOLS / 'render_release_report.py'),
                   '--network-cohort', str(self.directory), '--output', str(output),
                   '--cohort-manifest', str(self.directory / 'synthetic-cohort.json'),
                   '--cohort-capacity', str(self.directory / 'synthetic-capacity.json')]
        completed = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        text = output.read_text()
        self.assertIn('Recorded cohort outcome', text)
        self.assertNotIn('The matrix source SHA-256 is', text)
        self.assertIn(cohort.OLD_SOURCE, text)
        self.assertIn(cohort.NEW_SOURCE, text)
        self.assertIn('Pre-shutdown sampled peak GiB', text)
        self.assertIn('No network-1000 workload or document load ran', text)
        self.assertIn('may have extended into initial loading', text)
        self.assertIn('../benchmarks/results/release-matrix', text)
        manifest = cohort.read(self.directory / 'synthetic-cohort.json')
        self.assertEqual(manifest['artifact_path_base'], 'repository root')
        self.assertTrue(manifest['derived_capacity']['path'].startswith('target/'))
        self.assertEqual({entry['path'] for entry in manifest['renderers']},
                         {str((cohort.TOOLS / name).resolve().relative_to(cohort.ROOT)) for name in
                          ('render_release_report.py', 'release_cohort.py', 'render_completed_release_report.py')})
        self.assertEqual(manifest['derived_capacity']['sha256'], cohort.sha(self.directory / 'synthetic-capacity.json'))


if __name__ == '__main__':
    unittest.main()
