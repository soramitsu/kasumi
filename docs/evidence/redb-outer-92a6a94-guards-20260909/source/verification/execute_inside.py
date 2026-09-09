#!/usr/bin/env python3
"""Offline container entrypoint. Output is evidence, never a claim by intention."""
import json
import os
from pathlib import Path
import re
import shutil
import sys
import time

from prepare import LOCKS, checksum, inventory
from outer_guards import DEADLINES, atomic_json, need
from gate_process import run

OUTPUT = Path('/work')
PREPARED = Path('/opt/verification')
GENERATED = ('fuzz/corpus', 'fuzz/artifacts')


def input_check():
    prepared = json.loads((PREPARED / 'prepared.json').read_text())
    need(prepared['status'] == 'prepared' and prepared['locks'] == LOCKS, 'preparation differs')
    need(checksum(PREPARED / 'source-inputs.json') == prepared['source_inputs_sha256'],
         'prepared source receipt changed')
    source = json.loads((PREPARED / 'source-inputs.json').read_text())
    need(source == json.loads((OUTPUT / 'source-inputs.expected.json').read_text()),
         'built source differs from checked git archive')
    actual = inventory('/workspace')
    for root in GENERATED:
        need(not any(p == root or p.startswith(root + '/') for p in source),
             'generated mount hides source')
        need(actual.get(root, {}).get('kind') == 'directory', 'generated mount absent')
    actual = {k: v for k, v in actual.items()
              if not any(k == root or k.startswith(root + '/') for root in GENERATED)}
    need(actual == source, 'source changed during execution')
    need(inventory('/vendor') == prepared['vendor'], 'vendored dependencies changed')
    advisory = inventory(PREPARED / 'advisory-db')
    expected = prepared['advisory_inputs'].copy()
    advisory.pop('db.lock', None)
    expected.pop('db.lock', None)
    need(advisory == expected, 'advisory inputs changed')
    for root, record in prepared['advisory_databases'].items():
        for name, stamp in record['git_timestamp_inputs_ns'].items():
            need((Path(root) / '.git' / name).stat().st_mtime_ns == stamp,
                 'advisory timestamp changed')
    for name, key in (('vendor-config', 'vendor_config_sha256'), ('deny', 'deny_config_sha256')):
        need(checksum(PREPARED / (name + '.toml')) == prepared[key],
             'prepared configuration changed')
    for name, tool in prepared['tools'].items():
        path = tool.get('path', str(PREPARED / 'tools/bin' / name))
        need(checksum(path) == tool.get('sha256', tool.get('executable_sha256')),
             'prepared executable changed')
    return prepared


def cargo_home(prepared):
    root = OUTPUT / 'cargo'
    marker = OUTPUT / 'cargo-initialized.json'
    if marker.exists():
        need(json.loads(marker.read_text()) == {'registry_index': prepared['registry_index']},
             'Cargo initialization differs')
        return
    need(not root.exists(), 'unexpected prior Cargo state')
    (root / 'registry').mkdir(parents=True)
    shutil.copytree(PREPARED / 'cargo/registry/index', root / 'registry/index', copy_function=shutil.copy2)
    need(inventory(root / 'registry/index') == prepared['registry_index'], 'Cargo index copy differs')
    shutil.copy2(PREPARED / 'vendor-config.toml', root / 'config.toml')
    # This manifest can be large; it is evidence on the bounded work filesystem.
    marker.write_text(json.dumps({'registry_index': prepared['registry_index']}) + '\n')


def artifacts(log, phase):
    binaries = {}
    summaries = []
    root_features = []
    required_large = False
    with log.open() as stream:
        for line in stream:
            need(len(line) <= 8 << 20, 'artifact log line exceeds bounded parser limit')
            if line.startswith('{'):
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if item.get('reason') == 'compiler-artifact':
                    if item.get('package_id', '').startswith('path+file:///workspace#redb@'):
                        root_features.append(item.get('features', []))
                    if item.get('executable'):
                        path = Path(item['executable'])
                        need(path.resolve().is_relative_to('/target') or path.resolve().is_relative_to('/target-fuzz'),
                             'artifact outside owned target')
                        binaries[str(path)] = {'sha256': checksum(path), 'size': path.stat().st_size,
                                               'features': item.get('features'), 'target': item['target']}
            if line.startswith('test result: '):
                summaries.append(line.strip())
            if re.search(r'^test value_too_large \.\.\. ok\s*$', line):
                required_large = True
    if phase.startswith('fuzz-'):
        found = list(Path('/target-fuzz').glob('**/fuzz_redb'))
        found = [path for path in found if path.is_file() and os.access(path, os.X_OK)]
        need(len(found) == 1, 'expected exactly one actual fuzzer executable')
        path = found[0]
        binaries[str(path)] = {'sha256': checksum(path), 'size': path.stat().st_size}
    return {'binaries': binaries, 'test_summaries': summaries,
            'prototype_features': root_features, 'value_too_large_passed': required_large}


def main():
    phase = sys.argv[1]
    need(phase in ('test', 'fuzz-build', 'fuzz-smoke'), 'unknown verification phase')
    OUTPUT.joinpath('evidence').mkdir(exist_ok=True)
    result_path = OUTPUT / 'evidence' / (phase + '.json')
    log = OUTPUT / 'evidence' / (phase + '.raw.log')
    need(not result_path.exists() and not log.exists(), 'phase already attempted')
    result = {'phase': phase, 'status': 'running', 'started_utc_epoch': time.time(), 'error': None}
    atomic_json(result_path, result)
    try:
        prepared = input_check()
        cargo_home(prepared)
        environment = os.environ.copy()
        environment.update(CARGO_HOME=str(OUTPUT / 'cargo'), CARGO_NET_OFFLINE='true',
                           CARGO_TARGET_DIR='/target', TMPDIR='/work/tmp')
        with log.open('x') as stream:
            outcome = run(['just', '--justfile', 'justfile.verification', phase], '/workspace',
                          environment, stream, DEADLINES[phase],
                          lambda state: atomic_json(OUTPUT / 'evidence' / (phase + '.process.json'), state))
        result['process'] = outcome
        result['artifacts'] = artifacts(log, phase)
        input_check()
        need(outcome['status'] == 'passed', 'upstream command failed or did not drain')
        if phase == 'test':
            record = result['artifacts']
            need(record['binaries'] and record['value_too_large_passed'] and record['test_summaries'],
                 'required executable/test evidence absent')
            need(any('experimental-precommit-growth-admission' in f for f in record['prototype_features']),
                 'prototype feature not built by complete test gate')
            need(all(line.startswith('test result: ok.') for line in record['test_summaries']),
                 'a test summary failed')
        result['status'] = 'passed'
    except BaseException as error:
        result.update(status='failed', error=repr(error))
    finally:
        result['finished_utc_epoch'] = time.time()
        if log.exists():
            result['raw_log_sha256'] = checksum(log)
        atomic_json(result_path, result)
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
