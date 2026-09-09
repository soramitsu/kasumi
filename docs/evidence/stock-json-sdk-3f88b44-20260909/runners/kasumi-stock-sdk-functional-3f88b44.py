#!/usr/bin/env python3
"""Authorized external SDK-only tests, bounded original invocation and owned process groups."""
from pathlib import Path
import datetime
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
import re
import shutil

SOURCE = Path('/tmp/kasumi-stock-sdk-consumer').resolve()
OUTPUT = Path('/tmp/kasumi-stock-sdk-functional-3f88b44')
TARGET = Path('/tmp/kasumi-stock-sdk-consumer-target')
TOOLS = Path('/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin')
EXPECTED = '3f88b449299a33b23c48543566365cd97ebdb1ab'
MANIFEST = 'external-tests/stock-json-sdk/Cargo.toml'
LOCK = SOURCE / 'external-tests/stock-json-sdk/Cargo.lock'


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as source:
        for block in iter(lambda: source.read(1 << 20), b''):
            value.update(block)
    return value.hexdigest()


def output(command):
    return subprocess.check_output(command, cwd=SOURCE, text=True).strip()


def write(name, value):
    path = OUTPUT / name
    pending = path.with_suffix(path.suffix + '.tmp')
    with pending.open('w') as target:
        json.dump(value, target, indent=2)
        target.write('\n')
        target.flush()
        os.fsync(target.fileno())
    pending.replace(path)


def source_state():
    names = subprocess.check_output(['git', 'ls-files', '-z'], cwd=SOURCE).decode().split('\0')
    return {
        'commit': output(['git', 'rev-parse', 'HEAD']),
        'tree': output(['git', 'rev-parse', 'HEAD^{tree}']),
        'status': output(['git', 'status', '--porcelain', '--untracked-files=all']),
        'files': {name: digest(SOURCE / name) for name in names if name},
        'consumer_lock_sha256': digest(LOCK) if LOCK.is_file() else None,
    }


def unchanged_source(before, after):
    return (all(before[key] == after[key] for key in ('commit', 'tree', 'files'))
            and after['status'] in ('', '?? external-tests/stock-json-sdk/Cargo.lock'))


def members(group):
    listing = subprocess.check_output(['ps', '-axo', 'pid=,ppid=,pgid=,stat=,comm='], text=True)
    return [line.strip() for line in listing.splitlines()
            if len(line.split(None, 4)) >= 5 and line.split(None, 4)[2] == str(group)]


def drain(process):
    before = members(process.pid)
    sent = []
    for sig in (signal.SIGTERM, signal.SIGKILL):
        if not members(process.pid):
            break
        try:
            os.killpg(process.pid, sig)
            sent.append(sig.name)
        except ProcessLookupError:
            pass
        until = time.monotonic() + 5
        while time.monotonic() < until:
            process.poll()
            if not members(process.pid):
                break
            time.sleep(0.1)
    process.wait(timeout=5)
    after = members(process.pid)
    return {'group': process.pid, 'before': before, 'signals': sent,
            'after': after, 'drained': not after}


def interrupted(sig, frame):
    raise InterruptedError('runner received signal ' + str(sig))


def compiled(log, metadata, mode, expected_count):
    by_id = {package['id']: package for package in metadata['packages']}
    decoder_id = next(package['id'] for package in metadata['packages']
                      if package['name'] == 'serde_json')
    files, packages, test_binaries, decoder_features = {}, {}, [], []
    for line in log.read_text().splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if not isinstance(item, dict) or item.get('reason') != 'compiler-artifact':
            continue
        package_id = item['package_id']
        assert package_id in by_id, 'compiled package absent from verified graph: ' + package_id
        features = item['features']
        assert not {'test-utils', 'embedded-fixture', 'loopback-fixture'} & set(features)
        packages.setdefault(package_id, []).append({'features': features, 'target': item['target'],
                                                    'profile': item['profile'], 'fresh': item['fresh']})
        if package_id == decoder_id and 'lib' in item['target']['kind']:
            decoder_features.append(sorted(features))
        paths = set(item['filenames'])
        if item.get('executable'):
            paths.add(item['executable'])
        for filename in paths:
            path = Path(filename).resolve()
            relative = str(path.relative_to(TARGET.resolve()))
            assert path.is_file(), 'Cargo artifact is missing: ' + str(path)
            files[relative] = {'sha256': digest(path), 'bytes': path.stat().st_size,
                               'package_id': package_id, 'profile': item['profile'],
                               'executable': filename == item.get('executable')}
        if item.get('executable') and item['profile']['test']:
            path = Path(item['executable'])
            checksum = digest(path)
            preserve = OUTPUT / 'preserved-executables' / (checksum + '-' + path.name)
            if not preserve.exists():
                shutil.copy2(path, preserve)
            assert digest(preserve) == checksum
            test_binaries.append({'path': str(path), 'sha256': checksum,
                                  'preserved_path': str(preserve), 'package_id': package_id})
    expected = {'arbitrary_precision', 'default', 'raw_value', 'std'}
    if mode == 'ordered':
        expected |= {'indexmap', 'preserve_order'}
    assert decoder_features and all(set(features) == expected for features in decoder_features), \
        'compiled decoder features differ from verified mode: ' + repr(decoder_features)
    assert test_binaries, 'no exact test executable reported'
    summary = re.findall(r'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out', log.read_text())
    accepted = bool(summary) and all(row[0] == 'ok' and row[2:5] == ('0', '0', '0') for row in summary) and sum(int(row[1]) for row in summary) == expected_count
    return {'packages': packages, 'files': files, 'test_executables': test_binaries,
            'decoder_features': decoder_features, 'test_summaries': summary,
            'expected_test_count': expected_count, 'expected_count_passed': accepted}


for current_signal in (signal.SIGTERM, signal.SIGINT):
    signal.signal(current_signal, interrupted)
OUTPUT.mkdir(mode=0o700)
(OUTPUT / 'preserved-executables').mkdir(mode=0o700)
assert TARGET.is_dir() and not TARGET.is_symlink()
previous_path = Path('/tmp/kasumi-stock-sdk-selection-diagnostic-3f88b44/evidence.json')
assert digest(previous_path) == '43d7b072d144ef593d07dd073ee45993fb558548223ecb123d99111b29a219ba'
previous = json.loads(previous_path.read_bytes())
assert previous['status'] == 'passed' and previous['source'] == EXPECTED
assert all(gate['process_cleanup']['drained'] for gate in previous['gates'])
before = source_state()
assert before['commit'] == EXPECTED and before['status'] == ''
assert before['consumer_lock_sha256'] == 'a8e28648a99e39be408e011d28559ec2edbc8cc5c333f207b59315c438471699'
write('source-before.json', before)
env = dict(os.environ, PATH=str(TOOLS) + os.pathsep + os.environ['PATH'],
           CARGO_TARGET_DIR=str(TARGET), CARGO_BUILD_JOBS='1', RUST_TEST_THREADS='1',
           RUSTUP_TOOLCHAIN='1.97.1', RUSTC=str(TOOLS / 'rustc'), RUSTDOC=str(TOOLS / 'rustdoc'),
           PYTHONDONTWRITEBYTECODE='1', CARGO_TERM_COLOR='never')
cargo = str(TOOLS / 'cargo')
ordered = ['--features', 'kasumi-stock-json-sdk-consumer/ordered']
metadata_base = [cargo, 'metadata', '--manifest-path', MANIFEST, '--locked', '--format-version', '1']
test_base = [cargo, 'test', '--manifest-path', MANIFEST, '--locked', '-j1', '--message-format=json-render-diagnostics']
private = 'snapshot_decode::request::tests::canonical_wrapper_admission_bounds_actual_sorting_workspace'
gates = [
    ('metadata-ordered', metadata_base + ordered, None, None),
    ('guard-ordered', [sys.executable, 'external-tests/stock-json-sdk/check_graph.py', str(OUTPUT / 'metadata-ordered.stdout'), '--mode', 'ordered'], None, None),
    ('canonical-admission-ordered', test_base + ['-p', 'kasumi-stock-json-sdk-consumer', '-p', 'kasumi-client', '--lib'] + ordered + [private, '--', '--exact', '--test-threads=1'], 'ordered', 1),
    ('metadata-default', metadata_base, None, None),
    ('guard-default', [sys.executable, 'external-tests/stock-json-sdk/check_graph.py', str(OUTPUT / 'metadata-default.stdout'), '--mode', 'default'], None, None),
    ('public-default', test_base + ['--test', 'consumer', '--', '--test-threads=1'], 'default', 6),
    ('public-ordered', test_base + ordered + ['--test', 'consumer', '--', '--test-threads=1'], 'ordered', 6),
]
report = {
    'schema': 1, 'scope': 'Authorized external SDK-only client tests; no engine/store/server/Raft compilation or native listeners',
    'source': EXPECTED, 'tree': before['tree'], 'consumer_lock_sha256': before['consumer_lock_sha256'],
    'source_before_sha256': digest(OUTPUT / 'source-before.json'), 'runner_sha256': digest(__file__),
    'target': str(TARGET), 'warm_target_verified_prior': str(previous_path), 'jobs': 1, 'test_threads': 1, 'gates': [], 'status': 'running',
    'tools': {str(path): {'sha256': digest(path), 'version': output([str(path), '-V'])}
              for path in [TOOLS / 'cargo', TOOLS / 'rustc', TOOLS / 'rustdoc', Path(sys.executable)]},
    'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
}
write('evidence.json', report)
try:
    for name, command, mode, expected_count in gates:
        assert source_state() == before, 'frozen source changed before gate'
        print('START', name, flush=True)
        process, failure, expired = None, None, False
        start = time.monotonic()
        stdout_path, stderr_path = OUTPUT / (name + '.stdout'), OUTPUT / (name + '.stderr')
        with stdout_path.open('wb') as stdout, stderr_path.open('wb') as stderr:
            try:
                process = subprocess.Popen(command, cwd=SOURCE, env=env, stdout=stdout,
                                           stderr=stderr, start_new_session=True)
                write('progress.json', {'gate': name, 'pid': process.pid, 'group': process.pid,
                                       'command': command, 'timeout_seconds': 300})
                try:
                    code = process.wait(timeout=300)
                except subprocess.TimeoutExpired:
                    expired, code = True, 124
            except BaseException as error:
                failure, code = repr(error), 125
            finally:
                cleanup = drain(process) if process is not None else {'drained': True, 'after': []}
                for handle in (stdout, stderr):
                    handle.flush()
                    os.fsync(handle.fileno())
        unchanged = source_state() == before
        artifacts, artifact_error = None, None
        if mode:
            try:
                metadata = json.loads((OUTPUT / ('metadata-' + mode + '.stdout')).read_bytes())
                artifacts = compiled(stdout_path, metadata, mode, expected_count)
            except BaseException as error:
                artifact_error = repr(error)
        entry = {
            'name': name, 'command': command, 'timeout_seconds': 300, 'exit_code': code,
            'timed_out': expired, 'exception': failure, 'duration_seconds': round(time.monotonic() - start, 3),
            'stdout': stdout_path.name, 'stdout_sha256': digest(stdout_path),
            'stderr': stderr_path.name, 'stderr_sha256': digest(stderr_path),
            'process_cleanup': cleanup, 'source_unchanged': unchanged,
            'compiled_artifacts': artifacts, 'compiled_graph_error': artifact_error,
        }
        report['gates'].append(entry)
        failed = code != 0 or failure is not None or not cleanup['drained'] or not unchanged or artifact_error is not None or (mode and not artifacts['expected_count_passed'])
        report['status'] = 'failed' if failed else 'running'
        write('evidence.json', report)
        print('TERMINAL', name, 'exit', code, 'drained', cleanup['drained'], 'source_unchanged', unchanged, 'compiled_graph_error', artifact_error, flush=True)
        if failed:
            break
    else:
        report['status'] = 'passed'
except BaseException as error:
    report['status'] = 'failed'
    report['runner_error'] = repr(error)
finally:
    after = source_state()
    write('source-after.json', after)
    report['source_after_sha256'] = digest(OUTPUT / 'source-after.json')
    report['source_unchanged'] = after == before
    if after != before:
        report['status'] = 'failed'
    report['finished_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    write('evidence.json', report)
    write('progress.json', {'status': report['status'], 'terminal': True, 'gates': len(report['gates'])})
    print('COHORT', report['status'], 'evidence', OUTPUT / 'evidence.json', flush=True)
sys.exit(0 if report['status'] == 'passed' else 1)

