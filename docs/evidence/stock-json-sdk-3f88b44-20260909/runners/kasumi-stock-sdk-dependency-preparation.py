#!/usr/bin/env python3
"""Explicitly authorized graph preparation only: no build, test, or native work."""
from pathlib import Path
import datetime
import hashlib
import json
import os
import signal
import subprocess
import sys
import time

SOURCE = Path('/tmp/kasumi-stock-sdk-consumer').resolve()
OUTPUT = Path('/tmp/kasumi-stock-sdk-dependency-preparation-9aad42e')
TARGET = Path('/tmp/kasumi-stock-sdk-consumer-target')
TOOLS = Path('/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin')
EXPECTED = '9aad42eb6754b4d6eedad801497fe7eac0162015'
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


for current_signal in (signal.SIGTERM, signal.SIGINT):
    signal.signal(current_signal, interrupted)
OUTPUT.mkdir(mode=0o700)
before = source_state()
assert before['commit'] == EXPECTED and before['status'] == ''
assert before['consumer_lock_sha256'] is None
write('source-before.json', before)
env = dict(os.environ, PATH=str(TOOLS) + os.pathsep + os.environ['PATH'],
           CARGO_TARGET_DIR=str(TARGET), CARGO_BUILD_JOBS='1', RUST_TEST_THREADS='1',
           RUSTUP_TOOLCHAIN='1.97.1', RUSTC=str(TOOLS / 'rustc'), RUSTDOC=str(TOOLS / 'rustdoc'),
           PYTHONDONTWRITEBYTECODE='1', CARGO_TERM_COLOR='never')
cargo = str(TOOLS / 'cargo')
gates = [('generate-lockfile', [cargo, 'generate-lockfile', '--manifest-path', MANIFEST])]
for mode, features in [('default', []), ('ordered', ['--features', 'ordered'])]:
    gates += [
        ('metadata-' + mode, [cargo, 'metadata', '--manifest-path', MANIFEST,
                             '--locked', '--format-version', '1'] + features),
        ('guard-' + mode, [sys.executable, 'external-tests/stock-json-sdk/check_graph.py',
                          str(OUTPUT / ('metadata-' + mode + '.stdout')), '--mode', mode]),
    ]
config_paths = [Path.home() / '.cargo/config', Path.home() / '.cargo/config.toml']
config_paths += [parent / '.cargo' / name for parent in [SOURCE, *SOURCE.parents]
                 for name in ('config', 'config.toml')]
report = {
    'schema': 1, 'scope': 'External stock SDK dependency preparation only; no Rust compilation or native execution',
    'source': EXPECTED, 'tree': before['tree'], 'source_before_sha256': digest(OUTPUT / 'source-before.json'),
    'runner_sha256': digest(__file__), 'target': str(TARGET), 'jobs': 1, 'gates': [], 'status': 'running',
    'tools': {str(path): {'sha256': digest(path), 'version': output([str(path), '-V'])}
              for path in [TOOLS / 'cargo', TOOLS / 'rustc', TOOLS / 'rustdoc', Path(sys.executable)]},
    'cargo_configuration_hashes': {str(path): digest(path) for path in config_paths if path.is_file()},
    'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
}
write('evidence.json', report)
resolved_lock = None
try:
    for name, command in gates:
        current = source_state()
        assert unchanged_source(before, current), 'frozen source changed before gate'
        if resolved_lock is not None:
            assert digest(LOCK) == resolved_lock, 'locked dependency graph changed before gate'
        print('START', name, flush=True)
        process = None
        failure = None
        expired = False
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
        after = source_state()
        unchanged = unchanged_source(before, after)
        lock_now = after['consumer_lock_sha256']
        if name == 'generate-lockfile' and code == 0:
            assert lock_now is not None, 'successful resolver did not create lock'
            resolved_lock = lock_now
        lock_stable = resolved_lock is None or lock_now == resolved_lock
        report['gates'].append({
            'name': name, 'command': command, 'timeout_seconds': 300, 'exit_code': code,
            'timed_out': expired, 'exception': failure, 'duration_seconds': round(time.monotonic() - start, 3),
            'stdout': stdout_path.name, 'stdout_sha256': digest(stdout_path),
            'stderr': stderr_path.name, 'stderr_sha256': digest(stderr_path),
            'process_cleanup': cleanup, 'tracked_source_unchanged': unchanged,
            'consumer_lock_sha256': lock_now, 'locked_graph_unchanged': lock_stable,
        })
        failed = code != 0 or failure is not None or not cleanup['drained'] or not unchanged or not lock_stable
        report['status'] = 'failed' if failed else 'running'
        write('evidence.json', report)
        print('TERMINAL', name, 'exit', code, 'drained', cleanup['drained'], 'source_unchanged', unchanged, flush=True)
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
    report['tracked_source_unchanged'] = unchanged_source(before, after)
    report['consumer_lock_sha256'] = after['consumer_lock_sha256']
    if not report['tracked_source_unchanged']:
        report['status'] = 'failed'
    report['finished_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    write('evidence.json', report)
    write('progress.json', {'status': report['status'], 'terminal': True, 'gates': len(report['gates'])})
    print('COHORT', report['status'], 'evidence', OUTPUT / 'evidence.json', flush=True)
sys.exit(0 if report['status'] == 'passed' else 1)
