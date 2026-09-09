#!/usr/bin/env python3
"""Execute one frozen, bounded Kasumi gate plan and retain owned-process evidence."""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time

CANCELLED = None


def interrupted(number, _frame):
    # Never raise between Popen returning and assignment, or during cleanup.
    global CANCELLED
    CANCELLED = number


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def query(root, command):
    return subprocess.check_output(command, cwd=root, text=True, timeout=20).strip()


def state(root):
    names = subprocess.check_output(['git', 'ls-files', '-z'], cwd=root, timeout=20).decode().split('\0')
    return {
        'head': query(root, ['git', 'rev-parse', 'HEAD']),
        'tree': query(root, ['git', 'rev-parse', 'HEAD^{tree}']),
        'status': query(root, ['git', 'status', '--porcelain=v1', '--untracked-files=all']),
        'lock_sha256': digest(root / 'Cargo.lock'),
        'files': {name: digest(root / name) for name in names if name},
    }


def atomic(path, value):
    pending = path.with_suffix(path.suffix + '.pending')
    with pending.open('w') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    pending.replace(path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def alive(group):
    # Darwin can return EPERM for a just-reaped group when probed with signal 0.
    # Inspect exact numeric membership; never infer drain from the leader alone.
    listing = subprocess.check_output(['ps', '-axo', 'pid=,ppid=,pgid=,stat='], text=True, timeout=20)
    return any(len(fields := line.split()) == 4 and fields[2] == str(group)
               for line in listing.splitlines())


def drain(process):
    remaining = alive(process.pid)
    actions = []
    for number in (signal.SIGTERM, signal.SIGKILL):
        if not alive(process.pid):
            break
        try:
            os.killpg(process.pid, number)
            actions.append(signal.Signals(number).name)
        except ProcessLookupError:
            break
        until = time.monotonic() + 10
        while time.monotonic() < until:
            process.poll()
            if not alive(process.pid):
                break
            time.sleep(.05)
    process.poll()
    return {'group': process.pid, 'remaining_after_command': remaining,
            'signals': actions, 'drained': not alive(process.pid),
            'process_returncode': process.returncode}


def collect(log, target, preserved):
    artifacts, packages = {}, {}
    with log.open(errors='replace') as stream:
        for line in stream:
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if not isinstance(value, dict) or value.get('reason') != 'compiler-artifact':
                continue
            package = value['package_id']
            features = sorted(value.get('features', []))
            packages.setdefault(package, [])
            entry = {'features': features, 'target': value.get('target'), 'profile': value.get('profile')}
            if entry not in packages[package]:
                packages[package].append(entry)
            if not value.get('executable'):
                continue
            executable = Path(value['executable']).resolve()
            relative = str(executable.relative_to(target))
            checksum = digest(executable)
            copied = preserved / (checksum + '-' + executable.name)
            if not copied.exists():
                shutil.copy2(executable, copied)
            if digest(copied) != checksum:
                raise RuntimeError('preserved executable digest changed')
            artifacts[relative] = {'sha256': checksum, 'bytes': executable.stat().st_size,
                                   'preserved_path': str(copied), 'package_id': package,
                                   'features': features, 'profile': value.get('profile')}
    return artifacts, packages


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--plan', required=True, type=Path)
    args = parser.parse_args()
    plan = json.loads(args.plan.read_bytes())
    root, target, output = [Path(plan[key]).resolve() for key in ('source', 'target', 'output')]
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, interrupted)
    locks = []
    for path in (root, target):
        name = hashlib.sha256(str(path).encode()).hexdigest()
        handle = open('/tmp/kasumi-focused-' + name + '.lock', 'a')
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        locks.append(handle)
    before = state(root)
    if before['head'] != plan['expected_head'] or before['tree'] != plan['expected_tree'] or before['status']:
        raise RuntimeError('source does not match frozen clean plan')
    output.mkdir(mode=0o700)
    preserved = output / 'preserved-executables'
    preserved.mkdir(mode=0o700)
    atomic(output / 'source-before.json', before)
    shutil.copy2(args.plan, output / 'plan.json')
    shutil.copy2(__file__, output / 'runner.py')
    tools = Path(query(root, ['rustup', 'which', '--toolchain', '1.97.1', 'cargo'])).parent
    environment = dict(os.environ, RUSTUP_TOOLCHAIN='1.97.1', RUSTC=str(tools / 'rustc'),
                       RUSTDOC=str(tools / 'rustdoc'), CARGO_TARGET_DIR=str(target),
                       CARGO_BUILD_JOBS='1', RUST_TEST_THREADS='1', CARGO_TERM_COLOR='never',
                       PYTHONDONTWRITEBYTECODE='1', PATH=str(tools) + os.pathsep + os.environ['PATH'])
    record = {'scope': plan['scope'], 'status': 'running', 'source': before['head'],
              'tree': before['tree'], 'source_manifest_sha256': digest(output / 'source-before.json'),
              'lock_sha256': before['lock_sha256'], 'runner_sha256': digest(__file__),
              'plan_sha256': digest(args.plan), 'target': str(target),
              'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'tools': {str(tools / name): digest(tools / name) for name in ('cargo', 'rustc', 'rustdoc')},
              'gates': [dict(gate, status='not_run') for gate in plan['gates']]}
    evidence = output / 'evidence.json'
    atomic(evidence, record)
    try:
        for gate in record['gates']:
            if CANCELLED is not None:
                raise InterruptedError('cancelled before dispatch: ' + str(CANCELLED))
            if state(root) != before:
                raise RuntimeError('source changed before dispatch')
            command = [str(tools / 'cargo'), *gate['cargo_args']]
            gate.update(status='running', command=command)
            atomic(evidence, record)
            log = output / (gate['name'] + '.log')
            started = time.monotonic()
            process, error, code, cleanup = None, None, None, None
            print('START', gate['name'], flush=True)
            with log.open('wb') as stream:
                try:
                    process = subprocess.Popen(command, cwd=root, env=environment, stdout=stream,
                                               stderr=subprocess.STDOUT, start_new_session=True)
                    gate['process_group'] = process.pid
                    atomic(evidence, record)
                    while True:
                        code = process.poll()
                        if code is not None:
                            break
                        if CANCELLED is not None:
                            raise InterruptedError('cancelled: ' + str(CANCELLED))
                        if time.monotonic() - started >= gate['timeout_seconds']:
                            raise TimeoutError('original gate timeout exceeded')
                        time.sleep(.1)
                except BaseException as caught:
                    error = repr(caught)
                finally:
                    if process is not None:
                        try:
                            cleanup = drain(process)
                        except BaseException as caught:
                            # An inspection/signal failure is uncertain custody,
                            # never proof that this process group is absent.
                            cleanup = {'group': process.pid, 'drained': False,
                                       'error': repr(caught), 'membership': 'unknown',
                                       'process_returncode': process.poll()}
                    stream.flush()
                    os.fsync(stream.fileno())
            gate.update(duration_seconds=round(time.monotonic() - started, 3),
                        process_exit_code=code, error=error, cleanup=cleanup,
                        log=log.name, log_sha256=digest(log), source_unchanged=state(root) == before)
            try:
                gate['executables'], gate['compiled_packages'] = collect(log, target, preserved)
                content = log.read_text(errors='replace')
                gate['required_tests_passed'] = all('test ' + name + ' ... ok' in content for name in gate.get('required_tests', []))
                summaries = re.findall(r'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored;', content)
                gate['test_summaries'] = summaries
                if command[1] == 'test':
                    gate['required_tests_passed'] &= bool(summaries) and all(row[0] == 'ok' and row[2] == '0' for row in summaries) and sum(int(row[1]) for row in summaries) > 0
                    if not any(value.get('profile', {}).get('test') for value in gate['executables'].values()):
                        raise RuntimeError('test result has no preserved test executable')
            except BaseException as caught:
                gate['artifact_error'] = repr(caught)
            passed = (code == 0 and error is None and cleanup is not None and cleanup['drained']
                      and not cleanup['remaining_after_command'] and gate['source_unchanged']
                      and gate.get('required_tests_passed', False) and not gate.get('artifact_error'))
            gate['status'] = 'passed' if passed else 'failed'
            print('TERMINAL', gate['name'], gate['status'], cleanup, flush=True)
            atomic(evidence, record)
            if not passed:
                raise RuntimeError('gate failed: ' + gate['name'])
        record['status'] = 'passed'
    except BaseException as caught:
        record['status'] = 'failed'
        record['error'] = repr(caught)
        for gate in record['gates']:
            if gate['status'] == 'running':
                gate.update(status='failed', terminal_error=repr(caught))
    finally:
        record['finished_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        try:
            record['source_unchanged'] = state(root) == before
        except BaseException as caught:
            record['source_unchanged'] = False
            record['source_inspection_error'] = repr(caught)
        if not record['source_unchanged']:
            record['status'] = 'failed'
        atomic(evidence, record)
    return 0 if record['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
