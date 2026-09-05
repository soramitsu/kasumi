#!/usr/bin/env python3
"""Keep a benchmark run attached to regular logs across Codex continuations."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

root = next(parent for parent in Path(__file__).resolve().parents
            if (parent / 'scripts/run_benchmark_matrix.py').is_file())
directory = root / 'benchmarks/results/network-rerun-macos-arm64-20260905-listener'
expected = '28aeb80168d3ab02a0eec7bf2a0163a7cb99dbfd74adf596e849de17e1fa3c1d'
spec = importlib.util.spec_from_file_location('matrix', root / 'scripts/run_benchmark_matrix.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
assert driver.source_identity() == expected, 'source must remain frozen'
assert directory.is_dir(), 'prepare the archived run directory before launch'
assert not (directory / 'execution.json').exists(), 'never overwrite an existing execution'
assert not (directory / 'matrix.json').exists(), 'never restart an existing matrix'
validation = ['../macos-validation-20260905-listener/evidence.json',
              '../linux-validation-20260905-listener/evidence.json']
for relative in validation:
    gate = json.loads((directory / relative).read_text())
    assert gate.get('status') == 'passed', f'validation gate must pass: {relative}'
    assert gate.get('source_sha256_before') == gate.get('source_sha256_after') == expected, \
        f'validation must bind the frozen source: {relative}'
minio_evidence = '../linux-validation-20260905-listener/minio-evidence.json'
minio = json.loads((directory / minio_evidence).read_text())
assert minio.get('status') == 'passed' and minio.get('exit_code') == 0, 'fresh MinIO gate must pass'
assert minio.get('client_source_sha256') == minio.get('source_sha256_after') == expected, \
    'MinIO gate must bind the frozen source'
release_evidence = '../macos-validation-20260905-listener/release-build.json'
release = json.loads((directory / release_evidence).read_text())
assert release.get('status') == 'passed' and release.get('exit_code') == 0, 'fresh release build must pass'
assert release.get('source_sha256_before') == release.get('source_sha256_after') == expected, \
    'release build must bind the frozen source'
for name, digest in release['executable_sha256'].items():
    assert hashlib.sha256((root / 'target/release' / name).read_bytes()).hexdigest() == digest, f'release executable changed: {name}'
assert (directory / 'execution-wrapper.py').read_bytes() == Path(__file__).read_bytes(), \
    'executed wrapper must match its archived source'
assert (directory / 'network-driver.py').read_bytes() == (root / 'target/run_network_listener_matrix.py').read_bytes()
command = ['/usr/bin/caffeinate', '-i', sys.executable,
           'target/run_network_listener_matrix.py', '--skip-build', '--output-directory', str(directory),
           '--documents', '1000000', '--tenants', '1,100,1000', '--operations', '1000',
           '--allow-host-load']
execution = {
    'format': 1, 'status': 'starting', 'wrapper_pid': os.getpid(),
    'wrapper_pgid': os.getpgrp(), 'command': command, 'cwd': str(root),
    'started_unix_seconds': time.time(), 'source_sha256_before': expected,
    'log': 'driver.log', 'stdio': 'regular file stdout/stderr; stdin is /dev/null',
    'wrapper_source': 'execution-wrapper.py',
    'wrapper_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    'continuation_survival': 'Outer wrapper is a separate OS session. No output pipe depends on the initiating tool handle.',
    'sleep_inhibition': 'caffeinate -i for driver lifetime; no global power settings changed',
    'validation': validation,
    'minio_validation': minio_evidence,
    'release_build': release_evidence,
    'host_qualification': 'Unrelated host activity is recorded; no isolated-host performance or external speed comparison claim.'
}

def checkpoint():
    temporary = directory / 'execution.tmp'
    temporary.write_text(json.dumps(execution, indent=2) + '\n')
    temporary.replace(directory / 'execution.json')

checkpoint()
child = subprocess.Popen(command, cwd=root, stdin=subprocess.DEVNULL)
execution.update(status='running', driver_pid=child.pid)
checkpoint()
try:
    result = child.wait()
    execution.update(status='passed' if result == 0 else 'failed', exit_code=result)
except BaseException as error:
    execution.update(status='wrapper_failed', error=repr(error))
    raise
finally:
    execution.update(finished_unix_seconds=time.time(), source_sha256_after=driver.source_identity())
    execution['log_sha256'] = hashlib.sha256((directory / 'driver.log').read_bytes()).hexdigest()
    checkpoint()
raise SystemExit(result)
