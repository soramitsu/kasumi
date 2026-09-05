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

root = Path(__file__).resolve().parent.parent
directory = root / 'benchmarks/results/release-matrix-macos-arm64-20260905-05'
expected = 'fffa308bc84d9ab5d015ec7f7f0c33af9b592d04a49ff0005b5633c4ab58ed33'
spec = importlib.util.spec_from_file_location('matrix', root / 'scripts/run_benchmark_matrix.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
assert driver.source_identity() == expected, 'source must remain frozen'
command = ['/usr/bin/caffeinate', '-i', sys.executable,
           'scripts/run_benchmark_matrix.py', '--output-directory', str(directory),
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
    'validation': ['../macos-validation-20260905-shutdown/evidence.json',
                   '../linux-validation-20260905-shutdown/evidence.json'],
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
