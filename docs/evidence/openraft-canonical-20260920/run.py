"""Capture scoped upstream checks without leaving the canonical Kasumi checkout."""
import datetime
import hashlib
import json
import os
import pathlib
import signal
import shutil
import subprocess
import sys
import time

root = pathlib.Path(__file__).resolve().parents[3]
source = root / "vendor/openraft-0.9.25"
evidence = pathlib.Path(__file__).resolve().parent
assert pathlib.Path.cwd() == root
attempt = evidence / sys.argv[1]
attempt.mkdir(exist_ok=False)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def capture(tag):
    entries = [
        {"path": str(path.relative_to(source)), "sha256": digest(path.read_bytes()), "bytes": path.stat().st_size, "mode": oct(path.stat().st_mode & 0o777)}
        for path in sorted(source.rglob("*")) if path.is_file()
    ]
    data = json.dumps(entries, sort_keys=True, indent=2).encode()
    (attempt / (tag + "-source.json")).write_bytes(data)
    return digest(data)

env = os.environ.copy()
toolchain = pathlib.Path('/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin')
env.update(PATH=str(toolchain) + os.pathsep + env['PATH'], RUSTUP_TOOLCHAIN="1.97.1", CARGO_TARGET_DIR=str(root / "target/openraft-qualification"), CARGO_BUILD_JOBS="2")
command = [str(toolchain / 'cargo'), *sys.argv[2:]]
record = {"command": command, "cwd": str(root), "environment": {key: env[key] for key in ('RUSTUP_TOOLCHAIN', 'CARGO_TARGET_DIR', 'CARGO_BUILD_JOBS')}, "source_before": capture('before'), "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "deadline_seconds": 1200}
for name, args in [('rustc', ['-Vv']), ('cargo', ['-V'])]:
    tool = toolchain / name
    record[name] = {"identity": subprocess.check_output([str(tool), *args], cwd=root, env=env).decode(), "path": str(tool), "sha256": digest(tool.read_bytes())}
start = time.monotonic()
with (attempt / 'output.log').open('wb') as log:
    child = subprocess.Popen(command, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    record['pid'] = record['process_group'] = child.pid
    (attempt / 'receipt.json').write_text(json.dumps(record, indent=2) + '\n')
    try:
        code = child.wait(timeout=record['deadline_seconds'])
    except subprocess.TimeoutExpired:
        record['deadline_exceeded'] = True
        os.killpg(child.pid, signal.SIGTERM)
        try:
            code = child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            code = child.wait()
generated = source / 'tests/_log'
if generated.exists():
    shutil.move(str(generated), attempt / 'generated-logs')
record.update(exit_code=code, elapsed_seconds=time.monotonic()-start, finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), source_after=capture('after'), log_sha256=digest((attempt/'output.log').read_bytes()))
processes = subprocess.check_output(['ps', '-eo', 'pid,pgid,command'], cwd=root).decode().splitlines()
remaining = [line for line in processes[1:] if len(line.split(None, 2)) >= 2 and line.split(None, 2)[1] == str(child.pid)]
record['remaining_process_group'] = remaining
record['process_group_drained'] = not remaining
(attempt / 'receipt.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps({key: record[key] for key in ('command', 'exit_code', 'elapsed_seconds', 'source_before', 'source_after', 'process_group_drained')}))
print((attempt/'output.log').read_text()[-10000:])
sys.exit(code or int(bool(remaining)) or int(record['source_before'] != record['source_after']))
