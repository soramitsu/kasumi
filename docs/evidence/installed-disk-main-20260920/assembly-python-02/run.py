from pathlib import Path
import hashlib
import json
import os
import shutil
import sys

ROOT = Path('/Users/mtakemiya/dev/kasumi')
EVIDENCE = ROOT / 'target/installed-disk-validation/assembly-python-02'
sys.path.insert(0, str(ROOT / 'scripts'))
import gate_process
from release_gate import write_json

FILES = ('scripts/assembly_inputs.py', 'scripts/check_dependency_patches.py', 'scripts/fetch_openbao.py', 'scripts/gate_process.py', 'scripts/package_release.py', 'scripts/release_gate.py', 'scripts/release_host.py', 'scripts/repeatable_assembly.py', 'scripts/report_benchmark_capacity.py', 'scripts/run_benchmark_matrix.py', 'scripts/small_native_smoke.py', 'scripts/test_benchmark_matrix.py', 'scripts/test_check_dependency_patches.py', 'scripts/test_package_metadata.py', 'scripts/test_package_release.py', 'scripts/test_release_gate.py', 'scripts/test_release_host.py', 'scripts/test_repeatable_assembly.py', 'scripts/test_small_native_smoke.py', 'scripts/test_verify_release_acceptance.py', 'scripts/verify_release_acceptance.py', 'docs/release-artifacts.md', 'docs/repeatable-assembly.md', '.github/workflows/release-candidate.yml')

def file_record(path):
    raw = path.read_bytes()
    return {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw),
            'mode': oct(path.stat().st_mode & 0o777)}

def inputs():
    return {relative: file_record(ROOT / relative) for relative in FILES}

assert Path.cwd() == ROOT
before = inputs()
write_json(EVIDENCE / 'source-before.json', before)
for relative in FILES:
    copy = EVIDENCE / 'sources' / relative
    copy.parent.mkdir(parents=True, exist_ok=True)
    with copy.open('xb') as stream:
        stream.write((ROOT / relative).read_bytes())
command = [sys.executable, '-B', '-m', 'unittest', 'discover', '-s', 'scripts', '-p', 'test_*.py', '-v']
environment = dict(os.environ)
environment.update(TMPDIR=str(ROOT / 'target/tmp'), PYTHONDONTWRITEBYTECODE='1',
                   PYTHONPATH=str(ROOT / 'scripts'))
write_json(EVIDENCE / 'invocation.json', {
    'command': command, 'working_directory': str(ROOT), 'timeout_seconds': 600,
    'environment_overrides': {key: environment[key] for key in ('TMPDIR', 'PYTHONDONTWRITEBYTECODE', 'PYTHONPATH')},
    'python': {'path': sys.executable, 'resolved_path': str(Path(sys.executable).resolve()),
               'version': sys.version, **file_record(Path(sys.executable))},
    'runner': file_record(Path(__file__)), 'source_inventory': before,
    'qualification_scope': 'Complete Python tooling unit discovery including assembly custody; synthetic children only, no native Cargo/full candidate pair or acceptance qualification',
})
with (EVIDENCE / 'stdout.log').open('xb') as stdout, (EVIDENCE / 'stderr.log').open('xb') as stderr:
    process = gate_process.run(command, ROOT, environment, stdout, 600,
                               lambda receipt: write_json(EVIDENCE / 'process.json', receipt),
                               stderr=stderr)
after = inputs()
write_json(EVIDENCE / 'source-after.json', after)
fresh_members = gate_process.group_members(process['process_group']) if process['process_group'] else None
result = {
    'status': 'passed' if process['status'] == 'passed' and before == after and fresh_members == [] else 'failed',
    'process_status': process['status'], 'exit_code': process['exit_code'],
    'source_unchanged': before == after, 'fresh_group_members': fresh_members,
    'process': file_record(EVIDENCE / 'process.json'),
    'stdout': file_record(EVIDENCE / 'stdout.log'), 'stderr': file_record(EVIDENCE / 'stderr.log'),
}
write_json(EVIDENCE / 'result.json', result)
print(json.dumps(result, indent=2))
sys.exit(0 if result['status'] == 'passed' else 1)
