from pathlib import Path
import json
import os
import sys
import importlib

ROOT = Path('/Users/mtakemiya/dev/kasumi')
PROPOSAL = ROOT / 'target/installed-disk-validation/repeatable-assembly-v2'
DEST = PROPOSAL / 'python-tests-02'
DEST.mkdir(exist_ok=False)
sys.path[:0] = [str(PROPOSAL / 'proposed/scripts'), str(ROOT / 'scripts')]
import gate_process
from release_gate import sha256, write_json
interpreter = Path('/Users/mtakemiya/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3').resolve()
inner = DEST / 'test-owned.py'
inner.write_text('''from pathlib import Path
import importlib, json, sys, unittest
sys.path[:0] = ''' + repr([str(PROPOSAL / 'proposed/scripts'), str(ROOT / 'scripts')]) + '''
from release_gate import sha256, write_json
modules = [importlib.import_module(name) for name in ('test_repeatable_assembly', 'test_package_metadata', 'test_package_release', 'test_verify_release_acceptance')]
import verify_release_acceptance
root = Path(__file__).parent
paths = set()
for module in tuple(sys.modules.values()):
    name = getattr(module, '__file__', None)
    if name and not name.startswith('<'):
        paths.add(str(Path(name).resolve()))
paths.add(str(Path(__file__).resolve()))
before = {name: sha256(name) for name in sorted(paths)}
write_json(root / 'imports-before.json', before)
suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromModule(module) for module in modules)
result = unittest.TextTestRunner(verbosity=2).run(suite)
after = {name: sha256(name) for name in sorted(paths)}
write_json(root / 'imports-after.json', after)
new = sorted(set(str(Path(module.__file__).resolve()) for module in tuple(sys.modules.values()) if getattr(module, '__file__', None) and not module.__file__.startswith('<')) - paths)
write_json(root / 'new-imports.json', {name: sha256(name) for name in new})
write_json(root / 'unit-result.json', {'run': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors), 'skipped': len(result.skipped), 'unchanged_imports': before == after})
raise SystemExit(0 if result.wasSuccessful() and before == after else 1)
''')
write_json(DEST / 'command.json', {'command': [str(interpreter), '-B', str(inner)], 'cwd': str(ROOT),
            'runner_sha256': sha256(__file__), 'scope': 'Actual synthetic process unit tests; no native qualification or Cargo execution'})
env = os.environ.copy()
env['TMPDIR'] = str(ROOT / 'target/tmp')
env['PYTHONDONTWRITEBYTECODE'] = '1'
with (DEST / 'stdout.log').open('xb') as out, (DEST / 'stderr.log').open('xb') as err:
 result = gate_process.run([str(interpreter), '-B', str(inner)], ROOT, env, out, 300,
                           lambda value: write_json(DEST / 'process.json', value), stderr=err)
write_json(DEST / 'hashes.json', {str(p.relative_to(DEST)): sha256(p) for p in DEST.rglob('*') if p.is_file()})
print(json.dumps(result))
raise SystemExit(result['exit_code'])
