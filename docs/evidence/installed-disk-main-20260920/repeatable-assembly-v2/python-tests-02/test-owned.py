from pathlib import Path
import importlib, json, sys, unittest
sys.path[:0] = ['/Users/mtakemiya/dev/kasumi/target/installed-disk-validation/repeatable-assembly-v2/proposed/scripts', '/Users/mtakemiya/dev/kasumi/scripts']
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
