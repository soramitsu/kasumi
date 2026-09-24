"""Preserve immutable reviewed ownership prerequisites and terminal regressions."""
from pathlib import Path
import hashlib
import json
import subprocess

root = Path('/Users/mtakemiya/dev/kasumi')
assert subprocess.check_output(['git', 'branch', '--show-current'], cwd=root, text=True).strip() == 'master'
source = root / 'target/installed-disk-validation'
destination = root / 'docs/evidence/installed-disk-main-20260920'
manifest_path = destination / 'raw-sha256.json'
manifest = json.loads(manifest_path.read_text())
previous = len(manifest)
for name, expected in manifest.items():
    assert hashlib.sha256((destination / name).read_bytes()).hexdigest() == expected, name
files = {Path(__file__).resolve(), source / '107-prerequisites-applied.json',
         source / '107-retained-close-applied.json', source / '107-recovery-diagnostics-applied.json'}
for name in ['102-redb-terminal-corrections', '105-stopped-epoch-leader-fixture',
             '105-stopped-epoch-leader-fixture-authority-review',
             'redb-retained-database-close', 'redb-retained-database-close-revision2',
             'redb-retained-database-close-revision2-authority-review',
             'recovery-lifecycle-103-diagnostics', '113-control-leader-diagnostics',
             'unified-inode-census']:
    files.update(p for p in (source / name).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
# This package also contains ongoing successor work. Preserve only its frozen
# LRU proof and initial workspace audit, not partially written successor files.
workspace = source / 'redb-staging-workspace'
for name in ['cache.patch', 'cache-manifest.json', 'cache-review.md', 'native-receipt.json',
             'run-native.py', 'rustc-version.txt', 'compile-before.log', 'run-before.log',
             'compile-proposed.log', 'run-proposed.log', 'cache-tests.inc.rs',
             'native-extra.inc.rs', 'lru-before-tests', 'lru-proposed-tests',
             'workspace-derivation.md', 'workspace-source-manifest.json', 'plan-update.patch',
             'allocator-shape.py', 'allocator-shape.json']:
    files.add(workspace / name)
for name in ['before', 'proposed', 'native-input']:
    files.update(p for p in (workspace / name).rglob('*') if p.is_file())
attempts = []
for number in range(107, 114):
    receipt = source / f'{number}-result.json'
    if not receipt.exists():
        continue
    record = json.loads(receipt.read_text())
    assert record['drained'] and record['cwd'] == str(root), receipt
    attempts.append(number)
    files.add(source / f'run{number}.py')
    files.update(p for p in source.glob(f'{number}-*') if p.is_file())
omitted = []
for path in sorted(files):
    assert not path.is_symlink(), path
    relative = path.relative_to(source)
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if data[:4] in (b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe', b'\x7fELF', b'\xca\xfe\xba\xbe'):
        omitted.append({'path': str(relative), 'bytes': len(data), 'sha256': digest,
                        'reason': 'Native development executable remains under target; source, receipts and digest are archived.'})
        continue
    target = destination / relative
    if target.exists():
        assert target.read_bytes() == data, str(relative)
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    name = str(relative)
    if name in manifest:
        assert manifest[name] == digest, name
    else:
        manifest[name] = digest
omission_name = 'retained-prerequisites-probe-binary-omissions.json'
data = (json.dumps(omitted, indent=2) + '\n').encode()
target = destination / omission_name
if target.exists():
    assert target.read_bytes() == data
else:
    target.write_bytes(data)
manifest[omission_name] = hashlib.sha256(data).hexdigest()
manifest_path.write_text(json.dumps(dict(sorted(manifest.items())), indent=2) + '\n')
for name, expected in manifest.items():
    assert hashlib.sha256((destination / name).read_bytes()).hexdigest() == expected, name
print(json.dumps({'previous_entries_verified': previous, 'entries_verified': len(manifest),
                  'completed_attempts_archived': attempts,
                  'probe_binaries_retained_only_in_target': len(omitted)}))
