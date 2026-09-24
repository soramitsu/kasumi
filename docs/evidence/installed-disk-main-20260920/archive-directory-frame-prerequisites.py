"""Preserve frozen directory and exact-binary frame evidence, excluding native binaries."""
from pathlib import Path
import hashlib
import json
import shutil
import subprocess

root = Path('/Users/mtakemiya/dev/kasumi')
assert subprocess.check_output(['git', 'branch', '--show-current'], cwd=root, text=True).strip() == 'master'
source = root / 'target/installed-disk-validation'
destination = root / 'docs/evidence/installed-disk-main-20260920'
manifest_path = destination / 'raw-sha256.json'
manifest = json.loads(manifest_path.read_text())
previous = len(manifest)


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            result.update(block)
    return result.hexdigest()


for name, expected in manifest.items():
    assert digest(destination / name) == expected, name

packages = {
    'directory-parent-transitions': 'b5bea40431424e1a0be392e08a8c409fbce6d2c3000a05bd8057ac0135218775',
    '123-lifecycle-static-stack': 'ac24bec4732c65f6600f2b9017b4d0cefab0ba0c609d50028834d0940880a604',
}
files = {Path(__file__).resolve()}
for name, expected in packages.items():
    directory = source / name
    assert digest(directory / 'manifest.json') == expected, name
    files.update(p for p in directory.rglob('*') if p.is_file() and '__pycache__' not in p.parts)

omissions = []
for path in sorted(files):
    assert not path.is_symlink(), path
    relative = str(path.relative_to(source))
    actual = digest(path)
    with path.open('rb') as stream:
        magic = stream.read(8)
    native = magic[:4] in (b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe', b'\x7fELF', b'\xca\xfe\xba\xbe')
    dependency = path.suffix in ('.rlib', '.rmeta', '.dylib', '.so') or magic == b'!<arch>\n'
    if native or dependency:
        omissions.append({'path': relative, 'bytes': path.stat().st_size, 'sha256': actual,
                          'reason': 'Native development executable/dependency remains under target; source, inventory and receipts are archived.'})
        continue
    target = destination / relative
    if target.exists():
        assert digest(target) == actual, relative
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        assert digest(target) == actual, relative
    if relative in manifest:
        assert manifest[relative] == actual, relative
    else:
        manifest[relative] = actual

name = 'directory-frame-native-binary-omissions.json'
data = (json.dumps(omissions, indent=2) + '\n').encode()
target = destination / name
if target.exists():
    assert target.read_bytes() == data
else:
    target.write_bytes(data)
manifest[name] = hashlib.sha256(data).hexdigest()
manifest_path.write_text(json.dumps(dict(sorted(manifest.items())), indent=2) + '\n')
for name, expected in manifest.items():
    assert digest(destination / name) == expected, name
print(json.dumps({'previous_entries_verified': previous, 'entries_verified': len(manifest),
                  'native_binaries_retained_only_in_target': len(omissions),
                  'directory_package_status': 'UNAPPLIED_NOT_MERGE_READY',
                  'frame_package_status': 'STATIC_ONLY'}))
