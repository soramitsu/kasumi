#!/usr/bin/env python3
"""Prepare pinned tools and both complete graphs; never compile redb itself."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess


SOURCE = Path('/workspace')
OUTPUT = Path('/opt/verification')
LOCKS = {
    'Cargo.lock': 'de059020b773066b6abc56c3efe207eb6e6106f19a9145eaa9f41c6ceff4bcaf',
    'fuzz/Cargo.lock': '4095adc5bd8218e8d8f72ad9476344ca3793d2f2996e795607910666f385ec3e',
}
TOOLS = {'just': '1.36.0', 'cargo-deny': '0.20.2', 'cargo-fuzz': '0.12.0'}


def checksum(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def inventory(root):
    """Inventory a privately owned tree, propagating incomplete traversal errors."""
    root = Path(root)
    entries = {}

    def visit(path):
        metadata = path.lstat()
        mode = metadata.st_mode
        name = str(path.relative_to(root))
        if stat.S_ISLNK(mode):
            raise RuntimeError(f'unexpected input symlink: {path}')
        if stat.S_ISDIR(mode):
            entries[name] = {'kind': 'directory', 'mode': stat.S_IMODE(mode)}
            with os.scandir(path) as children:
                names = sorted(child.name for child in children)
            for child in names:
                visit(path / child)
        elif stat.S_ISREG(mode):
            entries[name] = {'kind': 'file', 'mode': stat.S_IMODE(mode),
                             'size': metadata.st_size, 'sha256': checksum(path)}
        else:
            raise RuntimeError(f'unexpected input file type: {path}')

    if not stat.S_ISDIR(root.lstat().st_mode):
        raise RuntimeError(f'inventory root is not a real directory: {root}')
    visit(root)
    return entries


def source_inventory(source, locks):
    before = inventory(source)
    for forbidden in ('.git', 'target', 'fuzz/target', 'fuzz/corpus', 'fuzz/artifacts'):
        if forbidden in before:
            raise RuntimeError(f'archive contains checkout or generated state: {forbidden}')
    for name, expected in locks.items():
        if before.get(name, {}).get('sha256') != expected:
            raise RuntimeError(f'unrecognized verification lock: {name}')
    return before


def run(arguments, *, stdout=None):
    return subprocess.run(arguments, cwd=SOURCE, check=True, stdout=stdout)


def query(arguments):
    return subprocess.check_output(arguments, cwd=SOURCE, text=True).strip()


def main():
    before = source_inventory(SOURCE, LOCKS)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    if (OUTPUT / 'prepared.json').exists():
        raise RuntimeError('preparation output already has a completion manifest')
    (OUTPUT / 'source-inputs.json').write_text(json.dumps(before, indent=2) + '\n')
    tools = {}
    for name, version in TOOLS.items():
        run(['cargo', 'install', '--locked', '-j1', '--root', str(OUTPUT / 'tools'),
             '--version', version, name])
        installed = OUTPUT / 'tools/bin' / name
        candidates = list((OUTPUT / 'cargo/registry/src').glob(f'*/{name}-{version}/Cargo.lock'))
        if len(candidates) != 1:
            raise RuntimeError(f'tool requires one retained packaged lock: {name}')
        lock = OUTPUT / f'{name}-Cargo.lock'
        shutil.copy2(candidates[0], lock)
        command = ['just', '--version'] if name == 'just' else ['cargo', name[6:], '--version']
        reported = query(command)
        if version not in reported.split():
            raise RuntimeError(f'installed tool version differs: {reported}')
        tools[name] = {'version': version, 'reported_version': reported,
                       'executable_sha256': checksum(installed),
                       'packaged_lock_sha256': checksum(lock)}
    with (OUTPUT / 'vendor-config.toml').open('w') as config:
        run(['cargo', 'vendor', '--locked', '--sync', 'fuzz/Cargo.toml',
             '--versioned-dirs', '/vendor'], stdout=config)
    original = (SOURCE / 'deny.toml').read_text()
    declaration = 'db-path = "~/.cargo/advisory-db"'
    if original.count(declaration) != 1:
        raise RuntimeError('upstream advisory database configuration changed')
    deny = OUTPUT / 'deny.toml'
    deny.write_text(original.replace(declaration,
                                    'db-path = "/opt/verification/advisory-db"'))
    run(['cargo', 'deny', '--locked', '--workspace', '--all-features',
         '--config', str(deny), 'fetch', 'db', 'index'])
    advisory = {}
    for directory, children, _ in os.walk(OUTPUT / 'advisory-db'):
        if '.git' in children:
            children.remove('.git')
            git = ['git', '--no-optional-locks', '-C', directory]
            if query(git + ['status', '--porcelain', '--untracked-files=all']):
                raise RuntimeError(f'advisory database has uncommitted inputs: {directory}')
            timestamps = {}
            for name in ('HEAD', 'FETCH_HEAD'):
                path = Path(directory) / '.git' / name
                if path.exists():
                    timestamps[name] = path.stat().st_mtime_ns
            advisory[directory] = {
                'commit': query(git + ['rev-parse', 'HEAD']),
                'commit_timestamp': query(git + ['show', '-s', '--format=%cI', 'HEAD']),
                'git_timestamp_inputs_ns': timestamps,
            }
    if not advisory:
        raise RuntimeError('no pinned advisory database checkout was retained')
    for name in ('cargo', 'rustc', 'rustdoc', 'rustfmt', 'clippy-driver'):
        path = query(['rustup', 'which', '--toolchain', '1.97.1', name])
        tools[name] = {'path': path, 'sha256': checksum(path)}
    after = inventory(SOURCE)
    if before != after:
        raise RuntimeError('dependency preparation changed a source input')
    packages = query(['dpkg-query', '--show', '--showformat=${Package}\t${Version}\n'])
    (OUTPUT / 'debian-packages.txt').write_text(packages + '\n')
    result = {
        'scope': 'Tools compiled; complete root and fuzz graphs vendored. No redb test or build ran.',
        'status': 'prepared',
        'source_inputs_sha256': checksum(OUTPUT / 'source-inputs.json'),
        'locks': LOCKS, 'tools': tools, 'advisory_databases': advisory,
        'advisory_inputs': inventory(OUTPUT / 'advisory-db'),
        'vendor': inventory(Path('/vendor')),
        'registry_index': inventory(OUTPUT / 'cargo/registry/index'),
        'debian_packages_sha256': checksum(OUTPUT / 'debian-packages.txt'),
        'vendor_config_sha256': checksum(OUTPUT / 'vendor-config.toml'),
        'deny_config_sha256': checksum(deny),
    }
    (OUTPUT / 'prepared.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
