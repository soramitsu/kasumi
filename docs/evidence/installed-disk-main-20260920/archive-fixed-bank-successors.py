"""Append immutable fixed-bank/policy/lifecycle evidence; never replace history.

Only Python/archive work runs. Native executable/dependency bytes are inventoried,
not copied. External inventory references are preserved without opening them.
Optional134 evidence is selected only once its original result is terminal/drained.
"""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess

ROOT = Path('/Users/mtakemiya/dev/kasumi')
SOURCE = ROOT / 'target/installed-disk-validation'
DESTINATION = ROOT / 'docs/evidence/installed-disk-main-20260920'
MANIFEST = DESTINATION / 'raw-sha256.json'
INPUTS = SOURCE / 'archive-fixed-bank-successors/inputs.json'
INPUT_SHA = '6d034a70f4d349d918f76e1dcef6f43043d9001fa918355f9c1cb20aefd1e07e'
BINARY_SUFFIXES = {'.rlib', '.rmeta', '.dylib', '.so', '.a', '.o', '.dll', '.exe'}
NATIVE_MAGIC = {
    b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xfe\xed\xfa\xce',
    b'\x7fELF', b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca', b'\xca\xfe\xba\xbf',
}


def require(condition, detail):
    if not condition:
        raise RuntimeError(str(detail))


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            result.update(block)
    return result.hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def safe_relative(name):
    path = Path(name)
    require(not path.is_absolute() and '..' not in path.parts, name)
    return path


def verify_archive(manifest):
    for name, expected in manifest.items():
        path = DESTINATION / safe_relative(name)
        require(not path.is_symlink(), path)
        require(digest(path) == expected, f'Archive hash differs: {name}')


def create_only(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open('xb') as stream:
            stream.write(data)
    except FileExistsError:
        require(not path.is_symlink() and path.read_bytes() == data,
                f'Existing evidence differs: {path}')


def main():
    require(subprocess.check_output(['git', 'branch', '--show-current'], cwd=ROOT,
                                   text=True).strip() == 'master', 'master required')
    old_bytes = MANIFEST.read_bytes()
    old = json.loads(old_bytes)
    require(len(old) >= 2774, 'Original2774-entry archive missing')
    verify_archive(old)
    require(digest(INPUTS) == INPUT_SHA, 'Pinned input inventory changed')
    inputs = json.loads(INPUTS.read_text())
    files = {Path(__file__).resolve(), INPUTS}
    for name, expected in inputs['controls'].items():
        require(digest(SOURCE / safe_relative(name)) == expected, name)
    for name, record in inputs['files'].items():
        path = SOURCE / safe_relative(name)
        require(not path.is_symlink() and path.stat().st_size == record['bytes']
                and digest(path) == record['sha256'], f'Frozen input differs: {name}')
        files.add(path)
    # Preserve exact raw package evidence, including the originally failed native01.
    raw_path = SOURCE / 'directory-fixed-maps/raw-sha256.json'
    raw = json.loads(raw_path.read_text())
    for name, record in raw.items():
        path = raw_path.parent / safe_relative(name)
        require(not path.is_symlink() and path.stat().st_size == record['bytes']
                and digest(path) == record['sha256'], f'Fixed-map raw input differs: {name}')
    selected134 = False
    result_path = SOURCE / '134-result.json'
    if result_path.exists():
        result = json.loads(result_path.read_text())
        require(result['cwd'] == str(ROOT), 'Foreign134 workspace')
        if result.get('drained') is True and type(result.get('exit_code')) is int:
            selected134 = True
            files.add(SOURCE / 'run134.py')
            files.update(p for p in SOURCE.glob('134-*') if p.is_file())
    planned = {}
    omissions = []
    source_hashes = {}
    for path in sorted(files):
        require(not path.is_symlink(), path)
        relative = str(path.relative_to(SOURCE))
        safe_relative(relative)
        actual = digest(path)
        source_hashes[relative] = actual
        with path.open('rb') as stream:
            magic = stream.read(8)
        binary = (magic[:4] in NATIVE_MAGIC or path.suffix in BINARY_SUFFIXES
                  or magic == b'!<arch>\n')
        if binary:
            omissions.append({'path': relative, 'bytes': path.stat().st_size,
                              'sha256': actual,
                              'reason': 'Exact local native/dependency bytes hashed and omitted; never executed.'})
        else:
            planned[relative] = {'source': path, 'sha256': actual}
    # Do not follow supplied absolute inventory paths. Archive their existing
    # fingerprints and source provenance, including repeated snapshots of a file.
    inventory_only = {}
    inventories = []
    for relative in sorted(source_hashes):
        if not relative.endswith('/before.json'):
            continue
        before_path = SOURCE / relative
        if not any(part.startswith('native-') for part in before_path.parts):
            continue
        before = json.loads(before_path.read_text())
        after_path = before_path.with_name('after.json')
        paired = after_path.exists()
        same = paired and json.loads(after_path.read_text()) == before
        inventories.append({'before': relative,
                            'after': str(after_path.relative_to(SOURCE)) if paired else None,
                            'before_after_equal': same})
        for name, record in before.items():
            path = Path(name)
            if (path.suffix not in BINARY_SUFFIXES and path.name not in {'rustc', 'rustfmt'}):
                continue
            if not isinstance(record, dict) or 'sha256' not in record:
                continue
            key = (name, record['sha256'])
            if key not in inventory_only:
                inventory_only[key] = {'path': name, **record, 'provenance': [],
                    'verification': 'Supplied immutable inventory only; referenced external bytes not reread.'}
            inventory_only[key]['provenance'].append(relative)
    omission_bytes = encoded({'selected_binary_omissions': omissions,
        'external_inventory_only': list(inventory_only.values()),
        'native_input_inventory_pairs': inventories,
        'policy': 'No native or dependency bytes copied. No paths outside repository opened. Original failures retained.'})
    omission_id = hashlib.sha256(omission_bytes).hexdigest()[:20]
    omission_name = f'fixed-bank-native-binary-omissions/{omission_id}.json'
    planned[omission_name] = {'data': omission_bytes,
                            'sha256': hashlib.sha256(omission_bytes).hexdigest()}
    for name, item in planned.items():
        if name in old:
            require(old[name] == item['sha256'], f'History replacement refused: {name}')
        target = DESTINATION / safe_relative(name)
        if target.exists():
            require(not target.is_symlink() and digest(target) == item['sha256'],
                    f'Existing destination differs: {name}')
    additions = {name: item['sha256'] for name, item in planned.items() if name not in old}
    summary = {'previous_entries_verified': len(old), 'entries_verified': len(old),
        'new_entries': 0, 'fixed_package_count': len(inputs['package_roots']),
        'fixed_input_files_verified': len(inputs['files']),
        'fixed_map_raw_entries_verified': len(raw),
        'selected_native_binaries_omitted': len(omissions),
        'selected_native_bytes_omitted': sum(v['bytes'] for v in omissions),
        'external_binary_inventory_only_entries': len(inventory_only),
        'terminal134_selected': selected134}
    if not additions:
        require(all(digest(SOURCE / name) == expected for name, expected in source_hashes.items()),
                'Frozen source changed during verification')
        verify_archive(old)
        require(MANIFEST.read_bytes() == old_bytes, 'Concurrent archive change')
        summary['raw_manifest_sha256'] = digest(MANIFEST)
        print(json.dumps(summary, sort_keys=True))
        return
    batch_id = hashlib.sha256(encoded(additions)).hexdigest()[:20]
    receipt_name = f'fixed-bank-append-receipts/{batch_id}.json'
    require(receipt_name not in old, 'Append receipt already indexed unexpectedly')
    summary.update({'entries_verified': len(old) + len(additions) + 1,
                    'new_entries': len(additions) + 1, 'append_receipt': receipt_name})
    receipt = {**summary, 'previous_raw_manifest_sha256': hashlib.sha256(old_bytes).hexdigest(),
        'preserved_old_entry_count': len(old), 'new_files': additions,
        'frozen_input_inventory_sha256': INPUT_SHA, 'frozen_package_controls': inputs['controls'],
        'binary_omission_manifest': omission_name, 'failure_bytes_preserved': True,
        'actual_source_or_release_narrative_edits': False,
        'outside_repository_bytes_opened': False, 'rust_or_native_execution': False}
    receipt_bytes = encoded(receipt)
    planned[receipt_name] = {'data': receipt_bytes,
                           'sha256': hashlib.sha256(receipt_bytes).hexdigest()}
    for name, item in planned.items():
        target = DESTINATION / safe_relative(name)
        if 'source' in item:
            require(digest(item['source']) == item['sha256'], f'Source changed: {name}')
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                with target.open('xb') as output, item['source'].open('rb') as source:
                    shutil.copyfileobj(source, output)
            except FileExistsError:
                require(not target.is_symlink() and digest(target) == item['sha256'], target)
        else:
            create_only(target, item['data'])
        require(digest(target) == item['sha256'], f'Copy verification failed: {name}')
    require(all(digest(SOURCE / name) == expected for name, expected in source_hashes.items()),
            'Selected frozen/terminal input changed during archive')
    verify_archive(old)
    require(MANIFEST.read_bytes() == old_bytes, 'Concurrent archive change; manifest not replaced')
    updated = {**old, **{name: item['sha256'] for name, item in planned.items()}}
    require(all(updated[name] == expected for name, expected in old.items()), 'Old mapping changed')
    temporary = DESTINATION / f'.raw-sha256-{batch_id}.tmp'
    with temporary.open('xb') as stream:
        stream.write(encoded(updated))
    os.replace(temporary, MANIFEST)
    verify_archive(updated)
    require(len(updated) == summary['entries_verified'], 'Final archive count differs')
    summary['raw_manifest_sha256'] = digest(MANIFEST)
    print(json.dumps(summary, sort_keys=True))


if __name__ == '__main__':
    main()
