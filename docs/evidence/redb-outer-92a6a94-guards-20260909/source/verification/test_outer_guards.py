"""Ownership guard tests only; never launch processes, Docker, or mounts."""
import copy
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import uuid

from outer_guards import (DISK, LABEL, MEMORY, archive_members, atomic_json,
                          check_container, check_loop, check_owner, identity,
                          private_directory)

RUN = 'b888f71a-1650-43fd-bb77-c819a047b009'


def owner():
    return {'schema': 1, 'run_id': RUN, 'unit': f'redb-verify-{RUN}.service',
            'source': '/source/redb', 'commit': 'a' * 40, 'archive_sha256': 'b' * 64}


def container():
    return {'Id': 'c' * 64, 'Name': '/owned-test', 'Image': 'sha256:' + 'd' * 64,
            'Config': {'Labels': {LABEL: RUN}},
            'HostConfig': {'NetworkMode': 'none', 'ReadonlyRootfs': True,
                           'Memory': MEMORY, 'MemorySwap': MEMORY, 'CapDrop': ['ALL'],
                           'Privileged': False, 'SecurityOpt': ['no-new-privileges'],
                           'CgroupParent': '/owned/containers', 'Init': True},
            'Mounts': [{'Type': 'bind', 'RW': True, 'Source': '/owned/work', 'Destination': '/work'}]}


class OwnerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.root.chmod(0o700)

    def test_owner_has_one_exact_version_identity_and_source(self):
        value = owner()
        check_owner(value, '/private/' + RUN)
        for field, substitute in [('schema', 2), ('run_id', str(uuid.UUID(int=0))),
                                  ('unit', 'docker.service'), ('source', '../source'),
                                  ('commit', 'a' * 7), ('archive_sha256', 'B' * 64)]:
            candidate = dict(value, **{field: substitute})
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                check_owner(candidate, '/private/' + RUN)
        with self.assertRaises(RuntimeError):
            check_owner(dict(value, legacy_alias='allowed'), '/private/' + RUN)
        with self.assertRaises(RuntimeError):
            check_owner(value, '/private/another-owner')

    def test_private_path_rejects_aliases_modes_and_mount_separators(self):
        self.assertEqual(private_directory(self.root), self.root)
        alias = self.root / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(RuntimeError):
            private_directory(alias)
        self.root.chmod(0o755)
        with self.assertRaises(RuntimeError):
            private_directory(self.root)
        self.root.chmod(0o700)
        comma = self.root / 'bad,path'
        comma.mkdir(mode=0o700)
        with self.assertRaises(RuntimeError):
            private_directory(comma)

    def test_atomic_status_is_bounded_private_and_replaces_complete_json(self):
        target = self.root / 'status.json'
        atomic_json(target, {'state': 'prepared'})
        self.assertEqual(identity(target)['mode'], 0o600)
        atomic_json(target, {'state': 'failed', 'original': 'preserved'})
        self.assertEqual(json.loads(target.read_text())['state'], 'failed')
        with self.assertRaises(RuntimeError):
            atomic_json(target, {'huge': 'x' * (1 << 20)})
        self.assertEqual(json.loads(target.read_text())['state'], 'failed')
        self.assertFalse(target.with_suffix('.json.new').exists())

    def test_identity_rejects_links(self):
        original = self.root / 'original'
        original.write_bytes(b'fixed')
        link = self.root / 'link'
        link.symlink_to(original)
        with self.assertRaises(RuntimeError):
            identity(link)
        link.unlink()
        os.link(original, link)
        with self.assertRaises(RuntimeError):
            identity(original)

    def test_container_requires_exact_isolation_owner_image_and_mounts(self):
        expected = container()
        def verify(value):
            check_container(value, owner(), 'owned-test', 'sha256:' + 'd' * 64,
                            [('/owned/work', '/work')], '/owned/containers')
        verify(expected)
        for key, value in [('NetworkMode', 'host'), ('ReadonlyRootfs', False),
                           ('Memory', 0), ('MemorySwap', -1), ('Privileged', True),
                           ('SecurityOpt', []), ('CapDrop', []),
                           ('CgroupParent', '/another'), ('Init', False)]:
            wrong = copy.deepcopy(expected)
            wrong['HostConfig'][key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                verify(wrong)
        for key, value in [('Id', 'short'), ('Name', '/another'), ('Image', 'mutable:tag')]:
            wrong = copy.deepcopy(expected)
            wrong[key] = value
            with self.assertRaises(RuntimeError):
                verify(wrong)
        wrong = copy.deepcopy(expected)
        wrong['Mounts'][0]['Source'] = '/unrelated'
        with self.assertRaises(RuntimeError):
            verify(wrong)
        wrong = copy.deepcopy(expected)
        wrong['Config']['Labels'][LABEL] = str(uuid.uuid4())
        with self.assertRaises(RuntimeError):
            verify(wrong)

    def test_loop_guard_rejects_path_inode_device_and_extent_substitution(self):
        expected = {'device': os.makedev(1, 2), 'inode': 123, 'size': DISK, 'mode': 0o600, 'uid': 0}
        loop = {'name': '/dev/loop7', 'back-file': '/owned/disk.ext4', 'back-ino': 123,
                'back-maj:min': '1:2', 'offset': 0, 'sizelimit': 0}
        with patch('outer_guards.identity', return_value=expected):
            check_loop(loop, '/owned/disk.ext4', expected)
            for key, value in [('name', '/dev/sda'), ('back-file', '/unrelated'),
                               ('back-ino', 124), ('back-maj:min', '2:2'),
                               ('offset', 4096), ('sizelimit', 4096)]:
                with self.subTest(key=key), self.assertRaises(RuntimeError):
                    check_loop(dict(loop, **{key: value}), '/owned/disk.ext4', expected)
        with patch('outer_guards.identity', return_value=dict(expected, inode=124)):
            with self.assertRaises(RuntimeError):
                check_loop(loop, '/owned/disk.ext4', expected)

    def test_archive_rejects_escape_links_duplicates_and_file_parent(self):
        def archive(entries):
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode='w') as output:
                for name, kind in entries:
                    entry = tarfile.TarInfo(name)
                    entry.type = kind
                    output.addfile(entry)
            buffer.seek(0)
            return tarfile.open(fileobj=buffer, mode='r:')
        with archive([('verification', tarfile.DIRTYPE), ('verification/runner.py', tarfile.REGTYPE)]) as value:
            self.assertEqual(len(archive_members(value)), 2)
        for entries in [[('../escape', tarfile.REGTYPE)], [('/absolute', tarfile.REGTYPE)],
                        [('link', tarfile.SYMTYPE)], [('link', tarfile.LNKTYPE)],
                        [('device', tarfile.CHRTYPE)], [('same', tarfile.REGTYPE)] * 2,
                        [('file', tarfile.REGTYPE), ('file/nested', tarfile.REGTYPE)]]:
            with self.subTest(entries=entries), archive(entries) as value, self.assertRaises(RuntimeError):
                archive_members(value)


if __name__ == '__main__':
    unittest.main()
