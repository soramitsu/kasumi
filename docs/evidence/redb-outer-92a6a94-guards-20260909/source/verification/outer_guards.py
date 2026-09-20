"""Pure fail-closed identity checks for the private Linux verification owner."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import uuid

MEMORY = 8 << 30
DISK = 40 << 30
LABEL = 'org.kasumi.redb.verification'
DEADLINES = {'prepare': 1800, 'test': 2700, 'fuzz-build': 1200, 'fuzz-smoke': 90}


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def private_directory(path):
    path = Path(path)
    need(path.is_absolute() and str(path) == str(path.resolve(strict=True))
         and re.fullmatch(r'/[A-Za-z0-9._/-]+', str(path)) is not None,
         'owner path must be canonical and free of mount separators')
    for ancestor in [*reversed(path.parents), path]:
        entry = ancestor.lstat()
        need(stat.S_ISDIR(entry.st_mode) and not stat.S_ISLNK(entry.st_mode),
             'owner path traverses a non-directory or symlink')
    entry = path.lstat()
    need(entry.st_uid == os.geteuid() and stat.S_IMODE(entry.st_mode) == 0o700,
         'owner directory must be exclusively owned with mode 0700')
    return path


def identity(path):
    info = Path(path).lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'not an exclusive regular file')
    return {'device': info.st_dev, 'inode': info.st_ino, 'size': info.st_size,
            'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid}


def check_owner(owner, run_directory):
    need(set(owner) == {'schema', 'run_id', 'unit', 'source', 'commit', 'archive_sha256'},
         'unsupported owner fields')
    need(owner['schema'] == 1, 'unsupported owner version')
    value = str(uuid.UUID(owner['run_id']))
    need(value == owner['run_id'] and value != str(uuid.UUID(int=0)), 'invalid owner UUID')
    need(owner['unit'] == f'redb-verify-{value}.service', 'unit identity differs')
    need(Path(run_directory).name == value, 'owner directory identity differs')
    need(re.fullmatch(r'[0-9a-f]{40}', owner['commit']) is not None, 'commit must be exact')
    need(re.fullmatch(r'[0-9a-f]{64}', owner['archive_sha256']) is not None,
         'archive digest must be exact')
    need(Path(owner['source']).is_absolute(), 'source path must be absolute')


def check_container(info, owner, name, image, mounts, cgroup_parent):
    need(re.fullmatch(r'[0-9a-f]{64}', info.get('Id', '')) is not None,
         'container ID is not exact')
    need(info['Name'] == '/' + name, 'container name differs')
    need(info['Config'].get('Labels', {}).get(LABEL) == owner['run_id'], 'container owner differs')
    need(info['Image'] == image, 'container image differs')
    config = info['HostConfig']
    need(config['NetworkMode'] == 'none' and config['ReadonlyRootfs'] is True,
         'container isolation differs')
    need(config['Memory'] == MEMORY and config['MemorySwap'] == MEMORY,
         'container memory bound differs')
    need(set(config.get('CapDrop', [])) == {'ALL'} and not config.get('Privileged'),
         'container privileges differ')
    need('no-new-privileges' in config.get('SecurityOpt', []), 'privilege escalation allowed')
    need(config.get('CgroupParent') == cgroup_parent and config.get('Init') is True,
         'container process ownership differs')
    observed = [(m['Source'], m['Destination']) for m in info.get('Mounts', [])
                if m['Type'] == 'bind' and m['RW'] is True]
    need(len(observed) == len(info.get('Mounts', [])) and sorted(observed) == sorted(mounts),
         'container mounts differ from owned filesystem')


def check_loop(loop, image, expected):
    need(identity(image) == expected and expected['size'] == DISK, 'loop image identity changed')
    need(Path(loop['back-file']) == Path(image), 'loop backing path differs')
    need(int(loop['back-ino']) == expected['inode'], 'loop backing inode differs')
    need(str(loop['back-maj:min']) == f"{os.major(expected['device'])}:{os.minor(expected['device'])}",
         'loop backing device differs')
    need(int(loop['offset']) == 0 and int(loop['sizelimit']) in (0, DISK), 'loop extent differs')
    need(re.fullmatch(r'/dev/loop[0-9]+', loop['name']) is not None, 'unexpected loop device')


def archive_members(archive):
    """Reject hidden generated inputs, links, duplicate paths, and traversal."""
    seen = {}
    for member in archive.getmembers():
        path = PurePosixPath(member.name)
        name = str(path)
        need(not path.is_absolute() and '..' not in path.parts and name not in ('', '.'),
             'invalid archive path')
        need(name not in seen, 'duplicate archive entry')
        need(member.isfile() or member.isdir(), 'archive contains a link or special file')
        need(member.mode & 0o7000 == 0, 'archive contains privileged mode')
        for ancestor in path.parents:
            need(str(ancestor) not in seen or seen[str(ancestor)] == 'directory',
                 'archive path traverses a file')
        seen[name] = 'directory' if member.isdir() else 'file'
    return archive.getmembers()


def extract_archive(path, destination):
    root = Path(destination)
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    with tarfile.open(path, 'r:') as archive:
        members = archive_members(archive)
        for member in members:
            target = root / member.name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as source, target.open('xb') as output:
                    while chunk := source.read(1 << 20):
                        output.write(chunk)
            target.chmod(member.mode & 0o777)
            os.utime(target, (member.mtime, member.mtime))


def atomic_json(path, value):
    data = (json.dumps(value, indent=2) + '\n').encode()
    need(len(data) <= 1 << 20, 'owner receipt exceeds bounded metadata allowance')
    path = Path(path)
    temporary = path.with_name(path.name + '.new')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()
