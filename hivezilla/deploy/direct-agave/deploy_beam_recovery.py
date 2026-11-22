#!/usr/bin/env python3
"""Install the finite recovery adapter without restarting any service.

Run as the Foundation stream owner. Inputs are the reviewed helper files and
the SHA of the complete existing dedicated key line, including its newline.
No key or credential contents are printed. The old helper remains admitted.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import tempfile


OLD_RELEASE = 'native-relay-access-20261122-c74ca0aa24f762ed'
OLD_GATEWAY_SHA = 'c74ca0aa24f762ed48db674db83b0033c51370d08f3f392733a022d50ddf23a0'
OLD_FORCED_SHA = 'd1f6d9ed3e8ef504775cb9269fdf371dcb9ed081b3f5f1e1e1ac48cb6207912d'
EXPECTED_LINE_SHA = '5b2bf6f7afd8c234a9b1886f69898014c52205251f93407b12c9b363df506177'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def private_regular(path, private=False):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
            or info.st_mode & (0o077 if private else 0o022)):
        raise ValueError('unsafe_file: ' + str(path))
    return path.read_bytes()


def checked_directory(path):
    if not path.is_absolute():
        raise ValueError('relative_directory')
    for part in [path, *path.parents]:
        if part.is_symlink():
            raise ValueError('symlink_directory')
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise ValueError('unsafe_directory: ' + str(path))


def command(root, release, gateway_sha, old=False):
    gateway = release / 'beam_ssh_gateway.py'
    result = ['/usr/bin/python3', '-I', '-u', '-B', str(release / 'beam_ssh_forced.py'),
              '--gateway', str(gateway), '--gateway-sha', gateway_sha,
              '--job', str(root / 'jobs/native-continuous-20261121')]
    if not old:
        result += ['--allow-gateway', str(root / 'releases' / OLD_RELEASE / 'beam_ssh_gateway.py'), OLD_GATEWAY_SHA]
    return shlex.join(result)


def replace_key(raw, old_command, new_command, expected_line_sha):
    old, new = old_command.encode(), new_command.encode()
    old_field, new_field = b'command="' + old + b'"', b'command="' + new + b'"'
    result, matched, already = [], [], False
    for line in raw.splitlines(keepends=True):
        if old_field in line or new_field in line:
            original = line.replace(new_field, old_field, 1) if new_field in line else line
            if sha(original) != expected_line_sha:
                raise ValueError('dedicated_key_line_changed')
            if line.count(old_field) + line.count(new_field) != 1:
                raise ValueError('ambiguous_key_command')
            updated = original.replace(old_field, new_field, 1)
            result.append(updated)
            matched.append((sha(original), sha(updated)))
            already = updated == line
        else:
            result.append(line)
    if len(matched) != 1:
        raise ValueError('dedicated_key_not_unique')
    return b''.join(result), matched[0], already


def install(args):
    root, ssh_directory = args.root, args.authorized_keys.parent
    checked_directory(root / 'releases')
    checked_directory(ssh_directory)
    old_release = root / 'releases' / OLD_RELEASE
    if (sha(private_regular(old_release / 'beam_ssh_gateway.py')) != OLD_GATEWAY_SHA
            or sha(private_regular(old_release / 'beam_ssh_forced.py')) != OLD_FORCED_SHA):
        raise ValueError('old_release_pin_changed')
    files = {name: private_regular(path) for name, path in [
        ('beam_ssh_gateway.py', args.gateway_file), ('beam_ssh_forced.py', args.forced_file)]}
    gateway_sha = sha(files['beam_ssh_gateway.py'])
    release = root / 'releases' / ('native-relay-recovery-20261122-' + gateway_sha[:16])
    old_command = command(root, old_release, OLD_GATEWAY_SHA, old=True)
    new_command = command(root, release, gateway_sha)
    lock_fd = os.open(ssh_directory / 'authorized_keys.recovery.lock',
                      os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        lock_info = os.fstat(lock_fd)
        if lock_info.st_uid != os.geteuid() or lock_info.st_nlink != 1 or lock_info.st_mode & 0o077:
            raise ValueError('unsafe_deployment_lock')
        before = private_regular(args.authorized_keys, private=True)
        after, line_hashes, already = replace_key(before, old_command, new_command, args.expected_line_sha)
        if release.exists():
            checked_directory(release)
            if set(path.name for path in release.iterdir()) != set(files):
                raise ValueError('release_file_set_changed')
            for name, raw in files.items():
                if private_regular(release / name) != raw:
                    raise ValueError('release_content_changed')
        else:
            staging = Path(tempfile.mkdtemp(prefix='.native-relay-recovery-', dir=release.parent))
            try:
                for name, raw in files.items():
                    path = staging / name
                    with path.open('xb') as stream:
                        stream.write(raw)
                        stream.flush()
                        os.fsync(stream.fileno())
                    path.chmod(0o555)
                staging.chmod(0o555)
                staging.rename(release)
            except BaseException:
                staging.chmod(0o700)
                for path in staging.iterdir():
                    path.unlink()
                staging.rmdir()
                raise
        backup = ssh_directory / ('authorized_keys.before-recovery-' + sha(before)[:16])
        if not already:
            if backup.exists():
                if private_regular(backup, private=True) != before:
                    raise ValueError('backup_content_changed')
            else:
                fd = os.open(backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(before)
                    stream.flush()
                    os.fsync(stream.fileno())
            # Compare the entire file again. Preserve unrelated concurrent edits.
            if private_regular(args.authorized_keys, private=True) != before:
                raise ValueError('authorized_keys_changed_during_install')
            fd, temporary = tempfile.mkstemp(prefix='.authorized_keys.recovery-', dir=ssh_directory)
            try:
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(after)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, args.authorized_keys)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        actual = private_regular(args.authorized_keys, private=True)
        if actual != after:
            raise ValueError('authorized_keys_verification_failed')
        return {'schema': 'blockzilla-beam-recovery-deployment-v1', 'release': str(release),
                'files': {name: {'sha256': sha(raw), 'bytes': len(raw)} for name, raw in files.items()},
                'authorized_keys_before_sha256': sha(before), 'authorized_keys_after_sha256': sha(after),
                'old_line_sha256': line_hashes[0], 'new_line_sha256': line_hashes[1],
                'already_installed': already, 'backup': str(backup) if not already else None,
                'old_gateway': str(old_release / 'beam_ssh_gateway.py'),
                'new_gateway': str(release / 'beam_ssh_gateway.py'),
                'service_restart': False, 'block_files_written': 0}
    finally:
        os.close(lock_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('/home/ubuntu/live/hivezilla-validator-20260930'))
    parser.add_argument('--gateway-file', type=Path, required=True)
    parser.add_argument('--forced-file', type=Path, required=True)
    parser.add_argument('--authorized-keys', type=Path, default=Path.home() / '.ssh/authorized_keys')
    parser.add_argument('--expected-line-sha', default=EXPECTED_LINE_SHA)
    args = parser.parse_args()
    if not re.fullmatch('[0-9a-f]{64}', args.expected_line_sha):
        raise SystemExit('invalid_expected_line_sha')
    print(json.dumps(install(args), sort_keys=True))


if __name__ == '__main__':
    main()
