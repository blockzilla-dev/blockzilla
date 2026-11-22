import hashlib
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import deploy_beam_recovery as deploy


class DeploymentTests(unittest.TestCase):
    def fixture(self, directory):
        directory = str(Path(directory).resolve())
        root = Path(directory) / 'native'
        releases = root / 'releases'
        old = releases / deploy.OLD_RELEASE
        old.mkdir(parents=True)
        old_gateway, old_forced = b'old_gateway', b'old_forced'
        (old / 'beam_ssh_gateway.py').write_bytes(old_gateway)
        (old / 'beam_ssh_forced.py').write_bytes(old_forced)
        inputs = Path(directory) / 'inputs'
        inputs.mkdir()
        gateway, forced = inputs / 'gateway.py', inputs / 'forced.py'
        gateway.write_bytes(b'new_gateway')
        forced.write_bytes(b'new_forced')
        ssh = Path(directory) / '.ssh'
        ssh.mkdir(mode=0o700)
        old_sha, forced_sha = deploy.sha(old_gateway), deploy.sha(old_forced)
        command = deploy.command(root, old, old_sha, old=True)
        dedicated = ('restrict,command="' + command + '" ssh-ed25519 dedicated-public-key pipe\n').encode()
        raw = b'ssh-ed25519 untouched-owner-key\n' + dedicated + b'\n# preserved comment\n'
        authorized = ssh / 'authorized_keys'
        authorized.write_bytes(raw)
        authorized.chmod(0o600)
        args = SimpleNamespace(root=root, gateway_file=gateway, forced_file=forced,
                               authorized_keys=authorized, expected_line_sha=deploy.sha(dedicated))
        return args, raw, old_sha, forced_sha

    def test_atomic_install_keeps_other_keys_and_admits_old_and_new_exact_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            args, raw, old_sha, forced_sha = self.fixture(directory)
            with patch.object(deploy, 'OLD_GATEWAY_SHA', old_sha), patch.object(deploy, 'OLD_FORCED_SHA', forced_sha):
                receipt = deploy.install(args)
                after = args.authorized_keys.read_bytes()
                self.assertTrue(after.startswith(b'ssh-ed25519 untouched-owner-key\n'))
                self.assertTrue(after.endswith(b'\n# preserved comment\n'))
                self.assertIn(b'--allow-gateway', after)
                self.assertEqual(Path(receipt['backup']).read_bytes(), raw)
                self.assertEqual(Path(receipt['new_gateway']).read_bytes(), b'new_gateway')
                self.assertEqual(Path(receipt['old_gateway']).read_bytes(), b'old_gateway')
                self.assertEqual(Path(receipt['new_gateway']).stat().st_mode & 0o777, 0o555)
                self.assertEqual(Path(receipt['release']).stat().st_mode & 0o777, 0o555)
                self.assertEqual(args.authorized_keys.stat().st_mode & 0o777, 0o600)
                again = deploy.install(args)
                self.assertTrue(again['already_installed'])
                self.assertEqual(args.authorized_keys.read_bytes(), after)
                self.assertEqual(receipt['authorized_keys_after_sha256'], again['authorized_keys_after_sha256'])
                self.assertEqual(receipt['block_files_written'], 0)
            # Allow the temporary directory to remove the immutable test release.
            Path(receipt['release']).chmod(0o700)

    def test_changed_dedicated_line_or_wrong_old_pin_does_not_change_authorized_keys(self):
        for failure in ('line', 'pin'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                args, raw, old_sha, forced_sha = self.fixture(directory)
                if failure == 'line':
                    args.expected_line_sha = '0' * 64
                with patch.object(deploy, 'OLD_GATEWAY_SHA', '0' * 64 if failure == 'pin' else old_sha):
                    with patch.object(deploy, 'OLD_FORCED_SHA', forced_sha):
                        with self.assertRaises(ValueError):
                            deploy.install(args)
                self.assertEqual(args.authorized_keys.read_bytes(), raw)
                self.assertEqual(len(list((args.root / 'releases').iterdir())), 1)

    def test_duplicate_dedicated_key_and_unknown_forcedcommand_fail(self):
        old, new = 'old command', 'new command'
        line = b'restrict,command="old command" ssh-ed25519 public\n'
        for raw in [line + line, line.replace(b'old command', b'changed command')]:
            with self.assertRaises(ValueError):
                deploy.replace_key(raw, old, new, deploy.sha(line))

    def test_existing_release_is_never_overwritten_on_a_conflicting_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            args, raw, old_sha, forced_sha = self.fixture(directory)
            release = args.root / 'releases' / ('native-relay-recovery-20261122-' + deploy.sha(b'new_gateway')[:16])
            release.mkdir()
            (release / 'beam_ssh_gateway.py').write_bytes(b'wrong')
            (release / 'beam_ssh_forced.py').write_bytes(b'new_forced')
            with patch.object(deploy, 'OLD_GATEWAY_SHA', old_sha), patch.object(deploy, 'OLD_FORCED_SHA', forced_sha):
                with self.assertRaises(ValueError):
                    deploy.install(args)
            self.assertEqual((release / 'beam_ssh_gateway.py').read_bytes(), b'wrong')
            self.assertEqual(args.authorized_keys.read_bytes(), raw)


if __name__ == '__main__':
    unittest.main()
