import shlex
import hashlib
from pathlib import Path
import tempfile
import unittest
from beam_ssh_forced import admitted, selected_gateway


class ForcedTests(unittest.TestCase):
    def command(self, *args):
        return shlex.join(['/usr/bin/python3', '-u', '-B', '/release/beam.py', '--job', '/job', *args])

    def test_only_pinned_adapter_and_job_with_bounded_unique_options(self):
        result = admitted(self.command('--mode', 'stream', '--generation', 'a' * 32,
                                       '--source-json', '{"session_id":"safe"}', '--after', 's:p9:hash'), '/release/beam.py', '/job')
        self.assertEqual(result[:5], ['/usr/bin/python3', '-I', '-u', '-B', '/release/beam.py'])
        for bad in ['id', '/bin/sh -c id', self.command('--mode', 'shell'),
                    self.command('--mode', 'head', '--job', '/other'),
                    self.command('--mode', 'head', '--mode', 'stream'),
                    self.command('--mode', 'head', '--after', 'x'), 'x' * 20000]:
            with self.assertRaises(ValueError):
                admitted(bad, '/release/beam.py', '/job')

    def test_shell_payload_is_an_argument_and_cannot_be_executed(self):
        value = "s:p1:x'; touch /tmp/never; '"
        result = admitted(self.command('--mode', 'stream', '--generation', 'a' * 32,
                                       '--source-json', '{}', '--after', value), '/release/beam.py', '/job')
        self.assertEqual(result[-1], value)
        with self.assertRaises(ValueError):
            admitted(self.command('--mode', 'head') + '; id', '/release/beam.py', '/job')

    def test_head_clock_and_exact_frame_fetch_are_allowed(self):
        for args in [('--mode', 'head'), ('--mode', 'clock'),
                     ('--mode', 'frame', '--generation', 'a' * 32, '--source-json', '{}', '--digest', 'b' * 64)]:
            self.assertTrue(admitted(self.command(*args), '/release/beam.py', '/job'))

    def test_finalized_lookup_has_its_own_exact_read_only_allowlist(self):
        args = ('--mode', 'finalized-block', '--generation', 'a' * 32,
                '--source-json', '{}', '--block-id', '9:' + '1' * 32)
        self.assertTrue(admitted(self.command(*args), '/release/beam.py', '/job'))
        for bad in [('--mode', 'finalized-block'), args[:-2],
                    (*args, '--digest', 'b' * 64), (*args, '--after', 's:p1:-'),
                    ('--mode', 'head', '--block-id', '9:' + '1' * 32)]:
            with self.assertRaises(ValueError):
                admitted(self.command(*bad), '/release/beam.py', '/job')

    def test_finalized_path_requires_explicit_target_anchor_and_hard_bounds(self):
        args = ('--mode', 'finalized-path', '--generation', 'a' * 32, '--source-json', '{}',
                '--block-id', '11:' + '1' * 32, '--anchor-id', '9:' + '1' * 32,
                '--max-blocks', '1024', '--max-wire-bytes', str(192 * 1024 * 1024))
        self.assertTrue(admitted(self.command(*args), '/release/beam.py', '/job'))
        for bad in [args[:-2], args[:-4], (*args, '--digest', 'a' * 64),
                    ('--mode', 'head', '--anchor-id', '9:' + '1' * 32)]:
            with self.assertRaises(ValueError):
                admitted(self.command(*bad), '/release/beam.py', '/job')

    def test_rollout_allows_only_two_exact_old_and_new_helper_content_pins(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = [Path(directory) / name for name in ['old.py', 'new.py', 'other.py']]
            for path in paths:
                path.write_text(path.name)
            pins = [(str(path), hashlib.sha256(path.read_bytes()).hexdigest()) for path in paths[:2]]
            for path in paths[:2]:
                command = shlex.join(['/usr/bin/python3', '-u', '-B', str(path), '--job', '/job', '--mode', 'head'])
                self.assertEqual(selected_gateway(command, pins), str(path))
            for value in [str(paths[2]), str(paths[0].parent / 'missing.py')]:
                with self.assertRaises(ValueError):
                    selected_gateway(shlex.join(['/usr/bin/python3', '-u', '-B', value]), pins)
            paths[0].write_text('changed')
            with self.assertRaises(ValueError):
                selected_gateway(shlex.join(['/usr/bin/python3', '-u', '-B', str(paths[0])]), pins)
            paths[0].unlink()
            paths[0].symlink_to(paths[1])
            with self.assertRaises(ValueError):
                selected_gateway(shlex.join(['/usr/bin/python3', '-u', '-B', str(paths[0])]), pins)


if __name__ == '__main__':
    unittest.main()
