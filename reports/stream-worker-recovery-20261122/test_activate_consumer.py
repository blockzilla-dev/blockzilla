import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from contextlib import ExitStack

SPEC = importlib.util.spec_from_file_location('activation', Path(__file__).with_name('activate-consumer.py'))
activation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(activation)


def cursor(kind, number, digest='a'):
    return activation.EXPECTED_SOURCE['session_id'] + ':' + kind + str(number) + ':' + digest * 64


def snapshot(number):
    return dict(device=1, inode=2, userVersion=0, schemaSha256='schema', configSha256='config',
                runtimeGeneration=activation.RUNTIME, bootstrapBoundary='initial',
                database=str(activation.DATABASE), databaseCount=1, projectionBytes=0,
                sourceCursor=cursor('p', number), outputCursor=cursor('o', number))


class ActivationTests(unittest.TestCase):
    def test_candidate_changes_only_binary_helper_and_two_recovery_flags(self):
        binary = Path('/opt/release/new/blockzilla-stream-sidecar')
        old = list(activation.EXPECTED_ARGV)
        new = activation.candidate_argv(binary, old)
        self.assertEqual(new[0], str(binary))
        self.assertEqual(new[-4:], ['--recovery-worker-url', 'https://getblock.blockzilla.dev',
                                  '--recovery-worker-api-key-file', '/etc/blockzilla-client-pipe/worker-api-key'])
        restored = list(new[:-4])
        restored[0] = old[0]
        restored[restored.index('--upstream-ssh-helper') + 1] = activation.OLD_HELPER
        self.assertEqual(restored, old)
        with self.assertRaises(ValueError):
            activation.candidate_argv(binary, old + ['--database', '/new.sqlite'])

    def test_cursor_regression_hash_change_or_changed_database_is_rejected(self):
        base = snapshot(10)
        for changed in [snapshot(9), dict(base, sourceCursor=cursor('p', 10, 'b')),
                        dict(snapshot(11), inode=99), dict(snapshot(11), schemaSha256='changed'),
                        dict(snapshot(11), bootstrapBoundary='rejoined')]:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                activation.same_database(base, changed)
        activation.same_database(base, snapshot(11))
        with self.assertRaises(ValueError):
            activation.checkpoint_not_before(base, base, strict=True)

    def test_fresh_health_requires_native_live_signing_and_completed_recovery(self):
        now = time.time_ns() // 1_000_000
        value = dict(source=activation.EXPECTED_SOURCE, producerGeneration=activation.PRODUCER,
                     runtimeGeneration=activation.RUNTIME, inputMode='raw_ssh', payloadMode='compact-only',
                     input='live', signingReady=True, error=None, beamReconcileError=None,
                     sampledAtMs=now, beamSourceObservedAtMs=now - 100, beamLastFrameAgeMs=10,
                     workerRecovery=dict(enabled=True, active=False))
        self.assertTrue(activation.fresh_head(value, recovery=True))
        for key, altered in [('input', 'unavailable'), ('inputMode', 'legacy_http_sse'),
                             ('signingReady', False), ('beamLastFrameAgeMs', 6000),
                             ('workerRecovery', None), ('workerRecovery', dict(enabled=True, active=True))]:
            self.assertFalse(activation.fresh_head(dict(value, **{key: altered}), recovery=True))

    def test_database_snapshot_opens_existing_one_in_read_only_mode_without_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'client.sqlite'
            with sqlite3.connect(path) as db:
                db.executescript('CREATE TABLE config(id INTEGER,source TEXT,targets TEXT,producer_generation TEXT);'
                                 'CREATE TABLE beam_input(id INTEGER,runtime_generation TEXT);'
                                 'CREATE TABLE checkpoint(id INTEGER,cursor TEXT,output_cursor TEXT,bootstrap_boundary TEXT);'
                                 'CREATE TABLE payloads(projection TEXT);')
                db.execute('INSERT INTO config VALUES(1,?,?,?)',
                           (json.dumps(activation.EXPECTED_SOURCE), '[]', activation.PRODUCER))
                db.execute('INSERT INTO beam_input VALUES(1,?)', (activation.RUNTIME,))
                db.execute('INSERT INTO checkpoint VALUES(1,?,?,?)', (cursor('p', 10), cursor('o', 10), 'initial'))
                db.execute("INSERT INTO payloads VALUES('')")
            db.close()
            before = hashlib.sha256(path.read_bytes()).hexdigest()
            with patch.object(activation, 'DATABASE', path):
                result = activation.database()
                self.assertEqual(result['databaseCount'], 1)
                self.assertEqual(result['sourceCursor'], cursor('p', 10))
                self.assertEqual(result['inode'], path.stat().st_ino)
                (Path(directory) / 'extra.sqlite').touch()
                with self.assertRaises(ValueError):
                    activation.database()
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)
            self.assertEqual(sorted(p.name for p in Path(directory).iterdir()), ['client.sqlite', 'extra.sqlite'])

    def test_code_install_is_immutable_and_refuses_conflicting_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            releases = root / 'releases'
            releases.mkdir()
            candidate = root / 'candidate'
            candidate.write_bytes(b'tested code')
            expected = activation.digest(candidate)
            with patch.object(activation, 'RELEASES', releases):
                binary = activation.install_binary(candidate, expected)
                self.assertEqual(binary.read_bytes(), candidate.read_bytes())
                self.assertEqual(binary.stat().st_mode & 0o777, 0o555)
                self.assertEqual(binary.parent.stat().st_mode & 0o777, 0o555)
                self.assertEqual(activation.install_binary(candidate, expected), binary)
                binary.chmod(0o644)
                binary.write_bytes(b'changed')
                with self.assertRaises(ValueError):
                    activation.install_binary(candidate, expected)
            binary.parent.chmod(0o755)

    def run_activation(self, directory, failed=False):
        root = Path(directory)
        source, key, build = root / 'SOURCE.json', root / 'worker-api-key', root / 'BUILD.json'
        source.write_text(json.dumps(activation.EXPECTED_SOURCE))
        key.write_text('k' * 48)
        key.chmod(0o600)
        expected = 'b' * 64
        build.write_text(json.dumps(dict(state='PASSED', artifacts={'blockzilla-stream-sidecar': {'sha256': expected}},
                         commands=[dict(phase=name, returncode=0) for name in
                                   ['sdk-tests', 'sidecar-tests', 'automatic-recovery-fixture', 'sidecar-release']])))
        args = SimpleNamespace(candidate=root / 'candidate', sha256=expected,
                               build_receipt=build, receipt=root / 'receipt.json')
        dropin = root / 'unit.d/50-worker-recovery.conf'
        binary = root / expected / 'blockzilla-stream-sidecar'
        new_argv = activation.candidate_argv(binary, activation.EXPECTED_ARGV)
        state = dict(running='old')
        actions = []
        def command(*argv):
            actions.append(argv)
            self.assertEqual(argv[0], 'systemctl')
            if argv[1] == 'stop':
                self.assertEqual(argv[2:], (activation.UNIT,))
                state['running'] = None
            if argv[1] == 'start':
                self.assertEqual(argv[2:], (activation.UNIT,))
                state['running'] = 'new' if dropin.exists() else 'old'
            return ''
        def properties():
            which = state['running']
            return dict({key: 'same' for key in activation.RESOURCE_KEYS},
                        MainPID='102' if which == 'new' else '101' if which == 'old' else '0',
                        ActiveState='active' if which else 'inactive',
                        InvocationID=which or '', NRestarts='0', FragmentPath='/unit', DropInPaths='')
        actual_digest = activation.digest
        def digest(path):
            if str(path) == '/proc/101/exe':
                return activation.PREVIOUS_SHA
            if str(path) == '/proc/102/exe':
                return expected
            return actual_digest(path)
        actual_read = Path.read_bytes
        def read_bytes(path):
            if str(path) == '/proc/101/cmdline':
                return ('\0'.join(activation.EXPECTED_ARGV) + '\0').encode()
            if str(path) == '/proc/102/cmdline':
                return ('\0'.join(activation.candidate_argv(binary, activation.EXPECTED_ARGV)) + '\0').encode()
            return actual_read(path)
        snapshots = [snapshot(10), snapshot(12), snapshot(17), snapshot(25)] if failed else [snapshot(10), snapshot(12), snapshot(20)]
        with ExitStack() as stack:
            for name, value in [('SOURCE_FILE', source), ('WORKER_KEY', key), ('DROPIN', dropin)]:
                stack.enter_context(patch.object(activation, name, value))
            stack.enter_context(patch.object(activation.os, 'geteuid', return_value=0))
            stack.enter_context(patch.object(activation.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=os.getuid())))
            stack.enter_context(patch.object(activation, 'command', side_effect=command))
            stack.enter_context(patch.object(activation, 'properties', side_effect=properties))
            stack.enter_context(patch.object(activation, 'digest', side_effect=digest))
            stack.enter_context(patch.object(Path, 'read_bytes', read_bytes))
            stack.enter_context(patch.object(activation, 'unit_files', return_value={'/unit': 'unchanged'}))
            stack.enter_context(patch.object(activation, 'service_invocations', return_value={'docker.service': {'InvocationID': 'unchanged'}}))
            stack.enter_context(patch.object(activation, 'containers', return_value={'container': {'startedAt': 'unchanged'}}))
            stack.enter_context(patch.object(activation, 'database', side_effect=snapshots))
            stack.enter_context(patch.object(activation, 'head', return_value={'source': activation.EXPECTED_SOURCE}))
            stack.enter_context(patch.object(activation, 'fresh_head', return_value=True))
            stack.enter_context(patch.object(activation, 'install_binary', return_value=binary))
            waits = [TimeoutError('candidate not live'), {'source': activation.EXPECTED_SOURCE}] if failed else [{'source': activation.EXPECTED_SOURCE}]
            stack.enter_context(patch.object(activation, 'wait_live', side_effect=waits))
            if failed:
                with self.assertRaises(TimeoutError):
                    activation.activate(args)
            else:
                activation.activate(args)
        return json.loads(args.receipt.read_text()), actions, dropin

    def test_activation_makes_one_controlled_restart_on_existing_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt, actions, dropin = self.run_activation(directory)
            self.assertEqual(receipt['state'], 'ACTIVATED')
            self.assertEqual(receipt['stoppedCheckpoint']['sourceCursor'], cursor('p', 12))
            self.assertEqual(receipt['afterDatabase']['sourceCursor'], cursor('p', 20))
            self.assertEqual(receipt['controlledStopStartCycles'], 1)
            self.assertEqual([action[1] for action in actions], ['stop', 'daemon-reload', 'start'])
            self.assertFalse(receipt['databaseBackupCreated'])
            self.assertFalse(receipt['databaseRestoreUsed'])
            self.assertTrue(dropin.exists())

    def test_failed_candidate_restores_old_config_on_current_advanced_database(self):
        with tempfile.TemporaryDirectory() as directory:
            receipt, actions, dropin = self.run_activation(directory, failed=True)
            self.assertEqual(receipt['state'], 'ROLLED_BACK_SAME_DATABASE')
            self.assertEqual(receipt['rollbackStartCheckpoint']['sourceCursor'], cursor('p', 17))
            self.assertEqual(receipt['rollbackDatabase']['sourceCursor'], cursor('p', 25))
            self.assertFalse(receipt['cursorRollbackUsed'])
            self.assertFalse(receipt['databaseRestoreUsed'])
            self.assertFalse(dropin.exists())
            self.assertEqual([action[1] for action in actions],
                             ['stop', 'daemon-reload', 'start', 'stop', 'daemon-reload', 'start'])


if __name__ == '__main__':
    unittest.main()
