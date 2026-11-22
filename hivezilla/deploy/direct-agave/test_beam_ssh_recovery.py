import base64
import hashlib
import io
import json
from pathlib import Path
import shlex
import sqlite3
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import beam_ssh_gateway as gateway
from beam_ssh_forced import admitted


SOURCE = dict(agave_revision='agave-test', genesis_hash='genesis', node_identity='node', session_id='session')
GENERATION = 'a' * 32
PRODUCER = 'c' * 64


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.job = Path(self.directory.name)
        self.root = self.job / 'runs' / GENERATION / 'bank-v2'
        self.root.mkdir(parents=True)
        self.db = sqlite3.connect(self.root / 'feed.sqlite')
        self.addCleanup(self.db.close)
        self.db.executescript('CREATE TABLE feed_events(sequence INTEGER PRIMARY KEY,event_json TEXT,frame_sha256 TEXT);'
                              'CREATE TABLE feed_retention(id INTEGER PRIMARY KEY,base_sequence INTEGER,base_sha256 TEXT);'
                              "INSERT INTO feed_retention VALUES(1,0,'-');")
        self.active = dict(generation=GENERATION, source=SOURCE)
        self.entries = []
        self.controls = {}
        for sequence, kind in [(1, 'block'), (2, 'confirmed'), (3, 'root'), (4, 'block')]:
            bank = dict(slot=10 + sequence, bank_id=sequence, blockhash=[sequence] * 32,
                        parent_slot=9 + sequence, parent_blockhash=[sequence - 1] * 32)
            event = dict(sequence=sequence, kind=kind, bank=bank)
            envelope = dict(profile='native-bank-compact-v2', marker=SOURCE, event=event, objects=[])
            meta = json.dumps(envelope, separators=(',', ':')).encode()
            wire = b'BZSTRM01' + struct.pack('<II', len(meta), 0) + meta
            digest = hashlib.sha256(wire).hexdigest()
            notice = dict(cursor='session:p' + str(sequence) + ':' + digest,
                          sha256=digest, event=event, source=SOURCE)
            self.entries.append(notice)
            if kind != 'block':
                self.controls[digest] = wire
            self.db.execute('INSERT INTO feed_events VALUES(?,?,?)', (sequence, json.dumps(event), digest))
        self.db.commit()

    def args(self, **changes):
        values = dict(job=self.job, mode='recovery-plan', source_json=json.dumps(SOURCE),
                      generation=GENERATION, after='session:p0:-', until=self.entries[-1]['cursor'], max_events=128)
        values.update(changes)
        return SimpleNamespace(**values)

    def run_plan(self, args=None):
        output = io.BytesIO()
        binding = (self.active, PRODUCER, '/sock', 'private')
        with patch.object(gateway, 'binding', return_value=binding):
            with patch.object(gateway, 'checked_control_bytes', side_effect=lambda _s, _t, notice: self.controls[notice['sha256']]) as control:
                self.assertEqual(gateway.serve(args or self.args(), output), 0)
        return [json.loads(line) for line in output.getvalue().splitlines()], control

    def test_exact_page_does_not_need_block_artifacts_or_copy_block_bytes(self):
        values, controls = self.run_plan()
        header, entries = values[0], values[1:]
        self.assertEqual(header['entry_count'], 4)
        self.assertEqual((header['start_cursor'], header['until_cursor'], header['end_cursor']),
                         ('session:p0:-', self.entries[-1]['cursor'], self.entries[-1]['cursor']))
        self.assertEqual(header['framing'], 'recovery-plan-ndjson-v1')
        self.assertEqual([dict((k, v) for k, v in entry.items() if k != 'control_wire_base64') for entry in entries], self.entries)
        self.assertEqual(controls.call_count, 2)
        self.assertNotIn('control_wire_base64', entries[0])
        self.assertNotIn('control_wire_base64', entries[3])
        for entry in entries[1:3]:
            self.assertEqual(base64.b64decode(entry['control_wire_base64'], validate=True), self.controls[entry['sha256']])
        self.assertNotIn('private', json.dumps(values))
        self.assertEqual(sorted(path.name for path in self.root.iterdir()), ['feed.sqlite'])

    def test_fixed_target_paginates_exactly_and_only_target_allows_empty(self):
        first, _ = self.run_plan(self.args(max_events=2))
        second, _ = self.run_plan(self.args(after=first[0]['end_cursor'], max_events=2))
        self.assertEqual([entry['cursor'] for entry in first[1:] + second[1:]], [entry['cursor'] for entry in self.entries])
        empty, _ = self.run_plan(self.args(after=self.entries[-1]['cursor']))
        self.assertEqual(len(empty), 1)
        self.assertEqual(empty[0]['entry_count'], 0)
        self.assertEqual(empty[0]['end_cursor'], self.entries[-1]['cursor'])

    def test_invalid_cursor_bounds_source_or_membership_fail_before_output(self):
        cases = [self.args(max_events=0), self.args(max_events=129),
                 self.args(after='session:p01:' + self.entries[0]['sha256']),
                 self.args(after='other:p0:-'), self.args(until='session:p99:' + 'd' * 64),
                 self.args(until='session:p1:' + 'd' * 64),
                 self.args(after=self.entries[-1]['cursor'], until=self.entries[0]['cursor'])]
        for args in cases:
            with self.subTest(args=args), self.assertRaises(gateway.Admission):
                gateway.recovery_rows(args, self.active)

    def test_expired_floor_and_missing_sequence_are_explicit_not_skipped(self):
        self.db.execute('UPDATE feed_retention SET base_sequence=1,base_sha256=?', (self.entries[0]['sha256'],))
        self.db.commit()
        with self.assertRaises(gateway.Admission) as expired:
            gateway.recovery_rows(self.args(), self.active)
        self.assertEqual((expired.exception.status, expired.exception.reason), (410, 'replay_unavailable'))
        self.db.execute('DELETE FROM feed_events WHERE sequence=3')
        self.db.commit()
        with self.assertRaises(gateway.Admission) as gap:
            gateway.recovery_rows(self.args(after=self.entries[0]['cursor']), self.active)
        self.assertEqual((gap.exception.status, gap.exception.reason), (410, 'replay_unavailable'))

    def test_changed_or_retired_binding_during_control_reads_emits_no_plan(self):
        for failure in [gateway.Admission(409, 'source_changed'), gateway.Admission(410, 'replay_unavailable')]:
            output = io.BytesIO()
            with patch.object(gateway, 'recovery_rows', side_effect=[self.entries, failure]):
                with patch.object(gateway, 'binding', return_value=(self.active, PRODUCER, '/sock', 'private')):
                    with patch.object(gateway, 'checked_control_bytes', side_effect=lambda _s, _t, notice: self.controls[notice['sha256']]):
                        with self.assertRaises(gateway.Admission):
                            gateway.recovery_plan(self.args(), output, self.active, PRODUCER, '/sock', 'private')
            self.assertEqual(output.getvalue(), b'')

    def test_control_read_checks_original_hash_event_source_and_no_block_payload(self):
        notice = self.entries[1]
        wire = self.controls[notice['sha256']]
        class Response:
            status = 200
            def getheader(self, name):
                return {'Content-Type': 'application/vnd.blockzilla.stream.v2',
                        'Content-Length': str(len(wire)), 'ETag': '"' + notice['sha256'] + '"'}.get(name)
            def read(self, _limit):
                return wire
        with patch.object(gateway, 'UnixHTTP') as http:
            http.return_value.getresponse.return_value = Response()
            self.assertEqual(gateway.checked_control_bytes('/sock', 'private', notice), wire)
            http.return_value.request.assert_called_once_with('GET', '/v2/banks/chunks/' + notice['sha256'], headers={'Authorization': 'Bearer private'})
        wrong = dict(notice, event=dict(notice['event'], kind='root'))
        with patch.object(gateway, 'UnixHTTP') as http:
            http.return_value.getresponse.return_value = Response()
            with self.assertRaises(gateway.Admission):
                gateway.checked_control_bytes('/sock', 'private', wrong)
        with patch.object(gateway, 'UnixHTTP') as http:
            response = Response()
            response.read = lambda _: wire[:-1] + b'!'
            http.return_value.getresponse.return_value = response
            with self.assertRaises(gateway.Admission) as mismatch:
                gateway.checked_control_bytes('/sock', 'private', notice)
            self.assertEqual(mismatch.exception.reason, 'recovery_control_digest_mismatch')

    def test_forced_wrapper_limits_recovery_mode_to_source_and_position_arguments(self):
        def command(*args):
            return shlex.join(['/usr/bin/python3', '-u', '-B', '/release/beam.py', '--job', '/job', *args])
        args = ('--mode', 'recovery-plan', '--generation', GENERATION, '--source-json', json.dumps(SOURCE),
                '--after', 'session:p0:-', '--until', self.entries[-1]['cursor'], '--max-events', '128')
        self.assertTrue(admitted(command(*args), '/release/beam.py', '/job'))
        for bad in [args[:-2], args[:-4], (*args, '--digest', 'd' * 64),
                    ('--mode', 'head', '--until', self.entries[-1]['cursor'])]:
            with self.assertRaises(ValueError):
                admitted(command(*bad), '/release/beam.py', '/job')

    def test_line_budget_or_producer_change_rejects_before_any_output(self):
        for changed in ('large', 'producer'):
            output = io.BytesIO()
            bindings = [(self.active, PRODUCER, '/sock', 'private'),
                        (self.active, 'd' * 64 if changed == 'producer' else PRODUCER, '/sock', 'private')]
            with patch.object(gateway, 'binding', side_effect=bindings):
                with patch.object(gateway, 'checked_control_bytes', side_effect=lambda _s, _t, notice: b'x' * gateway.MAX_JSON if changed == 'large' else self.controls[notice['sha256']]):
                    with self.assertRaises(gateway.Admission):
                        gateway.serve(self.args(), output)
            self.assertEqual(output.getvalue(), b'')

    def test_read_only_catalog_rejects_symlink_and_invalid_event_without_payload_access(self):
        path = self.root / 'feed.sqlite'
        for invalid in [dict(self.entries[0]['event'], sequence=2),
                        dict(self.entries[0]['event'], kind='unknown'),
                        dict(self.entries[0]['event'], bank=dict(self.entries[0]['event']['bank'], parent_slot=11))]:
            self.db.execute('UPDATE feed_events SET event_json=? WHERE sequence=1', (json.dumps(invalid),))
            self.db.commit()
            with self.assertRaises(gateway.Admission):
                gateway.recovery_rows(self.args(), self.active)
        self.db.close()
        moved = path.with_suffix('.moved')
        path.rename(moved)
        path.symlink_to(moved)
        with self.assertRaises(gateway.Admission) as unsafe:
            gateway.recovery_rows(self.args(), self.active)
        self.assertEqual(unsafe.exception.reason, 'unsafe_recovery_catalog')

    def test_partial_output_has_no_second_handshake_and_is_nonzero(self):
        class BrokenOutput(io.BytesIO):
            def write(self, data):
                if self.getvalue():
                    raise OSError('output closed')
                return super().write(data)
        output = BrokenOutput()
        with patch.object(gateway, 'binding', return_value=(self.active, PRODUCER, '/sock', 'private')):
            with patch.object(gateway, 'checked_control_bytes', side_effect=lambda _s, _t, notice: self.controls[notice['sha256']]):
                self.assertEqual(gateway.serve(self.args(), output), 75)
        self.assertEqual(len(output.getvalue().splitlines()), 1)
        self.assertEqual(json.loads(output.getvalue())['entry_count'], 4)


if __name__ == '__main__':
    unittest.main()
