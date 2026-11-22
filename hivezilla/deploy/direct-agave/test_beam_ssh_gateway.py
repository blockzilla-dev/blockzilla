import argparse
import hashlib
import io
import json
import os
import socket
import struct
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import beam_ssh_gateway as gateway


SOURCE = dict(agave_revision='agave-test', genesis_hash='genesis', node_identity='node', session_id='session')
GENERATION = 'a' * 32
CURSOR = 'session:p8:' + 'b' * 64


class Response:
    status = 200

    def __init__(self, parts):
        self.parts = list(parts)

    def getheader(self, name):
        return {'Content-Type': 'application/vnd.blockzilla.stream.v2',
                'X-Blockzilla-Start-Cursor': CURSOR}.get(name)

    def read1(self, size):
        part = self.parts.pop(0) if self.parts else b''
        if isinstance(part, Exception):
            raise part
        assert len(part) <= size
        return part

    def read(self, size):
        return self.read1(size)


class GatewayTests(unittest.TestCase):
    def native_frame(self, slot, parent):
        payload = b'original-compact-bytes'
        envelope = {'profile': 'native-bank-compact-v2', 'marker': SOURCE,
                    'event': {'kind': 'block', 'bank': {'slot': slot, 'parent_slot': parent,
                              'blockhash': [slot] * 32, 'parent_blockhash': [parent] * 32}},
                    'objects': [{'path': 'fixture', 'offset': 0, 'bytes': len(payload),
                                 'sha256': hashlib.sha256(payload).hexdigest()}]}
        meta = json.dumps(envelope, separators=(',', ':')).encode()
        return b'BZSTRM01' + struct.pack('<II', len(meta), len(payload)) + meta + payload, envelope

    def native_response(self, wire):
        response = Response([wire])
        response.getheader = {'Content-Type': 'application/vnd.blockzilla.stream.v2',
                              'X-Blockzilla-Commitment': 'finalized', 'Content-Length': str(len(wire)),
                              'ETag': '"' + hashlib.sha256(wire).hexdigest() + '"'}.get
        return response

    def test_finalized_path_reuses_one_session_and_keeps_original_frames_in_parent_order(self):
        first, event = self.native_frame(11, 10)
        second, second_event = self.native_frame(10, 9)
        target = gateway.native_id(event['event']['bank'])
        anchor = gateway.native_id(second_event['event']['bank'], parent=True)
        args = self.args(mode='finalized-path', block_id=target, anchor_id=anchor,
                         max_blocks=2, max_wire_bytes=len(first) + len(second))
        output = io.BytesIO()
        active = dict(generation=GENERATION, source=SOURCE)
        with patch.object(gateway, 'binding', return_value=(active, 'c' * 64, '/sock', 'private')):
            with patch.object(gateway, 'UnixHTTP') as http:
                http.return_value.getresponse.side_effect = [self.native_response(first), self.native_response(second)]
                self.assertEqual(gateway.serve(args, output), 0)
                self.assertEqual([call.args[1] for call in http.return_value.request.call_args_list],
                                 ['/v2/banks/finalized/blocks/' + target,
                                  '/v2/banks/finalized/blocks/' + gateway.native_id(second_event['event']['bank'])])
        line, actual = output.getvalue().split(b'\n', 1)
        header = json.loads(line)
        self.assertEqual((header['target_id'], header['anchor_id']), (target, anchor))
        self.assertEqual(header['framing'], 'sha256-raw32+bzstrm01')
        self.assertEqual(actual, hashlib.sha256(first).digest() + first + hashlib.sha256(second).digest() + second)
        self.assertNotIn(b'private', output.getvalue())

    def test_partial_finalized_paths_never_append_json_or_claim_anchor_completion(self):
        first, event = self.native_frame(11, 10)
        second, second_event = self.native_frame(10, 9)
        target = gateway.native_id(event['event']['bank'])
        anchor = gateway.native_id(second_event['event']['bank'], parent=True)
        active = dict(generation=GENERATION, source=SOURCE)
        for blocks, budget, missing in [(1, len(first) + len(second), False),
                                        (2, len(first), False), (2, len(first) + len(second), True)]:
            output = io.BytesIO()
            response = Response([b'{"error":"block_unavailable"}']) if missing else self.native_response(second)
            if missing:
                response.status = 410
            with patch.object(gateway, 'binding', return_value=(active, 'c' * 64, '/sock', 'private')):
                with patch.object(gateway, 'UnixHTTP') as http:
                    http.return_value.getresponse.side_effect = [self.native_response(first), response]
                    result = gateway.serve(self.args(mode='finalized-path', block_id=target, anchor_id=anchor,
                                           max_blocks=blocks, max_wire_bytes=budget), output)
            self.assertEqual(result, 75)
            self.assertEqual(output.getvalue().split(b'\n', 1)[1], hashlib.sha256(first).digest() + first)

    def test_finalized_path_checks_frame_source_etag_objects_and_bounds_before_binary_output(self):
        raw, event = self.native_frame(11, 10)
        block_id = gateway.native_id(event['event']['bank'])
        active = dict(generation=GENERATION, source=SOURCE)
        with patch.object(gateway, 'binding', return_value=(active, 'c' * 64, '/sock', 'private')):
            for blocks, budget in [(0, gateway.MAX_PATH_BYTES), (1025, gateway.MAX_PATH_BYTES),
                                    (1, 16), (1, gateway.MAX_PATH_BYTES + 1)]:
                with self.assertRaises(gateway.Admission):
                    gateway.serve(self.args(mode='finalized-path', block_id=block_id,
                                           anchor_id='9:' + '1' * 32, max_blocks=blocks, max_wire_bytes=budget), io.BytesIO())
        corrupted = raw[:-1] + bytes([raw[-1] ^ 1])
        # A matching outer ETag cannot hide changed compact object bytes.
        meta = struct.unpack('<I', raw[8:12])[0]
        changed = json.loads(raw[16:16 + meta])
        changed['marker'] = dict(SOURCE, session_id='wrong-source')
        changed_meta = json.dumps(changed, separators=(',', ':')).encode()
        wrong_source = b'BZSTRM01' + struct.pack('<II', len(changed_meta), len(raw) - 16 - meta) + changed_meta + raw[16 + meta:]
        for wire in [corrupted, wrong_source]:
            output = io.BytesIO()
            with patch.object(gateway, 'UnixHTTP') as http:
                http.return_value.getresponse.return_value = self.native_response(wire)
                with self.assertRaises(gateway.Admission):
                    gateway.checked_finalized_bytes('/sock', 'private', block_id, SOURCE, gateway.MAX_PATH_BYTES)
            self.assertEqual(output.getvalue(), b'')
        response = self.native_response(raw)
        original_header = response.getheader
        response.getheader = lambda name: '"' + 'e' * 64 + '"' if name == 'ETag' else original_header(name)
        with patch.object(gateway, 'UnixHTTP') as http:
            http.return_value.getresponse.return_value = response
            with self.assertRaises(gateway.Admission):
                gateway.checked_finalized_bytes('/sock', 'private', block_id, SOURCE, gateway.MAX_PATH_BYTES)

    def test_path_timeout_and_end_binding_failure_cannot_certify_complete_binary_output(self):
        first, event = self.native_frame(11, 10)
        second, second_event = self.native_frame(10, 9)
        target = gateway.native_id(event['event']['bank'])
        anchor = gateway.native_id(second_event['event']['bank'], parent=True)
        active = dict(generation=GENERATION, source=SOURCE)
        binding = (active, 'c' * 64, '/sock', 'private')
        output = io.BytesIO()
        with patch.object(gateway, 'binding', side_effect=[binding, binding, gateway.Admission(409, 'source_changed')]):
            with patch.object(gateway, 'UnixHTTP') as http:
                http.return_value.getresponse.side_effect = [self.native_response(first), self.native_response(second)]
                self.assertEqual(gateway.serve(self.args(mode='finalized-path', block_id=target, anchor_id=anchor,
                                         max_blocks=2, max_wire_bytes=len(first) + len(second)), output), 75)
        self.assertEqual(output.getvalue().split(b'\n', 1)[1],
                         hashlib.sha256(first).digest() + first + hashlib.sha256(second).digest() + second)
        output = io.BytesIO()
        slow = self.native_response(second)
        slow.read = lambda _: time.sleep(0.5)
        argv = ['gateway', '--job', '/job', '--mode', 'finalized-path', '--generation', GENERATION,
                '--source-json', json.dumps(SOURCE), '--block-id', target, '--anchor-id', anchor,
                '--max-blocks', '2', '--max-wire-bytes', str(len(first) + len(second))]
        with patch.object(gateway.sys, 'argv', argv), patch.object(gateway.sys, 'stdout', SimpleNamespace(buffer=output)):
            with patch.object(gateway, 'FINALIZED_TIMEOUT_SECONDS', 0.05), patch.object(gateway, 'binding', return_value=binding):
                with patch.object(gateway, 'UnixHTTP') as http:
                    http.return_value.getresponse.side_effect = [self.native_response(first), slow]
                    self.assertEqual(gateway.main(), 75)
        # A busy test host can exhaust the short deadline before the first
        # frame. Both zero and one complete frame remain incomplete paths.
        self.assertIn(output.getvalue().split(b'\n', 1)[1], [b'', hashlib.sha256(first).digest() + first])

    def test_finalized_helper_has_a_total_deadline_and_clears_its_alarm(self):
        output = io.BytesIO()
        argv = ['gateway', '--job', '/job', '--mode', 'finalized-block', '--generation', GENERATION,
                '--source-json', json.dumps(SOURCE), '--block-id', '9:' + '1' * 32]
        with patch.object(gateway.sys, 'argv', argv), patch.object(gateway.sys, 'stdout', SimpleNamespace(buffer=output)):
            with patch.object(gateway, 'FINALIZED_TIMEOUT_SECONDS', 0.01), patch.object(gateway, 'serve', side_effect=lambda *_: time.sleep(1)):
                self.assertEqual(gateway.main(), 75)
        self.assertEqual(json.loads(output.getvalue())['status'], 503)
        self.assertEqual(gateway.signal.getitimer(gateway.signal.ITIMER_REAL)[0], 0)

    def test_finalized_block_is_a_pinned_finite_binary_read_with_explicit_scope(self):
        block_id = '472564874:' + '1' * 32
        body = b'BZSTRM01' + bytes(32)
        digest = hashlib.sha256(body).hexdigest()
        active = dict(generation=GENERATION, source=SOURCE)
        for actual, expected in [(body, 0), (body[:-1], 75), (body + b'extra', 75)]:
            response = Response([actual])
            response.getheader = lambda name: {'Content-Type': 'application/vnd.blockzilla.stream.v2',
                    'Content-Length': str(len(body)), 'ETag': '"' + digest + '"',
                    'X-Blockzilla-Commitment': 'finalized'}.get(name)
            output = io.BytesIO()
            with patch.object(gateway, 'binding', return_value=(active, 'c' * 64, '/sock', 'private')):
                with patch.object(gateway, 'UnixHTTP') as http:
                    http.return_value.getresponse.return_value = response
                    result = gateway.serve(self.args(mode='finalized-block', block_id=block_id), output)
                    http.return_value.request.assert_called_once_with('GET', '/v2/banks/finalized/blocks/' + block_id,
                                                                      headers={'Authorization': 'Bearer private'})
            line, received = output.getvalue().split(b'\n', 1)
            header = json.loads(line)
            self.assertEqual((header['block_id'], header['commitment']), (block_id, 'finalized'))
            self.assertEqual((header['frame_sha256'], header['frame_bytes']), (digest, len(body)))
            self.assertEqual(header['retention'], 'rolling-native-only')
            self.assertFalse(header['complete_epoch_coverage'])
            self.assertNotIn(b'private', output.getvalue())
            self.assertEqual(result, expected)
            if expected == 0:
                self.assertEqual(received, body)

    def test_finalized_block_rejects_noncanonical_ids_unpinned_reads_and_unproven_headers(self):
        good = '9:' + '1' * 32
        for value in [good, str(gateway.SAFE_INTEGER) + ':' + '1' * 32]:
            self.assertTrue(gateway.block_id_valid(value))
        for value in [None, '', '09:' + '1' * 32, '+9:' + '1' * 32,
                      str(gateway.SAFE_INTEGER + 1) + ':' + '1' * 32,
                      '9:' + '1' * 31, '9:' + '1' * 33, '9:' + '0' * 32,
                      '9:' + '1' * 32 + ':extra', '../secret', good + ';id']:
            self.assertFalse(gateway.block_id_valid(value), value)
        active = dict(generation=GENERATION, source=SOURCE)
        with patch.object(gateway, 'binding', return_value=(active, 'c' * 64, '/sock', 'private')):
            for args in [self.args(mode='finalized-block', block_id=good, generation=None),
                         self.args(mode='finalized-block', block_id='../bad')]:
                with self.assertRaises(gateway.Admission):
                    gateway.serve(args, io.BytesIO())
            headers = {'Content-Type': 'application/vnd.blockzilla.stream.v2',
                       'Content-Length': '40', 'ETag': '"' + 'e' * 64 + '"',
                       'X-Blockzilla-Commitment': 'finalized'}
            for field, value in [('X-Blockzilla-Commitment', None), ('X-Blockzilla-Commitment', 'processed'),
                                 ('ETag', 'W/"' + 'e' * 64 + '"'), ('ETag', '"bad"'),
                                 ('Content-Length', str(gateway.MAX_FRAME + 1)), ('Content-Type', 'application/json')]:
                response = Response([])
                response.getheader = dict(headers, **{field: value}).get
                output = io.BytesIO()
                with patch.object(gateway, 'UnixHTTP') as http:
                    http.return_value.getresponse.return_value = response
                    with self.assertRaises(gateway.Admission):
                        gateway.serve(self.args(mode='finalized-block', block_id=good), output)
                self.assertEqual(output.getvalue(), b'')

    def test_finalized_miss_keeps_rolling_head_and_never_becomes_a_skipped_slot(self):
        response = Response([json.dumps({'error': 'block_unavailable', 'head': {'earliest_after': CURSOR}}).encode()])
        response.status = 410
        active = dict(generation=GENERATION, source=SOURCE)
        output = io.BytesIO()
        with patch.object(gateway, 'binding', return_value=(active, 'c' * 64, '/sock', 'private')):
            with patch.object(gateway, 'UnixHTTP') as http:
                http.return_value.getresponse.return_value = response
                self.assertEqual(gateway.serve(self.args(mode='finalized-block', block_id='9:' + '1' * 32), output), 78)
        value = json.loads(output.getvalue())
        self.assertEqual(value['status'], 410)
        self.assertEqual(value['reason'], 'block_unavailable')
        self.assertEqual(value['head']['earliest_after'], CURSOR)

    def test_finite_frame_fetch_has_exact_sha_length_and_no_extra_body(self):
        digest = 'e' * 64
        body = b'BZSTRM01' + bytes(32)
        active = dict(generation=GENERATION, source=SOURCE)
        for actual, expected_status in [(body, 0), (body[:-1], 75), (body + b'extra', 75)]:
            response = Response([actual])
            response.getheader = lambda name: {'Content-Type': 'application/vnd.blockzilla.stream.v2',
                    'Content-Length': str(len(body)), 'ETag': '"' + digest + '"'}.get(name)
            output = io.BytesIO()
            with patch.object(gateway, 'binding', return_value=(active, 'c' * 64, '/sock', 'private')):
                with patch.object(gateway, 'UnixHTTP') as http:
                    http.return_value.getresponse.return_value = response
                    result = gateway.serve(self.args(mode='frame', digest=digest), output)
                    http.return_value.request.assert_called_once_with('GET', '/v2/banks/chunks/' + digest,
                                                                      headers={'Authorization': 'Bearer private'})
            line, received = output.getvalue().split(b'\n', 1)
            self.assertEqual(json.loads(line)['frame_sha256'], digest)
            self.assertEqual(json.loads(line)['frame_bytes'], len(body))
            self.assertEqual(result, expected_status)
            if expected_status == 0:
                self.assertEqual(received, body)

    def test_frame_fetch_requires_both_pins_and_digest(self):
        active = dict(generation=GENERATION, source=SOURCE)
        with patch.object(gateway, 'binding', return_value=(active, 'c' * 64, '/sock', 'private')):
            for args in [self.args(mode='frame', digest='../wrong'), self.args(mode='frame', digest='e' * 64, generation=None)]:
                with self.assertRaises(gateway.Admission):
                    gateway.serve(args, io.BytesIO())

    def test_short_writes_cannot_drop_native_frame_bytes(self):
        class ShortWriter(io.BytesIO):
            def write(self, data):
                return super().write(data[:3])
        output = ShortWriter()
        gateway.write_all(output, b'BZSTRM01-native-byte-stream')
        self.assertEqual(output.getvalue(), b'BZSTRM01-native-byte-stream')

    def test_binding_checks_both_feeds_and_exact_retention_authority(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as directory:
            job = Path(directory)
            run = job / 'runs' / GENERATION
            (run / 'processed').mkdir(parents=True)
            (run / 'bank-v2').mkdir()
            limits = dict(retained_banks=1024, max_retained_banks=4096, min_retention_ms=120000, max_output_bytes=68719476736)
            rows = {
                job / 'CONFIG.json': dict(job=str(job), stream_mode='direct-v2', socket_root=str(job), retention=limits),
                job / 'ACTIVE.json': dict(state='CAPTURING', generation=GENERATION, source=SOURCE, run_root=str(run)),
                run / 'processed/FEED.json': dict(SOURCE, schema='hivezilla-processed-feed-v1', profile='native-processed-compact-v1', producer_role='native-live-continuous-v1', producer_generation='c' * 64),
                run / 'bank-v2/FEED.json': dict(SOURCE, schema='hivezilla-bank-feed-v2', profile='native-bank-compact-v2', producer_role='native-live-continuous-v1', producer_generation='c' * 64),
                run / 'bank-v2/RETENTION-AUTHORITY.json': dict(schema='blockzilla-retention-authority-v1', source=SOURCE, producer_generation='c' * 64, mode='local-beam-v1', frontier='full-committed-native-feed-tip', limits=limits, consumer_ack_required=False),
            }
            for path, row in rows.items():
                path.write_text(json.dumps(row))
            (run / 'origin-token').write_text('z' * 64)
            (run / 'origin-token').chmod(0o600)
            with socket.socket(socket.AF_UNIX) as sock:
                sock.bind(str(job / 'origin.sock'))
                (job / 'origin.sock').chmod(0o600)
                self.assertEqual(gateway.binding(job, GENERATION, SOURCE)[1], 'c' * 64)
                for relative, key in [('processed/FEED.json', 'session_id'), ('processed/FEED.json', 'producer_generation'),
                                      ('bank-v2/FEED.json', 'profile'), ('bank-v2/FEED.json', 'node_identity'),
                                      ('bank-v2/RETENTION-AUTHORITY.json', 'frontier'), ('bank-v2/RETENTION-AUTHORITY.json', 'schema')]:
                    path = run / relative
                    changed = dict(rows[path], **{key: 'wrong'})
                    path.write_text(json.dumps(changed))
                    with self.assertRaises(gateway.Admission):
                        gateway.binding(job, GENERATION, SOURCE)
                    path.write_text(json.dumps(rows[path]))
                with self.assertRaises(gateway.Admission) as failure:
                    gateway.binding(job, 'e' * 32, SOURCE)
                self.assertEqual(failure.exception.status, 409)

    def args(self, **changes):
        args = dict(job=Path('/job'), generation=GENERATION,
                    source_json=json.dumps(SOURCE), mode='stream', after=CURSOR)
        args.update(changes)
        return argparse.Namespace(**args)

    def run_stream(self, response, args=None):
        active = dict(generation=GENERATION, source=SOURCE)
        output = io.BytesIO()
        with patch.object(gateway, 'binding', return_value=(active, 'c' * 64, '/sock', 'private-test-credential')):
            with patch.object(gateway, 'UnixHTTP') as http:
                http.return_value.getresponse.return_value = response
                result = gateway.serve(args or self.args(), output)
                http.return_value.request.assert_called_once_with(
                    'GET', '/v2/banks/beam?after=session%3Ap8%3A' + 'b' * 64,
                    headers={'Authorization': 'Bearer private-test-credential'})
                http.return_value.close.assert_called_once()
        raw = output.getvalue()
        self.assertNotIn(b'private-test-credential', raw)
        return result, raw

    def test_original_binary_is_unchanged_after_one_handshake(self):
        body = b'BZSTRM01\x00\xff\nunchanged-body'
        result, raw = self.run_stream(Response([body[:9], body[9:]]))
        line, actual = raw.split(b'\n', 1)
        header = json.loads(line)
        self.assertEqual((header['status'], header['source'], header['start_cursor']), (200, SOURCE, CURSOR))
        self.assertEqual(header['producer_generation'], 'c' * 64)
        self.assertEqual(actual, body)
        self.assertEqual(result, 75)

    def test_midframe_io_failure_does_not_insert_json_into_frame(self):
        result, raw = self.run_stream(Response([b'BZSTRM01partial', OSError('private path')]))
        self.assertEqual(raw.split(b'\n', 1)[1], b'BZSTRM01partial')
        self.assertEqual(result, 75)
        self.assertNotIn(b'private path', raw)

    def test_expired_cursor_remains_explicit_410(self):
        response = Response([json.dumps({'reason': 'replay_unavailable', 'head': {'earliest_after': CURSOR}}).encode()])
        response.status = 410
        result, raw = self.run_stream(response)
        self.assertEqual(result, 78)
        self.assertEqual(json.loads(raw)['status'], 410)
        self.assertEqual(json.loads(raw)['head']['earliest_after'], CURSOR)

    def test_stream_requires_exact_source_and_generation(self):
        active = dict(generation=GENERATION, source=SOURCE)
        with patch.object(gateway, 'binding', return_value=(active, 'c' * 64, '/sock', 'private')):
            with self.assertRaises(gateway.Admission) as failure:
                gateway.serve(self.args(after='other:p8:-'), io.BytesIO())
            self.assertEqual(failure.exception.status, 409)

    def test_source_change_before_handshake_rejects_old_connection(self):
        active = dict(generation=GENERATION, source=SOURCE)
        output = io.BytesIO()
        with patch.object(gateway, 'binding', side_effect=[(active, 'c' * 64, '/sock', 'private'), gateway.Admission(409, 'source_changed')]):
            with patch.object(gateway, 'UnixHTTP') as http:
                http.return_value.getresponse.return_value = Response([])
                with self.assertRaises(gateway.Admission):
                    gateway.serve(self.args(), output)
        self.assertEqual(output.getvalue(), b'')

    def test_token_file_must_be_private_regular_single_link_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            token = Path(directory) / 'token'
            token.write_text('private')
            token.chmod(0o600)
            self.assertEqual(gateway.read_private(token, secret=True), b'private')
            token.chmod(0o644)
            with self.assertRaises(gateway.Admission):
                gateway.read_private(token, secret=True)
            token.chmod(0o600)
            os.link(token, Path(directory) / 'link')
            with self.assertRaises(gateway.Admission):
                gateway.read_private(token, secret=True)

    def test_fifo_metadata_is_rejected_without_blocking_open(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'token'
            os.mkfifo(path, 0o600)
            with self.assertRaises(gateway.Admission):
                gateway.read_private(path, secret=True)

    def test_producer_change_before_handshake_is_terminal(self):
        active = dict(generation=GENERATION, source=SOURCE)
        output = io.BytesIO()
        rows = [(active, 'c' * 64, '/sock', 'private'), (active, 'd' * 64, '/sock', 'private')]
        with patch.object(gateway, 'binding', side_effect=rows), patch.object(gateway, 'UnixHTTP') as http:
            http.return_value.getresponse.return_value = Response([])
            with self.assertRaises(gateway.Admission) as failure:
                gateway.serve(self.args(), output)
            self.assertEqual(failure.exception.reason, 'producer_generation_changed')
        self.assertEqual(output.getvalue(), b'')

    def test_clock_echo_is_bounded_and_has_no_origin_access(self):
        output = io.BytesIO()
        self.assertEqual(gateway.clock(io.BytesIO(b'7\n8\n'), output), 0)
        values = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual([v['nonce'] for v in values], ['7', '8'])
        self.assertTrue(all(v['server_receive_unix_ns'] <= v['server_send_unix_ns'] for v in values))
        self.assertEqual(gateway.clock(io.BytesIO(b'nope\n'), io.BytesIO()), 78)


if __name__ == '__main__':
    unittest.main()
