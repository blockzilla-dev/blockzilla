#!/usr/bin/env python3
"""Read-only SSH adapter for the private native beam. No credential leaves the host.

One bounded JSON line precedes the unchanged BZSTRM01 response bytes. This is
an owner SSH tool, not a public HTTP service or an authentication bypass.

finalized-block reads one exact retained native root. finalized-path follows
checked parent IDs in one session, includes the target and excludes the anchor.
Its body is repeated raw32 ETag digests plus unchanged BZSTRM01 frames. A
partial path or nonzero helper exit is never complete recovery. Both operations
are read-only and make no complete-epoch or long-outage coverage claim.
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import socket
import sqlite3
import stat
import struct
import sys
import time
from urllib.parse import urlencode

SCHEMA = 'blockzilla-ssh-beam-v1'
MAX_JSON = 65536
MAX_FRAME = 16 + MAX_JSON + 16 * 1024 * 1024
SAFE_INTEGER = 9007199254740991
FINALIZED_TIMEOUT_SECONDS = 25
MAX_PATH_BLOCKS = 1024
MAX_PATH_BYTES = 192 * 1024 * 1024
MAX_RECOVERY_EVENTS = 128
MAX_RECOVERY_BYTES = 4 * 1024 * 1024
MAX_CONTROL_BYTES = 32768


class Admission(Exception):
    def __init__(self, status, reason, head=None):
        self.status, self.reason, self.head = status, reason, head


def read_private(path, limit=MAX_JSON, secret=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_size > limit
                or info.st_mode & (0o077 if secret else 0o022)):
            raise Admission(503, 'unsafe_private_input')
        raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise Admission(503, 'oversized_private_input')
    return raw


def object_file(path):
    value = json.loads(read_private(path))
    if not isinstance(value, dict):
        raise Admission(503, 'invalid_metadata_object')
    return value


def valid_source(source):
    return (isinstance(source, dict)
            and set(source) == {'agave_revision', 'genesis_hash', 'node_identity', 'session_id'}
            and all(isinstance(v, str) and 1 <= len(v) <= 256
                    and all(33 <= ord(c) <= 126 for c in v) for v in source.values()))


def binding(job, generation=None, expected_source=None):
    config = object_file(job / 'CONFIG.json')
    active = object_file(job / 'ACTIVE.json')
    if (config.get('job') != str(job) or config.get('stream_mode') != 'direct-v2'
            or active.get('state') != 'CAPTURING'):
        raise Admission(503, 'direct_source_not_ready')
    current = active.get('generation', '')
    if not re.fullmatch('[0-9a-f]{32}', current) or not valid_source(active.get('source')):
        raise Admission(503, 'invalid_active_binding')
    if generation is not None and generation != current:
        raise Admission(409, 'runtime_generation_changed')
    if expected_source is not None and expected_source != active['source']:
        raise Admission(409, 'source_changed')
    run = job / 'runs' / current
    if active.get('run_root') != str(run) or run.is_symlink():
        raise Admission(503, 'invalid_run_path')
    processed = object_file(run / 'processed' / 'FEED.json')
    feed = object_file(run / 'bank-v2' / 'FEED.json')
    producer = feed.get('producer_generation', '')
    if not re.fullmatch('[0-9a-f]{64}', producer):
        raise Admission(503, 'invalid_producer_generation')
    for descriptor, schema, profile in ((processed, 'hivezilla-processed-feed-v1', 'native-processed-compact-v1'),
                                         (feed, 'hivezilla-bank-feed-v2', 'native-bank-compact-v2')):
        if (descriptor.get('schema') != schema or descriptor.get('profile') != profile
                or descriptor.get('producer_role') != 'native-live-continuous-v1'
                or descriptor.get('producer_generation') != producer
                or any(descriptor.get(k) != v for k, v in active['source'].items())):
            raise Admission(503, 'feed_source_binding_mismatch')
    authority = object_file(run / 'bank-v2' / 'RETENTION-AUTHORITY.json')
    limits = {key: config['retention'][key] for key in
              ('retained_banks', 'max_retained_banks', 'min_retention_ms', 'max_output_bytes')}
    if (authority.get('schema') != 'blockzilla-retention-authority-v1'
            or authority.get('source') != active['source']
            or authority.get('producer_generation') != producer
            or authority.get('mode') != 'local-beam-v1'
            or authority.get('frontier') != 'full-committed-native-feed-tip'
            or authority.get('limits') != limits
            or authority.get('consumer_ack_required') is not False):
        raise Admission(503, 'direct_authority_mismatch')
    sock = Path(config['socket_root']) / 'origin.sock'
    info = sock.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise Admission(503, 'unsafe_origin_socket')
    token = read_private(run / 'origin-token', limit=4096, secret=True).decode('ascii').strip()
    if not 32 <= len(token) <= 256 or not all(33 <= ord(c) <= 126 for c in token):
        raise Admission(503, 'invalid_private_credential')
    return active, producer, sock, token


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__('localhost', timeout=15)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(self.path))


def write_all(output, data):
    view = memoryview(data)
    while view:
        written = output.write(view)
        if not isinstance(written, int) or not 0 < written <= len(view):
            raise OSError('SSH output did not accept data')
        view = view[written:]


def emit(value, output):
    raw = json.dumps(value, separators=(',', ':')).encode('utf8')
    if len(raw) >= MAX_JSON:
        raise Admission(503, 'oversized_handshake')
    write_all(output, raw + b'\n')
    output.flush()


def cursor_valid(cursor, source):
    return (isinstance(cursor, str) and len(cursor) <= 512
            and re.fullmatch(re.escape(source['session_id']) + r':p[0-9]{1,16}:(?:-|[0-9a-f]{64})', cursor)
            is not None)


def block_id_valid(value):
    if not isinstance(value, str) or len(value) > 61:
        return False
    fields = value.split(':')
    if len(fields) != 2 or not re.fullmatch(r'(?:0|[1-9][0-9]{0,15})', fields[0]):
        return False
    if int(fields[0]) > SAFE_INTEGER:
        return False
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    encoded = fields[1]
    if not 32 <= len(encoded) <= 44 or any(char not in alphabet for char in encoded):
        return False
    number = 0
    for char in encoded:
        number = number * 58 + alphabet.index(char)
    zeroes = len(encoded) - len(encoded.lstrip('1'))
    return zeroes + (number.bit_length() + 7) // 8 == 32


def native_id(bank, parent=False):
    slot = bank['parent_slot' if parent else 'slot']
    value = bank['parent_blockhash' if parent else 'blockhash']
    if type(slot) is not int or not 0 <= slot <= SAFE_INTEGER or not isinstance(value, list) or len(value) != 32:
        raise Admission(503, 'invalid_native_block_identity')
    if any(type(byte) is not int or not 0 <= byte <= 255 for byte in value):
        raise Admission(503, 'invalid_native_block_identity')
    raw = bytes(value)
    number, encoded = int.from_bytes(raw, 'big'), ''
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    while number:
        number, digit = divmod(number, 58)
        encoded = alphabet[digit] + encoded
    return str(slot) + ':' + '1' * (len(raw) - len(raw.lstrip(b'\0'))) + encoded


def checked_finalized_bytes(sock, token, block_id, source, remaining):
    connection = UnixHTTP(sock)
    try:
        connection.request('GET', '/v2/banks/finalized/blocks/' + block_id,
                           headers={'Authorization': 'Bearer ' + token})
        response = connection.getresponse()
        if response.status != 200:
            raw = response.read(MAX_JSON + 1)
            head = None
            try:
                value = json.loads(raw) if len(raw) <= MAX_JSON else {}
                candidate = value.get('head')
                if isinstance(candidate, dict) and candidate.get('source') == source:
                    head = candidate
            except (ValueError, AttributeError):
                pass
            raise Admission(410 if response.status in (404, 410) else 503,
                            'finalized_block_unavailable', head)
        length, etag = response.getheader('Content-Length'), response.getheader('ETag')
        if (response.getheader('Content-Type') != 'application/vnd.blockzilla.stream.v2'
                or response.getheader('X-Blockzilla-Commitment') != 'finalized'
                or not isinstance(etag, str) or not re.fullmatch(r'"[0-9a-f]{64}"', etag)
                or not isinstance(length, str) or not length.isdigit()
                or not 16 < int(length) <= MAX_FRAME):
            raise Admission(503, 'finalized_frame_headers_mismatch')
        if int(length) > remaining:
            raise Admission(410, 'finalized_path_budget_exceeded')
        raw = response.read(int(length) + 1)
        if len(raw) != int(length) or hashlib.sha256(raw).hexdigest() != etag[1:-1]:
            raise Admission(503, 'finalized_frame_digest_mismatch')
        if raw[:8] != b'BZSTRM01':
            raise Admission(503, 'invalid_native_frame')
        meta, payload_bytes = struct.unpack('<II', raw[8:16])
        if not 0 < meta <= MAX_JSON or payload_bytes > 16 * 1024 * 1024 or len(raw) != 16 + meta + payload_bytes:
            raise Admission(503, 'invalid_native_frame')
        envelope = json.loads(raw[16:16 + meta])
        if (envelope.get('profile') != 'native-bank-compact-v2'
                or any(envelope.get('marker', {}).get(key) != value for key, value in source.items())
                or envelope.get('event', {}).get('kind') != 'block'
                or native_id(envelope['event']['bank']) != block_id):
            raise Admission(409, 'finalized_block_or_source_changed')
        payload = memoryview(raw)[16 + meta:]
        paths = set()
        for obj in envelope['objects']:
            start, count = obj['offset'], obj['bytes']
            if (type(start) is not int or type(count) is not int or start < 0 or count < 0
                    or start + count > len(payload) or obj['path'] in paths
                    or hashlib.sha256(payload[start:start + count]).hexdigest() != obj['sha256']):
                raise Admission(503, 'native_object_digest_mismatch')
            paths.add(obj['path'])
        parent = native_id(envelope['event']['bank'], parent=True)
        if int(parent.split(':')[0]) >= int(block_id.split(':')[0]):
            raise Admission(503, 'invalid_native_parent')
        return raw, bytes.fromhex(etag[1:-1]), parent
    except (ValueError, KeyError, TypeError, struct.error):
        raise Admission(503, 'invalid_native_frame')
    finally:
        connection.close()


def finalized_path(args, output, active, producer, sock, token):
    target, anchor = args.block_id, args.anchor_id
    if (not block_id_valid(target) or not block_id_valid(anchor)
            or int(target.split(':')[0]) <= int(anchor.split(':')[0])
            or type(args.max_blocks) is not int or not 1 <= args.max_blocks <= MAX_PATH_BLOCKS
            or type(args.max_wire_bytes) is not int or not 17 <= args.max_wire_bytes <= MAX_PATH_BYTES):
        raise Admission(400, 'invalid_finalized_path_bounds')
    current, count, total, started = target, 0, 0, False
    try:
        while current != anchor:
            if count >= args.max_blocks or int(current.split(':')[0]) <= int(anchor.split(':')[0]):
                raise Admission(410, 'finalized_anchor_not_reached')
            raw, digest, parent = checked_finalized_bytes(sock, token, current, active['source'], args.max_wire_bytes - total)
            if not started:
                _, after_producer, _, _ = binding(args.job, active['generation'], active['source'])
                if after_producer != producer:
                    raise Admission(409, 'producer_generation_changed')
                emit({'schema': SCHEMA, 'status': 200, 'source': active['source'],
                      'generation': active['generation'], 'producer_generation': producer,
                      'target_id': target, 'anchor_id': anchor, 'max_blocks': args.max_blocks,
                      'max_wire_bytes': args.max_wire_bytes, 'framing': 'sha256-raw32+bzstrm01',
                      'content_type': 'application/vnd.blockzilla.finalized-path.v1',
                      'commitment': 'finalized', 'retention': 'rolling-native-only',
                      'complete_epoch_coverage': False}, output)
                started = True
            write_all(output, digest)
            write_all(output, raw)
            output.flush()
            count += 1
            total += len(raw)
            current = parent
        _, after_producer, _, _ = binding(args.job, active['generation'], active['source'])
        if after_producer != producer:
            raise Admission(409, 'producer_generation_changed')
        return 0
    except (Admission, OSError, ValueError, KeyError, TypeError, http.client.HTTPException):
        if started:
            # Partial binary output is never followed by another JSON handshake.
            return 75
        raise


def recovery_cursor(value, source):
    if not cursor_valid(value, source):
        raise Admission(400, 'invalid_recovery_cursor')
    number, digest = value.rsplit(':p', 1)[1].split(':')
    sequence = int(number)
    if str(sequence) != number or sequence > SAFE_INTEGER or (sequence == 0) != (digest == '-'):
        raise Admission(400, 'invalid_recovery_cursor')
    return sequence, digest


def recovery_rows(args, active):
    """Read only committed identities. Never open a block payload or artifact."""
    after, after_sha = recovery_cursor(args.after, active['source'])
    until, until_sha = recovery_cursor(args.until, active['source'])
    if (after > until or type(args.max_events) is not int
            or not 1 <= args.max_events <= MAX_RECOVERY_EVENTS):
        raise Admission(400, 'invalid_recovery_bounds')
    path = args.job / 'runs' / active['generation'] / 'bank-v2' / 'feed.sqlite'
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1:
        raise Admission(503, 'unsafe_recovery_catalog')
    connection = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=0.25)
    try:
        connection.execute('PRAGMA query_only=ON')
        connection.execute('BEGIN')
        floor, floor_sha = connection.execute(
            'SELECT base_sequence,base_sha256 FROM feed_retention WHERE id=1').fetchone()
        tip = connection.execute('SELECT MAX(sequence) FROM feed_events').fetchone()[0]
        if after < floor or until < floor:
            raise Admission(410, 'replay_unavailable')
        if until > (tip if tip is not None else floor):
            raise Admission(400, 'recovery_cursor_ahead')
        for sequence, digest in ((after, after_sha), (until, until_sha)):
            actual = (floor_sha,) if sequence == floor else connection.execute(
                'SELECT frame_sha256 FROM feed_events WHERE sequence=?', (sequence,)).fetchone()
            if actual is None or actual[0] != digest:
                raise Admission(400, 'invalid_recovery_cursor')
        rows = connection.execute(
            'SELECT sequence,event_json,frame_sha256 FROM feed_events '
            'WHERE sequence>? AND sequence<=? ORDER BY sequence LIMIT ?',
            (after, until, args.max_events)).fetchall()
        expected = after + 1
        entries = []
        for sequence, raw, digest in rows:
            if sequence != expected:
                raise Admission(410, 'replay_unavailable')
            if (not isinstance(raw, str) or len(raw) >= MAX_JSON or len(raw.encode('utf8')) >= MAX_JSON
                    or not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest)):
                raise Admission(503, 'invalid_recovery_event')
            event = json.loads(raw)
            if (not isinstance(event, dict) or type(event.get('sequence')) is not int or event['sequence'] != sequence
                    or event.get('kind') not in ('block', 'confirmed', 'root', 'invalidate')):
                raise Admission(503, 'invalid_recovery_event')
            native_id(event['bank'])
            native_id(event['bank'], parent=True)
            bank_id = event['bank'].get('bank_id')
            if (type(bank_id) is not int or not 0 <= bank_id <= SAFE_INTEGER
                    or event['bank']['parent_slot'] >= event['bank']['slot']):
                raise Admission(503, 'invalid_recovery_event')
            entries.append({'cursor': active['source']['session_id'] + ':p' + str(sequence) + ':' + digest,
                            'sha256': digest, 'event': event, 'source': active['source']})
            expected += 1
        if len(rows) != min(until - after, args.max_events):
            raise Admission(410, 'replay_unavailable')
        return entries
    finally:
        connection.close()


def checked_control_bytes(sock, token, notice):
    """Fetch a tiny original control Frame; do not reconstruct it from JSON."""
    connection = UnixHTTP(sock)
    try:
        connection.request('GET', '/v2/banks/chunks/' + notice['sha256'],
                           headers={'Authorization': 'Bearer ' + token})
        response = connection.getresponse()
        if response.status != 200:
            raise Admission(410 if response.status in (404, 410) else 503, 'recovery_control_unavailable')
        length = response.getheader('Content-Length')
        if (response.getheader('Content-Type') != 'application/vnd.blockzilla.stream.v2'
                or response.getheader('ETag') != '"' + notice['sha256'] + '"'
                or not isinstance(length, str) or not length.isdigit()
                or not 16 < int(length) <= MAX_CONTROL_BYTES):
            raise Admission(503, 'recovery_control_headers_mismatch')
        raw = response.read(int(length) + 1)
        if len(raw) != int(length) or hashlib.sha256(raw).hexdigest() != notice['sha256']:
            raise Admission(503, 'recovery_control_digest_mismatch')
        if raw[:8] != b'BZSTRM01':
            raise Admission(503, 'invalid_recovery_control')
        meta, payload = struct.unpack('<II', raw[8:16])
        if not 0 < meta <= MAX_JSON or payload != 0 or len(raw) != 16 + meta:
            raise Admission(503, 'invalid_recovery_control')
        envelope = json.loads(raw[16:])
        if (envelope.get('profile') != 'native-bank-compact-v2'
                or envelope.get('event') != notice['event']
                or envelope.get('objects') != []
                or any(envelope.get('marker', {}).get(k) != v for k, v in notice['source'].items())
                or notice['event']['kind'] == 'block'):
            raise Admission(409, 'recovery_control_identity_changed')
        return raw
    finally:
        connection.close()


def recovery_plan(args, output, active, producer, sock, token):
    entries = recovery_rows(args, active)
    lines = []
    total = 0
    for notice in entries:
        entry = dict(notice)
        if notice['event']['kind'] != 'block':
            entry['control_wire_base64'] = base64.b64encode(checked_control_bytes(sock, token, notice)).decode('ascii')
        line = json.dumps(entry, separators=(',', ':')).encode('utf8') + b'\n'
        if len(line) > MAX_JSON or total + len(line) > MAX_RECOVERY_BYTES - MAX_JSON:
            raise Admission(503, 'recovery_plan_too_large')
        lines.append(line)
        total += len(line)
    # A request admitted under an old binding or retired page cannot succeed.
    _, current_producer, _, _ = binding(args.job, active['generation'], active['source'])
    if current_producer != producer:
        raise Admission(409, 'producer_generation_changed')
    if recovery_rows(args, active) != entries:
        raise Admission(409, 'recovery_plan_changed')
    try:
        emit({'schema': SCHEMA, 'status': 200, 'source': active['source'],
              'generation': active['generation'], 'producer_generation': producer,
              'start_cursor': args.after, 'until_cursor': args.until,
              'end_cursor': entries[-1]['cursor'] if entries else args.after,
              'entry_count': len(entries), 'framing': 'recovery-plan-ndjson-v1',
              'content_type': 'application/vnd.blockzilla.recovery-plan.v1+ndjson',
              'retention': 'rolling-native-only', 'complete_epoch_coverage': False}, output)
        # Emit only after the complete finite page is checked. EOF and exit0
        # are required; never append a JSON error to a partial page.
        for line in lines:
            write_all(output, line)
        output.flush()
        return 0
    except OSError:
        return 75


def serve(args, output):
    source = json.loads(args.source_json) if args.source_json else None
    if source is not None and not valid_source(source):
        raise Admission(409, 'invalid_expected_source')
    active, producer, sock, token = binding(args.job, args.generation, source)
    if args.mode in ('stream', 'frame', 'finalized-block', 'finalized-path', 'recovery-plan') and (not args.generation or source is None):
        raise Admission(409, 'exact_stream_binding_required')
    if args.mode == 'finalized-path':
        return finalized_path(args, output, active, producer, sock, token)
    if args.mode == 'recovery-plan':
        return recovery_plan(args, output, active, producer, sock, token)
    if args.mode == 'stream' and not cursor_valid(args.after, source):
        raise Admission(409, 'exact_stream_binding_required')
    if args.mode == 'finalized-block':
        if not block_id_valid(getattr(args, 'block_id', None)):
            raise Admission(400, 'invalid_block_id')
        path = '/v2/banks/finalized/blocks/' + args.block_id
    elif args.mode == 'frame':
        if not re.fullmatch('[0-9a-f]{64}', getattr(args, 'digest', '') or ''):
            raise Admission(400, 'invalid_frame_digest')
        path = '/v2/banks/chunks/' + args.digest
    else:
        path = '/v2/banks/head' if args.mode == 'head' else '/v2/banks/beam?' + urlencode({'after': args.after})
    connection = UnixHTTP(sock)
    try:
        connection.request('GET', path, headers={'Authorization': 'Bearer ' + token})
        response = connection.getresponse()
        del token
        if response.status != 200:
            body = response.read(MAX_JSON + 1)
            result = {'schema': SCHEMA, 'status': response.status, 'error': 'origin_rejected'}
            if len(body) <= MAX_JSON:
                try:
                    parsed = json.loads(body)
                    if isinstance(parsed, dict):
                        # Only protocol recovery metadata, never arbitrary headers or credentials.
                        for key in ('head', 'reason'):
                            if key in parsed:
                                result[key] = parsed[key]
                        if args.mode == 'finalized-block' and parsed.get('error') in (
                                'block_unavailable', 'replay_unavailable', 'source_changed'):
                            result['reason'] = parsed['error']
                except (ValueError, UnicodeError):
                    pass
            emit(result, output)
            return 78 if response.status in (400, 401, 403, 409, 410) else 75
        # Do not expose a new generation through an old authenticated connection.
        _, producer_after, _, _ = binding(args.job, active['generation'], active['source'])
        if producer_after != producer:
            raise Admission(409, 'producer_generation_changed')
        result = {'schema': SCHEMA, 'status': 200, 'source': active['source'],
                  'generation': active['generation'], 'producer_generation': producer,
                  'server_unix_ms': time.time_ns() // 1000000}
        if args.mode == 'head':
            raw = response.read(MAX_JSON + 1)
            if len(raw) > MAX_JSON:
                raise Admission(503, 'oversized_head')
            head = json.loads(raw)
            if not isinstance(head, dict) or head.get('source') != active['source']:
                raise Admission(409, 'head_source_mismatch')
            if not cursor_valid(head.get('cursor'), active['source']):
                raise Admission(503, 'invalid_head_cursor')
            result['head'] = head
            emit(result, output)
            return 0
        frame_bytes = None
        if args.mode in ('frame', 'finalized-block'):
            length = response.getheader('Content-Length')
            etag = response.getheader('ETag')
            digest = args.digest if args.mode == 'frame' else (
                etag[1:-1] if isinstance(etag, str) and re.fullmatch(r'"[0-9a-f]{64}"', etag) else None)
            if (not isinstance(length, str) or not length.isdigit()
                    or not 16 < int(length) <= MAX_FRAME
                    or digest is None or etag != '"' + digest + '"'):
                raise Admission(503, 'frame_headers_mismatch')
            if args.mode == 'finalized-block' and response.getheader('X-Blockzilla-Commitment') != 'finalized':
                raise Admission(503, 'native_finality_header_missing')
            frame_bytes = int(length)
        if (response.getheader('Content-Type') != 'application/vnd.blockzilla.stream.v2'
                or args.mode == 'stream' and response.getheader('X-Blockzilla-Start-Cursor') != args.after):
            raise Admission(503, 'beam_headers_mismatch')
        result.update(content_type='application/vnd.blockzilla.stream.v2')
        if args.mode in ('frame', 'finalized-block'):
            result.update(frame_sha256=digest, frame_bytes=frame_bytes)
            if args.mode == 'finalized-block':
                result.update(block_id=args.block_id, commitment='finalized',
                              retention='rolling-native-only', complete_epoch_coverage=False)
        else:
            result.update(start_cursor=args.after)
        try:
            emit(result, output)
            # After the handshake, stdout is exclusively the original response body.
            sent = 0
            while True:
                part = response.read1(65536)
                if not part:
                    return 0 if frame_bytes is not None and sent == frame_bytes else 75
                sent += len(part)
                if frame_bytes is not None and sent > frame_bytes:
                    return 75
                write_all(output, part)
                output.flush()
        except (OSError, http.client.HTTPException):
            return 75
    finally:
        connection.close()


def clock(input_stream, output):
    # A persistent SSH channel removes SSH setup time from the offset samples.
    for _ in range(32):
        line = input_stream.readline(257)
        received = time.time_ns()
        if not line:
            return 0
        if len(line) > 256 or not re.fullmatch(rb'[0-9]{1,20}\n', line):
            return 78
        emit({'schema': 'blockzilla-ssh-clock-v1', 'nonce': line.decode().strip(),
              'server_receive_unix_ns': received, 'server_send_unix_ns': time.time_ns()}, output)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--job', type=Path, required=True)
    parser.add_argument('--mode', choices=('head', 'stream', 'frame', 'finalized-block', 'finalized-path', 'recovery-plan', 'clock'), required=True)
    parser.add_argument('--generation')
    parser.add_argument('--source-json')
    parser.add_argument('--after')
    parser.add_argument('--until')
    parser.add_argument('--max-events', type=int)
    parser.add_argument('--digest')
    parser.add_argument('--block-id')
    parser.add_argument('--anchor-id')
    parser.add_argument('--max-blocks', type=int)
    parser.add_argument('--max-wire-bytes', type=int)
    args = parser.parse_args()
    if not args.job.is_absolute():
        return 78
    if args.mode == 'clock':
        return clock(sys.stdin.buffer, sys.stdout.buffer)
    previous_alarm = None
    if args.mode in ('finalized-block', 'finalized-path', 'recovery-plan'):
        def expired(_signal, _frame):
            raise TimeoutError('finite native lookup deadline')
        previous_alarm = signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, FINALIZED_TIMEOUT_SECONDS)
    try:
        return serve(args, sys.stdout.buffer)
    except Admission as error:
        value = {'schema': SCHEMA, 'status': error.status, 'error': error.reason}
        if error.head is not None:
            value['head'] = error.head
        emit(value, sys.stdout.buffer)
        return 78 if error.status in (400, 401, 403, 409, 410) else 75
    except (OSError, ValueError, KeyError, UnicodeError, sqlite3.Error, http.client.HTTPException):
        emit({'schema': SCHEMA, 'status': 503, 'error': 'private_origin_unavailable'}, sys.stdout.buffer)
        return 75
    finally:
        if previous_alarm is not None:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous_alarm)


if __name__ == '__main__':
    raise SystemExit(main())
