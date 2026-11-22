#!/usr/bin/env python3
"""Test an isolated stream reader and the recent-first Worker. No payload files.

Run on Foundation. Read the private Worker configuration from --config or stdin.
The report holds identities, digests and timings, but no keys, URLs or bodies.
"""
import argparse
import base64
import datetime as dt
import hashlib
import http.client
import json
from pathlib import Path
import re
import socket
import struct
import time
import urllib.parse

MAX_META = 65536
MAX_PAYLOAD = 16 * 1024 * 1024
MAX_FRAME = 16 + MAX_META + MAX_PAYLOAD
MAX_RETAINED = 16 * 1024 * 1024
SAFE = 9007199254740991
FILES = {
    'DIRECT-AGAVE-NORMALIZED.v1.json', 'archive-v2-blocks.index',
    'archive-v2-blocks.zstd', 'archive-v2-meta.wincode', 'available-poh.wincode',
    'blockhash_registry.bin', 'prev_blockhash_tail.bin', 'registry.bin',
    'registry.mphf', 'registry_counts.bin', 'signatures.bin', 'vote_hash_registry.bin',
}
REQUIRED = FILES - {'prev_blockhash_tail.bin', 'registry.mphf', 'registry_counts.bin', 'vote_hash_registry.bin'}
DIGEST = re.compile(r'^[a-f0-9]{64}$')
B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
SOURCE_FIELDS = ('genesis_hash', 'node_identity', 'agave_revision', 'session_id')

class CheckError(Exception):
    """Use fixed non-sensitive messages only."""


def ensure(value, code):
    if not value:
        raise CheckError(code)


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def sha(value):
    return hashlib.sha256(value).hexdigest()


def base58(value):
    ensure(isinstance(value, (bytes, bytearray, list)) and len(value) == 32, 'invalid_hash_bytes')
    value = bytes(value)
    number = int.from_bytes(value, 'big')
    result = ''
    while number:
        number, remainder = divmod(number, 58)
        result = B58[remainder] + result
    leading = len(value) - len(value.lstrip(b'\x00'))
    return '1' * leading + result


def cursor_parts(cursor):
    ensure(isinstance(cursor, str) and len(cursor) <= 220, 'invalid_cursor')
    parts = cursor.split(':')
    ensure(len(parts) == 3 and re.fullmatch(r'[A-Za-z0-9-]{1,128}', parts[0]), 'invalid_cursor')
    ensure(re.fullmatch(r'p(?:0|[1-9][0-9]*)', parts[1]), 'invalid_cursor')
    number = int(parts[1][1:])
    ensure(number <= SAFE and (DIGEST.fullmatch(parts[2]) or (number == 0 and parts[2] == '-')), 'invalid_cursor')
    return parts[0], number, parts[2]


def source_from_marker(marker):
    result = {key: marker.get(key) for key in SOURCE_FIELDS}
    ensure(all(isinstance(v, str) and v for v in result.values()), 'invalid_source')
    ensure(re.fullmatch(r'[A-Za-z0-9-]{1,128}', result['session_id']), 'invalid_session')
    return result


def frame_identity(wire, expected_source=None):
    ensure(isinstance(wire, bytes) and 16 <= len(wire) <= MAX_FRAME and wire[:8] == b'BZSTRM01', 'invalid_frame_header')
    meta_length, body_length = struct.unpack('<II', wire[8:16])
    ensure(1 <= meta_length <= MAX_META and body_length <= MAX_PAYLOAD and len(wire) == 16 + meta_length + body_length, 'invalid_frame_length')
    meta = json.loads(wire[16:16 + meta_length])
    ensure(meta.get('schema') == 'blockzilla-stream-envelope-v2' and meta.get('profile') == 'native-bank-compact-v2' and meta.get('evidence_included') is False, 'unsupported_frame_profile')
    event, marker, objects = meta['event'], meta['marker'], meta['objects']
    source = source_from_marker(marker)
    if expected_source is not None:
        ensure(source == expected_source, 'source_changed')
    bank = event['bank']
    for name in ('slot', 'bank_id', 'parent_slot'):
        ensure(type(bank.get(name)) is int and 0 <= bank[name] <= SAFE, 'invalid_bank_identity')
    ensure(bank['parent_slot'] < bank['slot'], 'invalid_parent_slot')
    blockhash, parent_hash = base58(bank['blockhash']), base58(bank['parent_blockhash'])
    ensure(type(event.get('sequence')) is int and 0 < event['sequence'] <= SAFE, 'invalid_event_sequence')
    ensure(type(event.get('source_sequence')) is int and 0 < event['source_sequence'] <= SAFE, 'invalid_source_sequence')
    ensure(DIGEST.fullmatch(event.get('payload_sha256', '')), 'invalid_payload_identity')
    payload = memoryview(wire)[16 + meta_length:]
    object_checks = []
    if event['kind'] == 'block':
        ensure(event.get('commitment') == 'processed' and event.get('payload_frame_sha256') is None, 'invalid_block_event')
        ensure(marker.get('schema') == 'hivezilla-direct-agave-processed-compact-v1' and marker.get('state') == 'COMPLETE', 'invalid_block_marker')
        ensure(marker.get('canonical') is False and marker.get('publication_ready') is False and marker.get('finalized') is False, 'invalid_processed_claim')
        produced = marker.get('produced_blocks')
        ensure(isinstance(produced, list) and len(produced) == 1 and all(produced[0].get(k) == bank[k] for k in bank), 'bank_marker_mismatch')
        ensure(isinstance(objects, list) and len(objects) <= len(FILES), 'invalid_object_count')
        seen, offset = set(), 0
        for obj in objects:
            name = obj.get('path')
            ensure(name in FILES and name not in seen and obj.get('offset') == offset and type(obj.get('bytes')) is int and obj['bytes'] >= 0, 'invalid_object_geometry')
            ensure(DIGEST.fullmatch(obj.get('sha256', '')), 'invalid_object_digest')
            end = offset + obj['bytes']
            ensure(end <= body_length and sha(payload[offset:end]) == obj['sha256'], 'object_digest_mismatch')
            matches = [f for f in marker.get('files', []) if f.get('path') == name]
            ensure(len(matches) == 1 and matches[0].get('bytes') == obj['bytes'] and matches[0].get('sha256') == obj['sha256'], 'marker_object_mismatch')
            object_checks.append({'path': name, 'bytes': obj['bytes'], 'sha256': obj['sha256']})
            offset, seen = end, seen | {name}
        ensure(offset == body_length and REQUIRED <= seen, 'incomplete_block_objects')
    else:
        ensure(event['kind'] in ('confirmed', 'root', 'invalidate') and body_length == 0 and objects == [], 'invalid_control_frame')
        ensure(marker.get('schema') == 'hivezilla-bank-control-v2' and marker.get('state') == 'COMPLETE', 'invalid_control_marker')
        ensure(marker.get('canonical') is False and marker.get('publication_ready') is False, 'invalid_control_claim')
        ensure(marker.get('finalized') is (event['kind'] == 'root'), 'invalid_control_commitment')
        ensure(DIGEST.fullmatch(event.get('payload_frame_sha256', '')), 'missing_control_payload')
    digest = sha(wire)
    cursor = f"{source['session_id']}:p{event['sequence']}:{digest}"
    return {'slot': bank['slot'], 'bank_id': bank['bank_id'], 'blockhash': blockhash,
            'parent_slot': bank['parent_slot'], 'parent_blockhash': parent_hash,
            'kind': event['kind'], 'sequence': event['sequence'], 'source_sequence': event['source_sequence'],
            'source': source, 'cursor': cursor, 'frame_sha256': digest, 'bytes': len(wire),
            'payload_sha256': event['payload_sha256'], 'payload_frame_sha256': event.get('payload_frame_sha256'),
            'objects': object_checks}


class VerifiedCursor:
    """A cursor changes only after complete frame and expected digest checks."""
    def __init__(self, after, source):
        self.cursor, self.source = after, source
        ensure(cursor_parts(after)[0] == source['session_id'], 'cursor_source_differs')

    def accept(self, wire, expected_digest):
        frame = frame_identity(wire, self.source)
        ensure(frame['frame_sha256'] == expected_digest, 'expected_frame_digest_differs')
        ensure(frame['sequence'] > cursor_parts(self.cursor)[1], 'nonadvancing_native_cursor')
        self.cursor = frame['cursor']
        return frame


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__('localhost', timeout=5)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class Origin:
    def __init__(self, root):
        root = Path(root)
        active = json.loads((root / 'jobs/native-continuous-20261121/ACTIVE.json').read_text())
        self.source = active['source']
        self.run_root = Path(active['run_root'])
        self.socket = root / 'runtime/live/origin.sock'
        self.token = (self.run_root / 'origin-token').read_text().strip()
        self.calls = 0

    def open(self, path):
        conn = UnixConnection(self.socket)
        conn.request('GET', path, headers={'Authorization': 'Bearer ' + self.token, 'Accept-Encoding': 'identity'})
        response = conn.getresponse()
        self.calls += 1
        ensure(response.status == 200, 'native_origin_response_failed')
        return conn, response

    def head(self):
        conn, response = self.open('/v2/banks/head')
        try:
            raw = response.read(65537)
            ensure(len(raw) <= 65536, 'native_head_exceeds_bound')
            head = json.loads(raw)
            ensure(head.get('source') == self.source and head.get('status') == 'live', 'native_source_not_live')
            cursor_parts(head['cursor'])
            return head
        finally:
            conn.close()

    def beam(self, after):
        conn, response = self.open('/v2/banks/beam?' + urllib.parse.urlencode({'after': after}))
        ensure(response.getheader('X-Blockzilla-Start-Cursor') == after, 'native_start_cursor_differs')
        return conn, response


def read_exact(response, count):
    result = bytearray()
    while len(result) < count:
        data = response.read(count - len(result))
        ensure(data, 'native_stream_truncated')
        result.extend(data)
    return bytes(result)


def read_frame(response, expected_source):
    header = read_exact(response, 16)
    ensure(header[:8] == b'BZSTRM01', 'native_stream_magic_differs')
    meta_length, body_length = struct.unpack('<II', header[8:])
    ensure(1 <= meta_length <= MAX_META and body_length <= MAX_PAYLOAD, 'native_stream_frame_exceeds_bound')
    wire = header + read_exact(response, meta_length + body_length)
    return wire, frame_identity(wire, expected_source)


def count_header(headers, name):
    value = headers.get(name.lower())
    ensure(isinstance(value, str) and re.fullmatch(r'(?:0|[1-9][0-9]*)', value), 'missing_operation_counter')
    return int(value)


def operation_receipt(headers):
    out = {}
    for name, field in [('R2', 'r2'), ('S3', 's3'), ('Foundation-R2', 'reader')]:
        out[field] = {kind.lower(): count_header(headers, f'X-Blockzilla-{name}-{kind}') for kind in ['GETs', 'HEADs']}
    out['archiveGets'] = sum(out[k]['gets'] for k in ('r2', 's3', 'reader'))
    out['archiveHeads'] = sum(out[k]['heads'] for k in ('r2', 's3', 'reader'))
    for field, name in [('recentHttp', 'Recent'), ('lookupHttp', 'Lookup'), ('resolveHttp', 'Resolve')]:
        out[field] = count_header(headers, f'X-Blockzilla-Foundation-{name}-HTTP-Requests')
    out['kvReads'] = count_header(headers, 'X-Blockzilla-Auth-KV-Reads')
    out['authCache'] = headers.get('x-blockzilla-auth-cache')
    out['responseCache'] = headers.get('x-blockzilla-cache')
    return out


class Worker:
    def __init__(self, config):
        url = urllib.parse.urlsplit(config['worker_url'])
        ensure(url.scheme == 'https' and url.hostname and not url.username and not url.password and not url.query and not url.fragment, 'invalid_worker_url')
        self.host, self.port, self.prefix = url.hostname, url.port or 443, url.path.rstrip('/')
        self.key = config['api_key']
        ensure(isinstance(self.key, str) and self.key and '\n' not in self.key and '\r' not in self.key, 'invalid_worker_key')
        self.connection = None
        self.calls = []
        self.attempts = 0

    def get(self, slot, query, phase):
        ensure(self.attempts < 40, 'worker_request_budget_exceeded')
        self.attempts += 1
        if self.connection is None:
            self.connection = http.client.HTTPSConnection(self.host, self.port, timeout=30)
        path = self.prefix + f'/block/{slot}.compact?' + urllib.parse.urlencode(query)
        started, at = time.perf_counter(), utc_now()
        self.connection.request('GET', path, headers={'Authorization': 'Bearer ' + self.key, 'Accept-Encoding': 'identity'})
        response = self.connection.getresponse()
        headers_at = time.perf_counter()
        headers = {k.lower(): v for k, v in response.getheaders()}
        body = response.read(MAX_FRAME + 1)
        ended = time.perf_counter()
        ensure(len(body) <= MAX_FRAME, 'worker_body_exceeds_bound')
        row = {'phase': phase, 'slot': slot, 'requestedCommitment': query.get('commitment', 'finalized'), 'status': response.status, 'startedAt': at,
               'completedAt': utc_now(), 'headersMs': round((headers_at - started) * 1000, 3),
               'totalMs': round((ended - started) * 1000, 3), 'bytes': len(body), 'bodySha256': sha(body),
               'contentType': headers.get('content-type'), 'source': headers.get('x-blockzilla-source'),
               'operations': None, 'ok': False,
               'nativeCpuMicros': int(headers['x-blockzilla-recent-native-cpu-micros']) if headers.get('x-blockzilla-recent-native-cpu-micros', '').isdigit() else None}
        self.calls.append(row)
        try:
            row['operations'] = operation_receipt(headers)
        except CheckError as error:
            row['receiptFailure'] = str(error)
            raise
        if response.status != 200 and len(body) <= 65536:
            try:
                error = json.loads(body).get('error')
                code = error.get('code') if isinstance(error, dict) else error
                if isinstance(code, str) and re.fullmatch(r'[a-zA-Z0-9_-]{1,80}', code):
                    row['responseErrorCode'] = code
            except (ValueError, AttributeError):
                pass
        return row, headers, body

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None


def recent_query(frame, profile=None, commitment='processed'):
    query = {'blockhash': frame['blockhash'], 'commitment': commitment}
    if commitment == 'processed':
        query.update(cursor=frame['cursor'], source_session=frame['source']['session_id'], bank_id=frame['bank_id'])
    if profile:
        query['profile'] = profile
    return query


def decode_recent_metadata(value):
    ensure(isinstance(value, str) and len(value) <= 16384 and re.fullmatch(r'[A-Za-z0-9_-]+', value), 'invalid_recent_metadata_header')
    raw = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    ensure(base64.urlsafe_b64encode(raw).decode().rstrip('=') == value, 'noncanonical_recent_metadata_header')
    return json.loads(raw)


def recent_check(row, headers, body, expected, cold=False):
    ensure(row['status'] == 200 and row['source'] == 'FOUNDATION_RECENT', 'recent_route_failed')
    ensure(row['contentType'].split(';')[0] == 'application/vnd.blockzilla.stream.v2', 'recent_content_type_differs')
    actual = frame_identity(body, expected['source'])
    ensure(actual == expected and headers.get('x-blockzilla-frame-sha256') == expected['frame_sha256'], 'recent_original_frame_differs')
    meta = decode_recent_metadata(headers.get('x-blockzilla-recent-metadata'))
    ensure(meta.get('version') == 1 and meta.get('commitment') == row['requestedCommitment'] == headers.get('x-blockzilla-commitment'), 'recent_commitment_differs')
    ensure(headers.get('x-blockzilla-recovery-format') == 'native-bank-stream-v2', 'recent_format_header_differs')
    for name in ['slot', 'blockhash', 'parent_slot', 'parent_blockhash', 'bank_id', 'source', 'cursor', 'frame_sha256']:
        ensure(meta.get(name) == expected[name], 'recent_metadata_differs')
    ops = row['operations']
    ensure(ops['archiveGets'] == 0 and ops['archiveHeads'] == 0 and ops['recentHttp'] == 1 and ops['lookupHttp'] == 0 and ops['resolveHttp'] == 0, 'recent_operation_counts_differ')
    ensure(ops['responseCache'] == 'BYPASS', 'recent_response_was_cached')
    if cold:
        ensure(ops['authCache'] == 'BYPASS' and ops['kvReads'] == 1, 'cold_auth_not_bypassed')
    row['frame'] = actual
    row['ok'] = True


def error_check(row, allowed):
    ensure(row['status'] in allowed and row['status'] != 200, 'expected_error_was_not_returned')
    ops = row['operations']
    ensure(ops['archiveGets'] == 0 and ops['archiveHeads'] == 0 and ops['resolveHttp'] == 0 and ops['lookupHttp'] == 0, 'error_used_archive_fallback')
    row['ok'] = True


def phase(report, name, action, worker):
    # Separate whole-second CPU query windows. This is not latency padding.
    time.sleep(2.2)
    start, count = utc_now(), worker.attempts
    report['activePhase'] = name
    try:
        action()
    finally:
        if worker.attempts > count:
            report['windows'][name] = {'start': start, 'end': utc_now(), 'expectedWorkerRequests': worker.attempts - count,
                                       'traffic': {'condition': name, 'representation': 'compact', 'measured': name not in ['RuntimeWarm', 'AuthPrime'],
                                                   'workerRequests': worker.attempts - count, 'heliusRequests': 0}}


def read_gap(origin, after, count):
    conn, response = origin.beam(after)
    frames, rows, total, block_count = [], [], 0, 0
    try:
        while block_count < count:
            ensure(len(rows) < 100, 'stream_fixture_event_limit')
            wire, row = read_frame(response, origin.source)
            total += len(wire)
            ensure(total <= MAX_RETAINED, 'stream_fixture_memory_limit')
            frames.append(wire); rows.append(row)
            block_count += row['kind'] == 'block'
    finally:
        conn.close()
    return frames, rows


def accept_root_proof(roots, wanted, frame):
    if frame['kind'] == 'root' and frame['payload_frame_sha256'] in wanted:
        original = wanted[frame['payload_frame_sha256']]
        ensure(all(frame[k] == original[k] for k in ['slot', 'bank_id', 'blockhash', 'parent_slot', 'parent_blockhash', 'source', 'payload_sha256']), 'native_root_payload_mismatch')
        roots[original['frame_sha256']] = frame


def wait_roots(origin, after, candidates, known_frames=()):
    wanted = {f['frame_sha256']: f for f in candidates}
    roots = {}
    # A root can occur inside the already validated gap. Replaying only after
    # its last cursor cannot find that older control a second time.
    for frame in known_frames:
        accept_root_proof(roots, wanted, frame)
    seeded = len(roots)
    started, checked = time.monotonic(), 0
    if len(roots) < len(wanted):
        conn, response = origin.beam(after)
        try:
            while len(roots) < len(wanted):
                ensure(time.monotonic() - started < 45 and checked < 500, 'root_proof_deadline')
                wire, frame = read_frame(response, origin.source)
                checked += 1
                accept_root_proof(roots, wanted, frame)
        finally:
            conn.close()
    return {'checkedFrames': checked, 'rootProofsAlreadyInGap': seeded,
            'waitSeconds': round(time.monotonic() - started, 3), 'roots': list(roots.values())}


def run(config, root):
    report = {'schema': 'blockzilla.recent-compact-recovery.v1', 'status': 'RUNNING', 'startedAt': utc_now(),
              'deployment': {k: config[k] for k in ['account_id', 'worker', 'version', 'wasmSha256']},
              'plan': {'heliusRequests': 0, 'archiveControlBlocks': 4, 'blockPayloadFilesWritten': 0,
                       'nativeServiceRestarts': 0, 'clientConnectionOnlyFault': True, 'captureMemoryLimit': MAX_RETAINED, 'maxWorkerRequests': 40, 'observabilityHeadSamplingRate': config.get('observability_head_sampling_rate', .01)},
              'samples': [], 'windows': {}, 'native': {}}
    origin, worker = Origin(root), Worker(config)
    try:
        head = origin.head()
        baseline_wires, baseline = read_gap(origin, head['cursor'], 2)
        del baseline_wires
        saved = baseline[-1]['cursor']
        report['native']['source'] = origin.source
        report['native']['baseline'] = baseline
        report['native']['savedCompleteCursor'] = saved
        report['native']['clientDisconnectedAt'] = utc_now()
        time.sleep(2)
        wires, gap = read_gap(origin, saved, 4)
        blocks = [f for f in gap if f['kind'] == 'block']
        report['native']['gapReference'] = gap
        report['native']['partialFrameCounted'] = False
        report['native']['failureType'] = 'isolated-client-connection-closed'
        ensure(sum(map(len, wires)) + 2 * max(f['bytes'] for f in blocks) <= MAX_RETAINED, 'recovery_reference_memory_limit')
        def unrooted():
            frame = blocks[-1]
            r, h, b = worker.get(frame['slot'], recent_query(frame, '1', 'finalized'), 'UnrootedFinalized')
            if r['status'] == 200:
                recent_check(r, h, b, frame, True)
                report['native']['unrootedRejectionProven'] = False
                report['native']['unrootedCandidateAlreadyFinalized'] = True
            else:
                error_check(r, {404, 409, 410})
                report['native']['unrootedRejectionProven'] = True
        phase(report, 'UnrootedFinalized', unrooted, worker)
        def recent_many(name, profile, rounds):
            for _ in range(rounds):
                for frame in blocks:
                    row, headers, body = worker.get(frame['slot'], recent_query(frame, profile), name)
                    recent_check(row, headers, body, frame, profile == '1')
        def warm():
            f = blocks[0]
            r, h, b = worker.get(f['slot'], recent_query(f, '1'), 'RuntimeWarm')
            recent_check(r, h, b, f, True)
        phase(report, 'RuntimeWarm', warm, worker)
        phase(report, 'RecentCold', lambda: recent_many('RecentCold', '1', 1), worker)
        phase(report, 'AuthPrime', lambda: recent_check(*worker.get(blocks[0]['slot'], recent_query(blocks[0]), 'AuthPrime'), blocks[0]), worker)
        phase(report, 'RecentAuthWarm', lambda: recent_many('RecentAuthWarm', None, 2), worker)
        # Reconnect from the last accepted cursor. A block repair does not invent
        # or skip confirmation/root/invalidation controls.
        conn, response = origin.beam(saved)
        try:
            resumed = []
            accepted = VerifiedCursor(saved, origin.source)
            for expected_wire, expected in zip(wires, gap):
                wire, actual = read_frame(response, origin.source)
                ensure(wire == expected_wire and actual == expected, 'exact_cursor_replay_differs')
                admitted = accepted.accept(wire, expected['frame_sha256'])
                ensure(admitted == actual, 'cursor_admission_differs')
                resumed.append(actual)
            report['native']['resumedCompleteCursor'] = accepted.cursor
        finally:
            conn.close()
        report['native']['resumed'] = resumed
        report['native']['recoveredBlocks'] = len(blocks)
        report['native']['replayedControlFrames'] = sum(f['kind'] != 'block' for f in resumed)
        report['native']['resumedAfterSavedCompleteCursor'] = True
        report['native']['rootProof'] = wait_roots(origin, gap[-1]['cursor'], blocks, gap)
        def finalized():
            for f in blocks:
                r, h, b = worker.get(f['slot'], recent_query(f, '1', 'finalized'), 'RecentFinalized')
                recent_check(r, h, b, f, True)
                ensure(decode_recent_metadata(h['x-blockzilla-recent-metadata']).get('commitment') == 'finalized', 'finalized_admission_missing')
        phase(report, 'RecentFinalized', finalized, worker)
        controls = config['archive_controls']
        ensure(len(controls) == 4 and len({r['slot'] for r in controls}) == 4, 'archive_control_count_differs')
        def archive():
            for f in controls:
                r, h, b = worker.get(f['slot'], {'blockhash': f['blockhash'], 'commitment': 'finalized', 'profile': '1'}, 'ArchiveFallback')
                ensure(r['status'] == 200 and r['source'] == 'R2_ARCHIVE' and r['contentType'].split(';')[0] == 'application/vnd.blockzilla.get-block-bundle.wincode', 'archive_fallback_representation_differs')
                ensure(sha(b) == f['bundleSha256'], 'archive_original_bundle_differs')
                ensure(h.get('x-blockzilla-blockhash') == f['blockhash'] and h.get('x-blockzilla-recovery-format') == 'archive-wincode-bundle-v1', 'archive_identity_headers_differ')
                ops = r['operations']
                ensure(ops['archiveGets'] == 2 and ops['archiveHeads'] == 0 and ops['recentHttp'] == 1 and ops['resolveHttp'] == 1, 'archive_operation_counts_differ')
                ensure('x-blockzilla-recent-metadata' not in h and 'x-blockzilla-frame-sha256' not in h and 'x-blockzilla-cursor' not in h, 'archive_faked_native_identity')
                r['ok'] = True
        phase(report, 'ArchiveFallback', archive, worker)
        def rejects():
            frame = blocks[0]
            wrong = recent_query(frame, '1'); wrong['blockhash'] = base58(bytes([255]) * 32)
            r, _, _ = worker.get(frame['slot'], wrong, 'IdentityReject'); error_check(r, {400, 409, 502, 503})
            old = dict(wrong); old.update(blockhash=frame['blockhash'], cursor=f"{frame['source']['session_id']}:p1:{'0' * 64}")
            r, _, _ = worker.get(frame['slot'], old, 'IdentityReject'); error_check(r, {410})
            wrong = recent_query(frame, '1'); wrong['source_session'] += '-wrong'
            r, _, _ = worker.get(frame['slot'], wrong, 'IdentityReject'); error_check(r, {400, 409, 410, 502})
            f = controls[0]
            r, _, _ = worker.get(f['slot'], {'blockhash': base58(bytes([255]) * 32), 'commitment': 'finalized', 'profile': '1'}, 'IdentityReject'); error_check(r, {409, 502})
        phase(report, 'IdentityReject', rejects, worker)
        report['native']['headAfter'] = origin.head()
        ensure(report['native']['headAfter']['source'] == head['source'], 'source_changed_during_recovery')
        report['status'] = 'PASS'
    except Exception as error:
        report['status'] = 'FAIL'
        report['failure'] = str(error) if isinstance(error, CheckError) else 'recovery_transport_or_validation_failed'
    finally:
        worker.close()
        report['samples'] = worker.calls
        report['completedAt'] = utc_now()
        report['native']['originHttpRequests'] = origin.calls
        complete_operations = len(worker.calls) == worker.attempts and all(isinstance(r.get('operations'), dict) for r in worker.calls)
        report['proof'] = {'workerRequestsAttempted': worker.attempts, 'workerRequests': len(worker.calls), 'passed': sum(r['ok'] for r in worker.calls),
                           'recentPayloads': sum(r['ok'] and r.get('source') == 'FOUNDATION_RECENT' for r in worker.calls),
                           'archivePayloads': sum(r['ok'] and r.get('source') == 'R2_ARCHIVE' for r in worker.calls),
                           'rejectedWithoutArchive': sum(r['ok'] and r['status'] != 200 and (r.get('operations') or {}).get('archiveGets') == 0 for r in worker.calls),
                           'archiveGETs': sum(r['operations']['archiveGets'] for r in worker.calls) if complete_operations else None,
                           'archiveHEADs': sum(r['operations']['archiveHeads'] for r in worker.calls) if complete_operations else None,
                           'blockPayloadFilesWritten': 0, 'servingCopiesAdded': 0}
        report['notes'] = [
            'Only an isolated test reader was disconnected. No validator, origin, production pipe or Worker was stopped.',
            'Reference frames and Worker bodies stayed in bounded process memory. Only identities, hashes and metrics are written.',
            'The four missing payload identities came from an independent reference reader. This test does not implement client discovery of unknown cursors.',
            'A repaired processed block cannot advance the canonical stream cursor past missing control events. Exact cursor replay verifies all intervening original frames.',
            'Archive fallback has a distinct Wincode content type. It does not create a native cursor or native control history.',
            'Wrong identities and expired processed requests must not read R2. Transport and malformed-body failure injection belongs to separate local tests.',
            'Clock times are client elapsed values. Platform CPU and cost require the separate version-filtered collector.',
        ]
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, help='Private JSON file, or - for stdin.')
    parser.add_argument('--native-root', default='/home/ubuntu/live/hivezilla-validator-20260930')
    parser.add_argument('--output', required=True)
    parser.add_argument('--cpu-plan', required=True)
    args = parser.parse_args()
    import sys
    config = json.load(sys.stdin) if args.config == '-' else json.loads(Path(args.config).read_text())
    output, plan_path = Path(args.output), Path(args.cpu_plan)
    ensure(not output.exists() and not plan_path.exists(), 'output_already_exists')
    report = run(config, args.native_root)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + '\n'); output.chmod(0o600)
    plan = {**report['deployment'], 'requestReceipt': str(output), 'observabilityHeadSamplingRate': report['plan']['observabilityHeadSamplingRate'],
            'windows': report['windows']}
    plan_path.write_text(json.dumps(plan, indent=2) + '\n'); plan_path.chmod(0o600)
    print(json.dumps({'status': report['status'], 'proof': report['proof'], 'failure': report.get('failure')}))
    return 0 if report['status'] == 'PASS' else 1

if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        print('Recent recovery harness stopped before a safe report could be written.')
        raise SystemExit(1)
