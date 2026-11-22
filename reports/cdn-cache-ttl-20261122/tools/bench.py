#!/usr/bin/env python3
"""Bounded CDN test. Save only hashes, identities, headers and timings."""
import argparse
import base64
import copy
import datetime as dt
from decimal import Decimal
import hashlib
import http.client
import ipaddress
import json
from pathlib import Path
import re
import socket
import ssl
import subprocess
import time
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent
SLOTS = [470987967, 471096104, 471204030, 471311999,
         470555971, 470663944, 470771932, 470879999]
MAX_REQUESTS = 100
MAX_SECONDS = 30
MAX_BODY = 16 * 1024 * 1024
WORKER_VERSION = '4d1b4d55-31f1-4e30-a287-717846eeff3c'
KEEP_HEADERS = ['cf-cache-status', 'age', 'cf-ray', 'cache-control', 'cdn-cache-control',
    'cloudflare-cdn-cache-control', 'etag', 'content-type', 'content-encoding',
    'x-blockzilla-cache', 'x-blockzilla-auth-cache', 'x-blockzilla-auth-kv-reads',
    'x-blockzilla-billable-reads', 'x-blockzilla-r2-gets', 'x-blockzilla-s3-gets']


class CheckError(Exception):
    pass


def require(value, message):
    if not value:
        raise CheckError(message)


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def load_canonical():
    def canonical(value):
        if value is None:
            return ['null']
        if type(value) in (int, Decimal):
            m = re.fullmatch(r'(-?)([0-9]+)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?', str(value))
            require(m is not None, 'invalid_json_number')
            digits = (m[2] + (m[3] or '')).lstrip('0')
            number = '0'
            if digits:
                zeroes = len(digits) - len(digits.rstrip('0'))
                exponent = int(m[4] or 0) - len(m[3] or '') + zeroes
                number = m[1] + digits.rstrip('0') + 'e' + str(exponent)
            return ['number', number]
        if isinstance(value, list):
            return ['array', [canonical(v) for v in value]]
        if isinstance(value, dict):
            return ['object', [[k, canonical(value[k])] for k in sorted(value)]]
        return ['boolean' if isinstance(value, bool) else 'string', value]
    return canonical


def digest_json(value, canonical):
    return hashlib.sha256(json.dumps(canonical(value), ensure_ascii=False,
        separators=(',', ':')).encode()).hexdigest()


def references():
    refs_path = ROOT / 'reports/public-getblock-benchmark-20261122/references.json'
    refs = {row['slot']: row for row in json.loads(refs_path.read_text())['samples']}
    old_json = ROOT / 'reports/public-getblock-benchmark-20261122/http.json'
    identities = {row['slot']: row['identity'] for row in json.loads(old_json.read_text())['samples']
                  if row.get('ok') and row.get('identity')}
    require(set(refs) == set(SLOTS) and set(identities) == set(SLOTS), 'reference_slots_differ')
    return refs, identities, {'references': str(refs_path),
        'references_sha256': hashlib.sha256(refs_path.read_bytes()).hexdigest(),
        'identity_reference': str(old_json),
        'identity_reference_sha256': hashlib.sha256(old_json.read_bytes()).hexdigest()}


def validate_block(row, body, slot, kind, refs, identities, canonical):
    require(row['status'] == 200, 'block_http_status_is_not_200')
    h = row['headers']
    require(h.get('x-blockzilla-auth-cache') == 'PUBLIC', 'public_auth_receipt_missing')
    require(h.get('x-blockzilla-auth-kv-reads') == '0', 'auth_kv_reads_not_zero')
    require(h.get('x-blockzilla-billable-reads') == '0', 'billable_reads_not_zero')
    require(not row['set_cookie_present'], 'cacheable_block_sets_cookie')
    if kind == 'bin':
        require(row['sha256'] == refs[slot]['binarySha256'], 'original_binary_digest_differs')
        row['original_binary_verified'] = True
        return
    value = json.loads(body, parse_float=Decimal)
    require(value.get('jsonrpc') == '2.0' and value.get('id') == 1 and 'error' not in value,
            'invalid_json_rpc_block')
    block = value.get('result')
    require(isinstance(block, dict), 'json_block_missing')
    expected = identities[slot]
    require(all(block.get(k) == expected[k] for k in ('blockhash', 'previousBlockhash', 'parentSlot')),
            'json_block_identity_differs')
    require(isinstance(block.get('transactions'), list) and
            len(block['transactions']) == expected['transactions'], 'transaction_count_differs')
    order = hashlib.sha256()
    for transaction in block['transactions']:
        wire = transaction.get('transaction')
        require(isinstance(wire, list) and len(wire) == 2 and wire[1] == 'base64',
                'transaction_is_not_base64')
        decoded = base64.b64decode(wire[0], validate=True)
        order.update(len(decoded).to_bytes(8, 'little'))
        order.update(decoded)
    projected = copy.deepcopy(block)
    projected.pop('rewards', None)
    projected.pop('numRewardPartitions', None)
    for transaction in projected['transactions']:
        if isinstance(transaction.get('meta'), dict):
            transaction['meta']['rewards'] = None
    projected_sha = digest_json(projected, canonical)
    require(projected_sha == refs[slot]['jsonSha256'], 'original_json_core_digest_differs')
    row.update({'identity': expected, 'ordered_transaction_bytes_sha256': order.hexdigest(),
        'canonical_full_sha256': digest_json(block, canonical),
        'canonical_rewards_false_sha256': projected_sha, 'original_json_core_verified': True,
        'rewards_present': 'rewards' in block, 'reward_partitions_present': 'numRewardPartitions' in block})


class Connection(http.client.HTTPSConnection):
    def __init__(self, host, address):
        super().__init__(host, timeout=MAX_SECONDS, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        self.sock = socket.create_connection((self.address, 443), self.timeout)
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--phase', choices=['pre', 'post', 'errors'], required=True)
    parser.add_argument('--repetitions', type=int, default=4)
    parser.add_argument('--slots', type=int, default=8)
    parser.add_argument('--baseline', type=Path)
    parser.add_argument('--direct-baseline', action='store_true',
                        help='In pre phase, read binary and JSON once per slot from the main Worker.')
    parser.add_argument('--invocation-header', default='X-Blockzilla-Proxy-Invocation')
    args = parser.parse_args()
    require(re.fullmatch(r'[A-Za-z0-9.-]+', args.host) is not None, 'invalid_host')
    require(1 <= args.slots <= 8 and 1 <= args.repetitions <= 4, 'invalid_plan_size')
    require(not args.output.exists(), 'output_exists')
    slots = SLOTS[:args.slots]
    planned = 8 if args.phase == 'errors' else ((len(slots) * 2 if args.direct_baseline else len(slots) * args.repetitions) if args.phase == 'pre' else len(slots) * 2 * (1 + args.repetitions) + 8)
    require(planned <= MAX_REQUESTS, 'request_budget_exceeded')
    invocation_header = args.invocation_header.lower()
    refs, identities, provenance = references()
    canonical = load_canonical()
    baselines = {}
    if args.baseline:
        prior = json.loads(args.baseline.read_text())
        require(prior.get('passed') is True, 'baseline_did_not_pass')
        baselines = {(r.get('slot'), r.get('kind')): r for r in prior['samples']
                     if r.get('passed') and r.get('slot') and r.get('kind')}
    raw_dns = subprocess.check_output(['dig', '@1.1.1.1', args.host, 'A', '+short'], text=True)
    addresses = [line for line in raw_dns.splitlines() if re.fullmatch(r'[0-9.]+', line)]
    require(addresses and all(ipaddress.ip_address(a).version == 4 for a in addresses), 'dns_failed')
    conn = Connection(args.host, addresses[0])
    report = {'schema': 'blockzilla-pages-cdn-benchmark-v1', 'phase': args.phase, 'host': args.host,
        'startedAt': utc(), 'slots': slots, 'repetitions': args.repetitions,
        'planned_requests': planned, 'hard_request_limit': MAX_REQUESTS, 'hard_run_limit_seconds': MAX_SECONDS,
        'concurrency': 1, 'keepalive': True, 'accept_encoding': 'identity', 'api_headers_sent': 0,
        'cookie_headers_sent': 0, 'credential_files_read': 0, 'block_payload_files_written': 0,
        'worker_version': WORKER_VERSION, 'proxy_invocation_header': invocation_header,
        'provenance': provenance, 'baseline': str(args.baseline) if args.baseline else None,
        'samples': [], 'windows': {}, 'passed': False, 'five_xx_checked': 0,
        'json_error_passthrough_verified': False, 'production_error_contract_compatible': None,
        'notes': ['No-query JSON uses the default rewards=true representation.',
            'The rewards=false projection removes block rewards and numRewardPartitions, and sets transaction metadata rewards to null.',
            'The independent old JSON digest verifies all other fields and ordered transactions. Reward values need the direct baseline full-body digest.',
            'Storage and upstream cache headers on a CDN hit are frozen response data, not per-hit operation counters.',
            'A frozen proxy UUID is checked with outer cache headers; invocation metrics are collected separately.',
            'No retries, browser cache or HTTP conditional headers are used. Phase guards are outside HTTP latency timers.']}
    started = time.monotonic()
    deadline = started + MAX_SECONDS
    fills = {}

    def left():
        remaining = deadline - time.monotonic()
        require(remaining > 0, 'run_deadline_exceeded')
        return remaining

    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')

    def fetch(name, path, slot=None, kind=None):
        require(len(report['samples']) < MAX_REQUESTS, 'hard_request_limit_exceeded')
        conn.timeout = min(MAX_SECONDS, left())
        if conn.sock:
            conn.sock.settimeout(conn.timeout)
        row = {'phase': name, 'path': path, 'slot': slot, 'kind': kind, 'startedAt': utc(), 'passed': False}
        report['samples'].append(row)
        t0 = time.perf_counter()
        conn.request('GET', path, headers={'Accept-Encoding': 'identity', 'User-Agent': 'blockzilla-cdn-canary-benchmark/1.0'})
        response = conn.getresponse()
        headers_ms = 1000 * (time.perf_counter() - t0)
        headers = {k.lower(): v for k, v in response.getheaders()}
        require(headers.get('content-encoding', 'identity') in ('identity', ''), 'unexpected_content_encoding')
        digest = hashlib.sha256()
        body, size, first = bytearray(), 0, None
        while True:
            if conn.sock:
                conn.sock.settimeout(min(MAX_SECONDS, left()))
            data = response.read(1 if first is None else 65536)
            if not data:
                break
            if first is None:
                first = 1000 * (time.perf_counter() - t0)
            size += len(data)
            require(size <= MAX_BODY, 'response_exceeds_body_limit')
            digest.update(data)
            if kind != 'bin':
                body.extend(data)
        row.update({'completedAt': utc(), 'status': response.status, 'bytes': size,
            'sha256': digest.hexdigest(), 'headers_ms': headers_ms, 'ttfb_ms': first,
            'total_ms': 1000 * (time.perf_counter() - t0),
            'headers': {k: headers.get(k) for k in KEEP_HEADERS + [invocation_header]},
            'set_cookie_present': 'set-cookie' in headers})
        return row, bytes(body)

    def phase(name, action):
        guard = (2000 - int(time.time() * 1000) % 1000) / 1000
        require(left() > guard, 'run_deadline_before_phase_guard')
        time.sleep(guard)
        window = {'start': utc(), 'http_requests': 0}
        report['windows'][name] = window
        count = len(report['samples'])
        try:
            action(name)
        finally:
            window['end'] = utc()
            window['http_requests'] = len(report['samples']) - count
            window['completed'] = all(r['passed'] for r in report['samples'][count:])
            save()

    def block(name, slot, kind, hit=False):
        row, body = fetch(name, f'/block/{slot}.{kind}', slot, kind)
        validate_block(row, body, slot, kind, refs, identities, canonical)
        prior = baselines.get((slot, kind))
        if prior:
            require(row['sha256'] == prior['sha256'], 'direct_baseline_body_digest_differs')
            row['direct_baseline_bytes_verified'] = True
        if args.phase == 'post' or (args.phase == 'pre' and not args.direct_baseline):
            proxy_id = row['headers'].get(invocation_header)
            require(proxy_id is not None and str(uuid.UUID(proxy_id)) == proxy_id.lower(), 'proxy_uuid_missing_or_invalid')
            require('public' in row['headers'].get('cache-control', ''), 'block_is_not_publicly_cacheable')
            if hit:
                require(row['headers'].get('cf-cache-status') == 'HIT', 'outer_cdn_hit_missing')
                require(str(row['headers'].get('age', '')).isdigit(), 'cdn_age_missing')
                require(proxy_id == fills[(slot, kind)]['headers'][invocation_header], 'proxy_was_invoked_again')
                require(row['sha256'] == fills[(slot, kind)]['sha256'], 'cached_body_changed')
                row['verified_outer_cdn_hit'] = True
            elif args.phase == 'post':
                fills[(slot, kind)] = row
            else:
                require(row['headers'].get('cf-cache-status') != 'HIT', 'pre_control_was_already_cached')
                previous = fills.get((slot, kind))
                if previous:
                    require(proxy_id != previous['headers'][invocation_header], 'pre_control_proxy_uuid_did_not_change')
                fills[(slot, kind)] = row
        row['passed'] = True

    def check_errors(name):
        slot = slots[0]
        tests = [('unsupported-encoding', f'/block/{slot}.json?encoding=base58', {400}),
                 ('malformed-slot', '/block/not-a-slot.json', {400}),
                 ('profile-query', f'/block/{slot}.json?profile=1', {400}),
                 ('unavailable-slot', '/block/472608000.json', {502})]
        seen = {}
        for repeat in range(2):
            for label, path, statuses in tests:
                row, body = fetch(name, path)
                row.update({'check': label, 'repeat': repeat})
                require(row['status'] in statuses, 'unexpected_check_status')
                require('no-store' in row['headers'].get('cache-control', ''), 'error_or_profile_query_is_cacheable')
                require(row['headers'].get('cf-cache-status') != 'HIT', 'error_or_query_was_cached')
                proxy_id = row['headers'].get(invocation_header)
                if label == 'unavailable-slot':
                    require(body == b'error code: 502\n', 'platform_502_body_differs')
                    require(row['headers'].get('cf-ray') is not None, 'platform_502_cf_ray_missing')
                    require(row['headers'].get('age') is None, 'platform_502_has_cache_age')
                    require(proxy_id is None, 'platform_502_proxy_uuid_unexpectedly_visible')
                    require('text/plain' in row['headers'].get('content-type', ''), 'platform_502_type_differs')
                    row.update({'error_body_format': 'cloudflare-synthetic-plain-text',
                        'platform_generated_error': True, 'proxy_uuid_observable': False,
                        'json_error_passthrough_verified': False,
                        'production_error_contract_compatible': False})
                    report['production_error_contract_compatible'] = False
                else:
                    require(proxy_id is not None and str(uuid.UUID(proxy_id)) == proxy_id.lower(), 'error_proxy_uuid_missing_or_invalid')
                    if label in seen:
                        require(proxy_id != seen[label], 'error_or_query_replayed_proxy_uuid')
                    seen[label] = proxy_id
                    require('text/plain' in row['headers'].get('content-type', '') and len(body) > 0,
                            'proxy_rejection_is_not_plain_text_400')
                    row['error_body_format'] = 'plain-text'
                if row['status'] >= 500:
                    report['five_xx_checked'] += 1
                row['passed'] = True

    try:
        if args.phase == 'errors':
            phase('ErrorAndQueryChecks', check_errors)
        elif args.phase == 'pre':
            if args.direct_baseline:
                phase('DirectBaseline', lambda name: [block(name, slot, kind) for slot in slots for kind in ('bin', 'json')])
            else:
                phase('PreControlJson', lambda name: [block(name, slot, 'json')
                    for _ in range(args.repetitions) for slot in slots])
        else:
            phase('Fill', lambda name: [block(name, slot, kind) for slot in slots for kind in ('bin', 'json')])
            require(len({row['headers'][invocation_header] for row in fills.values()}) == len(fills), 'proxy_uuid_reused_across_distinct_fills')
            for kind in ('bin', 'json'):
                phase('Hit' + kind.title(), lambda name, kind=kind:
                    [block(name, slot, kind, True) for _ in range(args.repetitions) for slot in slots])
            phase('ErrorAndQueryChecks', check_errors)
        require(len(report['samples']) == planned, 'planned_request_count_differs')
        report['passed'] = True
    except Exception as error:
        report['failure'] = str(error) if isinstance(error, CheckError) else type(error).__name__
    finally:
        conn.close()
        report['finishedAt'] = utc()
        report['elapsed_seconds'] = round(time.monotonic() - started, 3)
        report['requests'] = len(report['samples'])
        report['verified_outer_hits'] = sum(r.get('verified_outer_cdn_hit', False) for r in report['samples'])
        save()
    print(json.dumps({'path': str(args.output.resolve()), 'passed': report['passed'], 'requests': report['requests'],
        'verified_outer_hits': report['verified_outer_hits'], 'failure': report.get('failure'),
        'five_xx_checked': report['five_xx_checked']}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'passed': False, 'error': 'benchmark_setup_failed', 'error_type': type(error).__name__}))
        raise SystemExit(1)
