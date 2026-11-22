#!/usr/bin/env python3
"""Read Pages and getBlock invocation metrics. Never call either data endpoint."""
import argparse
import datetime as dt
import json
from pathlib import Path
import tomllib
import urllib.request

ACCOUNT = '8df0426c80fcd1a04ed439f441db9ff8'
PROJECT = 'blockzilla-getblock-cdn-canary'
PAGES_SCRIPT = 'pages-worker--24711630-production'
WORKER = 'blockzilla-get-block'
WORKER_VERSION = '4d1b4d55-31f1-4e30-a287-717846eeff3c'
PAGES_DEPLOYMENT = '85fdb391-70a1-444c-8131-72d9fe563476'
FIELDS = ('sum { requests errors cpuTimeUs startupCpuTimeUs subrequests } '
          'avg { sampleInterval } '
          'confidence(level:0.95) { sum { requests { estimate lower upper sampleSize isValid } '
          'cpuTimeUs { estimate lower upper sampleSize isValid } } }')
PAGES_FIELDS = ('sum { requests errors subrequests duration wallTime responseBodySize } '
                'avg { sampleInterval } confidence(level:0.95) { sum { '
                'requests { estimate lower upper sampleSize isValid } } }')


def instant(text):
    return dt.datetime.fromisoformat(text.replace('Z', '+00:00'))


def stamp(value):
    return value.isoformat().replace('+00:00', 'Z')


def metric(rows, expected):
    if not rows:
        return {'observedRequests': 0, 'expectedRequests': expected, 'countMatchesPlan': expected == 0,
                'cpuTimeUs': 0, 'startupCpuTimeUs': 0, 'meanCpuMs': None, 'startupCpuMs': 0,
                'errors': 0, 'sampleSize': 0, 'adaptiveSampleInterval': None,
                'unsampledPositiveCount': False, 'validEmptyResult': True}
    value = rows[0]
    sums = value.get('sum') or {}
    n = sums.get('requests', 0)
    confidence = (value.get('confidence') or {}).get('sum') or {}
    samples = (confidence.get('requests') or {}).get('sampleSize')
    interval = (value.get('avg') or {}).get('sampleInterval')
    return {'observedRequests': n, 'expectedRequests': expected, 'countMatchesPlan': n == expected,
            'cpuTimeUs': sums.get('cpuTimeUs'), 'startupCpuTimeUs': sums.get('startupCpuTimeUs'),
            'meanCpuMs': sums['cpuTimeUs'] / n / 1000 if n and 'cpuTimeUs' in sums else None,
            'startupCpuMs': sums['startupCpuTimeUs'] / n / 1000 if n and 'startupCpuTimeUs' in sums else None,
            'errors': sums.get('errors', 0), 'subrequests': sums.get('subrequests', 0),
            'sampleSize': samples, 'adaptiveSampleInterval': interval,
            'unsampledPositiveCount': expected > 0 and n == expected and samples == expected and interval == 1,
            'validEmptyResult': False, 'confidence95': confidence}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--before-start')
    parser.add_argument('--before-end')
    parser.add_argument('--before-count', type=int, default=2)
    parser.add_argument('--after-start')
    parser.add_argument('--after-end')
    parser.add_argument('--after-count', type=int, default=2)
    args = parser.parse_args()
    token = tomllib.loads((Path.home() / 'Library/Preferences/.wrangler/config/default.toml').read_text())['oauth_token']

    def api(path, query=None):
        headers = {'Authorization': 'Bearer ' + token}
        data = None
        if query:
            headers['Content-Type'] = 'application/json'
            data = json.dumps({'query': query}).encode()
        request = urllib.request.Request('https://api.cloudflare.com/client/v4' + path,
                                         headers=headers, data=data, method='POST' if data else 'GET')
        with urllib.request.urlopen(request, timeout=25) as response:
            raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError('metadata_response_exceeds_bound')
        value = json.loads(raw)
        if query:
            if value.get('errors'):
                raise ValueError('graphql_query_failed')
            accounts = ((value.get('data') or {}).get('viewer') or {}).get('accounts') or []
            if len(accounts) != 1:
                raise ValueError('graphql_account_result_missing')
            return accounts[0]
        if value.get('success') is not True:
            raise ValueError('metadata_read_failed')
        return value['result']

    project = api('/accounts/' + ACCOUNT + '/pages/projects/' + PROJECT)
    if project.get('production_script_name') != PAGES_SCRIPT:
        raise ValueError('pages_production_script_name_changed')
    pages_metadata = {'project': project['name'], 'production_script_name': project['production_script_name'],
        'canonical_deployment_id': (project.get('canonical_deployment') or {}).get('id'),
        'uses_functions': project.get('uses_functions'),
        'services': (project.get('deployment_configs') or {}).get('production', {}).get('services')}
    deployment = api('/accounts/' + ACCOUNT + '/workers/scripts/' + WORKER + '/deployments')['deployments'][0]
    worker_metadata = {k: deployment[k] for k in ('id', 'created_on', 'versions')}
    windows = {}
    receipts = []
    for receipt_path in args.receipt:
        receipt = json.loads(receipt_path.read_text())
        receipts.append({'path': str(receipt_path), 'passed': receipt.get('passed'), 'failure': receipt.get('failure')})
        for name, window in receipt['windows'].items():
            if not window.get('completed') or not window.get('end'):
                continue
            rows = [r for r in receipt['samples'] if r.get('phase') == name]
            if not rows or not all(r.get('passed') for r in rows):
                continue
            if name.startswith('Hit'):
                pages_expected = worker_expected = 0
            elif name == 'DirectBaseline':
                pages_expected, worker_expected = 0, len(rows)
            elif name == 'ErrorAndQueryChecks':
                pages_expected = len(rows)
                worker_expected = sum(r.get('check') == 'unavailable-slot' for r in rows)
            else:
                pages_expected = sum(r['headers'].get('cf-cache-status') != 'HIT' for r in rows)
                worker_expected = pages_expected
            label = name
            if label in windows:
                label += str(len(windows))
            windows[label] = {'start': window['start'], 'end': window['end'],
                'httpRequests': len(rows), 'expectedPagesInvocations': pages_expected,
                'expectedGetBlockInvocations': worker_expected,
                'beforePositiveControl': name == 'PreControlJson',
                'afterPositiveControl': name == 'ErrorAndQueryChecks'}
    if args.before_start or args.before_end:
        if not (args.before_start and args.before_end and 0 < args.before_count <= 10):
            raise ValueError('invalid_before_control')
        windows['BeforeControl'] = {'start': args.before_start, 'end': args.before_end,
            'httpRequests': args.before_count, 'expectedPagesInvocations': args.before_count,
            'expectedGetBlockInvocations': args.before_count, 'beforePositiveControl': True,
            'afterPositiveControl': False, 'source': 'Root recorded direct pre-rule JSON control; collector sent no requests.'}
    if args.after_start or args.after_end:
        if not (args.after_start and args.after_end and 0 < args.after_count <= 10):
            raise ValueError('invalid_after_control')
        windows['AfterControl'] = {'start': args.after_start, 'end': args.after_end,
            'httpRequests': args.after_count, 'expectedPagesInvocations': args.after_count,
            'expectedGetBlockInvocations': args.after_count, 'beforePositiveControl': False,
            'afterPositiveControl': True, 'source': 'Root recorded targeted post-run control; collector sent no requests.'}
    if not windows or len(windows) > 12:
        raise ValueError('invalid_window_count')
    start = min(instant(w['start']) for w in windows.values())
    end = max(instant(w['end']) for w in windows.values())
    discovery = ('query { viewer { accounts(filter:{accountTag:' + json.dumps(ACCOUNT) + '}) { '
        'pages: pagesFunctionsInvocationsAdaptiveGroups(limit:20,filter:{scriptName:' + json.dumps(PAGES_SCRIPT) +
        ',datetime_geq:' + json.dumps(stamp(start)) + ',datetime_leq:' + json.dumps(stamp(end)) +
        '}) { dimensions { scriptName } sum { requests } } } } }')
    discovered = api('/graphql', discovery).get('pages') or []
    pages_discovered = any(r['dimensions']['scriptName'] == PAGES_SCRIPT for r in discovered)
    aliases = {}
    clauses = []
    for index, (name, window) in enumerate(windows.items()):
        a, b = instant(window['start']), instant(window['end'])
        if b < a:
            raise ValueError('invalid_window_order')
        for boundary, lo, hi in [('Exact', a, b), ('Whole', a.replace(microsecond=0), b.replace(microsecond=0) + dt.timedelta(seconds=1))]:
            for script in ('Pages', 'GetBlock'):
                alias = 'w' + str(index) + boundary + script
                filters = {'scriptName': PAGES_SCRIPT if script == 'Pages' else WORKER,
                           'datetime_geq': stamp(lo), 'datetime_leq': stamp(hi)}
                if script == 'GetBlock':
                    filters['scriptVersion'] = WORKER_VERSION
                dataset = 'pagesFunctionsInvocationsAdaptiveGroups' if script == 'Pages' else 'workersInvocationsAdaptive'
                fields = PAGES_FIELDS if script == 'Pages' else FIELDS
                clauses.append(alias + ':' + dataset + '(limit:1,filter:{' +
                    ','.join(k + ':' + json.dumps(v) for k, v in filters.items()) + '}){' + fields + '}')
                aliases[alias] = {'window': name, 'boundary': boundary, 'script': script,
                    'dataset': dataset, 'filters': filters,
                    'expected': window['expectedPagesInvocations' if script == 'Pages' else 'expectedGetBlockInvocations']}
    query = 'query { viewer { accounts(filter:{accountTag:' + json.dumps(ACCOUNT) + '}) {' + '\n'.join(clauses) + '} } }'
    values = api('/graphql', query)
    if any(alias not in values for alias in aliases):
        raise ValueError('graphql_alias_result_missing')
    derived = {alias: metric(values[alias], spec['expected']) for alias, spec in aliases.items()}
    if not pages_discovered:
        for alias, spec in aliases.items():
            if spec['script'] == 'Pages':
                derived[alias].update({'observedRequests': None, 'countMatchesPlan': False,
                    'cpuTimeUs': None, 'startupCpuTimeUs': None, 'startupCpuMs': None,
                    'sampleSize': None, 'errors': None,
                    'measurementStatus': 'unavailable_project_analytics_identity_not_visible'})
    selected = {}
    for index, (name, window) in enumerate(windows.items()):
        selected[name] = {}
        for script in ('Pages', 'GetBlock'):
            exact, whole = 'w' + str(index) + 'Exact' + script, 'w' + str(index) + 'Whole' + script
            choice = next((x for x in (exact, whole) if derived[x]['unsampledPositiveCount']), None)
            choice = choice or next((x for x in (exact, whole) if derived[x]['countMatchesPlan']), exact)
            selected[name][script] = {'selectedQuery': choice, **derived[choice],
                'bothBoundariesZero': derived[exact]['observedRequests'] == 0 and derived[whole]['observedRequests'] == 0}
    before_ok = any(w.get('beforePositiveControl') and selected[name]['Pages']['unsampledPositiveCount']
                    for name, w in windows.items())
    after_ok = any(w.get('afterPositiveControl') and selected[name]['Pages']['unsampledPositiveCount']
                   for name, w in windows.items())
    hits = {name: value for name, value in selected.items() if name.startswith('Hit')}
    version_matches = deployment['versions'] == [{'version_id': WORKER_VERSION, 'percentage': 100}]
    project_after = api('/accounts/' + ACCOUNT + '/pages/projects/' + PROJECT)
    pages_pinned = (pages_metadata['canonical_deployment_id'] == PAGES_DEPLOYMENT
        and (project_after.get('canonical_deployment') or {}).get('id') == PAGES_DEPLOYMENT
        and project_after.get('production_script_name') == PAGES_SCRIPT)
    report = {'schema': 'blockzilla-pages-cdn-platform-cpu-v1', 'fetchedAt': stamp(dt.datetime.now(dt.timezone.utc)),
        'receipts': receipts, 'pages': pages_metadata, 'worker': worker_metadata, 'windows': windows,
        'discoveredPagesDimensions': discovered,
        'pagesCounterStatus': 'visible' if pages_discovered else 'unavailable_project_analytics_identity_not_visible',
        'queries': {'discovery': discovery, 'cohorts': query}, 'aliases': aliases,
        'rawResults': values, 'derived': derived, 'selectedPhases': selected,
        'checks': {'workerVersionUnchanged': version_matches, 'pagesScriptDiscovered': pages_discovered,
            'pagesDeploymentPinned': pages_pinned,
            'beforePagesControlUnsampled': before_ok, 'afterPagesControlUnsampled': after_ok,
            'bothHitFormatsPresent': {'HitBin', 'HitJson'} <= hits.keys(),
            'pagesZeroInBothHitBoundaryVariants': (bool(hits) and all(x['Pages']['bothBoundariesZero'] for x in hits.values())) if pages_discovered else None,
            'getBlockZeroInBothHitBoundaryVariants': bool(hits) and all(x['GetBlock']['bothBoundariesZero'] for x in hits.values())},
        'workerDataRequests': 0, 'mutations': 0, 'secretValuesWritten': False,
        'notes': ['Empty results are valid zero observations only after successful GraphQL responses; positive controls establish visibility.',
            'Adaptive weighted counts are not exact sample counts. Zero observations have no CPU mean or sampling interval.',
            'The Pages project is isolated. Other public getBlock traffic can affect its window totals.',
            'Service-bound callee invocations and billable request counts are different quantities. This is not an invoice.',
            'Pages uses pagesFunctionsInvocationsAdaptiveGroups. Its schema has no summed CPU or startup CPU field; null mean CPU is unavailable, not zero.',
            'Pages has no scriptVersion analytics filter. The project canonical deployment is checked before and after collection.',
            'This canary inventory returned only the account-wide Pages scriptName __unknown__. A missing project-specific Pages row is unavailable data, not a measured zero.',
            'Only completed successful receipt windows are queried; an overall deadline failure is retained in receipt metadata.']}
    report['supportedZeroInvocationObservation'] = all(report['checks'].values())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'path': str(args.output.resolve()), 'checks': report['checks'],
        'supportedZeroInvocationObservation': report['supportedZeroInvocationObservation'],
        'selectedPhases': selected}, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'passed': False, 'error': 'metadata_collection_failed',
                          'error_type': type(error).__name__, 'http_status': getattr(error, 'code', None)}))
        raise SystemExit(1)
