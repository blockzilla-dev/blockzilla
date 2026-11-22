from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import quote
import concurrent.futures, datetime, hashlib, hmac, json, math, os, threading, time

TASK = Path(__file__).resolve().parent
ROOT = TASK.parents[1]
M = json.loads((TASK / 'manifest.json').read_text())
SOURCE = json.loads((ROOT / '.codex-tmp/get-block-deploy-20261121/private/worker-secrets.json').read_text())
SECRET = json.loads((TASK / 'private/worker-secrets.json').read_text())['BZ_COPY_SECRET'].encode()
WORKER = 'https://blockzilla-epoch1089-copy-20261122.cheron-augustin.workers.dev'
STATE_PATH = TASK / 'private/checkpoint.json'
REPORT = ROOT / 'reports/get-block-own-r2-full1089-20261122'
LOCK = threading.Lock()
STATE = json.loads(STATE_PATH.read_text()) if STATE_PATH.exists() else {'startedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'objects': {}}

def utc(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def save():
    temporary = STATE_PATH.with_suffix('.tmp')
    temporary.write_text(json.dumps(STATE, indent=2) + '\n'); temporary.chmod(0o600); temporary.replace(STATE_PATH)
    completed = sum(sum(p['length'] for p in o.get('parts', {}).values()) for o in STATE['objects'].values())
    progress = {'updatedAt': utc(), 'completedBytes': completed, 'totalBytes': sum(v['length'] for v in M['objects'].values()), 'completedParts': sum(len(o.get('parts', {})) for o in STATE['objects'].values()), 'totalParts': sum(math.ceil(v['length'] / v['partSize']) for v in M['objects'].values()), 'completedObjects': sum('complete' in o for o in STATE['objects'].values())}
    (REPORT / 'progress.json').write_text(json.dumps(progress, indent=2) + '\n')
    return progress

def api(path, payload, timeout=600):
    data = json.dumps(payload, separators=(',', ':')).encode()
    expires = str(int(time.time()) + 90)
    canonical = '\n'.join(['copy-v1', 'POST', path, expires, hashlib.sha256(data).hexdigest()])
    mac = hmac.new(SECRET, canonical.encode(), hashlib.sha256).hexdigest()
    request = Request(WORKER + path, data=data, headers={'Content-Type': 'application/json', 'User-Agent': 'blockzilla-benchmark/1.0', 'X-BZ-Copy-Expires': expires, 'X-BZ-Copy-Signature': mac}, method='POST')
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read(65537)
            if len(raw) > 65536: raise RuntimeError('Oversized controller response')
            return json.loads(raw)
    except HTTPError as error:
        detail = error.read(2048).decode(errors='replace')
        raise RuntimeError('Copy Worker HTTP ' + str(error.code) + ': ' + detail) from None

def source_headers(name, part):
    obj = M['objects'][name]
    offset = (part - 1) * obj['partSize']; length = min(obj['partSize'], obj['length'] - offset)
    now = datetime.datetime.now(datetime.timezone.utc); date = now.strftime('%Y%m%d'); stamp = now.strftime('%Y%m%dT%H%M%SZ')
    host = SOURCE['BZ_S3_ENDPOINT'].removeprefix('https://').rstrip('/')
    key = f"{M['sourcePrefix']}/epoch-{M['epoch']}/{name}"
    uri = '/' + quote(SOURCE['BZ_S3_BUCKET'], safe='') + '/' + quote(key, safe='/-_.~')
    headers = {'host': host, 'if-match': obj['etag'], 'range': f'bytes={offset}-{offset+length-1}', 'x-amz-content-sha256': 'UNSIGNED-PAYLOAD', 'x-amz-date': stamp}
    names = ';'.join(sorted(headers))
    canonical = 'GET\n' + uri + '\n\n' + ''.join(k + ':' + headers[k] + '\n' for k in sorted(headers)) + '\n' + names + '\nUNSIGNED-PAYLOAD'
    scope = f'{date}/auto/s3/aws4_request'
    value = 'AWS4-HMAC-SHA256\n' + stamp + '\n' + scope + '\n' + hashlib.sha256(canonical.encode()).hexdigest()
    derived = ('AWS4' + SOURCE['BZ_S3_SECRET_ACCESS_KEY']).encode()
    for term in [date, 'auto', 's3', 'aws4_request']: derived = hmac.new(derived, term.encode(), hashlib.sha256).digest()
    signature = hmac.new(derived, value.encode(), hashlib.sha256).hexdigest()
    headers['authorization'] = f'AWS4-HMAC-SHA256 Credential={SOURCE["BZ_S3_ACCESS_KEY_ID"]}/{scope}, SignedHeaders={names}, Signature={signature}'
    del headers['host']
    return headers

def copy_part(job):
    name, part = job
    for attempt in range(3):
        try:
            result = api('/part', {'name': name, 'uploadId': STATE['objects'][name]['uploadId'], 'partNumber': part, 'sourceHeaders': source_headers(name, part)})
            expected = min(M['objects'][name]['partSize'], M['objects'][name]['length'] - (part - 1) * M['objects'][name]['partSize'])
            assert result['partNumber'] == part and result['length'] == expected and result['sourceEtag'] == M['objects'][name]['etag']
            with LOCK:
                STATE['objects'][name]['parts'][str(part)] = result
                progress = save()
            print(json.dumps({'event': 'part', 'name': name, 'part': part, 'bytes': expected, 'completedBytes': progress['completedBytes'], 'totalMs': round(result['totalMs'])}), flush=True)
            return result
        except (RuntimeError, URLError, TimeoutError) as error:
            if attempt == 2: raise
            print(json.dumps({'event': 'retry', 'name': name, 'part': part, 'attempt': attempt + 1, 'reason': str(error)}), flush=True)
            time.sleep(2 ** attempt)

def main():
    for name in M['objects']:
        if name not in STATE['objects']:
            current = api('/head', {'name': name})
            if current['object'] is not None: raise RuntimeError('Destination exists without a local checkpoint')
            created = api('/create', {'name': name})
            STATE['objects'][name] = {'uploadId': created['uploadId'], 'key': created['key'], 'parts': {}}
            save()
    jobs = [(name, part) for name, obj in M['objects'].items() if 'complete' not in STATE['objects'][name] for part in range(1, math.ceil(obj['length'] / obj['partSize']) + 1) if str(part) not in STATE['objects'][name]['parts']]
    # The first real part proves the streaming path before the bounded parallel run.
    if jobs and not any(o['parts'] for o in STATE['objects'].values()): copy_part(jobs.pop(0))
    with concurrent.futures.ThreadPoolExecutor(max_workers=M['concurrency']) as pool:
        list(pool.map(copy_part, jobs))
    for name, obj in M['objects'].items():
        entry = STATE['objects'][name]
        if 'complete' not in entry:
            parts = [{'partNumber': part, 'etag': entry['parts'][str(part)]['etag']} for part in range(1, math.ceil(obj['length'] / obj['partSize']) + 1)]
            result = api('/complete', {'name': name, 'uploadId': entry['uploadId'], 'parts': parts})
            assert result['object']['length'] == obj['length']
            entry['complete'] = result['object']; save()
        current = api('/head', {'name': name})['object']
        assert current['length'] == obj['length'] and current['etag'] == entry['complete']['etag']
    receipt = {'status': 'COMPLETE_LENGTH_VERIFIED', 'startedAt': STATE['startedAt'], 'finishedAt': utc(), 'bucket': M['bucket'], 'sourcePrefix': M['sourcePrefix'], 'destinationPrefix': M['destinationPrefix'], 'epoch': M['epoch'], 'partSizes': {n:o['partSize'] for n,o in M['objects'].items()}, 'concurrency': M['concurrency'], 'bytes': sum(o['length'] for o in M['objects'].values()), 'objects': [STATE['objects'][name]['complete'] | {'sourceEtag': M['objects'][name]['etag'], 'partCount': len(STATE['objects'][name]['parts'])} for name in M['objects']], 'verification': 'Every part used source If-Match and exact range/ETag/length checks. Completed object lengths and ETags were checked. Whole-object source SHA-256 was not read.'}
    (REPORT / 'copy-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({'event': 'complete', 'bytes': receipt['bytes'], 'objects': len(receipt['objects'])}), flush=True)

if __name__ == '__main__': main()
