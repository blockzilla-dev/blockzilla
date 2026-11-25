#!/usr/bin/env python3
"""Prepare a bounded partial-epoch native-R2 experiment from saved full bundles.

No network, cloud writes, source mutations, or decoded JSON output are used.
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
MAX_BUNDLE = 32 * 1024 * 1024
MAX_TOTAL_SOURCE = 16 * 1024 * 1024
BLOCKS = 'archive-v2-blocks.zstd'
SIGNATURES = 'signatures.bin'


def bounded(path: Path, maximum: int) -> bytes:
    with path.open('rb') as stream:
        value = stream.read(maximum + 1)
    if len(value) > maximum:
        raise ValueError(f'Input exceeds its bound: {path.name}')
    return value


def unsigned(data: memoryview, cursor: list[int]) -> int:
    start = cursor[0]
    value = 0
    for shift in range(0, 70, 7):
        if cursor[0] >= len(data):
            raise ValueError('Truncated Wincode integer')
        byte = data[cursor[0]]
        cursor[0] += 1
        value |= (byte & 127) << shift
        if not byte & 128:
            if value > (1 << 53) - 1 or (cursor[0] - start > 1 and byte == 0):
                raise ValueError('Noncanonical or oversized Wincode integer')
            return value
    raise ValueError('Oversized Wincode integer')


def vector(data: memoryview, cursor: list[int]) -> memoryview:
    length = unsigned(data, cursor)
    end = cursor[0] + length
    if end > len(data):
        raise ValueError('Truncated Wincode vector')
    result = data[cursor[0]:end]
    cursor[0] = end
    return result


def bundle_windows(raw: bytes, slot: int) -> tuple[memoryview, memoryview, int]:
    data = memoryview(raw)
    cursor = [0]
    if unsigned(data, cursor) != 1 or unsigned(data, cursor) != slot:
        raise ValueError('Bundle version or slot differs')
    if unsigned(data, cursor) != 1:
        raise ValueError('Original ZstdWincode frame is required')
    hot = vector(data, cursor)
    if unsigned(data, cursor) != 0 or unsigned(data, cursor) != 1:
        raise ValueError('Full Wincode access is required')
    access = vector(data, cursor)
    if cursor[0] != len(data):
        raise ValueError('Trailing bundle bytes')
    at = [0]
    if unsigned(access, at) != 2 or unsigned(access, at) != 0:
        raise ValueError('Unsupported access version or flags')
    at[0] += 64  # resolved current and previous block hashes
    if at[0] > len(access):
        raise ValueError('Truncated access hashes')
    counts = vector(access, at)
    signatures = vector(access, at)
    if sum(counts) * 64 != len(signatures):
        raise ValueError('Signature counts differ from the original window')
    return hot, signatures, len(counts)


def hashes(path: Path) -> dict:
    md5 = hashlib.md5()
    sha = hashlib.sha256()
    length = 0
    with path.open('rb') as stream:
        while chunk := stream.read(64 * 1024):
            md5.update(chunk)
            sha.update(chunk)
            length += len(chunk)
    return {'bytes': length, 'md5Hex': md5.hexdigest(), 'etag': '"' + md5.hexdigest() + '"', 'sha256': sha.hexdigest()}


def new_json(path: Path, value: dict) -> None:
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def checked_prefix(prefix: str) -> str:
    if len(prefix) > 512 or any(not re.fullmatch(r'[A-Za-z0-9._-]+', part) or part in ('.', '..') for part in prefix.split('/')):
        raise ValueError('Invalid publication prefix')
    return prefix


VERIFY_JS = r'''
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
const input=JSON.parse(readFileSync(0,'utf8'));
const {decodeResolution,decodeParts,decodeV1Bundle,reconstructV1Bundle}=await import(pathToFileURL(input.helperPath).href);
const sha=b=>createHash('sha256').update(b).digest('hex');
const rows=[];
for(const r of input.records){
 const original=readFileSync(r.originalBundlePath);
 const decodedOriginal=decodeV1Bundle(original);
 const resolution=decodeResolution(readFileSync(r.resolutionPath),r.slot);
 const loc=resolution.locator;
 assert.equal(loc.sourcePrefix,input.sourcePrefix);assert.equal(loc.generation,input.generation);
 const hotFile=readFileSync(r.blockObjectPath),sigFile=readFileSync(r.signatureObjectPath);
 assert.equal(loc.blocks.length,hotFile.length);assert.equal(loc.signatures.length,sigFile.length);
 const hot=hotFile.subarray(loc.hot.compressed_offset,loc.hot.compressed_offset+loc.hot.compressed_len);
 const signatures=sigFile.subarray(loc.hot.first_signature_ordinal*64,(loc.hot.first_signature_ordinal+loc.hot.signature_count)*64);
 assert.deepEqual(hot,decodedOriginal.hot);assert.deepEqual(signatures,decodedOriginal.signatures);
 assert.deepEqual(loc.blockhash,decodedOriginal.blockhash);assert.deepEqual(loc.previousBlockhash,decodedOriginal.previousBlockhash);
 assert.equal(loc.parentSlot<r.slot,true);assert.equal(loc.messageSchema,r.messageSchema);assert.equal(loc.metadataSchema,r.metadataSchema);
 const header=Buffer.alloc(64);header.write('BZPART2!',0,'ascii');header.writeBigUInt64LE(BigInt(r.slot),8);
 header.writeBigUInt64LE(BigInt(hot.length),16);header.writeBigUInt64LE(BigInt(signatures.length),24);resolution.locatorDigest.copy(header,32);
 const parts=decodeParts(Buffer.concat([header,hot,signatures]),resolution);
 const rebuilt=reconstructV1Bundle(resolution,parts);assert.deepEqual(rebuilt,original);
 assert.equal(sha(original),r.originalBundleSha256);
 rows.push({slot:r.slot,parentSlot:loc.parentSlot,compressedOffset:loc.hot.compressed_offset,
  firstSignatureOrdinal:loc.hot.first_signature_ordinal,compressedSha256:sha(hot),signatureSha256:sha(signatures),
  originalBundleSha256:sha(original),reconstructedBundleSha256:sha(rebuilt),binaryBundleByteExact:true});
}
process.stdout.write(JSON.stringify({status:'PASSED',checkedSlots:rows.length,records:rows}));
'''


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-manifest', type=Path, required=True)
    parser.add_argument('--builder', type=Path, default=ROOT / 'target/release/build-slot-resolution')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-prefix', default='compact-v2/example-native-sample')
    parser.add_argument('--generation', default='example-native-sample-v1')
    parser.add_argument('--resolution-prefix', default='serving/example-native-sample-v1')
    args = parser.parse_args()
    source_prefix = checked_prefix(args.source_prefix)
    resolution_prefix = checked_prefix(args.resolution_prefix)
    if not re.fullmatch(r'[A-Za-z0-9._-]{1,128}', args.generation):
        raise ValueError('Invalid serving generation')
    input_manifest = json.loads(bounded(args.input_manifest, 256 * 1024))
    inputs = sorted(input_manifest['records'], key=lambda record: (record['epoch'], record['slot']))
    if not 1 <= len(inputs) <= 8 or len({r['slot'] for r in inputs}) != len(inputs):
        raise ValueError('Select one to eight distinct saved blocks')
    args.output.mkdir(parents=True, exist_ok=True)
    objects_root = args.output / 'objects'
    descriptors_root = args.output / 'descriptors'
    objects_root.mkdir()
    descriptors_root.mkdir()
    records = []
    objects = []
    total_source = 0
    for epoch in sorted({r['epoch'] for r in inputs}):
        names = {name: f'{source_prefix}/epoch-{epoch}/{name}' for name in (BLOCKS, SIGNATURES)}
        paths = {name: objects_root / names[name] for name in names}
        paths[BLOCKS].parent.mkdir(parents=True)
        with paths[BLOCKS].open('xb') as hot_file, paths[SIGNATURES].open('xb') as sig_file:
            for original in [r for r in inputs if r['epoch'] == epoch]:
                slot = original['slot']
                if slot // 432000 != epoch:
                    raise ValueError('Input epoch differs from slot')
                bundle_path = Path(original['bundlePath'])
                descriptor_path = Path(original['descriptorPath'])
                raw = bounded(bundle_path, MAX_BUNDLE)
                if hashlib.sha256(raw).hexdigest() != original['bundleSha256']:
                    raise ValueError('Saved original bundle SHA256 differs')
                hot, signatures, tx_count = bundle_windows(raw, slot)
                descriptor = json.loads(bounded(descriptor_path, 64 * 1024))
                row = descriptor['hot_row']
                if row['slot'] != slot or row['compressed_len'] != len(hot) or row['signature_count'] * 64 != len(signatures) or row['tx_count'] != tx_count:
                    raise ValueError('Original descriptor differs from bundle windows')
                if hashlib.sha256(hot).hexdigest() != original['compressedSha256']:
                    raise ValueError('Saved original compressed SHA256 differs')
                if sig_file.tell() % 64:
                    raise ValueError('Packed signatures are not aligned')
                changed = copy.deepcopy(descriptor)
                changed.update(source_prefix=source_prefix, generation=args.generation)
                changed['hot_row']['compressed_offset'] = hot_file.tell()
                changed['hot_row']['first_signature_ordinal'] = sig_file.tell() // 64
                hot_file.write(hot)
                sig_file.write(signatures)
                total_source += len(hot) + len(signatures)
                if total_source > MAX_TOTAL_SOURCE:
                    raise ValueError('Prepared sample exceeds 16MiB source bound')
                records.append({'slot': slot, 'epoch': epoch, 'descriptor': changed,
                    'originalBundlePath': str(bundle_path.resolve()), 'originalBundleSha256': original['bundleSha256'],
                    'originalDescriptorSha256': hashlib.sha256(bounded(descriptor_path, 64 * 1024)).hexdigest(),
                    'originalSourcePrefix': descriptor['source_prefix'], 'originalHotRow': row,
                    'blockObjectPath': str(paths[BLOCKS].resolve()), 'signatureObjectPath': str(paths[SIGNATURES].resolve()),
                    'messageSchema': {'current': 0, 'may24': 1}[descriptor['message_schema']],
                    'metadataSchema': {'current': 0, 'legacy': 1}[descriptor['metadata_schema']]})
        identities = {}
        for name in (BLOCKS, SIGNATURES):
            digest = hashes(paths[name])
            identities[name] = {'length': digest['bytes'], 'etag': digest['etag']}
            objects.append({'role': 'source', 'epoch': epoch, 'key': names[name], 'localPath': str(paths[name].resolve()), **digest})
        for record in [r for r in records if r['epoch'] == epoch]:
            # Tables are complete in each resolution. Do not advertise an
            # unuploaded registry.bin as part of this partial-epoch publication.
            record['descriptor']['objects'] = copy.deepcopy(identities)
    builder_receipts = []
    for record in records:
        slot, epoch = record['slot'], record['epoch']
        descriptor_path = descriptors_root / f'{slot}.json'
        new_json(descriptor_path, record['descriptor'])
        key = f'{resolution_prefix}/epoch-{epoch}/slot-{slot}.resolution.v1'
        target = objects_root / key
        target.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run([str(args.builder.resolve()), '--bundle', record['originalBundlePath'], '--descriptor', str(descriptor_path.resolve()), '--output', str(target.resolve())], check=True, capture_output=True, text=True)
        built = json.loads(result.stdout)
        if not built.get('ok') or built['signature_bytes_stored'] != 0:
            raise ValueError('Resolution builder did not produce a signature-free serving object')
        builder_receipts.append(built)
        record.update(descriptorPath=str(descriptor_path.resolve()), resolutionPath=str(target.resolve()), resolutionKey=key)
        objects.append({'role': 'resolution', 'epoch': epoch, 'slot': slot, 'key': key, 'localPath': str(target.resolve()), **hashes(target)})
    verify = subprocess.run(['node', '--input-type=module', '-e', VERIFY_JS], input=json.dumps({'helperPath': str(ROOT / 'blockzilla/get-block/scripts/bench-resolution-client.mjs'), 'sourcePrefix': source_prefix, 'generation': args.generation, 'records': [{k: v for k, v in r.items() if k != 'descriptor'} for r in records]}), check=True, capture_output=True, text=True)
    verification = json.loads(verify.stdout)
    by_slot = {r['slot']: r for r in verification['records']}
    public_records = []
    for record in records:
        descriptor = record.pop('descriptor')
        public_records.append({**record, **by_slot[record['slot']], 'hotRow': descriptor['hot_row'],
            'blockhash': descriptor['blockhash'], 'previousBlockhash': descriptor['previous_blockhash'],
            'parentIsInSample': by_slot[record['slot']]['parentSlot'] in by_slot})
    source_bytes = sum(o['bytes'] for o in objects if o['role'] == 'source')
    resolution_bytes = sum(o['bytes'] for o in objects if o['role'] == 'resolution')
    manifest = {'schema': 'blockzilla-owner-native-r2-partial-epoch-v1', 'status': 'LOCAL_VERIFIED',
        'preparedAt': dt.datetime.now(dt.timezone.utc).isoformat(), 'sourcePrefix': source_prefix,
        'generation': args.generation, 'resolutionPrefix': resolution_prefix,
        'coverage': {'partialEpochs': True, 'fullEpoch': False, 'epochs': sorted({r['epoch'] for r in records}),
            'admittedSlots': [r['slot'] for r in records], 'blockCount': len(records), 'otherSlots': 'not included; no skipped-slot or full-history claim'},
        'provenance': {'inputManifest': str(args.input_manifest.resolve()), 'inputManifestSha256': hashlib.sha256(bounded(args.input_manifest, 256 * 1024)).hexdigest(),
            'sourcePayloadByteExact': True, 'originalFoundationDataChanged': False, 'cloudWritesPerformed': False,
            'etagAssumption': 'Quoted MD5 for one small single-part PUT. Publisher must check actual native R2 httpEtag and object length before admitting these resolutions.'},
        'totals': {'objectCount': len(objects), 'sourceObjectCount': sum(o['role'] == 'source' for o in objects),
            'resolutionObjectCount': sum(o['role'] == 'resolution' for o in objects), 'sourceBytes': source_bytes,
            'resolutionBytes': resolution_bytes, 'uploadBytes': source_bytes + resolution_bytes,
            'resolutionOverSourceFraction': resolution_bytes / source_bytes,
            'resolutionOverTotalFraction': resolution_bytes / (source_bytes + resolution_bytes)},
        'objects': objects, 'records': public_records, 'builderReceipts': builder_receipts, 'verification': verification,
        'notes': ['This copies only eight selected compressed frames and their original signature windows for an explicitly authorized owner-account experiment.',
            'Rows retain original logical block IDs and first transaction ordinals. Only physical byte/signature offsets and source object identities are rebased.',
            'Current and previous block hashes, actual parent slots, schemas and block-local dictionaries come from the original complete bundles.',
            'No JSON response cache or JSON body artifact is prepared. No index, marker, registry or unselected archive payload is published.',
            'The object list contains all four source objects and eight serving objects. Descriptors, manifests and verification receipts are local preparation files.']}
    new_json(args.output / 'manifest.json', manifest)
    new_json(args.output / 'verification.json', verification)
    print(json.dumps({'status': manifest['status'], 'manifest': str((args.output / 'manifest.json').resolve()), 'coverage': manifest['coverage'], 'totals': manifest['totals']}))


if __name__ == '__main__':
    main()
