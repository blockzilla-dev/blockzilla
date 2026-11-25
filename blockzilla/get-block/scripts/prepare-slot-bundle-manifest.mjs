#!/usr/bin/env node
// Read-only preparation. This helper never uploads or changes archive objects.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { fixturePath } from './fixture-inputs.mjs';
import { decodeResolution, decodeV1Bundle } from './bench-resolution-client.mjs';

const PACKAGE = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ROOT = resolve(PACKAGE, '../..');
export const BUNDLE_SLOTS = [470555971, 470663944, 470771932, 470879999];
const hash = (algorithm, value) => createHash(algorithm).update(value).digest('hex');

export async function prepareSlotBundleManifest(options = {}) {
  const verification = JSON.parse(await readFile(fixturePath(options.fixtureRoot, 'verification.json'), 'utf8'));
  assert.equal(verification.status, 'REMOTE_VERIFIED');
  const prefix = options.prefix ?? 'serving/example-slot-bundles-v1';
  const generation = options.generation ?? 'example-slot-bundles-v1';
  assert.match(prefix, /^[A-Za-z0-9._/-]{1,512}$/);
  assert.ok(!prefix.split('/').some(part => ['', '.', '..'].includes(part)));
  assert.match(generation, /^[A-Za-z0-9._-]{1,128}$/);
  const manifest = []; const objects = [];
  for (const slot of BUNDLE_SLOTS) {
    const row = verification.resolutionObjects.find(row => row.slot === slot);
    assert.ok(row);
    const resolution = decodeResolution(await readFile(row.localPath), slot);
    const locator = resolution.locator;
    const localPath = fixturePath(options.fixtureRoot, 'inputs', `${slot}.bundle.wincode`);
    const bytes = await readFile(localPath);
    const bundle = decodeV1Bundle(bytes);
    assert.equal(bundle.slot, slot);
    assert.ok(bundle.blockhash.equals(locator.blockhash));
    assert.ok(bundle.previousBlockhash.equals(locator.previousBlockhash));
    assert.ok(bundle.signatureCounts.equals(resolution.signatureCounts));
    assert.equal(bundle.hot.length, locator.hot.compressed_len);
    assert.equal(bundle.signatures.length, locator.signatureBytes);
    assert.equal(bytes.length, 1 + 5 + 1 + 3 + bundle.hot.length + 2 + 3 + bundle.access.length,
      'the selected modern sample has the expected exact original V1 frame');
    const identity = { length: bytes.length, etag: `"${hash('md5', bytes)}"` };
    const sha256 = hash('sha256', bytes);
    const provenance = {
      version: locator.version, source_prefix: locator.sourcePrefix, generation: locator.generation,
      epoch: locator.epoch, hot: locator.hot, parent_slot: locator.parentSlot,
      blockhash: [...locator.blockhash], previous_blockhash: [...locator.previousBlockhash],
      message_schema: locator.messageSchema, metadata_schema: locator.metadataSchema,
      blocks: locator.blocks, signatures: locator.signatures,
    };
    manifest.push({ identity, sha256, provenance });
    objects.push({ slot, key: `${prefix}/epoch-${locator.epoch}/slot-${slot}.bundle.wincode`, localPath,
      ...identity, sha256, sha256Base64: Buffer.from(sha256, 'hex').toString('base64'),
      compressedHotBytes: bundle.hot.length, signatureBytes: bundle.signatures.length,
      resolutionBytes: resolution.bytes.length, accessBytes: bundle.access.length });
  }
  return { prefix, generation, manifest, objects,
    bundleBytes: objects.reduce((sum, row) => sum + row.length, 0),
    oldSourceWindowBytes: objects.reduce((sum, row) => sum + row.compressedHotBytes + row.signatureBytes, 0),
    oldResolutionBytes: objects.reduce((sum, row) => sum + row.resolutionBytes, 0),
    notes: ['Four original epoch-1089 test bundles only. No full epoch migration.',
      'Binary identity uses a single-PUT strong MD5 ETag and native R2 SHA256 checksum metadata.',
      'JSON additionally computes SHA256 over the delivered bounded body before parsing.'] };
}

async function main() {
  const { values } = parseArgs({ options: { 'fixture-root': { type: 'string' }, out: { type: 'string' }, prefix: { type: 'string' }, generation: { type: 'string' } } });
  assert.ok(values.out, '--out receipt.json is required');
  const receipt = await prepareSlotBundleManifest({ ...values, fixtureRoot: values['fixture-root'] });
  const path = resolve(values.out); await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(receipt, null, 2)}\n`);
  console.log(JSON.stringify({ path, slots: BUNDLE_SLOTS, bundleBytes: receipt.bundleBytes,
    oldSourceWindowBytes: receipt.oldSourceWindowBytes, oldResolutionBytes: receipt.oldResolutionBytes }));
}
if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}
