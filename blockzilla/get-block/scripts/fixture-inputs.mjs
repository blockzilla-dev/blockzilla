import assert from 'node:assert/strict';
import { resolve } from 'node:path';

// Saved input layout: verification.json, reference-base64.json, input-manifest.json,
// inputs/<slot>.{bundle.wincode,descriptor.json}, and descriptors/<slot>.json.
export function fixturePath(root, ...parts) {
  const value = root ?? process.env.BLOCKZILLA_TEST_FIXTURE_ROOT;
  assert.ok(typeof value === 'string' && value.length > 0,
    'Supply --fixture-root DIR, fixtureRoot, or BLOCKZILLA_TEST_FIXTURE_ROOT for saved test inputs.');
  return resolve(value, ...parts);
}
