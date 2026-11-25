# Opt-in native bank client

Use `./banks.mjs` on your backend with `decoder-banks-v2.wasm`. This module uses
separate Rust decoder exports. It does not change v1 admission. Keep the Bearer
key in a server secret or private file. Do not put it in a URL or browser setting.

```js
import { createBankClient } from './banks.mjs';
const client = createBankClient({
  url: 'https://stream.blockzilla.dev/',
  apiKey: privateServerKey,
  source: operatorSuppliedSource, // exact genesis, node, Agave revision, session
});
for await (const frame of client.stream({
  after: databaseCursor,
  onBootstrap: async ({ after, payload, control }) => {
    await saveBootstrapDependency(after, payload, control);
  },
})) {
  // One database transaction: payload/dependency + control + application + cursor.
  await commitBankEventAndCursor(frame);
  await frame.ack();
}
```

Supply a saved `after` cursor to resume. With no cursor, the client explicitly
joins at the current head. A source change or replay gap stops the iterator. It
never resets a saved position. Your database must pin the complete source tuple.
Network failures retry the last acknowledged position. An application commit
failure stops the iterator; reopen it from the database checkpoint.

A block is a complete processed candidate. Match confirmation by bank identity,
original marker digest, and full payload frame digest. Failed transactions remain
present with a non-null error. Controls contain no second compact block. A missing
control dependency is fetched at the exact relative chunk path. The bootstrap
head resolves its exact control and full payload before selection. Save that
payload in your database if later controls will need its transaction records.

`client.readyHash()` returns a native confirmed/finalized tuple only when the
client has reached the provider head and health is current. It throws on stale
health, a processed-only source, invalidated confirmed state, or excessive age.
Repeated status or an older root does not renew the selected tuple's monotonic
age. This is a blockhash selection helper, not a wallet or send implementation.
Use the tuple's `context_slot` as the send floor. Keep the signed blockhash and
expiry bound to the same transaction.

The decoder checks strict v2 JSON fields, required nulls, object layout/digests,
signatures, loaded addresses, outcomes, and native block height. The client also
checks source, SSE start boundary, notice ID, sequence, byte length, slot bounds,
relative URL, and full-frame SHA before application. Credentialed GETs do not
follow redirects. Metadata proofs have a 16,384-bank hard limit and are pruned by
height. Transaction payload storage and application rollback belong to the
consumer. Do not insert processed blocks into finalized history.

Run `./build-wasm.sh` from `../decoder/` with the
[decoder instructions](../decoder/README.md). The script writes
`decoder-banks-v2.wasm` here with the required exports and generic build paths.
Run `node --test test.mjs sdk-test.mjs banks-test.mjs` here. The checked-in fixtures
are synthetic, not live mainnet data. These tests do not prove native plugin
compatibility; run a matched host/plugin load test separately. The package has
not been published to npm.

A delayed health sample can still be valid evidence of its original sample. It
must not stop replay. Readiness checks its current age and uses the stricter
five-second source age policy, in addition to the 15-second monotonic selection
limit. A delayed or repeated old sample cannot make a hash ready. Product client
headers identify this backend to the public edge; no API key enters that header.


Finite reads run in parallel, with a bound of four. Notices, decoded results,
application effects, and acknowledgements keep event order. Closing the iterator
cancels its pending reads. Wasm decode runs on the JavaScript thread; the bound
is not a claim that one thread can render all transaction details at every live
rate. Measure the Rust consumer for applications that need full-detail throughput.
A worker pool for Node/browser decode remains a possible client improvement.

Finite fixture tests do not establish sustained live throughput. Measure decode
time, durable writes and source age with the intended workload before using
`readyHash()` for live transaction submission.
