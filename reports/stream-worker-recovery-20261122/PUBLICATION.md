# Published evidence scope

These records describe the tests and deployments completed on 22 November
2026. They contain measurements, identities, hashes and acceptance results.
They contain no API keys, origin tokens, private SSH keys, raw block payloads,
runtime databases or compiled programs.

The live recovery records apply to their named source snapshots and artifact
hashes. They show the original Worker checks, the isolated native SDK
disconnect test and the consumer update on its existing compact-only database.
They do not prove that every later source combination has passed those tests.

Fresh assembled-branch integration checks: **passed** on 22 November 2026.
The branch keeps the newer `origin/main` archive and consensus code. It passed
53 SDK, 54 consumer, 40 protocol, 15 decoder, 130 Worker, 30 resolution, 72 relay
and three memo tests. The Python gateway and activation tools passed 41 and
seven tests. The Worker count includes its 53 core tests.

The fresh release WASM passed 162 local workerd checks. Native body handling
passed ten checks; the optional native R2 reader passed twelve local checks.
The all-target, all-feature Worker Cargo check passed. Three consumer, three
relay and one decoder real-data test remain ignored locally. The earlier
Linux/live receipts remain separate evidence for their named source snapshots.

The first relay runs exposed nonportable socket test paths and permissions.
The fixtures now use canonical private directories with explicit `0700` mode.
The production guards remain unchanged. The final serial relay run passed.
Legacy fixture constructors also set the newer optional archive fields to
empty values. No production behavior was changed by those fixture fixes.

See [fresh package validation](package-validation.json) and its
[local WASM receipt](package-tests/actual-wasm-checks.json). The new local WASM
artifact was not deployed. Source manifests can name private build directories
and omitted owner work files; they are identity records, not instructions to
copy those directories into the repository.

## Publication redaction

`consumer-activation.json` omits the unrelated service and container inventories
from the shared host. Its `publication_redaction` object records the original
file SHA-256 and inventory counts. The activation result, unchanged-resource
assertions, same-database checks and forward cursor checks remain. The owner
keeps the original full record. The published file is not byte-identical to
that original, and its own hash must not be presented as the original hash.
Terminal blank lines in published log files are normalized; test assertions
and result lines are unchanged.

## Owner operations

The historical `get-block-own-r2-full1089-20261122/copy-controller.py` and
`copy-worker.mjs` are records of the earlier native R2 experiment. They can
write archive objects and need the owner's omitted private source credentials,
copy secret, checkpoint and Worker configuration. They are not part of stream
recovery and must not run as an installation or test step. The temporary copy
Worker was removed after that experiment.

`blockzilla-recent-get-block.service` is a record of the accepted Foundation
unit. It names owner machine paths, a private token file and pinned source
directories. It is not a portable service template. A new deployment needs
its own reviewed paths, credentials and source pins.

The Python operation tools in this report directory, and the earlier
`recent-get-block-recovery-20261122/live-recovery.py`, also use owner paths and
omitted private credentials. They are manual audit/deployment tools, not
installation hooks. `test_activate_consumer.py` runs only mocked local checks.

Normal retained-stream recovery uses the existing producer data. Publishing
these test records does not authorize another archive copy or a new block
store.
