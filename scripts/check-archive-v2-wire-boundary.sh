#!/usr/bin/env bash
set -euo pipefail

if ! command -v rg >/dev/null 2>&1; then
  echo 'Archive V2 boundary check requires ripgrep (rg).' >&2
  exit 1
fi

# Archive readers must use generation-bound wire profile validation.
# Only the writer output checks, Worker schema dispatch, and decoder mutation
# fixtures listed below may deserialize a message directly. Exact counts keep
# new direct-decoder sites visible during review.
pattern='ArchiveV2HotMessagePayload\s*=\s*wincode::config::deserialize|deserialize(?:_exact)?::<\s*ArchiveV2HotMessagePayload|fn\s+decode_message[\s\S]{0,1200}wincode::config::deserialize'

actual="$({
  rg --count-matches -U "$pattern" \
    --glob '*.rs' \
    --glob '!crates/compact-v2/blockzilla-archive-v2/**' \
    --glob '!crates/compact-v2/blockzilla-compact-v2-reader/**' \
    . || true
} | sed 's#^\./##' | LC_ALL=C sort)"

expected="$(LC_ALL=C sort <<'EOF'
blockzilla/cli/src/archive_v2/execution_canary.rs:1
blockzilla/get-block/src/archive_schema.rs:1
blockzilla/ledger-archive/src/convert.rs:1
blockzilla/ledger-archive/src/slot_compact.rs:1
zillastream/relay/decoder/src/tests.rs:2
EOF
)"

if [[ "$actual" != "$expected" ]]; then
  echo 'Archive V2 wire boundary changed.' >&2
  echo 'New readers and indexers must use the format reader with generation-bound schema validation.' >&2
  echo 'Expected direct-decoder sites:' >&2
  printf '%s\n' "$expected" >&2
  echo 'Found:' >&2
  printf '%s\n' "$actual" >&2
  exit 1
fi

