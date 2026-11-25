# Native account client

This private Rust library reads owned account values and finalized ledger blocks through a local Unix
socket. It has no Agave or Agave RPC dependency. It requires a Tokio runtime.

```rust,ignore
use blockzilla_account_client::{AccountClient, ClientOptions};

let client = AccountClient::new(socket_path, operator_pinned_source, ClientOptions::default())?;
let limits = client.describe().await?;
let account = client.get_account(&exact_bank, &pubkey).await?;
let ordered_entries = client.get_multiple_accounts(&exact_bank, &pubkeys).await?;
let block = client.get_block(slot, Some(&expected_blockhash)).await?;
```

The operator must provide the full source identity, including the unique native
host instance ID. Describe checks that identity and returns protocol limits. It
does not select a source or a Bank. Obtain the exact Bank from an admitted stream
observation or another trusted native source. Each request opens one connection.
There are no automatic retries or substitutions.

The client checks the complete source, protocol version, request ID, operation,
Bank context, account order, duplicate values and frame bounds. It preserves
explicit missing accounts and all `u64` account fields. A response with the wrong
Bank is rejected even when its slot is newer. A requested parent PoH proof cannot
be removed. Passing `parent_blockhash: None` omits only that additional proof and
still pins the exact Bank.

`get_block(slot, expected_blockhash)` reads one complete finalized block from
the native ledger. `Some(hash)` pins its exact hash; `None` omits that extra
constraint but still pins the source and slot. The client returns the signed
transaction bytes as canonical base64, typed execution metadata, parent and
block identity, time, height and rewards. Failed transactions remain in order
with their error metadata. This is the bridge format, not the Solana JSON-RPC
response format. Block reads do not require or replace an AccountsDB read.

The host must verify ledger rooting and complete metadata before returning
success. Unavailable, unrooted, incomplete and hash-mismatched blocks have
distinct errors. The client cannot turn an unavailable result into an empty
block, another slot, an RPC fallback or proof of a skipped slot. All optional
metadata fields require explicit JSON null when no value is available. Blocks
use the same response byte bound and overall request deadline as account reads.

`ClientOptions` sets one timeout for connect, write and the complete response;
the default is eight seconds. It can also lower the 32 MiB response limit. There
is no unbounded connection retry. Errors retain native distinctions such as
`BankRemoved`, `StaleBank`, `SourceMismatch` and `BudgetExceeded`. Admission errors
and truncated responses cannot become missing accounts. The native host must
also enforce private socket permissions, peer checks and cleanup-safe batch reads.

An account response is a read at a Bank. It is not a historical last-write record
or an account subscription. These two libraries do not establish full account
bootstrap, continuous updates, simulation or native fork/cleanup correctness.

Run tests on Foundation with the selected host toolchain (Rust 1.98.0 in the
21 November validation). The crate minimum is Rust 1.97.1. Each crate has a standalone
`[workspace]`; generate and retain its lockfile on that host before a locked test
run. Local Unix-socket mocks cover exact source and Bank checks, parent-proof
downgrade, ordering, duplicate requests, native error codes, byte limits,
truncation and a stalled response. No live validator is needed for those tests.
Ledger mock tests also cover success and failed execution, exact slot/hash/source
admission, typed ledger errors, omitted metadata, invalid base64 and invalid
response status. These tests do not establish a live ledger's completeness.
