# Native account and ledger bridge protocol

This standalone Rust crate defines protocol version 1 for a private Unix socket.
It has no Agave or Agave RPC dependency. The native host owns Bank and AccountsDB
handles. The client receives owned account values and rooted ledger blocks.

Each frame contains a four-byte big-endian JSON byte length, followed by exactly
that many UTF-8 JSON bytes. Requests are limited to 16 KiB and responses to
32 MiB. One request is allowed per connection. The host must bound concurrent
requests, the complete read lifetime and response construction. The codec bounds
serialized buffers but does not implement host access control or Bank reads.

`Request` contains `version`, `request_id`, `expected_source` and `operation`.
The operation is `describe`, `get_account`, `get_multiple_accounts` or
`get_block`. An account read requires an exact `BankContext`; it has no latest-Bank mode. Multi-account reads
allow 1–100 keys. Order and duplicate keys are preserved. The whole batch must
use one frozen Bank, one ancestor set and the native cleanup guard.

`SourceIdentity` binds the host instance, genesis, node and Agave revision.
`instance_id` must contain 16–128 ASCII letters, digits, hyphens or underscores.
The host creates a new unique ID for each process instance. All public keys and
hashes are canonical base58 encodings of 32 bytes.

`BankContext.parent_blockhash` is an optional extra parent PoH constraint.
`Some(hash)` requires that exact proof. If the host cannot prove it, or it does
not match, the host returns `stale_bank`; it must not remove the constraint.
`None` explicitly omits only this constraint. The host still verifies the exact
instance, slot, Bank ID, blockhash and parent slot. The response echoes the
admitted context. It does not substitute a parent Bank state hash for PoH.

The response includes its request ID and actual source. Its outcome is either
an operation-specific result or a typed error. Errors distinguish removed
Banks, stale Banks, changed sources, exceeded budgets and invalid requests.
An internal failure is separate from an absent account. Error messages are
limited to 256 bytes and must not contain control characters or secrets.

An account contains lamports, owner, executable flag, rent epoch and canonical
base64 data, limited to 10 MiB before encoding. Integer values remain `u64`.
`AccountEntry.account: null` means the native read established absence at the
requested Bank. A missing field is rejected. A present zero-lamport account is
not converted into null by this protocol. Values contain no inferred last-write
slot, write version or transaction. The Bank context is the read context.

`get_block` contains `slot` and `expected_blockhash`. A null hash explicitly
requests the complete rooted block at that slot without an additional hash pin.
A present hash must match exactly. A missing hash field is rejected. The host
must admit only finalized ledger blocks, with complete transaction execution
metadata; a Bank account read does not supply this history. The block response
has `slot`, `blockhash`, `previous_blockhash`, `parent_slot`, `block_time`,
`block_height`, `transactions`, `rewards` and `num_partitions`.

Each transaction has canonical `transaction_base64` and typed `execution`
metadata. Transaction bytes must be nonempty. Legacy and V0 wire data retain
the 1,232-byte bound. SDK 5 V1 wire data starts with `0x81` and has a 4,096-byte
bound. The native SDK regression checks these version and size constants. A block
allows at most 100,000 transactions and remains subject to the 32 MiB response
limit. The codec checks base64 syntax and size, not transaction execution or
cryptographic signatures. The host must use its native ledger decoder.

Execution metadata keeps failures, fees, balances, inner instructions, token
balances, rewards, logs, loaded addresses, return data and compute/cost units.
Every optional field must be present as a value or explicit JSON null. Null
means unavailable for optional metadata; it is not an empty array. Optional
collection values and block rewards must be arrays when present. Loaded
addresses and return-data program IDs must be canonical public keys. Return
data must be canonical base64. Ledger errors distinguish `block_unavailable`,
`block_not_finalized`, `block_metadata_incomplete` and `block_hash_mismatch`.
A missing or pruned block is an error, not proof that the slot was skipped.
This additive operation keeps protocol version 1 and the account wire format.
It does not add the Solana JSON-RPC `getBlock` response format.

The host must protect the socket directory and socket permissions and check
peer credentials before reading requests. The operator supplies the full source
pin to the client. Describe checks that pin; it is not an automatic trust or
source-handoff operation. A network or source error never authorizes another
Bank or an RPC fallback.

Use `read_request`, `write_request`, `read_response` and `write_response` for
synchronous streams. `encode_request` and `encode_response` return bounded JSON
payloads without the length prefix. `decode_request` and `decode_response`
validate those payloads. The receiver must also call
`Response::validate_for(&request)` before using a result.

Run checks with Rust 1.97.1 or later. This crate has its own `[workspace]`.
Generate and retain its standalone lockfile before using `cargo test --locked`.
Tests cover framing, exact identity, required nulls, key order and duplicates, integer values, base64 and protocol limits. These tests
do not prove native Bank or cleanup correctness.
