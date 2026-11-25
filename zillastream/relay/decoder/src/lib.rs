//! Portable reader for the current, operator-trusted native projection.
//! Transport admission and SHA-256 checks belong to the JavaScript source.
//! The existing Rust schemas, rather than a second codec, decode the payload.
use anyhow::{Context, Result, ensure};
use blockzilla_archive_v2::*;
use blockzilla_compact::CompactMetaV1;
use blockzilla_primitives::{CompactPubkey, bounded_historical_source_wincode_leb128_config};
use ruzstd::decoding::StreamingDecoder;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    borrow::Cow,
    collections::{BTreeSet, HashMap},
    io::{Read, Write},
};

const MAX_FRAME: usize = 16 * 1024 * 1024 + 65_536 + 16;
const MAX_BLOCK: usize = 64 * 1024 * 1024;
const MAX_OUTPUT: usize = 32 * 1024 * 1024;
const MAX_TX: usize = 65_536;
const MAX_PORTABLE_FILTER_KEYS: usize = 256;
#[cfg(not(target_arch = "wasm32"))]
const MAX_LOCAL_FILTER_KEYS: usize = 4096;
const SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    #[serde(default)]
    pub programs: Vec<String>,
    #[serde(default)]
    pub accounts: Vec<String>,
    #[serde(default)]
    pub successful_only: bool,
    #[serde(default = "yes")]
    pub include_details: bool,
}
fn yes() -> bool {
    true
}
impl Default for Options {
    fn default() -> Self {
        Self {
            programs: vec![],
            accounts: vec![],
            successful_only: false,
            include_details: true,
        }
    }
}

struct Filter {
    programs: BTreeSet<[u8; 32]>,
    accounts: BTreeSet<[u8; 32]>,
    successful_only: bool,
}
impl Filter {
    fn new(o: &Options, max_keys: usize) -> Result<Self> {
        fn keys(values: &[String], max_keys: usize) -> Result<BTreeSet<[u8; 32]>> {
            ensure!(values.len() <= max_keys, "too_many_filter_keys");
            values
                .iter()
                .map(|s| {
                    ensure!(s.len() <= 44, "invalid_filter_key");
                    let key: [u8; 32] = bs58::decode(s)
                        .into_vec()?
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("invalid_filter_key"))?;
                    ensure!(bs58::encode(key).into_string() == *s, "invalid_filter_key");
                    Ok(key)
                })
                .collect()
        }
        Ok(Self {
            programs: keys(&o.programs, max_keys)?,
            accounts: keys(&o.accounts, max_keys)?,
            successful_only: o.successful_only,
        })
    }
}

#[derive(Deserialize)]
struct Object {
    path: String,
    offset: usize,
    bytes: usize,
}
#[derive(Deserialize)]
struct Envelope {
    profile: String,
    #[serde(default)]
    event: Option<Value>,
    marker: Marker,
    objects: Vec<Object>,
}
#[derive(Deserialize)]
struct Marker {
    epoch: u64,
    session_id: String,
    finalized: bool,
    canonical: bool,
    publication_ready: bool,
    produced_blocks: Vec<Identity>,
}
#[derive(Deserialize)]
struct Identity {
    #[serde(default)]
    bank_id: u64,
    block_id: u32,
    slot: u64,
    parent_slot: u64,
    blockhash: [u8; 32],
    parent_blockhash: [u8; 32],
}

#[derive(Clone, Copy)]
struct IndexRow {
    block_id: u32,
    slot: u64,
    offset: usize,
    compressed: usize,
    uncompressed: usize,
    transactions: usize,
    first_tx: usize,
    first_signature: usize,
    signatures: usize,
}
fn u32_at(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(at..at + 4)
            .context("truncated_index")?
            .try_into()?,
    ))
}
fn u64_at(bytes: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(at..at + 8)
            .context("truncated_index")?
            .try_into()?,
    ))
}
fn index(bytes: &[u8], blob_len: usize) -> Result<(u32, Vec<IndexRow>)> {
    ensure!(
        bytes.get(..8) == Some(b"BZV2HIX1"),
        "invalid_hot_index_magic"
    );
    ensure!(
        bytes.get(8..12) == Some(&[1, 0, 0, 0]),
        "unsupported_hot_index_version"
    );
    let n = usize::try_from(u64_at(bytes, 12)?)?;
    ensure!(
        (1..=32).contains(&n) && bytes.len() == 36 + n * 52,
        "invalid_hot_index_length"
    );
    ensure!(
        u64_at(bytes, 20)? == blob_len as u64,
        "hot_blob_length_mismatch"
    );
    let flags = u32_at(bytes, 32)?;
    ensure!(
        flags == 0 || flags == 2,
        "unsupported_zstd_dictionary_or_flags"
    );
    let mut rows = Vec::with_capacity(n);
    let (mut offset, mut tx, mut sig) = (0, 0, 0);
    for b in bytes[36..].chunks_exact(52) {
        let r = IndexRow {
            block_id: u32_at(b, 0)?,
            slot: u64_at(b, 4)?,
            offset: usize::try_from(u64_at(b, 12)?)?,
            compressed: u32_at(b, 20)? as usize,
            uncompressed: u32_at(b, 24)? as usize,
            transactions: u32_at(b, 28)? as usize,
            first_tx: usize::try_from(u64_at(b, 32)?)?,
            first_signature: usize::try_from(u64_at(b, 40)?)?,
            signatures: u32_at(b, 48)? as usize,
        };
        ensure!(
            r.block_id as usize == rows.len()
                && r.offset == offset
                && r.first_tx == tx
                && r.first_signature == sig,
            "non_contiguous_hot_index"
        );
        ensure!(
            r.compressed > 0
                && r.uncompressed > 0
                && r.uncompressed <= MAX_BLOCK
                && r.transactions <= MAX_TX,
            "block_limit_exceeded"
        );
        offset = offset.checked_add(r.compressed).context("index_overflow")?;
        tx = tx.checked_add(r.transactions).context("index_overflow")?;
        sig = sig.checked_add(r.signatures).context("index_overflow")?;
        ensure!(offset <= blob_len, "hot_range_outside_blob");
        rows.push(r);
    }
    ensure!(offset == blob_len, "unindexed_hot_bytes");
    Ok((flags, rows))
}
fn hot_block_bytes<'a>(blob: &'a [u8], flags: u32, row: &IndexRow) -> Result<Cow<'a, [u8]>> {
    let input = &blob[row.offset..row.offset + row.compressed];
    let decoded = if flags == 2 {
        Cow::Borrowed(input)
    } else {
        let mut decoded = Vec::with_capacity(row.uncompressed.min(1_048_576));
        let mut zstd = StreamingDecoder::new(input).context("zstd_header")?;
        (&mut zstd)
            .take(row.uncompressed as u64 + 1)
            .read_to_end(&mut decoded)
            .context("zstd_decode")?;
        ensure!(zstd.into_inner().is_empty(), "trailing_zstd_bytes");
        Cow::Owned(decoded)
    };
    ensure!(
        decoded.len() == row.uncompressed,
        "decoded_block_length_mismatch"
    );
    Ok(decoded)
}
fn hot_block<'a>(
    bytes: &'a [u8],
    row: &IndexRow,
    parent_slot: u64,
) -> Result<BorrowedArchiveV2HotBlockBlob<'a>> {
    let block = deserialize_archive_v2_hot_block_blob_borrowed_current_with_preallocation_limit::<
        1_048_576,
    >(bytes)?;
    ensure!(
        block.header.slot == row.slot
            && block.header.parent_slot == parent_slot
            && block.tx_count as usize == row.transactions
            && block.tx_rows_len() == row.transactions,
        "decoded_block_identity_mismatch"
    );
    ensure!(
        block.header.blockhash_id == row.block_id
            && block.header.previous_blockhash_id == row.block_id.saturating_sub(1),
        "native_blockhash_id_mismatch"
    );
    Ok(block)
}
fn validate_transaction_row(row: &ArchiveV2HotTxRow, index: usize) -> Result<()> {
    ensure!(
        row.tx_index as usize == index && row.reserved == [0; 3] && row.flags & !2047 == 0,
        "invalid_transaction_row"
    );
    ensure!(
        row.flags & (ARCHIVE_V2_TX_FLAG_TX_RAW_FALLBACK | ARCHIVE_V2_TX_FLAG_METADATA_RAW_FALLBACK)
            == 0,
        "raw_fallback_not_supported"
    );
    Ok(())
}
fn take_signatures<'a>(signatures: &'a [u8], at: &mut usize, count: u8) -> Result<&'a [u8]> {
    let end = at
        .checked_add(usize::from(count) * 64)
        .context("signature_overflow")?;
    let sig = signatures.get(*at..end).context("signature_outside_file")?;
    *at = end;
    Ok(sig)
}
fn key(k: &CompactPubkey, registry: &[u8]) -> Result<[u8; 32]> {
    match k {
        CompactPubkey::Raw(k) => Ok(*k),
        CompactPubkey::Id(id) => {
            ensure!(*id > 0, "zero_registry_id");
            let at = (*id as usize - 1)
                .checked_mul(32)
                .context("registry_overflow")?;
            Ok(registry
                .get(at..at + 32)
                .context("registry_id_outside_dictionary")?
                .try_into()?)
        }
    }
}
fn base58(k: &[u8]) -> String {
    bs58::encode(k).into_string()
}
fn exact<
    'a,
    T: wincode::SchemaRead<
            'a,
            blockzilla_primitives::BoundedHistoricalSourceWincodeLeb128Config<1_048_576>,
            Dst = T,
        >,
>(
    bytes: &'a [u8],
) -> Result<T> {
    Ok(wincode::config::deserialize_exact::<T, _>(
        bytes,
        bounded_historical_source_wincode_leb128_config::<1_048_576>(),
    )?)
}

/// Return semantic compact values. This is not an RPC JSON or exact signed-wire renderer.
pub fn decode(wire: &[u8], options: &Options) -> Result<Vec<u8>> {
    encode_projection(&decode_projection(wire, options, false, false, None, None, MAX_PORTABLE_FILTER_KEYS)?)
}

/// Typed semantic admission for an original native Bank payload. It uses the
/// same bounded message/metadata walker as the portable renderer, without
/// generating base58 strings, transaction JSON, or serialized projection bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BankPayloadSummary {
    pub transactions: usize,
    pub successful: usize,
    pub failed: usize,
    pub execution_unavailable: usize,
    pub signatures: usize,
}
pub fn validate_bank_payload(
    frame: &blockzilla_bank_stream_v2::Frame,
) -> Result<BankPayloadSummary> {
    let admitted = blockzilla_bank_stream_v2::decode(frame.wire.clone())?;
    ensure!(
        admitted.sha256 == frame.sha256
            && admitted.cursor == frame.cursor
            && admitted.source == frame.source
            && admitted.envelope.event == frame.envelope.event,
        "payload_frame_mismatch"
    );
    ensure!(
        admitted.envelope.event.kind == "block",
        "bank_block_required"
    );
    let mut summary = BankPayloadSummary::default();
    decode_projection(
        &frame.wire,
        &Options::default(),
        false,
        true,
        Some(&mut summary),
        None,
        MAX_PORTABLE_FILTER_KEYS,
    )?;
    Ok(summary)
}

/// Successful native transaction signer/program facts from the existing typed
/// semantic walker. This does not expand instruction bytes, logs or JSON keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BankWalletPrograms {
    pub signers: Vec<[u8; 32]>,
    pub programs: Vec<[u8; 32]>,
}

pub fn bank_wallet_programs(
    frame: &blockzilla_bank_stream_v2::Frame,
) -> Result<(BankPayloadSummary, Vec<BankWalletPrograms>)> {
    let admitted = blockzilla_bank_stream_v2::decode(frame.wire.clone())?;
    ensure!(
        admitted.sha256 == frame.sha256
            && admitted.cursor == frame.cursor
            && admitted.source == frame.source
            && admitted.envelope.event == frame.envelope.event,
        "payload_frame_mismatch"
    );
    ensure!(
        admitted.envelope.event.kind == "block",
        "bank_block_required"
    );
    let mut summary = BankPayloadSummary::default();
    let mut wallets = Vec::new();
    decode_projection(
        &frame.wire,
        &Options {
            include_details: false,
            ..Options::default()
        },
        false,
        true,
        Some(&mut summary),
        Some(&mut wallets),
        MAX_PORTABLE_FILTER_KEYS,
    )?;
    Ok((summary, wallets))
}

/// Opt-in v2 entry point. Controls carry identity and native expiry, never a
/// second block. The v1 entry points continue to reject this profile.
pub fn decode_banks(wire: &[u8], options: &Options) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&decode_bank_value(wire, options, MAX_PORTABLE_FILTER_KEYS)?)?)
}

/// Project a Bank for a trusted local caller with a larger, bounded filter.
/// The caller must bound serialized output before exporting or storing it.
#[cfg(not(target_arch = "wasm32"))]
pub fn decode_banks_local(wire: &[u8], options: &Options) -> Result<Value> {
    decode_bank_value(wire, options, MAX_LOCAL_FILTER_KEYS)
}

fn decode_bank_value(wire: &[u8], options: &Options, max_keys: usize) -> Result<Value> {
    let frame = blockzilla_bank_stream_v2::decode(wire.to_vec().into())?;
    if frame.envelope.event.kind != "block" {
        return Ok(json!({"profile":frame.envelope.profile,"event":frame.envelope.event}));
    }
    let mut value = decode_projection(wire, options, false, true, None, None, max_keys)?;
    if max_keys == MAX_PORTABLE_FILTER_KEYS {
        encode_projection(&value)?;
    }
    ensure!(
        value["blocks"].as_array().is_some_and(|b| b.len() == 1)
            && value["blocks"][0]["blockHeight"]
                == frame
                    .envelope
                    .event
                    .block_height
                    .context("missing_height")?,
        "native_payload_height_mismatch"
    );
    value["event"] = serde_json::to_value(&frame.envelope.event)?;
    Ok(value)
}

/// Project the first signature of each transaction in an admitted v2 block.
/// The caller supplies a frame from v2 transport admission. Transaction order
/// and signature counts come from the compact rows, without expanding messages
/// or metadata. Controls do not carry signatures.
pub fn bank_first_signatures(frame: &blockzilla_bank_stream_v2::Frame) -> Result<Vec<[u8; 64]>> {
    let envelope = &frame.envelope;
    let event = &envelope.event;
    let bank = &event.bank;
    ensure!(
        envelope.profile == blockzilla_bank_stream_v2::PROFILE && event.kind == "block",
        "bank_block_required"
    );
    ensure!(
        blockzilla_bank_stream_v2::frame_length(&frame.wire)? == frame.wire.len(),
        "invalid_transport_length"
    );
    let meta = u32_at(&frame.wire, 8)? as usize;
    let payload = frame
        .wire
        .get(16 + meta..)
        .context("invalid_transport_length")?;
    let object = |name: &str| -> Result<&[u8]> {
        let entry = envelope
            .objects
            .iter()
            .find(|entry| entry.path == name)
            .with_context(|| format!("missing_object:{name}"))?;
        let end = entry
            .offset
            .checked_add(entry.bytes)
            .context("object_overflow")?;
        payload
            .get(entry.offset..end)
            .context("object_outside_payload")
    };
    let blob = object("archive-v2-blocks.zstd")?;
    let (flags, rows) = index(object("archive-v2-blocks.index")?, blob.len())?;
    let [row] = rows.as_slice() else {
        anyhow::bail!("one_bank_required");
    };
    ensure!(
        row.slot == bank.slot && envelope.marker["produced_blocks"][0]["block_id"] == row.block_id,
        "index_identity_mismatch"
    );
    let parent = object("prev_blockhash_tail.bin")?;
    ensure!(
        object("blockhash_registry.bin")? == bank.blockhash
            && parent.len() == 40
            && parent[..32] == bank.parent_blockhash
            && u64_at(parent, 32)? == bank.parent_slot,
        "native_blockhash_mismatch"
    );
    let signatures = object("signatures.bin")?;
    ensure!(
        signatures.len().is_multiple_of(64) && signatures.len() / 64 == row.signatures,
        "signature_file_count_mismatch"
    );
    let bytes = hot_block_bytes(blob, flags, row)?;
    let block = hot_block(&bytes, row, bank.parent_slot)?;
    ensure!(
        block.header.block_height == event.block_height,
        "native_payload_height_mismatch"
    );
    let mut first = Vec::with_capacity(row.transactions);
    let mut at = 0;
    for (index, tx) in block.tx_rows().enumerate() {
        validate_transaction_row(&tx, index)?;
        ensure!(tx.signature_count > 0, "missing_transaction_signature");
        let transaction_signatures = take_signatures(signatures, &mut at, tx.signature_count)?;
        first.push(transaction_signatures[..64].try_into()?);
    }
    ensure!(at == signatures.len(), "signature_file_count_mismatch");
    Ok(first)
}

/// Native consumer projection. Uses the same typed metadata and key resolver,
/// and emits exact recorded token balances without expanding messages or logs.
#[cfg(not(target_arch = "wasm32"))]
pub fn decode_token_balances(wire: &[u8]) -> Result<Vec<u8>> {
    encode_projection(&decode_projection(
        wire,
        &Options {
            include_details: false,
            ..Options::default()
        },
        true,
        false,
        None,
        None,
        MAX_PORTABLE_FILTER_KEYS,
    )?)
}

fn decode_projection(
    wire: &[u8],
    options: &Options,
    token_only: bool,
    bank_v2: bool,
    mut validation: Option<&mut BankPayloadSummary>,
    mut wallets: Option<&mut Vec<BankWalletPrograms>>,
    max_filter_keys: usize,
) -> Result<Value> {
    let validation_only = validation.is_some() || wallets.is_some();
    let mut wallet_fact_keys = 0usize;
    ensure!(
        wire.len() >= 16 && wire.len() <= MAX_FRAME && &wire[..8] == b"BZSTRM01",
        "invalid_transport_frame"
    );
    let meta = u32_at(wire, 8)? as usize;
    let payload_len = u32_at(wire, 12)? as usize;
    ensure!(
        meta > 0 && meta <= 65_536 && wire.len() == 16 + meta + payload_len,
        "invalid_transport_length"
    );
    let e: Envelope = serde_json::from_slice(&wire[16..16 + meta])?;
    ensure!(
        !token_only || (e.profile == "native-compact-projection-v1" && e.marker.finalized),
        "processed_token_index_requires_fork_undo"
    );
    ensure!(
        ((e.profile == "native-compact-projection-v1" && e.marker.finalized)
            || (e.profile == "native-processed-compact-v1"
                && !e.marker.finalized
                && e.event.as_ref().is_some_and(|v| v["kind"] == "block"))
            || (bank_v2
                && e.profile == "native-bank-compact-v2"
                && !e.marker.finalized
                && e.event.as_ref().is_some_and(|v| v["kind"] == "block")))
            && !e.marker.canonical
            && !e.marker.publication_ready,
        "unsupported_projection"
    );
    let payload = &wire[16 + meta..];
    let object = |name: &str| -> Result<&[u8]> {
        let mut matches = e.objects.iter().filter(|o| o.path == name);
        let o = matches
            .next()
            .with_context(|| format!("missing_object:{name}"))?;
        ensure!(matches.next().is_none(), "duplicate_object");
        let end = o.offset.checked_add(o.bytes).context("object_overflow")?;
        payload.get(o.offset..end).context("object_outside_payload")
    };
    let blob = object("archive-v2-blocks.zstd")?;
    let (flags, rows) = index(object("archive-v2-blocks.index")?, blob.len())?;
    let registry = object("registry.bin")?;
    let blockhashes = object("blockhash_registry.bin")?;
    let parent_tail = object("prev_blockhash_tail.bin")?;
    let signatures = object("signatures.bin")?;
    ensure!(
        registry.len().is_multiple_of(32)
            && blockhashes.len().is_multiple_of(32)
            && signatures.len().is_multiple_of(64),
        "invalid_dictionary_or_signatures"
    );
    ensure!(
        rows.len() == e.marker.produced_blocks.len(),
        "block_identity_count_mismatch"
    );
    // Native batches use produced-only zero-based hashes. The first predecessor
    // is the separate hash+slot tail, not a boundary prefix in this registry.
    ensure!(
        blockhashes.len() == rows.len() * 32 && parent_tail.len() == 40,
        "invalid_native_blockhash_layout"
    );
    ensure!(
        parent_tail[..32] == e.marker.produced_blocks[0].parent_blockhash
            && u64_at(parent_tail, 32)? == e.marker.produced_blocks[0].parent_slot,
        "native_parent_tail_mismatch"
    );
    let last = rows.last().unwrap();
    ensure!(
        last.first_signature + last.signatures == signatures.len() / 64,
        "signature_file_count_mismatch"
    );
    let filter = Filter::new(options, max_filter_keys)?;
    let mut blocks = Vec::with_capacity(rows.len());
    let mut total = 0;
    for (r, identity) in rows.iter().zip(&e.marker.produced_blocks) {
        ensure!(
            r.slot <= SAFE_INTEGER && r.slot == identity.slot && r.block_id == identity.block_id,
            "index_identity_mismatch"
        );
        let decoded = hot_block_bytes(blob, flags, r)?;
        let block = hot_block(&decoded, r, identity.parent_slot)?;
        if bank_v2 {
            ensure!(
                block.header.block_height
                    == e.event
                        .as_ref()
                        .and_then(|event| event["block_height"].as_u64()),
                "native_payload_height_mismatch"
            );
        }
        let start = r.block_id as usize * 32;
        ensure!(
            blockhashes.get(start..start + 32) == Some(identity.blockhash.as_slice()),
            "decoded_blockhash_mismatch"
        );
        if r.block_id > 0 {
            ensure!(
                blockhashes.get(start - 32..start) == Some(identity.parent_blockhash.as_slice()),
                "decoded_parent_blockhash_mismatch"
            );
        }
        let mut transactions = Vec::new();
        let mut encoded_keys = HashMap::<[u8; 32], String>::new();
        let mut encode_key = |key: &[u8; 32]| {
            encoded_keys.entry(*key).or_insert_with(|| base58(key)).clone()
        };
        let mut signature_at = r.first_signature * 64;
        let mut message_at = 0usize;
        let mut metadata_at = 0usize;
        for (tx_index, row) in block.tx_rows().enumerate() {
            validate_transaction_row(&row, tx_index)?;
            ensure!(
                row.message_offset as usize == message_at
                    && row.metadata_offset as usize == metadata_at,
                "non_contiguous_transaction_regions"
            );
            message_at = message_at
                .checked_add(row.message_len as usize)
                .context("message_overflow")?;
            metadata_at = metadata_at
                .checked_add(row.metadata_len as usize)
                .context("metadata_overflow")?;
            let message: ArchiveV2HotMessagePayload = exact(
                block
                    .message_bytes
                    .get(row.message_offset as usize..message_at)
                    .context("message_outside_block")?,
            )?;
            let metadata: Option<CompactMetaV1> =
                if row.flags & ARCHIVE_V2_TX_FLAG_HAS_METADATA != 0 {
                    Some(exact(
                        block
                            .metadata_bytes
                            .get(row.metadata_offset as usize..metadata_at)
                            .context("metadata_outside_block")?,
                    )?)
                } else {
                    ensure!(
                        row.metadata_len == 0 && row.flags & ARCHIVE_V2_TX_FLAG_HAS_ERROR == 0,
                        "missing_metadata"
                    );
                    None
                };
            let (header, static_keys, instructions, expected_loaded, is_v0) = match &message {
                ArchiveV2HotMessagePayload::Legacy(m) => {
                    (&m.header, &m.account_keys, &m.instructions, (0, 0), false)
                }
                ArchiveV2HotMessagePayload::V0(m) => (
                    &m.header,
                    &m.account_keys,
                    &m.instructions,
                    (
                        m.address_table_lookups
                            .iter()
                            .map(|l| l.writable_indexes.len())
                            .sum(),
                        m.address_table_lookups
                            .iter()
                            .map(|l| l.readonly_indexes.len())
                            .sum(),
                    ),
                    true,
                ),
                ArchiveV2HotMessagePayload::V1(m) => {
                    (&m.header, &m.account_keys, &m.instructions, (0, 0), false)
                }
            };
            ensure!(
                header.num_required_signatures == row.signature_count
                    && row.signature_count > 0
                    && usize::from(row.signature_count) <= static_keys.len(),
                "signature_header_mismatch"
            );
            ensure!(
                header.num_readonly_signed_accounts <= header.num_required_signatures
                    && usize::from(header.num_readonly_unsigned_accounts)
                        <= static_keys.len() - usize::from(header.num_required_signatures),
                "invalid_account_header"
            );
            ensure!(
                is_v0 == (row.flags & ARCHIVE_V2_TX_FLAG_MESSAGE_V0 != 0),
                "message_version_flag_mismatch"
            );
            ensure!(
                (expected_loaded != (0, 0))
                    == (row.flags & ARCHIVE_V2_TX_FLAG_HAS_LOADED_ADDRESSES != 0),
                "loaded_address_flag_mismatch"
            );
            let mut accounts = static_keys
                .iter()
                .map(|k| key(k, registry))
                .collect::<Result<Vec<_>>>()?;
            if let Some(m) = &metadata {
                ensure!(
                    (
                        m.loaded_writable_addresses.len(),
                        m.loaded_readonly_addresses.len()
                    ) == expected_loaded,
                    "loaded_address_count_mismatch"
                );
                ensure!(
                    m.err.is_some() == (row.flags & ARCHIVE_V2_TX_FLAG_HAS_ERROR != 0),
                    "execution_status_flag_mismatch"
                );
                ensure!(
                    m.inner_instructions.is_some()
                        == (row.flags & ARCHIVE_V2_TX_FLAG_HAS_INNER_IX != 0),
                    "inner_instruction_flag_mismatch"
                );
                for k in m
                    .loaded_writable_addresses
                    .iter()
                    .chain(&m.loaded_readonly_addresses)
                {
                    accounts.push(key(k, registry)?);
                }
            } else {
                ensure!(expected_loaded == (0, 0), "loaded_addresses_unavailable");
            }
            ensure!(
                accounts.len() <= 256 && instructions.len() <= 65_536,
                "transaction_limit_exceeded"
            );
            if let Some(m) = &metadata {
                ensure!(
                    m.pre_balances.len() == accounts.len()
                        && m.post_balances.len() == accounts.len(),
                    "balance_account_count_mismatch"
                );
                for balance in m.pre_token_balances.iter().chain(&m.post_token_balances) {
                    ensure!(
                        (balance.account_index as usize) < accounts.len(),
                        "invalid_token_account_index"
                    );
                    for reference in [&balance.mint, &balance.owner, &balance.program_id]
                        .into_iter()
                        .flatten()
                    {
                        key(reference, registry)?;
                    }
                }
                for reward in &m.rewards {
                    key(&reward.pubkey, registry)?;
                }
                if let Some(return_data) = &m.return_data {
                    key(&return_data.program_id, registry)?;
                }
            }
            if let ArchiveV2HotMessagePayload::V0(message) = &message {
                for lookup in &message.address_table_lookups {
                    key(&lookup.account_key, registry)?;
                }
            }
            let mut top = BTreeSet::new();
            let mut inner = BTreeSet::new();
            for ix in instructions {
                top.insert(
                    *accounts
                        .get(ix.program_id_index as usize)
                        .context("invalid_program_index")?,
                );
                ensure!(
                    ix.accounts.iter().all(|i| (*i as usize) < accounts.len()),
                    "invalid_instruction_account_index"
                );
            }
            if let Some(groups) = metadata
                .as_ref()
                .and_then(|m| m.inner_instructions.as_ref())
            {
                for group in groups {
                    ensure!(
                        (group.index as usize) < instructions.len(),
                        "invalid_inner_instruction_group"
                    );
                    for ix in &group.instructions {
                        inner.insert(
                            *accounts
                                .get(ix.program_id_index as usize)
                                .context("invalid_cpi_program_index")?,
                        );
                        ensure!(
                            ix.accounts.iter().all(|i| (*i as usize) < accounts.len()),
                            "invalid_cpi_account_index"
                        );
                    }
                }
            }
            let success = metadata.as_ref().map(|m| m.err.is_none());
            let sig = take_signatures(signatures, &mut signature_at, row.signature_count)?;
            if let Some(summary) = validation.as_deref_mut() {
                summary.transactions += 1;
                summary.signatures += usize::from(row.signature_count);
                match success {
                    Some(true) => summary.successful += 1,
                    Some(false) => summary.failed += 1,
                    None => summary.execution_unavailable += 1,
                }
            }
            if let Some(wallets) = wallets.as_deref_mut() {
                if success == Some(true) {
                    let keys = usize::from(header.num_required_signatures)
                        .checked_add(top.union(&inner).count())
                        .context("wallet_fact_count_overflow")?;
                    wallet_fact_keys = wallet_fact_keys.checked_add(keys)
                        .context("wallet_fact_count_overflow")?;
                    ensure!(wallet_fact_keys <= 1_048_576, "wallet_fact_memory_limit_exceeded");
                    wallets.push(BankWalletPrograms {
                        signers: accounts[..usize::from(header.num_required_signatures)].to_vec(),
                        programs: top.union(&inner).copied().collect(),
                    });
                }
            }
            if validation_only {
                continue;
            }
            let any_filter = !filter.programs.is_empty() || !filter.accounts.is_empty();
            let matched = !any_filter
                || top
                    .iter()
                    .chain(&inner)
                    .any(|p| filter.programs.contains(p))
                || accounts.iter().any(|a| filter.accounts.contains(a));
            if !matched || (filter.successful_only && success != Some(true)) {
                continue;
            }
            let mut tx = if token_only {
                json!({"index":tx_index,"signature":base58(&sig[..64]),"success":success})
            } else {
                let signatures = sig.chunks_exact(64).map(base58).collect::<Vec<_>>();
                json!({"index":tx_index,"signature":signatures[0],"success":success,
                "innerCoverage": if metadata.as_ref().is_some_and(|m| m.inner_instructions.is_some()) {"recorded"} else {"unavailable"},
                "signatures":signatures,
                "topLevelPrograms":top.iter().map(&mut encode_key).collect::<Vec<_>>(),
                "innerPrograms":inner.iter().map(&mut encode_key).collect::<Vec<_>>()})
            };
            if token_only {
                let m = metadata.as_ref().context("token_metadata_unavailable")?;
                let mut balances = Vec::new();
                for (side, rows) in [
                    ("pre", &m.pre_token_balances),
                    ("post", &m.post_token_balances),
                ] {
                    for (index, b) in rows.iter().enumerate() {
                        let resolve = |k: &Option<CompactPubkey>| -> Result<Option<String>> {
                            k.as_ref()
                                .map(|k| key(k, registry).map(|k| base58(&k)))
                                .transpose()
                        };
                        let account = accounts
                            .get(b.account_index as usize)
                            .context("invalid_token_account_index")?;
                        balances.push(json!({"side":side,"balanceIndex":index,"accountIndex":b.account_index,
                            "account":base58(account),"mint":resolve(&b.mint)?,"owner":resolve(&b.owner)?,
                            "tokenProgram":resolve(&b.program_id)?,"amount":b.amount.to_string(),"decimals":b.decimals}));
                    }
                }
                tx["tokenBalances"] = json!(balances);
            }
            if options.include_details {
                tx["accountKeys"] = json!(accounts.iter().map(&mut encode_key).collect::<Vec<_>>());
                tx["message"] = serde_json::to_value(&message)?;
                tx["metadata"] = serde_json::to_value(&metadata)?;
            }
            if bank_v2 {
                tx["err"] = serde_json::to_value(metadata.as_ref().and_then(|m| m.err.as_ref()))?;
            }
            transactions.push(tx);
        }
        ensure!(
            signature_at == (r.first_signature + r.signatures) * 64
                && message_at == block.message_bytes.len()
                && metadata_at == block.metadata_bytes.len(),
            "transaction_regions_or_signatures_mismatch"
        );
        total += r.transactions;
        if validation_only {
            continue;
        }
        let mut result = json!({"slot":r.slot,"parentSlot":identity.parent_slot,"blockhash":base58(&identity.blockhash),
            "parentBlockhash":base58(&identity.parent_blockhash),"bankId":identity.bank_id,"finality":if e.marker.finalized {"finalized"}else{"processed"},"transactionCount":r.transactions,
            "transactions":transactions});
        if bank_v2 {
            result["blockHeight"] = json!(block.header.block_height);
        }
        blocks.push(result);
    }
    if validation_only {
        return Ok(Value::Null);
    }
    let mut value = json!({"profile":e.profile,"epoch":e.marker.epoch,"session":e.marker.session_id,
        "canonical":false,"publicationReady":false,"transactionCount":total,"blocks":blocks});
    preserve_large_integers(&mut value);
    Ok(value)
}

fn encode_projection(value: &Value) -> Result<Vec<u8>> {
    let mut out = BoundedOutput(Vec::new());
    serde_json::to_writer(&mut out, value)?;
    Ok(out.0)
}
fn preserve_large_integers(v: &mut Value) {
    match v {
        Value::Number(n)
            if n.as_u64().is_some_and(|v| v > SAFE_INTEGER)
                || n.as_i64().is_some_and(|v| v < -(SAFE_INTEGER as i64)) =>
        {
            *v = Value::String(n.to_string())
        }
        Value::Array(values) => values.iter_mut().for_each(preserve_large_integers),
        Value::Object(values) => values.values_mut().for_each(preserve_large_integers),
        _ => {}
    }
}
struct BoundedOutput(Vec<u8>);
impl Write for BoundedOutput {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if data.len() > MAX_OUTPUT.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("decoded_output_limit_exceeded"));
        }
        self.0.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// Tiny owned-buffer ABI. The SDK allocates and frees every buffer in finally.
// This needs no generated JavaScript runtime or host imports.
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn bz_alloc(len: u32) -> u32 {
    Box::into_raw(vec![0u8; len as usize].into_boxed_slice()) as *mut u8 as u32
}
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bz_free(ptr: u32, len: u32) {
    unsafe {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            ptr as *mut u8,
            len as usize,
        )));
    }
}
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bz_decode(ptr: u32, len: u32, opts_ptr: u32, opts_len: u32) -> u64 {
    let result = (|| -> Result<Vec<u8>> {
        ensure!(
            len as usize <= MAX_FRAME && opts_len <= 65_536,
            "decoder_input_limit_exceeded"
        );
        let bytes = unsafe { std::slice::from_raw_parts(ptr as *const u8, len as usize) };
        let options: Options = serde_json::from_slice(unsafe {
            std::slice::from_raw_parts(opts_ptr as *const u8, opts_len as usize)
        })?;
        decode(bytes, &options)
    })();
    let bytes =
        result.unwrap_or_else(|e| serde_json::to_vec(&json!({"error":format!("{e:#}")})).unwrap());
    let len = bytes.len() as u64;
    let ptr = Box::into_raw(bytes.into_boxed_slice()) as *mut u8 as u32;
    (len << 32) | u64::from(ptr)
}

#[cfg(test)]
mod tests;

// Separate v2 exports. The original bz_decode admission stays unchanged.
#[cfg(target_arch = "wasm32")]
fn bank_output(result: Result<Vec<u8>>) -> u64 {
    let bytes =
        result.unwrap_or_else(|e| serde_json::to_vec(&json!({"error":format!("{e:#}")})).unwrap());
    let len = bytes.len() as u64;
    let ptr = Box::into_raw(bytes.into_boxed_slice()) as *mut u8 as u32;
    (len << 32) | u64::from(ptr)
}
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bz_decode_banks(ptr: u32, len: u32, opts_ptr: u32, opts_len: u32) -> u64 {
    bank_output((|| {
        ensure!(
            len as usize <= MAX_FRAME && opts_len <= 65_536,
            "decoder_input_limit_exceeded"
        );
        let bytes = unsafe { std::slice::from_raw_parts(ptr as *const u8, len as usize) };
        let options: Options = serde_json::from_slice(unsafe {
            std::slice::from_raw_parts(opts_ptr as *const u8, opts_len as usize)
        })?;
        decode_banks(bytes, &options)
    })())
}
#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bz_validate_bank_head(
    ptr: u32,
    len: u32,
    opts_ptr: u32,
    opts_len: u32,
) -> u64 {
    bank_output((|| {
        ensure!(
            len <= 65_536 && opts_len <= 65_536,
            "head_input_limit_exceeded"
        );
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Config {
            source: blockzilla_bank_stream_v2::SourceIdentity,
            now: u64,
        }
        let config: Config = serde_json::from_slice(unsafe {
            std::slice::from_raw_parts(opts_ptr as *const u8, opts_len as usize)
        })?;
        let head: blockzilla_bank_stream_v2::Head = serde_json::from_slice(unsafe {
            std::slice::from_raw_parts(ptr as *const u8, len as usize)
        })?;
        head.validate(
            &config.source,
            config.now,
            blockzilla_bank_stream_v2::DEFAULT_MAX_LAG_MS,
        )?;
        Ok(serde_json::to_vec(&head)?)
    })())
}
