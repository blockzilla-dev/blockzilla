//! Discover committed direct mint initializations before processing the same block.
//!
//! Run on a published or trusted local mainnet Compact V2 epoch:
//! cargo run --release --locked -p blockzilla-compact-v2-reader --example peek_mints -- \
//!   /absolute/path/to/epoch-dir START_ROW END_ROW
//!
//! The row range is half-open. Output uses 32-byte arrays for mint public keys.
//! The example reports recorded CPI mint calls as unverified and counts
//! unexpanded Token Batch instructions. The output has one record per block.

use std::{env, path::Path};

use anyhow::{Context, Result, ensure};
use blockzilla_archive_v2::{
    ARCHIVE_V2_TX_FLAG_HAS_ERROR, ARCHIVE_V2_TX_FLAG_METADATA_RAW_FALLBACK,
    ARCHIVE_V2_TX_FLAG_TX_RAW_FALLBACK, ArchiveV2HotInstructionData, ArchiveV2HotMessagePayload,
};
use blockzilla_compact_v2_reader::{
    ArchiveReader, COMPACT_V2_CURRENT_MESSAGE_SCHEMA_MARKER_FILE,
    COMPACT_V2_LEGACY_METADATA_SCHEMA_MARKER_FILE, COMPACT_V2_MAY24_MESSAGE_SCHEMA_MARKER_FILE,
    COMPACT_V2_OPTIONAL_OBJECTS, COMPACT_V2_REQUIRED_OBJECTS, CompactPubkey, CompiledPubkeyFilter,
    CursorBlock, OpenOptions, PinnedLocalRangeSource, RangeSource, compact_v2_first_slot,
    detect_compact_v2_message_schema, detect_compact_v2_metadata_schema, mainnet_identity_for_slot,
    manifest::{GENERATION_MANIFEST_FILE, GENESIS_BIN_FILE},
};
use blockzilla_model::token::CLASSIC_SPL_TOKEN_PROGRAM_ID;
use serde::Serialize;
use serde_json::json;

// TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb
const TOKEN_2022_PROGRAM_ID: [u8; 32] = [
    6, 221, 246, 225, 238, 117, 143, 222, 24, 66, 93, 188, 228, 108, 205, 218, 182, 26, 252, 77,
    131, 185, 13, 39, 254, 189, 249, 40, 216, 161, 139, 252,
];

#[derive(Clone, Copy)]
enum TokenProgram {
    Legacy,
    Token2022,
}

const INITIALIZE_MINT: u8 = 0;
const INITIALIZE_MINT2: u8 = 20;
const TOKEN_BATCH: u8 = 255;

const PROGRAMS: [([u8; 32], TokenProgram); 2] = [
    (CLASSIC_SPL_TOKEN_PROGRAM_ID, TokenProgram::Legacy),
    (TOKEN_2022_PROGRAM_ID, TokenProgram::Token2022),
];

#[derive(Serialize)]
struct Mint {
    transaction: u32,
    instruction: u32,
    program: &'static str,
    address: [u8; 32],
    decimals: u8,
}

#[derive(Default, Serialize)]
struct MintDiscovery {
    committed: Vec<Mint>,
    // Each position contains the transaction, outer instruction and inner instruction indices.
    unverified_cpi: Vec<(u32, u32, usize)>,
    transactions_with_unavailable_data: usize,
    transactions_without_cpi_recording: usize,
    unexpanded_batches: usize,
}

fn open_archive(path: &Path) -> Result<ArchiveReader<PinnedLocalRangeSource>> {
    let names: Vec<_> = COMPACT_V2_REQUIRED_OBJECTS
        .into_iter()
        .chain(COMPACT_V2_OPTIONAL_OBJECTS)
        .chain([
            GENESIS_BIN_FILE,
            GENERATION_MANIFEST_FILE,
            COMPACT_V2_CURRENT_MESSAGE_SCHEMA_MARKER_FILE,
            COMPACT_V2_MAY24_MESSAGE_SCHEMA_MARKER_FILE,
            COMPACT_V2_LEGACY_METADATA_SCHEMA_MARKER_FILE,
        ])
        .collect();
    let source = PinnedLocalRangeSource::new_anchored(path, &names)?;
    let options = OpenOptions::default();
    if source.size(GENERATION_MANIFEST_FILE)?.is_some() {
        return Ok(ArchiveReader::open_with_options(source, options)?);
    }
    let slot = compact_v2_first_slot(&source)?.context("archive index is empty")?;
    let identity = mainnet_identity_for_slot(slot, "local-peek-mints")?;
    let message_schema =
        detect_compact_v2_message_schema(&source, identity.epoch, &identity.cluster_id)?;
    let metadata_schema = detect_compact_v2_metadata_schema(&source)?;
    Ok(ArchiveReader::open_pinned_with_schemas(
        source,
        identity,
        options,
        message_schema,
        metadata_schema,
    )?)
}

fn token_program(
    filter: &CompiledPubkeyFilter,
    keys: &[CompactPubkey],
    program_index: usize,
) -> Result<Option<TokenProgram>> {
    let reference = keys
        .get(program_index)
        .context("program index is outside the resolved transaction accounts")?;
    Ok(PROGRAMS
        .iter()
        .find_map(|(key, program)| filter.matches_reference(reference, key).then_some(*program)))
}

fn is_mint_init(data: &[u8]) -> bool {
    matches!(
        data.first().copied(),
        Some(INITIALIZE_MINT | INITIALIZE_MINT2)
    )
}

// This example only needs the shared InitializeMint/InitializeMint2 layout.
// The enclosing transaction must have succeeded before this is used as a fact.
fn mint_decimals(data: &[u8]) -> Result<u8> {
    ensure!(is_mint_init(data), "not a mint initialization");
    let decimals = *data.get(1).context("mint decimals are missing")?;
    match data.get(34) {
        Some(0) => {}
        Some(1) => ensure!(data.len() >= 67, "mint freeze authority is truncated"),
        _ => anyhow::bail!("mint freeze authority option is invalid"),
    }
    Ok(decimals)
}

fn discover(
    reader: &ArchiveReader<PinnedLocalRangeSource>,
    filter: &CompiledPubkeyFilter,
    block: &CursorBlock<'_>,
) -> Result<MintDiscovery> {
    let mut facts = MintDiscovery::default();
    for tx in block.block.transactions() {
        let tx = tx?;
        if tx.metadata_bytes.is_empty()
            || tx.row.flags
                & (ARCHIVE_V2_TX_FLAG_TX_RAW_FALLBACK | ARCHIVE_V2_TX_FLAG_METADATA_RAW_FALLBACK)
                != 0
        {
            facts.transactions_with_unavailable_data += 1;
            continue;
        }
        // A production scanner can skip owned decoding when a compact program
        // and CPI prefilter proves that this transaction cannot invoke Token.
        let meta = reader.decode_metadata(tx.metadata_bytes)?;
        ensure!(
            meta.err.is_some() == (tx.row.flags & ARCHIVE_V2_TX_FLAG_HAS_ERROR != 0),
            "transaction outcome differs from its row flags"
        );
        if meta.err.is_some() {
            continue;
        }

        let (mut keys, instructions, writable_count, readonly_count) = match reader
            .decode_message(tx.message_bytes)?
        {
            ArchiveV2HotMessagePayload::Legacy(msg) => (msg.account_keys, msg.instructions, 0, 0),
            ArchiveV2HotMessagePayload::V0(msg) => {
                let writable = msg
                    .address_table_lookups
                    .iter()
                    .map(|l| l.writable_indexes.len())
                    .sum();
                let readonly = msg
                    .address_table_lookups
                    .iter()
                    .map(|l| l.readonly_indexes.len())
                    .sum();
                (msg.account_keys, msg.instructions, writable, readonly)
            }
            ArchiveV2HotMessagePayload::V1(msg) => (msg.account_keys, msg.instructions, 0, 0),
        };
        ensure!(
            meta.loaded_writable_addresses.len() == writable_count
                && meta.loaded_readonly_addresses.len() == readonly_count,
            "loaded accounts differ from message lookup counts"
        );
        keys.extend(meta.loaded_writable_addresses);
        keys.extend(meta.loaded_readonly_addresses);

        for (index, instruction) in instructions.iter().enumerate() {
            let Some(program) =
                token_program(filter, &keys, usize::from(instruction.program_id_index))?
            else {
                continue;
            };
            let ArchiveV2HotInstructionData::Raw(data) = &instruction.data else {
                anyhow::bail!("token instruction payload is not raw");
            };
            if data.first() == Some(&TOKEN_BATCH) {
                facts.unexpanded_batches += 1;
                continue;
            }
            if !is_mint_init(data) {
                continue;
            }
            let accounts = instruction
                .accounts
                .iter()
                .map(|&index| {
                    let reference = keys
                        .get(usize::from(index))
                        .context("invalid mint account index")?;
                    Ok(reader.resolve_pubkey(reference)?)
                })
                .collect::<Result<Vec<_>>>()?;
            let index = u32::try_from(index)?;
            let address = *accounts.first().context("mint account is missing")?;
            facts.committed.push(Mint {
                transaction: tx.row.tx_index,
                instruction: index,
                program: match program {
                    TokenProgram::Legacy => "spl-token",
                    TokenProgram::Token2022 => "token-2022",
                },
                address,
                decimals: mint_decimals(data)?,
            });
        }

        let Some(inner_groups) = &meta.inner_instructions else {
            facts.transactions_without_cpi_recording += 1;
            continue;
        };
        for group in inner_groups {
            for (index, instruction) in group.instructions.iter().enumerate() {
                if token_program(
                    filter,
                    &keys,
                    usize::try_from(instruction.program_id_index)?,
                )?
                .is_some()
                {
                    if instruction.data.first() == Some(&TOKEN_BATCH) {
                        facts.unexpanded_batches += 1;
                    } else if is_mint_init(&instruction.data) {
                        facts
                            .unverified_cpi
                            .push((tx.row.tx_index, group.index, index));
                    }
                }
            }
        }
    }
    Ok(facts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_layout_accepts_both_tags_and_checks_freeze_authority() {
        for tag in [INITIALIZE_MINT, INITIALIZE_MINT2] {
            let mut data = vec![0; 35];
            data[0] = tag;
            data[1] = 9;
            assert_eq!(mint_decimals(&data).unwrap(), 9);
            data[34] = 1;
            assert!(mint_decimals(&data).is_err());
            data.resize(67, 3);
            assert_eq!(mint_decimals(&data).unwrap(), 9);
            data[34] = 2;
            assert!(mint_decimals(&data).is_err());
        }
        assert!(!is_mint_init(&[]));
        assert!(!is_mint_init(&[TOKEN_BATCH]));
    }
}

fn main() -> Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    let [path, start, end] = args.as_slice() else {
        anyhow::bail!("usage: peek_mints EPOCH_DIR START_ROW END_ROW");
    };
    let reader = open_archive(&Path::new(path).canonicalize()?)?;
    let filter = reader.compile_pubkey_filter(PROGRAMS.map(|(key, _)| key))?;
    let mut cursor = reader.block_cursor(start.parse()?..end.parse()?)?;
    while cursor
        .next_block_with_discovery(
            |block| discover(&reader, &filter, block),
            |block, facts| {
                // Install rules for facts.committed before visiting the transactions again.
                // Keep the creation coordinates if a rule only applies from creation onward.
                reader.source().verify_unchanged()?;
                println!(
                    "{}",
                    json!({"row": block.row, "slot": block.block.header().slot,
                        "transactions": block.block.tx_count(), "mint_discovery": facts})
                );
                Ok(())
            },
        )?
        .is_some()
    {}
    Ok(())
}
