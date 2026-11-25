//! Build one optional serving object from a checked, full getBlock bundle.
use anyhow::{Context, Result, anyhow, ensure};
use blockzilla_archive_v2::{
    ARCHIVE_V2_BLOCKS_FILE, ARCHIVE_V2_SIGNATURES_FILE, ARCHIVE_V2_TX_FLAG_HAS_METADATA,
    ARCHIVE_V2_TX_FLAG_METADATA_RAW_FALLBACK, ARCHIVE_V2_TX_FLAG_TX_RAW_FALLBACK,
    ArchiveV2BlockAccessBlob, ArchiveV2HotBlockBlob, ArchiveV2HotInstructionData,
    ArchiveV2HotMessagePayload, ArchiveV2VoteHashRef, BlockzillaGetBlockBlobEncoding,
    BlockzillaGetBlockBundleV1, WINCODE_BLOCKZILLA_GET_BLOCK_BUNDLE_VERSION,
    deserialize_archive_v2_hot_block_blob,
};
use blockzilla_get_block::slot_resolution::{
    LocatorV1, MESSAGE_CURRENT, MESSAGE_MAY24, METADATA_CURRENT, METADATA_LEGACY,
    NamedSourceObject, ResolutionHotRow, ResolutionV1, SourceObjectIdentity, VERSION, encode,
};
use blockzilla_primitives::{CompactPubkey, bounded_historical_source_wincode_leb128_config};
use clap::Parser;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[path = "../archive_schema.rs"]
mod archive_schema;

const MAX_BUNDLE_BYTES: usize = 32 * 1024 * 1024;

#[derive(Parser)]
#[command(about = "Build one bounded block-resolution object without changing archive objects")]
struct Args {
    #[arg(long)]
    bundle: PathBuf,
    #[arg(long)]
    descriptor: PathBuf,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    source_prefix: String,
    generation: String,
    epoch: u64,
    hot_row: ResolutionHotRow,
    message_schema: String,
    metadata_schema: String,
    objects: BTreeMap<String, SourceObjectIdentity>,
    #[serde(default)]
    parent_slot: Option<u64>,
    #[serde(default)]
    blockhash: Option<String>,
    #[serde(default)]
    previous_blockhash: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(
        !args.output.exists(),
        "output already exists: {}",
        args.output.display()
    );
    let descriptor: Descriptor =
        serde_json::from_slice(&read_bounded(&args.descriptor, 64 * 1024)?)?;
    let bundle_bytes = read_bounded(&args.bundle, MAX_BUNDLE_BYTES)?;
    let bundle: BlockzillaGetBlockBundleV1 = wincode::config::deserialize_exact(
        &bundle_bytes,
        bounded_historical_source_wincode_leb128_config::<MAX_BUNDLE_BYTES>(),
    )?;
    let resolution = build(descriptor, bundle)?;
    let bytes = encode(&resolution).map_err(|e| anyhow!(e))?;
    publish_new(&args.output, &bytes)?;
    println!(
        "{}",
        serde_json::json!({"ok":true,"slot":resolution.locator.hot.slot,"epoch":resolution.locator.epoch,
        "generation":resolution.locator.generation,"bytes":bytes.len(),"sha256":hex(&Sha256::digest(&bytes)),
        "signature_bytes_stored":0,"source_signature_bytes":resolution.signature_bytes().map_err(|e|anyhow!(e))?,
        "access_prefix_bytes":resolution.access_prefix().len(),"access_suffix_bytes":resolution.access_suffix().len(),"output":args.output})
    );
    Ok(())
}

fn build(descriptor: Descriptor, bundle: BlockzillaGetBlockBundleV1) -> Result<ResolutionV1> {
    ensure!(
        bundle.version == WINCODE_BLOCKZILLA_GET_BLOCK_BUNDLE_VERSION
            && bundle.slot == descriptor.hot_row.slot,
        "bundle version or slot differs from the descriptor"
    );
    ensure!(
        bundle.hot_block_encoding == BlockzillaGetBlockBlobEncoding::ZstdWincode,
        "resolution building requires the original compressed hot frame; normalized historical bundles are unsupported"
    );
    ensure!(
        bundle.block_access_encoding == BlockzillaGetBlockBlobEncoding::Wincode,
        "bundle access encoding is unsupported"
    );
    ensure!(
        bundle.hot_block.len() == descriptor.hot_row.compressed_len as usize
            && bundle.hot_block.len() <= 16 * 1024 * 1024
            && descriptor.hot_row.uncompressed_len <= 32 * 1024 * 1024,
        "hot frame length differs from its source row or byte bound"
    );
    let decoded = zstd::bulk::decompress(
        &bundle.hot_block,
        descriptor.hot_row.uncompressed_len as usize,
    )?;
    ensure!(
        decoded.len() == descriptor.hot_row.uncompressed_len as usize,
        "decoded hot frame length differs from its source row"
    );
    let block = deserialize_archive_v2_hot_block_blob(&decoded)?;
    ensure!(
        block.header.slot == bundle.slot
            && block.tx_count == descriptor.hot_row.tx_count
            && block.tx_rows.len() == descriptor.hot_row.tx_count as usize,
        "decoded block identity differs from its source row"
    );
    let access: ArchiveV2BlockAccessBlob = wincode::config::deserialize_exact(
        bundle
            .block_access
            .as_deref()
            .ok_or_else(|| anyhow!("full bundle access data is required"))?,
        bounded_historical_source_wincode_leb128_config::<MAX_BUNDLE_BYTES>(),
    )?;
    let message_schema = match descriptor.message_schema.as_str() {
        "current" => MESSAGE_CURRENT,
        "may24" => MESSAGE_MAY24,
        _ => return Err(anyhow!("unsupported descriptor message schema")),
    };
    let metadata_schema = match descriptor.metadata_schema.as_str() {
        "current" => METADATA_CURRENT,
        "legacy" => METADATA_LEGACY,
        _ => return Err(anyhow!("unsupported descriptor metadata schema")),
    };
    let source = |name: &str| {
        descriptor
            .objects
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow!("descriptor is missing {name}"))
    };
    let locator = LocatorV1 {
        version: VERSION,
        source_prefix: descriptor.source_prefix.clone(),
        generation: descriptor.generation.clone(),
        epoch: descriptor.epoch,
        hot: descriptor.hot_row,
        parent_slot: block.header.parent_slot,
        blockhash: access.blockhash,
        previous_blockhash: access.previous_blockhash,
        message_schema,
        metadata_schema,
        blocks: source(ARCHIVE_V2_BLOCKS_FILE)?,
        signatures: source(ARCHIVE_V2_SIGNATURES_FILE)?,
    };
    if let Some(parent) = descriptor.parent_slot {
        ensure!(
            parent == locator.parent_slot,
            "descriptor parent slot differs from the source block"
        );
    }
    for (expected, actual, name) in [
        (
            descriptor.blockhash.as_deref(),
            locator.blockhash,
            "blockhash",
        ),
        (
            descriptor.previous_blockhash.as_deref(),
            locator.previous_blockhash,
            "previous_blockhash",
        ),
    ] {
        if let Some(expected) = expected {
            let value = bs58::decode(expected).into_vec()?;
            ensure!(
                value.as_slice() == actual,
                "descriptor {name} differs from the source bundle"
            );
        }
    }
    ensure!(
        access.signature_counts
            == block
                .tx_rows
                .iter()
                .map(|v| v.signature_count)
                .collect::<Vec<_>>(),
        "source access signature counts differ from hot transaction rows"
    );
    let current_id = i32::try_from(block.header.blockhash_id)?;
    let previous_id = i32::try_from(block.header.previous_blockhash_id)?;
    ensure!(
        access
            .blockhashes
            .iter()
            .find(|v| v.id == current_id)
            .map(|v| v.blockhash)
            == Some(access.blockhash),
        "source access table blockhash differs from its header reference"
    );
    if block.header.slot != 0 && !(current_id == 0 && previous_id == 0) {
        ensure!(
            access
                .blockhashes
                .iter()
                .find(|v| v.id == previous_id)
                .map(|v| v.blockhash)
                == Some(access.previous_blockhash),
            "source access table previous blockhash differs from its parent reference"
        );
    }
    let objects = descriptor
        .objects
        .into_iter()
        .map(|(name, identity)| NamedSourceObject { name, identity })
        .collect();
    let resolution = ResolutionV1::new(locator, objects, &access).map_err(|e| anyhow!(e))?;
    validate_membership(&block, &resolution)?;
    Ok(resolution)
}

#[derive(Default)]
struct References {
    pubkeys: Vec<u32>,
    hashes: Vec<i32>,
    votes: Vec<(u32, bool, bool)>,
}
impl References {
    fn key(&mut self, key: CompactPubkey) {
        if let CompactPubkey::Id(id) = key {
            self.pubkeys.push(id);
        }
    }
    fn hash(&mut self, value: &blockzilla_compact::OwnedCompactRecentBlockhash) {
        if let blockzilla_compact::OwnedCompactRecentBlockhash::Id(id) = value {
            self.hashes.push(*id);
        }
    }
    fn vote(&mut self, value: ArchiveV2VoteHashRef, bank: bool, block: bool) {
        if let ArchiveV2VoteHashRef::Block(id) = value {
            self.votes.push((id, bank, block));
        }
    }
}

fn validate_membership(block: &ArchiveV2HotBlockBlob, resolution: &ResolutionV1) -> Result<()> {
    let mut refs = References::default();
    refs.hashes.push(i32::try_from(block.header.blockhash_id)?);
    refs.hashes
        .push(i32::try_from(block.header.previous_blockhash_id)?);
    if let Some(rewards) = &block.header.rewards {
        for reward in &rewards.decoded {
            refs.key(reward.pubkey);
        }
    }
    let message_schema = if resolution.locator.message_schema == MESSAGE_CURRENT {
        archive_schema::MessageSchema::Current
    } else {
        archive_schema::MessageSchema::May24
    };
    let metadata_schema = if resolution.locator.metadata_schema == METADATA_CURRENT {
        archive_schema::MetadataSchema::Current
    } else {
        archive_schema::MetadataSchema::Legacy
    };
    for (index, row) in block.tx_rows.iter().enumerate() {
        ensure!(
            row.tx_index as usize == index && row.reserved == [0; 3],
            "invalid transaction index or reserved bytes"
        );
        ensure!(
            row.flags
                & (ARCHIVE_V2_TX_FLAG_TX_RAW_FALLBACK | ARCHIVE_V2_TX_FLAG_METADATA_RAW_FALLBACK)
                == 0,
            "source raw fallback cannot supply a complete resolution object"
        );
        let message = archive_schema::decode_message(
            message_schema,
            region(&block.message_bytes, row.message_offset, row.message_len)?,
        )
        .map_err(|e| anyhow!(e))?;
        let instructions = match &message {
            ArchiveV2HotMessagePayload::Legacy(m) => {
                for k in &m.account_keys {
                    refs.key(*k);
                }
                refs.hash(&m.recent_blockhash);
                &m.instructions
            }
            ArchiveV2HotMessagePayload::V0(m) => {
                for k in &m.account_keys {
                    refs.key(*k);
                }
                refs.hash(&m.recent_blockhash);
                for l in &m.address_table_lookups {
                    refs.key(l.account_key);
                }
                &m.instructions
            }
            ArchiveV2HotMessagePayload::V1(m) => {
                for k in &m.account_keys {
                    refs.key(*k);
                }
                refs.hash(&m.recent_blockhash);
                &m.instructions
            }
        };
        for instruction in instructions {
            match &instruction.data {
                ArchiveV2HotInstructionData::VoteCompactUpdateVoteState(v)
                | ArchiveV2HotInstructionData::VoteCompactUpdateVoteStateSwitch {
                    update: v, ..
                } => refs.vote(v.hash, true, false),
                ArchiveV2HotInstructionData::VoteTowerSync(v)
                | ArchiveV2HotInstructionData::VoteTowerSyncSwitch { tower: v, .. } => {
                    refs.vote(v.update.hash, true, false);
                    refs.vote(v.block_id_hash, false, true);
                }
                _ => {}
            }
        }
        if row.flags & ARCHIVE_V2_TX_FLAG_HAS_METADATA != 0 {
            let meta = archive_schema::decode_metadata(
                metadata_schema,
                region(&block.metadata_bytes, row.metadata_offset, row.metadata_len)?,
            )
            .map_err(|e| anyhow!(e))?;
            for key in meta
                .loaded_writable_addresses
                .iter()
                .chain(&meta.loaded_readonly_addresses)
            {
                refs.key(*key);
            }
            for balance in meta
                .pre_token_balances
                .iter()
                .chain(&meta.post_token_balances)
            {
                for key in [balance.mint, balance.owner, balance.program_id]
                    .into_iter()
                    .flatten()
                {
                    refs.key(key);
                }
            }
            for reward in &meta.rewards {
                refs.key(reward.pubkey);
            }
            if let Some(value) = meta.return_data {
                refs.key(value.program_id);
            }
            if let Some(logs) = meta.logs {
                logs.try_for_each_pubkey(|key| {
                    refs.key(key);
                    Ok::<(), String>(())
                })
                .map_err(|e| anyhow!(e))?;
            }
        }
    }
    resolution
        .validate_membership(&refs.pubkeys, &refs.hashes, &refs.votes)
        .map_err(|e| anyhow!(e))
}

fn region(bytes: &[u8], offset: u32, length: u32) -> Result<&[u8]> {
    let start = offset as usize;
    let end = start
        .checked_add(length as usize)
        .context("source region overflow")?;
    bytes
        .get(start..end)
        .context("source transaction region exceeds the block")
}
fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && metadata.len() <= maximum as u64,
        "input is not a bounded regular file: {}",
        path.display()
    );
    let file = File::open(path)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() == metadata.len() as usize && bytes.len() <= maximum,
        "input changed or exceeded its bound"
    );
    Ok(bytes)
}
fn publish_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|v| !v.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .context("output has no file name")?
        .to_string_lossy();
    let temporary = parent.join(format!(".{name}.tmp-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::hard_link(&temporary, path)
        .with_context(|| format!("publish new {} without overwrite", path.display()))?;
    std::fs::remove_file(temporary)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|v| format!("{v:02x}")).collect()
}
