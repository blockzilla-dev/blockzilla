//! Range-only reads of the compact query archive, without block-access sidecars.

use super::*;
use crate::archive_schema::{
    CURRENT_MESSAGE_MARKER_BYTES, CURRENT_MESSAGE_MARKER_FILE, LEGACY_METADATA_MARKER_BYTES,
    LEGACY_METADATA_MARKER_FILE, MAY24_MESSAGE_MARKER_BYTES, MAY24_MESSAGE_MARKER_FILE,
    MessageSchema, MetadataSchema,
};
use crate::slot_index::{self, SlotIndexHeader, SlotIndexRow};
use blockzilla_archive_v2::{
    ARCHIVE_V2_BLOCK_INDEX_FILE, ARCHIVE_V2_BLOCKHASH_REGISTRY_FILE,
    ARCHIVE_V2_HOT_INDEX_HEADER_LEN, ARCHIVE_V2_HOT_INDEX_MAGIC, ARCHIVE_V2_HOT_INDEX_ROW_LEN,
    ARCHIVE_V2_HOT_INDEX_VERSION, ARCHIVE_V2_PREV_BLOCKHASH_TAIL_FILE,
    ARCHIVE_V2_PUBKEY_REGISTRY_FILE, ARCHIVE_V2_SIGNATURES_FILE,
    ARCHIVE_V2_VOTE_HASH_REGISTRY_FILE, ArchiveV2BlockAccessVoteHash,
};
use blockzilla_program_logs::{
    program_logs::system_program::{PubkeyOrString, SystemAddress, SystemProgramLog},
    program_logs::token_2022::Token2022Log,
};
use futures_util::{TryStreamExt, stream};

const INDEX_PAGE_ROWS: u64 = 256;
const REGISTRY_PAGE_BYTES: usize = 64 * 1024;
const MAX_REGISTRY_FAMILY_BYTES: usize = 4 * 1024 * 1024;
const MAX_REGISTRY_RANGE_BYTES: usize = 256 * 1024;
const MAX_REGISTRY_REQUEST_BYTES: usize = 16 * 1024 * 1024;
const REGISTRY_CONCURRENCY: usize = 8;
const MAX_REFERENCES: usize = 65_536;
const MAX_COMPRESSED_BLOCK_BYTES: usize = 16 * 1024 * 1024;
const MAX_UNCOMPRESSED_BLOCK_BYTES: usize = 32 * 1024 * 1024;
const MAX_SIGNATURE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
struct IndexHeader {
    rows: u64,
    blocks_bytes: u64,
}

struct LocatedRow {
    hot: ArchiveV2HotBlockIndexRow,
    blocks: u64,
    dense: Option<(SlotIndexHeader, SlotIndexRow)>,
}

#[derive(Default)]
struct RegistryBudget {
    bytes: std::cell::Cell<usize>,
    active_reads: std::cell::Cell<usize>,
    waiters: RefCell<Vec<std::task::Waker>>,
}

struct RegistryPermit<'a>(&'a RegistryBudget);

impl Drop for RegistryPermit<'_> {
    fn drop(&mut self) {
        self.0.active_reads.set(self.0.active_reads.get() - 1);
        let waiters = self.0.waiters.take();
        for waiter in waiters {
            waiter.wake();
        }
    }
}

impl RegistryBudget {
    fn reserve(&self, bytes: usize) -> std::result::Result<(), String> {
        let total = self
            .bytes
            .get()
            .checked_add(bytes)
            .filter(|total| *total <= MAX_REGISTRY_REQUEST_BYTES)
            .ok_or_else(|| "block registry reads exceed the 16 MiB request limit".to_string())?;
        self.bytes.set(total);
        Ok(())
    }

    async fn acquire(&self) -> RegistryPermit<'_> {
        future::poll_fn(|context| {
            let active = self.active_reads.get();
            if active < REGISTRY_CONCURRENCY {
                self.active_reads.set(active + 1);
                return std::task::Poll::Ready(RegistryPermit(self));
            }
            let mut waiters = self.waiters.borrow_mut();
            if !waiters
                .iter()
                .any(|waiter| waiter.will_wake(context.waker()))
            {
                waiters.push(context.waker().clone());
            }
            std::task::Poll::Pending
        })
        .await
    }
}

pub(super) async fn fetch_block(
    source: &WorkerSource,
    slot: u64,
    access_mode: AccessFetchMode,
) -> std::result::Result<Option<FetchedHotBlock>, String> {
    let started = now_ms();
    let epoch = epoch_for_slot(slot);
    let Some(location) = find_index_row(source, epoch, slot).await? else {
        return Ok(None);
    };
    let row = location.hot;
    let schemas = select_schemas(source, epoch).await?;
    let compressed = read_compressed(source, epoch, &row).await?;
    let (block_bytes, block) = decode_block(source, slot, &row, &compressed)?;
    drop(compressed);
    let access = build_access(source, epoch, &location, &block, access_mode, schemas).await?;
    source.record_elapsed(
        "fetch_block_total",
        started,
        block_bytes.len() as u64,
        "stored",
        None,
    );
    Ok(Some(FetchedHotBlock {
        epoch,
        index_row: ArchiveV2GetBlockIndexRow {
            block_offset: row.compressed_offset,
            block_len: row.compressed_len,
            access_offset: 0,
            access_len: 0,
        },
        row,
        decoded_len: block_bytes.len(),
        block,
        access,
        message_schema: schemas.0,
        metadata_schema: schemas.1,
    }))
}

pub(super) async fn fetch_bundle(
    source: &WorkerSource,
    slot: u64,
    access_mode: BlockBinAccessMode,
) -> std::result::Result<Option<Vec<u8>>, String> {
    let epoch = epoch_for_slot(slot);
    let Some(location) = find_index_row(source, epoch, slot).await? else {
        return Ok(None);
    };
    let row = location.hot;
    let compressed = read_compressed(source, epoch, &row).await?;
    let mut hot_block_encoding = BlockzillaGetBlockBlobEncoding::ZstdWincode;
    let mut hot_block = compressed;
    let block_access = if access_mode == BlockBinAccessMode::Include {
        let schemas = select_schemas(source, epoch).await?;
        let (_, block) = decode_block(source, slot, &row, &hot_block)?;
        let Some(FetchedAccess::Full(access)) = build_access(
            source,
            epoch,
            &location,
            &block,
            AccessFetchMode::Full,
            schemas,
        )
        .await?
        else {
            return Err("stored binary response requires full access data".to_string());
        };
        let access_bytes = wincode::config::serialize(&access, wincode_leb128_config())
            .map_err(|error| format!("encode block access for slot {slot}: {error}"))?;
        if schemas.0 != MessageSchema::Current || schemas.1 != MetadataSchema::Current {
            hot_block = normalize_historical_hot_block(block, schemas)?;
            hot_block_encoding = BlockzillaGetBlockBlobEncoding::Wincode;
        }
        Some(access_bytes)
    } else {
        None
    };
    let bundle = BlockzillaGetBlockBundleV1 {
        version: WINCODE_BLOCKZILLA_GET_BLOCK_BUNDLE_VERSION,
        slot,
        hot_block_encoding,
        hot_block,
        block_access_encoding: BlockzillaGetBlockBlobEncoding::Wincode,
        block_access,
    };
    wincode::config::serialize(&bundle, wincode_leb128_config())
        .map(Some)
        .map_err(|error| format!("encode stored block bundle for slot {slot}: {error}"))
}

pub(super) fn normalize_historical_hot_block(
    mut block: ArchiveV2HotBlockBlob,
    schemas: Schemas,
) -> std::result::Result<Vec<u8>, String> {
    let mut messages = Vec::new();
    let mut metadata = Vec::new();
    let mut rows = Vec::with_capacity(block.tx_rows.len());
    for tx in &block.tx_rows {
        if tx.flags
            & (ARCHIVE_V2_TX_FLAG_TX_RAW_FALLBACK | ARCHIVE_V2_TX_FLAG_METADATA_RAW_FALLBACK)
            != 0
        {
            return Err(format!(
                "tx_index {} has raw fallback data that cannot be normalized",
                tx.tx_index
            ));
        }
        let message = decode_message(&block, tx, schemas.0)?;
        let message = wincode::config::serialize(&message, wincode_leb128_config())
            .map_err(|error| format!("normalize message tx_index {}: {error}", tx.tx_index))?;
        let mut row = *tx;
        (row.message_offset, row.message_len) = append_normalized_region(&mut messages, &message)?;
        if let Some(meta) = decode_metadata(&block, tx, schemas.1)? {
            let meta = wincode::config::serialize(&meta, wincode_leb128_config())
                .map_err(|error| format!("normalize metadata tx_index {}: {error}", tx.tx_index))?;
            (row.metadata_offset, row.metadata_len) =
                append_normalized_region(&mut metadata, &meta)?;
        } else {
            row.metadata_offset = metadata.len() as u32;
            row.metadata_len = 0;
        }
        rows.push(row);
    }
    block.tx_rows = rows;
    block.message_bytes = messages;
    block.metadata_bytes = metadata;
    let length = wincode::config::serialized_size(&block, wincode_leb128_config())
        .map_err(|error| format!("measure normalized historical hot block: {error}"))?;
    if length > MAX_UNCOMPRESSED_BLOCK_BYTES as u64 {
        return Err("normalized historical block exceeds the 32 MiB Worker limit".to_string());
    }
    let bytes = wincode::config::serialize(&block, wincode_leb128_config())
        .map_err(|error| format!("normalize historical hot block: {error}"))?;
    if bytes.len() > MAX_UNCOMPRESSED_BLOCK_BYTES {
        return Err("normalized historical block exceeds the 32 MiB Worker limit".to_string());
    }
    Ok(bytes)
}

fn append_normalized_region(
    region: &mut Vec<u8>,
    bytes: &[u8],
) -> std::result::Result<(u32, u32), String> {
    let start = region.len();
    let end = start
        .checked_add(bytes.len())
        .filter(|end| *end <= MAX_UNCOMPRESSED_BLOCK_BYTES)
        .ok_or_else(|| {
            "normalized historical block region exceeds the 32 MiB Worker limit".to_string()
        })?;
    region.extend_from_slice(bytes);
    Ok((start as u32, (end - start) as u32))
}

type Schemas = (MessageSchema, MetadataSchema);

async fn select_schemas(source: &WorkerSource, epoch: u64) -> std::result::Result<Schemas, String> {
    let synthetic_path = epoch_file(
        &source.archive_prefix,
        epoch,
        "__worker-selected-schemas-v1",
    );
    let cache_key = source.range_cache_key(&synthetic_path, 0, 2);
    if let Some(key) = &cache_key {
        if let Some(bytes) = source.cached_bytes(key, 2).await {
            let message = match bytes[0] {
                0 => Some(MessageSchema::Current),
                1 => Some(MessageSchema::May24),
                _ => None,
            };
            let metadata = match bytes[1] {
                0 => Some(MetadataSchema::Current),
                1 => Some(MetadataSchema::Legacy),
                _ => None,
            };
            if let (Some(message), Some(metadata)) = (message, metadata) {
                return Ok((message, metadata));
            }
        }
    }
    let current = epoch_file(&source.archive_prefix, epoch, CURRENT_MESSAGE_MARKER_FILE);
    let historical = epoch_file(&source.archive_prefix, epoch, MAY24_MESSAGE_MARKER_FILE);
    let metadata = epoch_file(&source.archive_prefix, epoch, LEGACY_METADATA_MARKER_FILE);
    let (current_size, historical_size, metadata_size) = future::try_join3(
        source.object_size(&current),
        source.object_size(&historical),
        source.object_size(&metadata),
    )
    .await?;
    if current_size.is_some() && historical_size.is_some() {
        return Err(format!(
            "epoch {epoch} has conflicting message-schema markers"
        ));
    }
    let message = if let Some(size) = historical_size {
        check_marker(source, &historical, size, MAY24_MESSAGE_MARKER_BYTES).await?;
        MessageSchema::May24
    } else if let Some(size) = current_size {
        check_marker(source, &current, size, CURRENT_MESSAGE_MARKER_BYTES).await?;
        MessageSchema::Current
    } else if let Some(schema) = source.message_schema_overrides.get(&epoch) {
        *schema
    } else if epoch <= 2 {
        return Err(format!(
            "epoch {epoch} needs an explicit message-schema marker"
        ));
    } else {
        MessageSchema::Current
    };
    if (historical_size.is_some() || current_size.is_some())
        && source
            .message_schema_overrides
            .get(&epoch)
            .is_some_and(|schema| *schema != message)
    {
        return Err("message schema declaration conflicts with the archive marker".into());
    }
    let metadata_schema = if let Some(size) = metadata_size {
        check_marker(source, &metadata, size, LEGACY_METADATA_MARKER_BYTES).await?;
        if source.metadata_schema_override == Some(MetadataSchema::Current) {
            return Err("metadata schema declaration conflicts with the archive marker".into());
        }
        MetadataSchema::Legacy
    } else {
        source
            .metadata_schema_override
            .unwrap_or(MetadataSchema::Current)
    };
    if let Some(key) = cache_key {
        let message_tag = match message {
            MessageSchema::Current => 0,
            MessageSchema::May24 => 1,
        };
        let metadata_tag = match metadata_schema {
            MetadataSchema::Current => 0,
            MetadataSchema::Legacy => 1,
        };
        source.cache_bytes(key, &[message_tag, metadata_tag]);
    }
    Ok((message, metadata_schema))
}

async fn check_marker(
    source: &WorkerSource,
    path: &str,
    actual_size: u64,
    expected: &[u8],
) -> std::result::Result<(), String> {
    if actual_size != expected.len() as u64 {
        return Err(format!("invalid schema marker size: {path}"));
    }
    let bytes = source.get_cached_range(path, 0, expected.len()).await?;
    if bytes != expected {
        return Err(format!("invalid schema marker bytes: {path}"));
    }
    Ok(())
}

async fn find_index_row(
    source: &WorkerSource,
    epoch: u64,
    slot: u64,
) -> std::result::Result<Option<LocatedRow>, String> {
    if source.use_dense_slot_index {
        return find_dense_row(source, epoch, slot).await;
    }
    let path = epoch_file(&source.archive_prefix, epoch, ARCHIVE_V2_BLOCK_INDEX_FILE);
    let header_bytes = source
        .get_cached_range(&path, 0, ARCHIVE_V2_HOT_INDEX_HEADER_LEN)
        .await?;
    let Some(size) = source.object_size(&path).await? else {
        return Err(format!("archive epoch {epoch} is unavailable"));
    };
    let header = parse_index_header(&header_bytes, size)?;
    let candidates = crate::slot_lookup::ordinal_window(
        epoch
            .checked_mul(SLOTS_PER_EPOCH)
            .ok_or_else(|| "epoch slot range overflows".to_string())?,
        SLOTS_PER_EPOCH,
        header.rows,
        slot,
    )?;
    let mut low = candidates.start;
    let mut high = candidates.end;
    while low < high {
        let middle = low + (high - low) / 2;
        let page_start = (middle / INDEX_PAGE_ROWS) * INDEX_PAGE_ROWS;
        let count = INDEX_PAGE_ROWS.min(header.rows - page_start);
        let offset = ARCHIVE_V2_HOT_INDEX_HEADER_LEN as u64
            + page_start * ARCHIVE_V2_HOT_INDEX_ROW_LEN as u64;
        let bytes = source
            .get_cached_range(&path, offset, count as usize * ARCHIVE_V2_HOT_INDEX_ROW_LEN)
            .await?;
        let rows = parse_index_page(&bytes, epoch, page_start, header.blocks_bytes)?;
        let first = rows
            .first()
            .ok_or_else(|| "empty hot-index page".to_string())?;
        let last = rows
            .last()
            .ok_or_else(|| "empty hot-index page".to_string())?;
        if slot < first.slot {
            high = page_start;
        } else if slot > last.slot {
            low = page_start + count;
        } else {
            return Ok(rows
                .binary_search_by_key(&slot, |row| row.slot)
                .ok()
                .map(|index| LocatedRow {
                    hot: rows[index],
                    blocks: header.rows,
                    dense: None,
                }));
        }
    }
    Ok(None)
}

async fn find_dense_row(
    source: &WorkerSource,
    epoch: u64,
    slot: u64,
) -> std::result::Result<Option<LocatedRow>, String> {
    let path = epoch_file(&source.archive_prefix, epoch, slot_index::SLOT_INDEX_FILE);
    let bytes = source
        .get_cached_range(&path, 0, slot_index::SLOT_INDEX_HEADER_LEN)
        .await?;
    let header = slot_index::parse_header(&bytes)?;
    if source.object_size(&path).await? != Some(header.file_len()?) {
        return Err("slot-index object length differs from its header geometry".to_string());
    }
    if header.epoch != epoch
        || header.slot_count != SLOTS_PER_EPOCH
        || header.first_slot
            != epoch
                .checked_mul(SLOTS_PER_EPOCH)
                .ok_or_else(|| "slot-index epoch overflow".to_string())?
    {
        return Err("slot-index header does not match the requested epoch".to_string());
    }
    let ordinal = slot
        .checked_sub(header.first_slot)
        .filter(|ordinal| *ordinal < header.slot_count)
        .ok_or_else(|| "requested slot is outside the slot index".to_string())?;
    let page_rows = 512u64;
    let page_start = ordinal / page_rows * page_rows;
    let count = page_rows.min(header.slot_count - page_start);
    let offset = slot_index::SLOT_INDEX_HEADER_LEN as u64
        + page_start * slot_index::SLOT_INDEX_ROW_LEN as u64;
    let bytes = source
        .get_cached_range(
            &path,
            offset,
            count as usize * slot_index::SLOT_INDEX_ROW_LEN,
        )
        .await?;
    let within = (ordinal - page_start) as usize * slot_index::SLOT_INDEX_ROW_LEN;
    let Some(row) = slot_index::parse_row(&bytes[within..within + slot_index::SLOT_INDEX_ROW_LEN])?
    else {
        return Ok(None);
    };
    slot_index::validate_row(&header, slot, &row)?;
    validate_row_bounds(&row.hot, header.blocks_bytes)?;
    Ok(Some(LocatedRow {
        hot: row.hot,
        blocks: header.block_count,
        dense: Some((header, row)),
    }))
}

fn parse_index_header(bytes: &[u8], actual_size: u64) -> std::result::Result<IndexHeader, String> {
    if bytes.len() != ARCHIVE_V2_HOT_INDEX_HEADER_LEN
        || &bytes[..8] != ARCHIVE_V2_HOT_INDEX_MAGIC
        || u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != ARCHIVE_V2_HOT_INDEX_VERSION
        || bytes[10..12] != [0, 0]
    {
        return Err("invalid Compact V2 hot-index header".to_string());
    }
    let rows = u64::from_le_bytes(bytes[12..20].try_into().unwrap());
    let blocks_bytes = u64::from_le_bytes(bytes[20..28].try_into().unwrap());
    let flags = u32::from_le_bytes(bytes[32..36].try_into().unwrap());
    if flags != 0 {
        return Err(format!(
            "unsupported Compact V2 hot-index flags {flags:#x}; independent zstd frames are required"
        ));
    }
    if rows > SLOTS_PER_EPOCH {
        return Err(format!("hot-index row count {rows} exceeds an epoch"));
    }
    let expected_size =
        ARCHIVE_V2_HOT_INDEX_HEADER_LEN as u64 + rows * ARCHIVE_V2_HOT_INDEX_ROW_LEN as u64;
    if actual_size != expected_size {
        return Err(format!(
            "hot-index length {actual_size} does not match {rows} rows ({expected_size} bytes)"
        ));
    }
    Ok(IndexHeader { rows, blocks_bytes })
}

fn parse_index_page(
    bytes: &[u8],
    epoch: u64,
    first_ordinal: u64,
    blocks_bytes: u64,
) -> std::result::Result<Vec<ArchiveV2HotBlockIndexRow>, String> {
    if !bytes.len().is_multiple_of(ARCHIVE_V2_HOT_INDEX_ROW_LEN) {
        return Err("invalid hot-index page length".to_string());
    }
    let mut rows: Vec<ArchiveV2HotBlockIndexRow> = Vec::new();
    for (index, bytes) in bytes.chunks_exact(ARCHIVE_V2_HOT_INDEX_ROW_LEN).enumerate() {
        let row = ArchiveV2HotBlockIndexRow {
            block_id: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            slot: u64::from_le_bytes(bytes[4..12].try_into().unwrap()),
            compressed_offset: u64::from_le_bytes(bytes[12..20].try_into().unwrap()),
            compressed_len: u32::from_le_bytes(bytes[20..24].try_into().unwrap()),
            uncompressed_len: u32::from_le_bytes(bytes[24..28].try_into().unwrap()),
            tx_count: u32::from_le_bytes(bytes[28..32].try_into().unwrap()),
            first_tx_ordinal: u64::from_le_bytes(bytes[32..40].try_into().unwrap()),
            first_signature_ordinal: u64::from_le_bytes(bytes[40..48].try_into().unwrap()),
            signature_count: u32::from_le_bytes(bytes[48..52].try_into().unwrap()),
        };
        if u64::from(row.block_id) != first_ordinal + index as u64
            || epoch_for_slot(row.slot) != epoch
        {
            return Err("hot-index row identity does not match its epoch and ordinal".to_string());
        }
        validate_row_bounds(&row, blocks_bytes)?;
        if let Some(previous) = rows.last() {
            if previous.slot >= row.slot
                || previous
                    .compressed_offset
                    .checked_add(u64::from(previous.compressed_len))
                    != Some(row.compressed_offset)
                || previous
                    .first_tx_ordinal
                    .checked_add(u64::from(previous.tx_count))
                    != Some(row.first_tx_ordinal)
                || previous
                    .first_signature_ordinal
                    .checked_add(u64::from(previous.signature_count))
                    != Some(row.first_signature_ordinal)
            {
                return Err("hot-index page rows are not contiguous and ascending".to_string());
            }
        }
        rows.push(row);
    }
    Ok(rows)
}

fn validate_row_bounds(
    row: &ArchiveV2HotBlockIndexRow,
    blocks_bytes: u64,
) -> std::result::Result<(), String> {
    if row.compressed_len == 0
        || row.compressed_len as usize > MAX_COMPRESSED_BLOCK_BYTES
        || row.uncompressed_len == 0
        || row.uncompressed_len as usize > MAX_UNCOMPRESSED_BLOCK_BYTES
        || row
            .compressed_offset
            .checked_add(u64::from(row.compressed_len))
            .is_none_or(|end| end > blocks_bytes)
        || u64::from(row.signature_count) * SIGNATURE_BYTES > MAX_SIGNATURE_BYTES as u64
        || row
            .first_signature_ordinal
            .checked_add(u64::from(row.signature_count))
            .is_none()
        || row
            .first_tx_ordinal
            .checked_add(u64::from(row.tx_count))
            .is_none()
    {
        return Err(format!("slot {} exceeds stored block bounds", row.slot));
    }
    Ok(())
}

async fn read_compressed(
    source: &WorkerSource,
    epoch: u64,
    row: &ArchiveV2HotBlockIndexRow,
) -> std::result::Result<Vec<u8>, String> {
    let path = epoch_file(&source.archive_prefix, epoch, ARCHIVE_V2_BLOCKS_FILE);
    source
        .get_cached_range(&path, row.compressed_offset, row.compressed_len as usize)
        .await
}

pub(super) fn decode_block(
    source: &WorkerSource,
    slot: u64,
    row: &ArchiveV2HotBlockIndexRow,
    compressed: &[u8],
) -> std::result::Result<(Vec<u8>, ArchiveV2HotBlockBlob), String> {
    let started = now_ms();
    let mut decoder =
        StreamingDecoder::new_with_max_window_size(compressed, MAX_UNCOMPRESSED_BLOCK_BYTES as u64)
            .map_err(|error| format!("initialize zstd slot {slot}: {error}"))?;
    let mut bytes = Vec::with_capacity(row.uncompressed_len as usize);
    std::io::Read::by_ref(&mut decoder)
        .take(u64::from(row.uncompressed_len) + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("decode zstd slot {slot}: {error}"))?;
    if bytes.len() != row.uncompressed_len as usize {
        return Err(format!(
            "slot {slot} decoded length differs from its hot index"
        ));
    }
    if !decoder.into_inner().is_empty() {
        return Err(format!(
            "slot {slot} compressed range contains bytes after its zstd frame"
        ));
    }
    let block = deserialize_archive_v2_hot_block_blob(&bytes)
        .map_err(|error| format!("decode stored hot block slot {slot}: {error}"))?;
    validate_block(&block, row)?;
    source.record_elapsed(
        "stored_block_decode",
        started,
        bytes.len() as u64,
        "zstd_wincode",
        None,
    );
    Ok((bytes, block))
}

fn validate_block(
    block: &ArchiveV2HotBlockBlob,
    row: &ArchiveV2HotBlockIndexRow,
) -> std::result::Result<(), String> {
    if block.header.slot != row.slot
        || block.tx_count != row.tx_count
        || block.tx_rows.len() != row.tx_count as usize
    {
        return Err(
            "decoded block identity or transaction count differs from its hot index".to_string(),
        );
    }
    if block.header.slot == 0 {
        if block.header.parent_slot != 0 || block.header.previous_blockhash_id != 0 {
            return Err(
                "genesis block has an invalid parent or previous blockhash reference".to_string(),
            );
        }
    } else if block.header.parent_slot >= block.header.slot {
        return Err("block parent slot does not precede this block".to_string());
    }
    if block.header.previous_blockhash_id >= block.header.blockhash_id
        && !(block.header.blockhash_id == 0 && block.header.previous_blockhash_id == 0)
    {
        return Err("previous blockhash ID does not precede this block".to_string());
    }
    let mut signatures = 0u32;
    for (index, tx) in block.tx_rows.iter().enumerate() {
        if tx.tx_index as usize != index || tx.reserved != [0; 3] {
            return Err("decoded transaction index or reserved bytes are invalid".to_string());
        }
        region_slice(
            &block.message_bytes,
            tx.message_offset,
            tx.message_len,
            "message",
            tx.tx_index,
        )?;
        region_slice(
            &block.metadata_bytes,
            tx.metadata_offset,
            tx.metadata_len,
            "metadata",
            tx.tx_index,
        )?;
        signatures = signatures
            .checked_add(u32::from(tx.signature_count))
            .ok_or_else(|| "signature count overflow".to_string())?;
    }
    if signatures != row.signature_count {
        return Err("decoded signature count differs from its hot index".to_string());
    }
    Ok(())
}

async fn build_access(
    source: &WorkerSource,
    epoch: u64,
    location: &LocatedRow,
    block: &ArchiveV2HotBlockBlob,
    mode: AccessFetchMode,
    schemas: Schemas,
) -> std::result::Result<Option<FetchedAccess>, String> {
    if mode == AccessFetchMode::None {
        return Ok(None);
    }
    let row = &location.hot;
    if let Some((header, dense)) = &location.dense {
        if block.header.parent_slot != dense.parent_slot {
            return Err("decoded block parent differs from the slot index".to_string());
        }
        validate_hash_ordinal(
            block.header.blockhash_id,
            row.block_id,
            header.block_count,
            header.blockhash_registry_bytes,
        )?;
        if block.header.previous_blockhash_id >= block.header.blockhash_id
            && !(block.header.blockhash_id == 0 && block.header.previous_blockhash_id == 0)
        {
            return Err("decoded previous blockhash ID does not precede this block".to_string());
        }
    }
    let blockhash_id = i32::try_from(block.header.blockhash_id)
        .map_err(|_| "blockhash ID exceeds i32".to_string())?;
    let previous_id = i32::try_from(block.header.previous_blockhash_id)
        .map_err(|_| "previous blockhash ID exceeds i32".to_string())?;
    let mut pubkey_ids = Vec::new();
    let mut blockhash_ids = vec![blockhash_id, previous_id];
    let mut vote_ids = Vec::new();
    if mode == AccessFetchMode::Full {
        if let Some(rewards) = &block.header.rewards {
            for reward in &rewards.decoded {
                collect_access_pubkey_id(reward.pubkey, &mut pubkey_ids);
            }
        }
        for tx in &block.tx_rows {
            let message = decode_message(block, tx, schemas.0)?;
            collect_access_message_refs(&message, &mut pubkey_ids, &mut blockhash_ids);
            collect_access_message_vote_hash_refs(&message, &mut vote_ids);
            if tx.flags & ARCHIVE_V2_TX_FLAG_METADATA_RAW_FALLBACK != 0 {
                return Err(format!(
                    "tx_index {} uses raw metadata fallback; complete JSON access is unavailable",
                    tx.tx_index
                ));
            }
            if let Some(meta) = decode_metadata(block, tx, schemas.1)? {
                collect_access_metadata_refs(&meta, &mut pubkey_ids);
            }
            if pubkey_ids.len() > MAX_REFERENCES * 16
                || blockhash_ids.len() > MAX_REFERENCES * 16
                || vote_ids.len() > MAX_REFERENCES * 16
            {
                return Err("block has too many registry references".to_string());
            }
        }
    }
    pubkey_ids.sort_unstable();
    pubkey_ids.dedup();
    blockhash_ids.sort_unstable();
    blockhash_ids.dedup();
    vote_ids.sort_unstable();
    vote_ids.dedup();
    if [pubkey_ids.len(), blockhash_ids.len(), vote_ids.len()]
        .into_iter()
        .any(|len| len > MAX_REFERENCES)
    {
        return Err("block has too many distinct registry references".to_string());
    }
    if location.dense.is_some() {
        blockhash_ids.retain(|id| *id != blockhash_id && *id != previous_id);
    }
    let genesis = block.header.slot == 0;
    if epoch == 0 && blockhash_ids.iter().any(|id| *id < 0) {
        return Err("genesis epoch cannot reference a previous-epoch blockhash tail".to_string());
    }
    let needs_tail = blockhash_ids.iter().any(|id| *id < 0)
        || (location.dense.is_none() && !genesis && blockhash_id == 0 && previous_id == 0);
    let budget = RegistryBudget::default();
    let hashes_future = resolve_blockhashes(
        source,
        epoch,
        &blockhash_ids,
        needs_tail,
        &budget,
        (block.header.blockhash_id, row.block_id, location.blocks),
        location
            .dense
            .as_ref()
            .map(|(header, _)| header.blockhash_registry_bytes),
    );
    let keys_future = async {
        let ids = pubkey_ids
            .iter()
            .map(|id| {
                u64::from(*id)
                    .checked_sub(1)
                    .ok_or_else(|| "pubkey ID zero is reserved".to_string())
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        read_records::<32>(
            source,
            &epoch_file(
                &source.archive_prefix,
                epoch,
                ARCHIVE_V2_PUBKEY_REGISTRY_FILE,
            ),
            &ids,
            &budget,
            location
                .dense
                .as_ref()
                .map(|(header, _)| header.registry_bytes),
        )
        .await
    };
    let votes_future = async {
        let ids = vote_ids.iter().copied().map(u64::from).collect::<Vec<_>>();
        read_records::<65>(
            source,
            &epoch_file(
                &source.archive_prefix,
                epoch,
                ARCHIVE_V2_VOTE_HASH_REGISTRY_FILE,
            ),
            &ids,
            &budget,
            None,
        )
        .await
    };
    let signatures_future = async {
        if mode == AccessFetchMode::BlockhashOnly {
            return Ok(Vec::new());
        }
        let offset = row
            .first_signature_ordinal
            .checked_mul(SIGNATURE_BYTES)
            .ok_or_else(|| "signature offset overflow".to_string())?;
        source
            .get_cached_range(
                &epoch_file(&source.archive_prefix, epoch, ARCHIVE_V2_SIGNATURES_FILE),
                offset,
                row.signature_count as usize * SIGNATURE_BYTES as usize,
            )
            .await
    };
    let ((mut hashes, tail), keys, votes, signatures) =
        future::try_join4(hashes_future, keys_future, votes_future, signatures_future).await?;
    if let Some((_, dense)) = &location.dense {
        hashes.insert(blockhash_id, dense.blockhash);
        if blockhash_id != previous_id {
            hashes.insert(previous_id, dense.previous_blockhash);
        }
    }
    let blockhash = *hashes
        .get(&blockhash_id)
        .ok_or_else(|| "missing block hash".to_string())?;
    let previous_blockhash = if genesis {
        [0; 32]
    } else if let Some((_, dense)) = &location.dense {
        dense.previous_blockhash
    } else if blockhash_id == 0 && previous_id == 0 {
        if tail
            .last()
            .and_then(|entry| entry.1)
            .is_some_and(|slot| slot != block.header.parent_slot)
        {
            return Err("legacy predecessor-tail slot differs from the block parent".to_string());
        }
        tail.last()
            .map(|entry| entry.0)
            .ok_or_else(|| "first legacy block has no predecessor tail".to_string())?
    } else {
        *hashes
            .get(&previous_id)
            .ok_or_else(|| "missing previous block hash".to_string())?
    };
    if mode != AccessFetchMode::Full {
        return Ok(Some(FetchedAccess::Lite(FetchedAccessLite {
            blockhash,
            previous_blockhash,
            signature_counts: block.tx_rows.iter().map(|tx| tx.signature_count).collect(),
            signatures,
        })));
    }
    let pubkeys = pubkey_ids
        .into_iter()
        .map(|id| {
            keys.get(&(u64::from(id) - 1))
                .copied()
                .map(|pubkey| ArchiveV2BlockAccessPubkey { id, pubkey })
                .ok_or_else(|| "missing resolved pubkey".to_string())
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let blockhashes = hashes
        .into_iter()
        .map(|(id, blockhash)| ArchiveV2BlockAccessBlockhash { id, blockhash })
        .collect();
    let vote_hashes = vote_ids
        .into_iter()
        .map(|block_id| {
            let bytes = votes
                .get(&u64::from(block_id))
                .ok_or_else(|| "missing resolved vote hash".to_string())?;
            if bytes[0] & !3 != 0 {
                return Err("invalid vote-hash registry flags".to_string());
            }
            Ok(ArchiveV2BlockAccessVoteHash {
                block_id,
                bank_hash: (bytes[0] & 1 != 0).then(|| bytes[1..33].try_into().unwrap()),
                block_id_hash: (bytes[0] & 2 != 0).then(|| bytes[33..65].try_into().unwrap()),
            })
        })
        .collect::<std::result::Result<Vec<_>, String>>()?;
    let access = ArchiveV2BlockAccessBlob {
        version: WINCODE_ARCHIVE_V2_BLOCK_ACCESS_VERSION,
        flags: 0,
        blockhash,
        previous_blockhash,
        signature_counts: block.tx_rows.iter().map(|tx| tx.signature_count).collect(),
        signatures,
        pubkeys,
        blockhashes,
        vote_hashes,
    };
    validate_access_blob(&access, row)?;
    Ok(Some(FetchedAccess::Full(access)))
}

struct RegistryPage {
    first: u64,
    count: u64,
    ids: Vec<u64>,
}

struct RegistryRange {
    first: u64,
    count: u64,
    pages: Vec<RegistryPage>,
}

fn plan_registry_pages<const N: usize>(
    ids: &[u64],
    records: u64,
) -> std::result::Result<Vec<RegistryPage>, String> {
    plan_registry_pages_with_size::<N>(ids, records, REGISTRY_PAGE_BYTES)
}

fn plan_registry_pages_with_size<const N: usize>(
    ids: &[u64],
    records: u64,
    page_bytes: usize,
) -> std::result::Result<Vec<RegistryPage>, String> {
    if ids.len() > MAX_REFERENCES {
        return Err("too many registry records".to_string());
    }
    if N == 0 {
        return Err("registry record width must be nonzero".to_string());
    }
    let page_rows = (page_bytes / N).max(1) as u64;
    let mut pages: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for id in ids {
        if *id >= records {
            return Err(format!("registry ID {id} is outside {records} records"));
        }
        pages.entry(*id / page_rows).or_default().push(*id);
    }
    Ok(pages
        .into_iter()
        .map(|(page, ids)| {
            let first = page * page_rows;
            RegistryPage {
                first,
                count: page_rows.min(records - first),
                ids,
            }
        })
        .collect())
}

fn planned_registry_bytes<const N: usize>(
    pages: &[RegistryPage],
) -> std::result::Result<usize, String> {
    pages.iter().try_fold(0usize, |total, page| {
        let bytes = usize::try_from(page.count)
            .ok()
            .and_then(|count| count.checked_mul(N))
            .ok_or_else(|| "registry page length overflow".to_string())?;
        total
            .checked_add(bytes)
            .ok_or_else(|| "registry plan length overflow".to_string())
    })
}

/// Select the largest fixed page geometry that admits this registry family.
/// Page boundaries depend only on geometry and record width, never on the
/// particular block. Thus every selected page still has a reusable cache key.
fn plan_adaptive_registry_pages<const N: usize>(
    ids: &[u64],
    records: u64,
) -> std::result::Result<(Vec<RegistryPage>, usize), String> {
    for page_bytes in [REGISTRY_PAGE_BYTES, 16 * 1024, 4 * 1024, 1024, 256, 64, N] {
        let pages = plan_registry_pages_with_size::<N>(ids, records, page_bytes)?;
        let bytes = planned_registry_bytes::<N>(&pages)?;
        if bytes <= MAX_REGISTRY_FAMILY_BYTES {
            return Ok((pages, bytes));
        }
    }
    Err("required registry records exceed the 4 MiB family limit".to_string())
}

fn coalesce_registry_pages<const N: usize>(pages: Vec<RegistryPage>) -> Vec<RegistryRange> {
    let mut ranges: Vec<RegistryRange> = Vec::new();
    for page in pages {
        if let Some(range) = ranges.last_mut()
            && range.first + range.count == page.first
            && (range.count + page.count) as usize * N <= MAX_REGISTRY_RANGE_BYTES
        {
            range.count += page.count;
            range.pages.push(page);
        } else {
            ranges.push(RegistryRange {
                first: page.first,
                count: page.count,
                pages: vec![page],
            });
        }
    }
    ranges
}

fn extract_records<const N: usize>(
    bytes: &[u8],
    first: u64,
    ids: &[u64],
) -> std::result::Result<Vec<(u64, [u8; N])>, String> {
    ids.iter()
        .map(|id| {
            let offset = (id - first) as usize * N;
            let record = bytes
                .get(offset..offset + N)
                .ok_or_else(|| "truncated registry page".to_string())?;
            Ok((*id, record.try_into().unwrap()))
        })
        .collect()
}

async fn read_records<const N: usize>(
    source: &WorkerSource,
    path: &str,
    ids: &[u64],
    budget: &RegistryBudget,
    known_size: Option<u64>,
) -> std::result::Result<BTreeMap<u64, [u8; N]>, String> {
    if ids.is_empty() {
        return Ok(BTreeMap::new());
    }
    if ids.len() > MAX_REFERENCES {
        return Err("too many registry records".to_string());
    }
    let size = match known_size {
        Some(size) => size,
        None => source
            .object_size(path)
            .await?
            .ok_or_else(|| format!("missing registry object {path}"))?,
    };
    if !size.is_multiple_of(N as u64) {
        return Err(format!("registry {path} has an invalid record width"));
    }
    let (pages, planned_bytes) = plan_adaptive_registry_pages::<N>(ids, size / N as u64)?;
    budget.reserve(planned_bytes)?;
    // Cache keys always refer to one canonical page. A backend read may join
    // adjacent cache misses, without changing the cache representation.
    let cached = stream::iter(pages.into_iter().map(|page| async move {
        let _permit = budget.acquire().await;
        let key = source.range_cache_key(path, page.first * N as u64, page.count as usize * N);
        let records = if let Some(key) = key {
            source
                .cached_bytes(&key, page.count as usize * N)
                .await
                .map(|bytes| extract_records::<N>(&bytes, page.first, &page.ids))
                .transpose()?
        } else {
            None
        };
        Ok::<_, String>((page, records))
    }))
    .buffer_unordered(REGISTRY_CONCURRENCY)
    .try_collect::<Vec<_>>()
    .await?;
    let mut out = BTreeMap::new();
    let mut missing = Vec::new();
    for (page, records) in cached {
        if let Some(records) = records {
            out.extend(records);
        } else {
            missing.push(page);
        }
    }
    // Cache probes finish in arbitrary order. Restore registry order before
    // joining adjacent missing pages into bounded backend ranges.
    missing.sort_unstable_by_key(|page| page.first);
    let ranges = coalesce_registry_pages::<N>(missing);
    let batches = stream::iter(ranges.into_iter().map(|range| async move {
        let _permit = budget.acquire().await;
        let bytes = source
            .get_range(path, range.first * N as u64, range.count as usize * N)
            .await?;
        let mut records = Vec::new();
        for page in range.pages {
            let offset = (page.first - range.first) as usize * N;
            let page_bytes = bytes
                .get(offset..offset + page.count as usize * N)
                .ok_or_else(|| "truncated coalesced registry range".to_string())?;
            if let Some(key) =
                source.range_cache_key(path, page.first * N as u64, page.count as usize * N)
            {
                source.cache_bytes(key, page_bytes);
            }
            records.extend(extract_records::<N>(page_bytes, page.first, &page.ids)?);
        }
        Ok::<_, String>(records)
    }))
    .buffer_unordered(REGISTRY_CONCURRENCY)
    .try_collect::<Vec<_>>()
    .await?;
    out.extend(batches.into_iter().flatten());
    Ok(out)
}

type TailEntry = ([u8; 32], Option<u64>);

async fn resolve_blockhashes(
    source: &WorkerSource,
    epoch: u64,
    ids: &[i32],
    needs_tail: bool,
    budget: &RegistryBudget,
    identity: (u32, u32, u64),
    known_size: Option<u64>,
) -> std::result::Result<(BTreeMap<i32, [u8; 32]>, Vec<TailEntry>), String> {
    let positive_ids = ids
        .iter()
        .filter(|id| **id >= 0)
        .map(|id| *id as u64)
        .collect::<Vec<_>>();
    let path = epoch_file(
        &source.archive_prefix,
        epoch,
        ARCHIVE_V2_BLOCKHASH_REGISTRY_FILE,
    );
    let size = match known_size {
        Some(size) => size,
        None => source
            .object_size(&path)
            .await?
            .ok_or_else(|| "missing blockhash registry".to_string())?,
    };
    validate_hash_ordinal(identity.0, identity.1, identity.2, size)?;
    let tail_future = async {
        if !needs_tail {
            return Ok(Vec::new());
        }
        let path = epoch_file(
            &source.archive_prefix,
            epoch,
            ARCHIVE_V2_PREV_BLOCKHASH_TAIL_FILE,
        );
        let size = source
            .object_size(&path)
            .await?
            .ok_or_else(|| "required previous-blockhash tail is missing".to_string())?;
        if size == 0 || size > 300 * 40 {
            return Err("previous-blockhash tail exceeds its 300-record bound".to_string());
        }
        budget.reserve(size as usize)?;
        let _permit = budget.acquire().await;
        let bytes = source.get_cached_range(&path, 0, size as usize).await?;
        parse_tail(&bytes, epoch)
    };
    let (positive, tail) = future::try_join(
        read_records::<32>(source, &path, &positive_ids, budget, Some(size)),
        tail_future,
    )
    .await?;
    let mut out = BTreeMap::new();
    for id in ids {
        let hash = if *id >= 0 {
            *positive
                .get(&(*id as u64))
                .ok_or_else(|| "missing current blockhash".to_string())?
        } else {
            let index = i64::try_from(tail.len()).unwrap() + i64::from(*id);
            let index = usize::try_from(index)
                .map_err(|_| "negative blockhash ID is outside the previous tail".to_string())?;
            tail.get(index)
                .map(|entry| entry.0)
                .ok_or_else(|| "negative blockhash ID is outside the previous tail".to_string())?
        };
        out.insert(*id, hash);
    }
    Ok((out, tail))
}

fn validate_hash_ordinal(
    blockhash_id: u32,
    block_ordinal: u32,
    blocks: u64,
    registry_bytes: u64,
) -> std::result::Result<(), String> {
    if !registry_bytes.is_multiple_of(32) {
        return Err("blockhash registry has an invalid record width".to_string());
    }
    let records = registry_bytes / 32;
    if blocks == 0
        || u64::from(block_ordinal) >= blocks
        || (records != blocks && records != blocks + 1)
    {
        return Err("blockhash registry count differs from the hot index".to_string());
    }
    if u64::from(blockhash_id) != u64::from(block_ordinal) + records - blocks {
        return Err("decoded blockhash ID differs from the hot-index ordinal".to_string());
    }
    Ok(())
}

fn parse_tail(bytes: &[u8], epoch: u64) -> std::result::Result<Vec<TailEntry>, String> {
    let epoch_start = epoch
        .checked_mul(SLOTS_PER_EPOCH)
        .ok_or_else(|| "previous-tail epoch overflow".to_string())?;
    let previous_start = epoch
        .checked_sub(1)
        .and_then(|epoch| epoch.checked_mul(SLOTS_PER_EPOCH))
        .ok_or_else(|| "genesis cannot use a previous-epoch tail".to_string())?;
    let current = if !bytes.is_empty() && bytes.len().is_multiple_of(40) && bytes.len() / 40 <= 300
    {
        let rows = bytes
            .chunks_exact(40)
            .map(|row| {
                (
                    row[..32].try_into().unwrap(),
                    Some(u64::from_le_bytes(row[32..40].try_into().unwrap())),
                )
            })
            .collect::<Vec<TailEntry>>();
        let valid_slots = rows.iter().all(|entry| {
            entry
                .1
                .is_some_and(|slot| (previous_start..epoch_start).contains(&slot))
        });
        let ascending = rows.windows(2).all(|pair| pair[0].1 < pair[1].1);
        (valid_slots && ascending).then_some(rows)
    } else {
        None
    };
    let legacy = if !bytes.is_empty() && bytes.len().is_multiple_of(32) && bytes.len() / 32 <= 300 {
        Some(
            bytes
                .chunks_exact(32)
                .map(|hash| (hash.try_into().unwrap(), None))
                .collect::<Vec<TailEntry>>(),
        )
    } else {
        None
    };
    match (current, legacy) {
        (Some(tail), None) | (None, Some(tail)) => Ok(tail),
        (Some(_), Some(_)) => Err("previous-blockhash tail schema is ambiguous".to_string()),
        (None, None) => Err("invalid previous-blockhash tail".to_string()),
    }
}

fn collect_access_message_refs(
    message: &ArchiveV2HotMessagePayload,
    pubkey_ids: &mut Vec<u32>,
    blockhash_ids: &mut Vec<i32>,
) {
    match message {
        ArchiveV2HotMessagePayload::Legacy(message) => {
            collect_access_pubkeys(message.account_keys.iter().copied(), pubkey_ids);
            collect_access_recent_blockhash_id(&message.recent_blockhash, blockhash_ids);
        }
        ArchiveV2HotMessagePayload::V0(message) => {
            collect_access_pubkeys(message.account_keys.iter().copied(), pubkey_ids);
            collect_access_recent_blockhash_id(&message.recent_blockhash, blockhash_ids);
            for lookup in &message.address_table_lookups {
                collect_access_pubkey_id(lookup.account_key, pubkey_ids);
            }
        }
        ArchiveV2HotMessagePayload::V1(message) => {
            collect_access_pubkeys(message.account_keys.iter().copied(), pubkey_ids);
            collect_access_recent_blockhash_id(&message.recent_blockhash, blockhash_ids);
        }
    }
}

fn collect_access_message_vote_hash_refs(
    message: &ArchiveV2HotMessagePayload,
    vote_hash_block_ids: &mut Vec<u32>,
) {
    let instructions = match message {
        ArchiveV2HotMessagePayload::Legacy(message) => message.instructions.as_slice(),
        ArchiveV2HotMessagePayload::V0(message) => message.instructions.as_slice(),
        ArchiveV2HotMessagePayload::V1(message) => message.instructions.as_slice(),
    };
    for instruction in instructions {
        collect_access_instruction_vote_hash_refs(&instruction.data, vote_hash_block_ids);
    }
}

fn collect_access_instruction_vote_hash_refs(
    data: &ArchiveV2HotInstructionData,
    vote_hash_block_ids: &mut Vec<u32>,
) {
    match data {
        ArchiveV2HotInstructionData::VoteCompactUpdateVoteState(update) => {
            collect_access_vote_hash_ref(update.hash, vote_hash_block_ids);
        }
        ArchiveV2HotInstructionData::VoteCompactUpdateVoteStateSwitch { update, .. } => {
            collect_access_vote_hash_ref(update.hash, vote_hash_block_ids);
        }
        ArchiveV2HotInstructionData::VoteTowerSync(tower) => {
            collect_access_vote_hash_ref(tower.update.hash, vote_hash_block_ids);
            collect_access_vote_hash_ref(tower.block_id_hash, vote_hash_block_ids);
        }
        ArchiveV2HotInstructionData::VoteTowerSyncSwitch { tower, .. } => {
            collect_access_vote_hash_ref(tower.update.hash, vote_hash_block_ids);
            collect_access_vote_hash_ref(tower.block_id_hash, vote_hash_block_ids);
        }
        ArchiveV2HotInstructionData::Raw(_)
        | ArchiveV2HotInstructionData::UnknownSystem(_)
        | ArchiveV2HotInstructionData::UnknownVote(_)
        | ArchiveV2HotInstructionData::ComputeBudget(_)
        | ArchiveV2HotInstructionData::System(_) => {}
    }
}

fn collect_access_vote_hash_ref(value: ArchiveV2VoteHashRef, vote_hash_block_ids: &mut Vec<u32>) {
    if let ArchiveV2VoteHashRef::Block(block_id) = value {
        vote_hash_block_ids.push(block_id);
    }
}

fn collect_access_metadata_refs(metadata: &CompactMetaV1, pubkey_ids: &mut Vec<u32>) {
    collect_access_pubkeys(
        metadata
            .loaded_writable_addresses
            .iter()
            .chain(metadata.loaded_readonly_addresses.iter())
            .copied(),
        pubkey_ids,
    );
    for balance in metadata
        .pre_token_balances
        .iter()
        .chain(metadata.post_token_balances.iter())
    {
        if let Some(key) = balance.mint {
            collect_access_pubkey_id(key, pubkey_ids);
        }
        if let Some(key) = balance.owner {
            collect_access_pubkey_id(key, pubkey_ids);
        }
        if let Some(key) = balance.program_id {
            collect_access_pubkey_id(key, pubkey_ids);
        }
    }
    for reward in &metadata.rewards {
        collect_access_pubkey_id(reward.pubkey, pubkey_ids);
    }
    if let Some(return_data) = &metadata.return_data {
        collect_access_pubkey_id(return_data.program_id, pubkey_ids);
    }
    if let Some(logs) = &metadata.logs {
        collect_access_log_refs(logs, pubkey_ids);
    }
}

fn collect_access_pubkeys(keys: impl Iterator<Item = CompactPubkey>, pubkey_ids: &mut Vec<u32>) {
    for key in keys {
        collect_access_pubkey_id(key, pubkey_ids);
    }
}

fn collect_access_pubkey_id(key: CompactPubkey, pubkey_ids: &mut Vec<u32>) {
    if let CompactPubkey::Id(id) = key {
        pubkey_ids.push(id);
    }
}

fn collect_access_log_refs(logs: &CompactLogStream, pubkey_ids: &mut Vec<u32>) {
    for event in &logs.events {
        match event {
            LogEvent::LoaderUpgradedProgram { program }
            | LogEvent::BpfInvoke { program }
            | LogEvent::Consumed { program, .. }
            | LogEvent::Success { program }
            | LogEvent::BpfSuccess { program }
            | LogEvent::Failure { program, .. }
            | LogEvent::BpfFailure { program, .. }
            | LogEvent::FailureCustomProgramError { program, .. }
            | LogEvent::BpfFailureCustomProgramError { program, .. }
            | LogEvent::FailureInvalidAccountData { program }
            | LogEvent::BpfFailureInvalidAccountData { program }
            | LogEvent::FailureInvalidProgramArgument { program }
            | LogEvent::BpfFailureInvalidProgramArgument { program }
            | LogEvent::Return { program, .. }
            | LogEvent::Invoke { program, .. } => collect_access_pubkey_id(*program, pubkey_ids),
            LogEvent::LoaderFinalizedAccount { account }
            | LogEvent::RuntimeWritablePrivilegeEscalated { account }
            | LogEvent::RuntimeSignerPrivilegeEscalated { account }
            | LogEvent::RuntimeAccountOwnerBalanceVerificationFailed { account } => {
                collect_access_pubkey_id(*account, pubkey_ids)
            }
            LogEvent::ProgramIdLog { program, log } => {
                collect_access_pubkey_id(*program, pubkey_ids);
                collect_access_program_log_refs(log, pubkey_ids);
            }
            LogEvent::ProgramLog(log) | LogEvent::ProgramPlainLog(log) => {
                collect_access_program_log_refs(log, pubkey_ids);
            }
            LogEvent::ProgramNotDeployed { program } | LogEvent::ProgramNotCached { program } => {
                if let Some(program) = program {
                    collect_access_pubkey_id(*program, pubkey_ids);
                }
            }
            LogEvent::System(log) => collect_access_system_log_refs(log, pubkey_ids),
            LogEvent::LogTruncated
            | LogEvent::StakeMergingAccounts
            | LogEvent::ProgramLogError { .. }
            | LogEvent::ProgramAccountNotWritable
            | LogEvent::ProgramIdMismatch
            | LogEvent::ProgramNotUpgradeable
            | LogEvent::ProgramAndProgramDataAccountMismatch
            | LogEvent::ProgramWasExtendedInThisBlockAlready
            | LogEvent::BpfConsumed { .. }
            | LogEvent::FailedToComplete { .. }
            | LogEvent::CustomProgramError { .. }
            | LogEvent::Data { .. }
            | LogEvent::Consumption { .. }
            | LogEvent::CbRequestUnits { .. }
            | LogEvent::UnknownProgram { .. }
            | LogEvent::UnknownAccount { .. }
            | LogEvent::VerifyEd25519
            | LogEvent::VerifySecp256k1
            | LogEvent::CloseContextState
            | LogEvent::Plain { .. }
            | LogEvent::Unparsed { .. } => {}
        }
    }
}

fn collect_access_program_log_refs(log: &ProgramLog, pubkey_ids: &mut Vec<u32>) {
    if let ProgramLog::Token2022(
        Token2022Log::ErrorHarvestingFrom { account_key, .. }
        | Token2022Log::ErrorHarvestingFrom2 { account_key, .. }
        | Token2022Log::ErrorHarvestingFrom3 { account_key, .. }
        | Token2022Log::ErrorHarvestingFrom4 { account_key, .. },
    ) = log
    {
        collect_access_pubkey_id(*account_key, pubkey_ids);
    }
}

fn collect_access_system_log_refs(log: &SystemProgramLog, pubkey_ids: &mut Vec<u32>) {
    match log {
        SystemProgramLog::CreateAddressMismatch {
            provided_addr,
            derived_addr,
        }
        | SystemProgramLog::TransferFromAddressMismatch {
            provided_addr,
            derived_addr,
        } => {
            collect_access_pubkey_id(*provided_addr, pubkey_ids);
            collect_access_pubkey_or_string_ref(*derived_addr, pubkey_ids);
        }
        SystemProgramLog::CreateAccountAlreadyInUse { addr }
        | SystemProgramLog::AllocateAlreadyInUse { addr }
        | SystemProgramLog::AllocateToMustSign { addr }
        | SystemProgramLog::AllocateAccountAlreadyInUse { addr }
        | SystemProgramLog::AssignAccountMustSign { addr }
        | SystemProgramLog::CreateAccountAccountAlreadyInUse { addr } => {
            collect_access_system_address_refs(*addr, pubkey_ids);
        }
        SystemProgramLog::TransferFromMustSign { from } => {
            collect_access_pubkey_id(*from, pubkey_ids);
        }
        SystemProgramLog::NonceAccountMustBeWriteable { account, .. }
        | SystemProgramLog::NonceAccountMustBeSigner { account, .. }
        | SystemProgramLog::NonceAccountMustSign { account, .. }
        | SystemProgramLog::NonceAccountStateInvalid { account, .. } => {
            collect_access_pubkey_or_string_ref(*account, pubkey_ids);
        }
        SystemProgramLog::Instruction(_)
        | SystemProgramLog::AllocateRequestedTooLarge { .. }
        | SystemProgramLog::CreateAccountDataSizeLimitedInInnerInstructions { .. }
        | SystemProgramLog::TransferFromMustNotCarryData
        | SystemProgramLog::TransferInsufficient { .. }
        | SystemProgramLog::AdvanceNonceRecentBlockhashesEmpty
        | SystemProgramLog::InitializeNonceRecentBlockhashesEmpty
        | SystemProgramLog::AuthorizeNonceAccount { .. }
        | SystemProgramLog::NonceInsufficientLamports { .. }
        | SystemProgramLog::NonceCanOnlyAdvanceOncePerSlot { .. } => {}
    }
}

fn collect_access_system_address_refs(address: SystemAddress, pubkey_ids: &mut Vec<u32>) {
    match address {
        SystemAddress::Pubkey(pubkey) => collect_access_pubkey_or_string_ref(pubkey, pubkey_ids),
        SystemAddress::Debug { address, base } => {
            collect_access_pubkey_or_string_ref(address, pubkey_ids);
            if let Some(base) = base {
                collect_access_pubkey_or_string_ref(base, pubkey_ids);
            }
        }
    }
}

fn collect_access_pubkey_or_string_ref(value: PubkeyOrString, pubkey_ids: &mut Vec<u32>) {
    if let PubkeyOrString::Pubkey(pubkey) = value {
        collect_access_pubkey_id(pubkey, pubkey_ids);
    }
}

fn collect_access_recent_blockhash_id(
    value: &OwnedCompactRecentBlockhash,
    blockhash_ids: &mut Vec<i32>,
) {
    if let OwnedCompactRecentBlockhash::Id(id) = value {
        collect_access_blockhash_id(*id, blockhash_ids);
    }
}

fn collect_access_blockhash_id(id: i32, blockhash_ids: &mut Vec<i32>) {
    blockhash_ids.push(id);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: u32, slot: u64) -> ArchiveV2HotBlockIndexRow {
        ArchiveV2HotBlockIndexRow {
            block_id: id,
            slot,
            compressed_offset: u64::from(id) * 100,
            compressed_len: 100,
            uncompressed_len: 200,
            tx_count: 1,
            first_tx_ordinal: u64::from(id),
            first_signature_ordinal: u64::from(id),
            signature_count: 1,
        }
    }

    fn row_bytes(row: &ArchiveV2HotBlockIndexRow) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(row.block_id.to_le_bytes());
        bytes.extend(row.slot.to_le_bytes());
        bytes.extend(row.compressed_offset.to_le_bytes());
        bytes.extend(row.compressed_len.to_le_bytes());
        bytes.extend(row.uncompressed_len.to_le_bytes());
        bytes.extend(row.tx_count.to_le_bytes());
        bytes.extend(row.first_tx_ordinal.to_le_bytes());
        bytes.extend(row.first_signature_ordinal.to_le_bytes());
        bytes.extend(row.signature_count.to_le_bytes());
        bytes
    }

    #[test]
    fn index_header_checks_exact_object_length_and_frame_mode() {
        let mut bytes = vec![0; ARCHIVE_V2_HOT_INDEX_HEADER_LEN];
        bytes[..8].copy_from_slice(ARCHIVE_V2_HOT_INDEX_MAGIC);
        bytes[8..10].copy_from_slice(&ARCHIVE_V2_HOT_INDEX_VERSION.to_le_bytes());
        bytes[12..20].copy_from_slice(&2u64.to_le_bytes());
        bytes[20..28].copy_from_slice(&200u64.to_le_bytes());
        let size = (ARCHIVE_V2_HOT_INDEX_HEADER_LEN + 2 * ARCHIVE_V2_HOT_INDEX_ROW_LEN) as u64;
        assert_eq!(parse_index_header(&bytes, size).unwrap().rows, 2);
        assert!(parse_index_header(&bytes, size - 1).is_err());
        bytes[32] = 1;
        assert!(parse_index_header(&bytes, size).is_err());
    }

    #[test]
    fn sparse_page_accepts_skipped_slots_and_checks_offsets_and_ordinals() {
        let mut bytes = row_bytes(&row(0, 432_000));
        bytes.extend(row_bytes(&row(1, 432_002)));
        let rows = parse_index_page(&bytes, 1, 0, 200).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.binary_search_by_key(&432_001, |row| row.slot).is_err());
        assert!(parse_index_page(&bytes, 1, 1, 200).is_err());
        assert!(parse_index_page(&bytes, 1, 0, 199).is_err());
        bytes[ARCHIVE_V2_HOT_INDEX_ROW_LEN + 12] = 101;
        assert!(parse_index_page(&bytes, 1, 0, 201).is_err());
    }

    #[test]
    fn request_budget_is_shared_across_registry_kinds() {
        let budget = RegistryBudget::default();
        budget.reserve(12 * 1024 * 1024).unwrap();
        budget.reserve(4 * 1024 * 1024).unwrap();
        assert!(budget.reserve(1).is_err());
        assert_eq!(budget.bytes.get(), MAX_REGISTRY_REQUEST_BYTES);
    }

    #[test]
    fn sparse_hash_ordinal_binds_legacy_and_boundary_prefixed_registries() {
        validate_hash_ordinal(0, 0, 2, 64).unwrap();
        validate_hash_ordinal(1, 1, 2, 64).unwrap();
        validate_hash_ordinal(1, 0, 2, 96).unwrap();
        validate_hash_ordinal(2, 1, 2, 96).unwrap();
        assert!(validate_hash_ordinal(0, 0, 2, 96).is_err());
        assert!(validate_hash_ordinal(1, 0, 2, 64).is_err());
        assert!(validate_hash_ordinal(1, 0, 2, 128).is_err());
        assert!(validate_hash_ordinal(1, 0, 2, 95).is_err());
        assert!(validate_hash_ordinal(2, 2, 2, 96).is_err());
    }

    #[test]
    fn registry_pages_have_stable_keys_and_only_missing_neighbors_are_coalesced() {
        let pages = plan_registry_pages::<32>(&[2048, 4096, 10_240], 20_000).unwrap();
        assert_eq!(
            pages
                .iter()
                .map(|page| (page.first, page.count))
                .collect::<Vec<_>>(),
            vec![(2048, 2048), (4096, 2048), (10_240, 2048)]
        );
        let single = plan_registry_pages::<32>(&[4097], 20_000).unwrap();
        assert_eq!(
            (single[0].first, single[0].count),
            (pages[1].first, pages[1].count)
        );
        let ranges = coalesce_registry_pages::<32>(pages);
        assert_eq!(ranges.len(), 2);
        assert_eq!(
            (ranges[0].first, ranges[0].count, ranges[0].pages.len()),
            (2048, 4096, 2)
        );
        let all = plan_registry_pages::<32>(&[0, 2048, 4096, 6144, 8192], 20_000).unwrap();
        let ranges = coalesce_registry_pages::<32>(all);
        assert_eq!(ranges[0].count as usize * 32, MAX_REGISTRY_RANGE_BYTES);
        assert_eq!(ranges.len(), 2);
        assert!(plan_registry_pages::<32>(&[20_000], 20_000).is_err());
    }

    #[test]
    fn adaptive_registry_pages_admit_wide_ids_without_losing_references() {
        let ids = (0..1024).map(|id| id * 2048).collect::<Vec<_>>();
        let records = ids.last().unwrap() + 2048;
        let (pages, bytes) = plan_adaptive_registry_pages::<32>(&ids, records).unwrap();
        assert_eq!(bytes, MAX_REGISTRY_FAMILY_BYTES);
        assert_eq!(pages.len(), ids.len());
        // 64 KiB and 16 KiB pages exceed the family limit; 4 KiB fits.
        assert!(pages.iter().all(|page| page.count == 128));
        assert_eq!(
            pages
                .iter()
                .flat_map(|page| page.ids.iter().copied())
                .collect::<Vec<_>>(),
            ids
        );
        let same_page = plan_registry_pages_with_size::<32>(&[2049], records, 4096).unwrap();
        assert_eq!(
            (same_page[0].first, same_page[0].count),
            (pages[1].first, pages[1].count)
        );
    }

    #[test]
    fn adaptive_registry_pages_keep_the_largest_geometry_when_dense() {
        let ids = (0..65_536).collect::<Vec<_>>();
        let (pages, bytes) = plan_adaptive_registry_pages::<32>(&ids, 1_000_000).unwrap();
        assert_eq!(bytes, 2 * 1024 * 1024);
        assert_eq!(pages.len(), 32);
        assert!(
            pages
                .iter()
                .all(|page| page.count == (REGISTRY_PAGE_BYTES / 32) as u64)
        );
        assert_eq!(
            pages
                .iter()
                .flat_map(|page| page.ids.iter().copied())
                .collect::<Vec<_>>(),
            ids
        );
    }

    #[test]
    fn adaptive_registry_pages_respect_vote_record_width_and_coalesced_bounds() {
        let ids = (0..4096).map(|id| id * 1024).collect::<Vec<_>>();
        let records = ids.last().unwrap() + 1024;
        let (pages, bytes) = plan_adaptive_registry_pages::<65>(&ids, records).unwrap();
        // 4 KiB would exceed the limit; 1 KiB contains fifteen 65-byte records.
        assert!(pages.iter().all(|page| page.count == 15));
        assert_eq!(bytes, 4096 * 15 * 65);
        assert!(bytes <= MAX_REGISTRY_FAMILY_BYTES);
        assert_eq!(
            pages
                .iter()
                .flat_map(|page| page.ids.iter().copied())
                .collect::<Vec<_>>(),
            ids
        );
        assert!(
            coalesce_registry_pages::<65>(pages)
                .iter()
                .all(|range| range.count as usize * 65 <= MAX_REGISTRY_RANGE_BYTES)
        );
    }

    #[test]
    fn adaptive_registry_pages_reject_required_records_above_family_quota() {
        let ids = (0..65_536).collect::<Vec<_>>();
        let error = plan_adaptive_registry_pages::<65>(&ids, 65_536)
            .err()
            .unwrap();
        assert!(error.contains("4 MiB family limit"));
        assert!(plan_adaptive_registry_pages::<32>(&[10], 10).is_err());
        assert!(plan_adaptive_registry_pages::<0>(&[], 10).is_err());
    }

    #[test]
    fn registry_concurrency_limit_is_shared_and_releases_cancelled_reads() {
        use std::{
            future::Future,
            task::{Context, Poll},
        };
        let budget = RegistryBudget::default();
        let waker = futures_util::task::noop_waker();
        let mut context = Context::from_waker(&waker);
        let mut permits = Vec::new();
        for _ in 0..REGISTRY_CONCURRENCY {
            let mut future = Box::pin(budget.acquire());
            let Poll::Ready(permit) = future.as_mut().poll(&mut context) else {
                panic!("available permit was blocked");
            };
            permits.push(permit);
        }
        let mut waiting = Box::pin(budget.acquire());
        assert!(waiting.as_mut().poll(&mut context).is_pending());
        permits.pop();
        assert!(waiting.as_mut().poll(&mut context).is_ready());
    }

    #[test]
    fn tail_accepts_exact_schemas_and_rejects_ambiguous_or_wrong_epoch_rows() {
        let mut current = vec![7; 32];
        current.extend(431_999u64.to_le_bytes());
        assert_eq!(
            parse_tail(&current, 1).unwrap(),
            vec![([7; 32], Some(431_999))]
        );
        assert_eq!(parse_tail(&[8; 32], 1).unwrap(), vec![([8; 32], None)]);
        assert!(parse_tail(&current, 0).is_err());
        current[32..40].copy_from_slice(&432_000u64.to_le_bytes());
        assert!(parse_tail(&current, 1).is_err());
        let mut ambiguous = Vec::new();
        for slot in 431_996u64..432_000 {
            ambiguous.extend([9; 32]);
            ambiguous.extend(slot.to_le_bytes());
        }
        assert!(parse_tail(&ambiguous, 1).unwrap_err().contains("ambiguous"));
    }

    #[test]
    fn block_validation_checks_index_signature_count_and_transaction_regions() {
        let index = row(0, 432_000);
        let mut block = ArchiveV2HotBlockBlob {
            consensus_block_id: None,
            block_markers: Vec::new(),
            header: blockzilla_archive_v2::ArchiveV2HotBlockHeader {
                slot: 432_000,
                parent_slot: 431_999,
                blockhash_id: 1,
                previous_blockhash_id: 0,
                block_time: None,
                block_height: None,
                rewards: None,
            },
            tx_count: 1,
            tx_rows: vec![ArchiveV2HotTxRow {
                signature_count: 1,
                ..Default::default()
            }],
            message_bytes: Vec::new(),
            metadata_bytes: Vec::new(),
        };
        validate_block(&block, &index).unwrap();
        block.tx_rows[0].signature_count = 2;
        assert!(validate_block(&block, &index).is_err());
        block.tx_rows[0].signature_count = 1;
        block.tx_rows[0].message_len = 1;
        assert!(validate_block(&block, &index).is_err());
    }

    #[test]
    fn sparse_genesis_has_an_explicit_zero_parent_without_a_previous_epoch() {
        let index = row(0, 0);
        let mut block = ArchiveV2HotBlockBlob {
            consensus_block_id: None,
            block_markers: Vec::new(),
            header: blockzilla_archive_v2::ArchiveV2HotBlockHeader {
                slot: 0,
                parent_slot: 0,
                blockhash_id: 0,
                previous_blockhash_id: 0,
                block_time: None,
                block_height: None,
                rewards: None,
            },
            tx_count: 1,
            tx_rows: vec![ArchiveV2HotTxRow {
                signature_count: 1,
                ..Default::default()
            }],
            message_bytes: Vec::new(),
            metadata_bytes: Vec::new(),
        };
        validate_block(&block, &index).unwrap();
        block.header.parent_slot = 1;
        assert!(validate_block(&block, &index).is_err());
        block.header.parent_slot = 0;
        block.header.previous_blockhash_id = 1;
        assert!(validate_block(&block, &index).is_err());
    }

    #[test]
    fn historical_full_bundle_normalizes_exact_records_and_repairs_region_offsets() {
        // Real source records also checked by the native reader and schema codec.
        let hex = "0002010206121813150e0d00c0e60c02040202000209ccf1736d29ad6e301871d2d5a34e01709272ebdc60b9b855a31b7c3036fae9360131c80106a1d8179137542a983437bdfe2a7ab2557f535c8a78722b68a49dc0000000000503030201000c030000000080c6a47e8d0300";
        let message = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect::<Vec<_>>();
        let metadata = vec![
            0x01, 0x0d, 0x08, 0x00, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x90, 0x4e, 0x03, 0xcc, 0xef, 0xf0, 0xf2, 0x32, 0x80, 0xf6, 0xed, 0xdf, 0x09,
            0x01, 0x03, 0xbc, 0xa1, 0xf0, 0xf2, 0x32, 0x80, 0xf6, 0xed, 0xdf, 0x09, 0x01, 0x01,
            0x00, 0x01, 0x02, 0x0e, 0x03, 0x01, 0x16, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xb4, 0x10, 0x01, 0xe4, 0x1a,
        ];
        let mut block = ArchiveV2HotBlockBlob {
            consensus_block_id: None,
            block_markers: Vec::new(),
            header: blockzilla_archive_v2::ArchiveV2HotBlockHeader {
                slot: 432_000,
                parent_slot: 431_999,
                blockhash_id: 1,
                previous_blockhash_id: 0,
                block_time: None,
                block_height: None,
                rewards: None,
            },
            tx_count: 2,
            tx_rows: Vec::new(),
            message_bytes: vec![0xff],
            metadata_bytes: vec![0xee],
        };
        for tx_index in 0..2 {
            block.tx_rows.push(ArchiveV2HotTxRow {
                tx_index,
                flags: ARCHIVE_V2_TX_FLAG_HAS_METADATA,
                message_offset: block.message_bytes.len() as u32,
                message_len: message.len() as u32,
                metadata_offset: block.metadata_bytes.len() as u32,
                metadata_len: metadata.len() as u32,
                signature_count: 2,
                reserved: [0; 3],
            });
            block.message_bytes.extend(&message);
            block.message_bytes.push(0xff);
            block.metadata_bytes.extend(&metadata);
            block.metadata_bytes.push(0xee);
        }
        let bytes =
            normalize_historical_hot_block(block, (MessageSchema::May24, MetadataSchema::Legacy))
                .unwrap();
        let normalized: ArchiveV2HotBlockBlob =
            wincode::config::deserialize_exact(&bytes, wincode_leb128_config()).unwrap();
        assert_eq!(normalized.tx_rows[0].message_offset, 0);
        assert_eq!(normalized.tx_rows[0].metadata_offset, 0);
        assert_eq!(
            normalized.tx_rows[1].message_offset,
            normalized.tx_rows[0].message_len
        );
        assert_eq!(
            normalized.tx_rows[1].metadata_offset,
            normalized.tx_rows[0].metadata_len
        );
        assert_eq!(normalized.tx_rows[1].signature_count, 2);
        for row in &normalized.tx_rows {
            let ArchiveV2HotMessagePayload::Legacy(message) =
                decode_message(&normalized, row, MessageSchema::Current).unwrap()
            else {
                panic!("expected legacy message");
            };
            assert!(
                matches!(&message.instructions[0].data, ArchiveV2HotInstructionData::System(blockzilla_archive_v2::ArchiveV2SystemInstructionData::AllocateWithSeed { space: 200, seed, .. }) if seed == "1")
            );
            let meta = decode_metadata(&normalized, row, MetadataSchema::Current)
                .unwrap()
                .unwrap();
            assert_eq!(meta.fee, 10_000);
            assert!(matches!(
                meta.err,
                Some(StoredTransactionError::InstructionError(
                    0,
                    InstructionError::Custom(0)
                ))
            ));
            assert_eq!(meta.compute_units_consumed, Some(2_100));
        }
    }
}
